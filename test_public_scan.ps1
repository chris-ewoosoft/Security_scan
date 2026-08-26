# Security Portal - Test with public website

# Step 1: Register new test user
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$testUsername = "testuser-$timestamp"
$testEmail = "test-$timestamp@local.test"
$testPassword = "Test@123456789"

Write-Host "Step 1: Registering new test user..." -ForegroundColor Cyan
$registerRequest = @{
    Email = $testEmail
    Username = $testUsername
    Password = $testPassword
    FirstName = "Test"
    LastName = "User"
    OrganizationName = "SecurityPortal Test"
}

$registerResponse = Invoke-RestMethod -Uri "http://localhost/api/v1/auth/register" `
    -Method Post `
    -Body ($registerRequest | ConvertTo-Json) `
    -ContentType "application/json"

$token = $registerResponse.accessToken
Write-Host "User registered successfully" -ForegroundColor Green

# Step 2: Create scan targeting public website
Write-Host ""
Write-Host "Step 2: Creating scan for public website..." -ForegroundColor Cyan

$scanRequest = @{
    TargetUrl = "https://example.com"
    Checks = @("reachability", "https-tls", "security-headers", "cookie-security", "information-disclosure", "cors-policy")
    Tools = @("http-probe", "ssl-checker", "header-analyzer", "fingerprint", "cookie-inspector", "cors-checker")
    ReportType = "technical"
}

$response = Invoke-RestMethod -Uri "http://localhost/api/v1/scans" `
    -Method Post `
    -Body ($scanRequest | ConvertTo-Json -Depth 10) `
    -Headers @{
        "Authorization" = "Bearer $token"
        "Content-Type" = "application/json"
    }

$scanId = $response.id
$scanAccessToken = $response.accessToken

Write-Host "Scan created: $scanId" -ForegroundColor Green
Write-Host ""

# Step 3: Monitor scan
Write-Host "Step 3: Monitoring scan progress..." -ForegroundColor Cyan
$maxAttempts = 120
$attempt = 0

while ($attempt -lt $maxAttempts) {
    $attempt++
    
    $status = Invoke-RestMethod -Uri "http://localhost/api/v1/scans/$scanId" `
        -Method Get `
        -Headers @{ "X-Scan-Token" = $scanAccessToken }
    
    $progress = if ($status.progress) { "$($status.progress)%" } else { "N/A" }
    Write-Host "[$attempt] Status: $($status.status) - Progress: $progress - Findings: $($status.findings.Count)"
    
    if ($status.status -eq "Completed" -or $status.status -eq "Failed") {
        Write-Host ""
        Write-Host "Scan $($status.status)" -ForegroundColor Green
        Write-Host "==================" -ForegroundColor Green
        Write-Host "Response Time: $($status.responseTimeMs)ms"
        Write-Host "HTTP Status: $($status.httpStatusCode)"
        Write-Host "Has HTTPS: $($status.hasHttps)"
        Write-Host "Findings: $($status.findings.Count)"
        
        if ($status.findings.Count -gt 0) {
            Write-Host ""
            Write-Host "Findings:" -ForegroundColor Yellow
            $status.findings | ForEach-Object {
                Write-Host "  [$($_.severity)] $($_.checkName): $($_.title)"
                if ($_.detail) { Write-Host "    > $($_.detail)" }
            }
        }
        break
    }
    
    Start-Sleep -Seconds 2
}
