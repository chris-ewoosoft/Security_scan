# Security Portal - Authenticated Scan with Access Token

# Step 1: Register new test user
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$testUsername = "testuser-$timestamp"
$testEmail = "test-$timestamp@local.test"
$testPassword = "Test@123456789"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Step 1: Registering new test user..."
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$registerRequest = @{
    Email = $testEmail
    Username = $testUsername
    Password = $testPassword
    FirstName = "Test"
    LastName = "User"
    OrganizationName = "SecurityPortal Test"
}

try {
    $registerResponse = Invoke-RestMethod -Uri "http://localhost/api/v1/auth/register" `
        -Method Post `
        -Body ($registerRequest | ConvertTo-Json) `
        -ContentType "application/json" `
        -ErrorAction Stop
    
    Write-Host "Registration successful!" -ForegroundColor Green
    Write-Host ""
    
    $token = $registerResponse.accessToken
    
} catch {
    Write-Host "Registration failed:" -ForegroundColor Red
    Write-Host $_.Exception.Message
    exit 1
}

# Step 2: Create new authenticated scan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Step 2: Creating authenticated scan..."
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$scanRequest = @{
    TargetUrl = "https://cvmanager.vnm2.vnclever.com/login"
    Checks = @("reachability", "https-tls", "security-headers", "authenticated-scan", "cookie-security", "information-disclosure")
    Tools = @("http-probe", "ssl-checker", "header-analyzer", "fingerprint", "cookie-inspector")
    ReportType = "technical"
    Auth = @{
        Type = "form"
        LoginUrl = "https://cvmanager.vnm2.vnclever.com/login"
        Username = "admin"
        Password = "2026clever!"
        UsernameField = "username"
        PasswordField = "password"
        SuccessUrlContains = "dashboard"
    }
}

$json = $scanRequest | ConvertTo-Json -Depth 10

try {
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type" = "application/json"
    }
    
    $response = Invoke-RestMethod -Uri "http://localhost/api/v1/scans" `
        -Method Post `
        -Body $json `
        -Headers $headers `
        -ErrorAction Stop
    
    Write-Host "Scan created successfully!" -ForegroundColor Green
    Write-Host "Scan ID: $($response.id)"
    Write-Host "Status: $($response.status)"
    Write-Host "Target: $($response.targetUrl)"
    Write-Host "Created: $($response.createdAt)"
    Write-Host "Access Token: $($response.accessToken.Substring(0, 50))..."
    Write-Host ""
    
    $scanId = $response.id
    $scanAccessToken = $response.accessToken
    
} catch {
    Write-Host "Failed to create scan:" -ForegroundColor Red
    Write-Host $_.Exception.Message
    
    if ($_.Exception.Response) {
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = [System.IO.StreamReader]::new($stream)
        $errorBody = $reader.ReadToEnd()
        Write-Host ""
        Write-Host "Response body:"
        Write-Host $errorBody
    }
    exit 1
}

# Step 3: Monitor scan progress using scan's access token
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Step 3: Monitoring scan progress..."
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$maxAttempts = 120
$attempt = 0
$lastStatus = ""

while ($attempt -lt $maxAttempts) {
    $attempt++
    
    try {
        # Use X-Scan-Token header for hardened access
        $headers = @{
            "X-Scan-Token" = $scanAccessToken
        }
        
        $status = Invoke-RestMethod -Uri "http://localhost/api/v1/scans/$scanId" `
            -Method Get `
            -Headers $headers
        
        $progressStr = if ($status.progress) { "$($status.progress)%" } else { "N/A" }
        
        # Only print if status changed to reduce noise
        if ($status.status -ne $lastStatus) {
            Write-Host "[$attempt/$maxAttempts] Status changed to: $($status.status) - Progress: $progressStr" -ForegroundColor Yellow
            $lastStatus = $status.status
        } else {
            Write-Host "[$attempt/$maxAttempts] Status: $($status.status) - Progress: $progressStr"
        }
        
        if ($status.status -eq "Completed" -or $status.status -eq "Failed") {
            Write-Host ""
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host "Scan $($status.status)!" -ForegroundColor Green
            Write-Host "========================================" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Scan Details:"
            Write-Host "  Response Time: $($status.responseTimeMs)ms"
            Write-Host "  HTTP Status Code: $($status.httpStatusCode)"
            Write-Host "  Has HTTPS: $($status.hasHttps)"
            Write-Host "  Findings Count: $($status.findings.Count)"
            
            if ($status.findings.Count -gt 0) {
                Write-Host ""
                Write-Host "Security Findings:" -ForegroundColor Cyan
                Write-Host "==================" -ForegroundColor Cyan
                
                $findings = $status.findings | Group-Object -Property severity
                
                $findings | ForEach-Object {
                    Write-Host ""
                    Write-Host "[$($_.Name.ToUpper())] - $($_.Count) finding(s)" -ForegroundColor Yellow
                    $_.Group | ForEach-Object {
                        Write-Host "  • $($_.checkName)"
                        Write-Host "    Title: $($_.title)"
                        if ($_.detail) {
                            Write-Host "    Detail: $($_.detail)"
                        }
                        if ($_.evidence) {
                            Write-Host "    Evidence: $($_.evidence)"
                        }
                        if ($_.recommendation) {
                            Write-Host "    Recommendation: $($_.recommendation)"
                        }
                    }
                }
            } else {
                Write-Host ""
                Write-Host "No security findings detected." -ForegroundColor Green
            }
            
            break
        }
    } catch {
        Write-Host "Error retrieving scan status: $($_.Exception.Message)" -ForegroundColor Red
        
        if ($_.Exception.Response) {
            $stream = $_.Exception.Response.GetResponseStream()
            $reader = [System.IO.StreamReader]::new($stream)
            $errorBody = $reader.ReadToEnd()
            Write-Host "Response: $errorBody"
        }
        
        break
    }
    
    Start-Sleep -Seconds 2
}

if ($attempt -ge $maxAttempts) {
    Write-Host ""
    Write-Host "Scan monitoring timeout after $($maxAttempts * 2) seconds!" -ForegroundColor Red
    Write-Host "The scan may still be processing in the background."
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
