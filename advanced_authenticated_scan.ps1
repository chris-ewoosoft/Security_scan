# Security Portal - Advanced Authenticated Scan Example
# This script demonstrates scanning with login credentials and detailed analysis

Write-Host ""
Write-Host "========== Security Portal - Advanced Authenticated Scan ==========" -ForegroundColor Cyan
Write-Host ""

# Step 1: Register test user
Write-Host "--- Step 1: User Registration" -ForegroundColor Cyan

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$testUsername = "scan-$timestamp"
$testEmail = "scan-$timestamp@local"
$testPassword = "SecureTest@123456789"

$registerRequest = @{
    Email = $testEmail
    Username = $testUsername
    Password = $testPassword
    FirstName = "Scanner"
    LastName = "Bot"
    OrganizationName = "Security Scanning"
} | ConvertTo-Json

try {
    $registerResponse = Invoke-RestMethod -Uri "http://localhost/api/v1/auth/register" `
        -Method Post `
        -Body $registerRequest `
        -ContentType "application/json" `
        -ErrorAction Stop
    
    $token = $registerResponse.accessToken
    $userId = $registerResponse.user.id
    
    Write-Host "[OK] User registered"
    Write-Host "     Username: $testUsername"
    Write-Host "     User ID: $userId"
} catch {
    Write-Host "[ERROR] Registration failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Step 2: Create authenticated scan
Write-Host "--- Step 2: Scan Creation" -ForegroundColor Cyan

$scanRequest = @{
    TargetUrl = "https://cvmanager.vnm2.vnclever.com/login"
    Checks = @(
        "reachability",
        "https-tls",
        "security-headers",
        "server-fingerprint",
        "cookie-security",
        "information-disclosure",
        "authenticated-scan"
    )
    Tools = @(
        "http-probe",
        "ssl-checker",
        "header-analyzer",
        "fingerprint",
        "cookie-inspector"
    )
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
} | ConvertTo-Json -Depth 10

$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

try {
    $scanResponse = Invoke-RestMethod -Uri "http://localhost/api/v1/scans" `
        -Method Post `
        -Body $scanRequest `
        -Headers $headers `
        -ErrorAction Stop
    
    $scanId = $scanResponse.id
    $scanToken = $scanResponse.accessToken
    
    Write-Host "[OK] Scan created"
    Write-Host "     Scan ID: $scanId"
    Write-Host "     Status: $($scanResponse.status)"
} catch {
    Write-Host "[ERROR] Scan creation failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Step 3: Monitor scan progress
Write-Host "--- Step 3: Scan Execution" -ForegroundColor Cyan

$scanHeaders = @{ "X-Scan-Token" = $scanToken }
$maxAttempts = 120
$attempt = 0
$lastStatus = ""
$startTime = Get-Date

while ($attempt -lt $maxAttempts) {
    $attempt++
    
    try {
        $status = Invoke-RestMethod -Uri "http://localhost/api/v1/scans/$scanId" `
            -Method Get `
            -Headers $scanHeaders
        
        $elapsed = (Get-Date) - $startTime
        $progress = if ($status.progress) { [int]$status.progress } else { 0 }
        
        if ($status.status -ne $lastStatus) {
            Write-Host "     Status: $($status.status.PadRight(12)) Progress: $($progress.ToString().PadRight(3))%  Time: $([math]::Round($elapsed.TotalSeconds, 1))s"
            $lastStatus = $status.status
        }
        
        if ($status.status -eq "Completed" -or $status.status -eq "Failed") {
            Write-Host ""
            
            # Display results
            Write-Host "--- Step 4: Scan Results" -ForegroundColor Cyan
            
            Write-Host ""
            Write-Host "Summary:"
            Write-Host "  Status: $($status.status)"
            Write-Host "  Response Time: $($status.responseTimeMs)ms"
            Write-Host "  HTTP Status Code: $($status.httpStatusCode)"
            Write-Host "  HTTPS Available: $(if ($status.hasHttps) {'Yes'} else {'No'})"
            Write-Host "  Total Findings: $($status.findings.Count)"
            
            if ($status.findings.Count -gt 0) {
                Write-Host ""
                Write-Host "Findings by Severity:"
                $bySeverity = $status.findings | Group-Object -Property severity
                foreach ($group in $bySeverity) {
                    Write-Host "  [$($group.Name.PadRight(8))]: $($group.Count) findings"
                    
                    $group.Group | ForEach-Object {
                        Write-Host "    - $($_.checkName): $($_.title)"
                        if ($_.detail) { Write-Host "      Detail: $($_.detail)" }
                    }
                }
            } else {
                Write-Host ""
                Write-Host "No security findings detected."
            }
            
            Write-Host ""
            Write-Host "Statistics:"
            Write-Host "  Total Execution Time: $([math]::Round($elapsed.TotalSeconds, 2))s"
            Write-Host "  Unique Checks: $(($status.findings | Select-Object -ExpandProperty checkName -Unique | Measure-Object).Count)"
            
            Write-Host ""
            Write-Host "========== Scan Complete [OK] ==========" -ForegroundColor Green
            
            break
        }
    } catch {
        Write-Host ""
        Write-Host "[ERROR] Status retrieval failed: $($_.Exception.Message)" -ForegroundColor Red
        break
    }
    
    Start-Sleep -Seconds 2
}

if ($attempt -ge $maxAttempts) {
    Write-Host ""
    Write-Host "[WARNING] Scan monitoring timeout after $($maxAttempts * 2) seconds" -ForegroundColor Yellow
}

Write-Host ""
