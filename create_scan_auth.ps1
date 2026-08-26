# Security Portal - Authentication and Scan Monitoring

# First, get an authentication token
$authRequest = @{
    Email = "admin@securityportal.local"
    Password = "Admin123!"
}

Write-Host "Step 1: Requesting authentication token..."
Write-Host ""

try {
    $authResponse = Invoke-RestMethod -Uri "http://localhost/api/v1/auth/login" -Method Post -Body ($authRequest | ConvertTo-Json) -ContentType "application/json"
    Write-Host "Authentication successful!" -ForegroundColor Green
    Write-Host "Access Token: $($authResponse.accessToken.Substring(0, 50))..."
    Write-Host "Refresh Token: $($authResponse.refreshToken.Substring(0, 50))..."
    $token = $authResponse.accessToken
} catch {
    Write-Host "Authentication failed:" -ForegroundColor Red
    Write-Host $_.Exception.Message
    Write-Host ""
    
    if ($_.Exception.Response) {
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = [System.IO.StreamReader]::new($stream)
        $errorBody = $reader.ReadToEnd()
        Write-Host "Response body:"
        Write-Host $errorBody
    }
    exit 1
}

Write-Host ""
Write-Host "Step 2: Creating scan request..."
Write-Host ""

# Create scan for target
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
    
    $response = Invoke-RestMethod -Uri "http://localhost/api/v1/scans" -Method Post -Body $json -Headers $headers
    Write-Host "Scan created successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Scan ID: $($response.id)"
    Write-Host "Status: $($response.status)"
    Write-Host "Target: $($response.targetUrl)"
    Write-Host "Created: $($response.createdAt)"
    
    # Store scan ID for monitoring
    $scanId = $response.id
    
    # Monitor scan progress
    Write-Host ""
    Write-Host "Step 3: Monitoring scan progress..."
    Write-Host ""
    
    $maxAttempts = 120
    $attempt = 0
    
    while ($attempt -lt $maxAttempts) {
        $attempt++
        
        try {
            $headers = @{
                "Authorization" = "Bearer $token"
            }
            
            $status = Invoke-RestMethod -Uri "http://localhost/api/v1/scans/$scanId" -Method Get -Headers $headers
            
            $progressStr = if ($status.progress) { "$($status.progress)%" } else { "N/A" }
            
            Write-Host "[$attempt/$maxAttempts] Status: $($status.status) - Progress: $progressStr"
            
            if ($status.status -eq "Completed" -or $status.status -eq "Failed") {
                Write-Host ""
                Write-Host "Scan $($status.status)!" -ForegroundColor Green
                Write-Host ""
                Write-Host "Response Time: $($status.responseTimeMs)ms"
                Write-Host "HTTP Status: $($status.httpStatusCode)"
                Write-Host "Has HTTPS: $($status.hasHttps)"
                Write-Host "Findings Count: $($status.findings.Count)"
                
                # Display findings
                if ($status.findings.Count -gt 0) {
                    Write-Host ""
                    Write-Host "Findings:" -ForegroundColor Cyan
                    $status.findings | ForEach-Object {
                        Write-Host "  - $($_.checkName) [$($_.severity)]: $($_.title)"
                        if ($_.detail) {
                            Write-Host "    Detail: $($_.detail)"
                        }
                    }
                }
                
                break
            }
        } catch {
            Write-Host "Error retrieving scan status: $($_.Exception.Message)" -ForegroundColor Yellow
            break
        }
        
        Start-Sleep -Seconds 2
    }
    
    if ($attempt -ge $maxAttempts) {
        Write-Host ""
        Write-Host "Scan monitoring timeout after $($maxAttempts * 2) seconds!" -ForegroundColor Red
    }
    
} catch {
    Write-Host "Error creating scan:" -ForegroundColor Red
    Write-Host $_.Exception.Message
    
    if ($_.Exception.Response) {
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = [System.IO.StreamReader]::new($stream)
        $errorBody = $reader.ReadToEnd()
        Write-Host ""
        Write-Host "Response body:"
        Write-Host $errorBody
    }
}
