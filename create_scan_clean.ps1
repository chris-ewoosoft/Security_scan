# Security Portal - Create and Monitor Scan

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

Write-Host "Creating scan request..."
Write-Host $json

try {
    $response = Invoke-RestMethod -Uri "http://localhost/api/v1/scans" -Method Post -Body $json -ContentType "application/json" -ErrorAction Stop
    Write-Host ""
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
    Write-Host "Monitoring scan progress..."
    $maxAttempts = 120
    $attempt = 0
    
    while ($attempt -lt $maxAttempts) {
        $attempt++
        $status = Invoke-RestMethod -Uri "http://localhost/api/v1/scans/$scanId" -Method Get
        
        $progressStr = ""
        if ($status.progress) {
            $progressStr = "$($status.progress)%"
        } else {
            $progressStr = "N/A"
        }
        
        Write-Host "[$attempt] Status: $($status.status) - Progress: $progressStr"
        
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
                }
            }
            
            # Display report summary if available
            if ($status.summary) {
                Write-Host ""
                Write-Host "Report Summary:" -ForegroundColor Cyan
                Write-Host $status.summary
            }
            break
        }
        
        Start-Sleep -Seconds 2
    }
    
    if ($attempt -ge $maxAttempts) {
        Write-Host "Scan monitoring timeout!" -ForegroundColor Red
    }
    
} catch {
    Write-Host "Error creating scan:" -ForegroundColor Red
    Write-Host $_.Exception.Message
    
    if ($_.Exception.Response) {
        $stream = $_.Exception.Response.GetResponseStream()
        $reader = [System.IO.StreamReader]::new($stream)
        $errorBody = $reader.ReadToEnd()
        Write-Host ""
        Write-Host "Detailed Error Response:"
        Write-Host $errorBody
    }
}
