# Security Portal - Register User, Authenticate, and Monitor Scan

# Unique test user credentials
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$testUsername = "testuser-$timestamp"
$testEmail = "test-$timestamp@local.test"
$testPassword = "Test@123456789"

Write-Host "Step 1: Registering new test user..."
Write-Host "  Username: $testUsername"
Write-Host "  Email: $testEmail"
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
    Write-Host "User ID: $($registerResponse.user.id)"
    Write-Host "Access Token: $($registerResponse.accessToken.Substring(0, 50))..."
    Write-Host ""
    
    $token = $registerResponse.accessToken
    
} catch {
    Write-Host "Registration failed:" -ForegroundColor Red
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

# Now try to get the previously created scan
$scanId = "e3dc21f2-243d-4e62-99b9-efa50dbe8492"
Write-Host "Step 2: Retrieving previously created scan..."
Write-Host "Scan ID: $scanId"
Write-Host ""

try {
    $headers = @{
        "Authorization" = "Bearer $token"
    }
    
    $scanStatus = Invoke-RestMethod -Uri "http://localhost/api/v1/scans/$scanId" `
        -Method Get `
        -Headers $headers `
        -ErrorAction Stop
    
    Write-Host "Scan retrieved successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Target URL: $($scanStatus.targetUrl)"
    Write-Host "Status: $($scanStatus.status)"
    Write-Host "Created: $($scanStatus.createdAt)"
    Write-Host "Progress: $($scanStatus.progress)%"
    
    if ($scanStatus.findings) {
        Write-Host "Findings Count: $($scanStatus.findings.Count)"
        if ($scanStatus.findings.Count -gt 0) {
            Write-Host ""
            Write-Host "Findings:" -ForegroundColor Cyan
            $scanStatus.findings | ForEach-Object {
                Write-Host "  - $($_.checkName) [$($_.severity)]: $($_.title)"
            }
        }
    }
    
    # If scan is still in progress, monitor it
    if ($scanStatus.status -ne "Completed" -and $scanStatus.status -ne "Failed") {
        Write-Host ""
        Write-Host "Step 3: Monitoring scan progress..."
        Write-Host ""
        
        $maxAttempts = 120
        $attempt = 0
        
        while ($attempt -lt $maxAttempts) {
            $attempt++
            
            try {
                $status = Invoke-RestMethod -Uri "http://localhost/api/v1/scans/$scanId" `
                    -Method Get `
                    -Headers $headers
                
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
    }
    
} catch {
    Write-Host "Error retrieving scan:" -ForegroundColor Red
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
