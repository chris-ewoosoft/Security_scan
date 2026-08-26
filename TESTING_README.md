# Security Portal - API Testing Scripts & Documentation

This folder contains production-ready PowerShell scripts for testing and integrating with the Security Portal REST API.

## Quick Start

### 1. Full Scan Workflow (Recommended)
```powershell
.\full_scan_workflow.ps1
```
✅ **Best for:** Complete end-to-end testing with all details  
- Registers new user
- Creates authenticated scan  
- Monitors scan in real-time
- Displays findings with recommendations

**Example Run:**
```
Step 1: Registering new test user...
[Successful registration]

Step 2: Creating authenticated scan...
Scan created successfully!
  Scan ID: f68cb83f-f3c8-4aa5-82b1-3c7a398f2720
  Status: Queued

Step 3: Monitoring scan progress...
[3/120] Status: Completed - Findings: 0
```

### 2. Public Website Scan
```powershell
.\test_public_scan.ps1
```
✅ **Best for:** Quick test against a public website  
- Tests against example.com
- Verifies basic scan functionality
- Fast execution (< 5 seconds)

### 3. Advanced Authenticated Scan
```powershell
.\advanced_authenticated_scan.ps1
```
✅ **Best for:** Testing authenticated scanning with credentials  
- Scans targets that require login
- Provides detailed result formatting
- Includes severity breakdowns

## API Architecture

### Authentication Flow
```
User Registration
  └─> POST /api/v1/auth/register
      └─> Returns: accessToken, refreshToken
      
Create Scan (with Bearer token)
  └─> POST /api/v1/scans
      └─> Returns: scanId, accessToken (for hardened access)
      
Monitor Scan (with X-Scan-Token header)
  └─> GET /api/v1/scans/{scanId}
      └─> Returns: status, findings, progress
```

### Key Concepts

**Bearer Token (JWT)**
- Issued on user registration/login
- Valid for 1 hour
- Used for: creating scans, accessing user's own scans
- Sent in: `Authorization: Bearer {token}` header

**Scan Access Token**
- Issued when scan is created
- Unique per scan
- Used for: retrieving scan results with hardened access
- Sent in: `X-Scan-Token: {token}` header
- Allows anonymous users to check scan status

## API Endpoints Reference

### Register User
```http
POST /api/v1/auth/register
Content-Type: application/json

Request:
{
  "email": "user@example.com",
  "username": "testuser",
  "password": "Test@123456789",
  "firstName": "Test",
  "lastName": "User",
  "organizationName": "Test Org"
}

Response:
{
  "accessToken": "eyJhbGc...",
  "refreshToken": "...",
  "accessTokenExpiry": "2026-08-26T10:30:00Z",
  "user": { "id": "...", "username": "testuser", ... }
}
```

### Create Scan
```http
POST /api/v1/scans
Authorization: Bearer {accessToken}
Content-Type: application/json

Request:
{
  "targetUrl": "https://example.com",
  "checks": ["reachability", "https-tls", "security-headers"],
  "tools": ["http-probe", "ssl-checker", "header-analyzer"],
  "reportType": "technical",
  "auth": {
    "type": "form",
    "loginUrl": "https://example.com/login",
    "username": "admin",
    "password": "password",
    "usernameField": "username",
    "passwordField": "password",
    "successUrlContains": "dashboard"
  }
}

Response:
{
  "id": "f68cb83f-f3c8-4aa5-82b1-3c7a398f2720",
  "status": "Queued",
  "targetUrl": "https://example.com",
  "createdAt": "2026-08-26T09:31:20Z",
  "accessToken": "972EFBDC1CA5BAB5FBECB283...",
  "checksSelected": ["reachability", "https-tls", ...],
  ...
}
```

### Get Scan Status
```http
GET /api/v1/scans/{scanId}
X-Scan-Token: {scanAccessToken}

Response:
{
  "id": "f68cb83f-f3c8-4aa5-82b1-3c7a398f2720",
  "status": "Completed",
  "progress": 100,
  "responseTimeMs": 102,
  "httpStatusCode": 200,
  "hasHttps": true,
  "serverHeader": "nginx",
  "findings": [
    {
      "checkName": "security-headers",
      "severity": "HIGH",
      "title": "Missing Security Headers",
      "detail": "X-Content-Type-Options header is missing",
      "evidence": "Response headers: Content-Type, Server, ...",
      "recommendation": "Add X-Content-Type-Options: nosniff"
    }
  ]
}
```

## Available Security Checks

| Check ID | Description | Category |
|----------|-------------|----------|
| `reachability` | Target connectivity and HTTP response | Baseline |
| `https-tls` | TLS/SSL certificate and protocol version | Baseline |
| `security-headers` | HTTP security headers (CSP, X-Frame-Options, etc.) | Baseline |
| `server-fingerprint` | Server technology detection | Baseline |
| `cookie-security` | Cookie security attributes (SameSite, Secure, etc.) | Baseline |
| `cors-policy` | CORS configuration analysis | Baseline |
| `information-disclosure` | Information leakage detection | Baseline |
| `authenticated-scan` | Post-login vulnerability scanning | Advanced |

## Available Scanning Tools

### Built-in Tools (Always Available)
- `http-probe` - HTTP connectivity and basic analysis
- `ssl-checker` - TLS/SSL certificate analysis
- `header-analyzer` - HTTP security header detection
- `fingerprint` - Server technology fingerprinting
- `cookie-inspector` - Cookie analysis
- `cors-checker` - CORS policy analysis

### External Tools (Requires Installation)
- `nuclei` - Vulnerability pattern matching
- `naabu` - Port scanning
- `ffuf` - Directory fuzzing
- `feroxbuster` - Directory brute-forcing
- `dnsx` - DNS security
- `wafw00f` - WAF detection

## Report Types

- **`technical`** - Detailed technical findings with evidence and recommendations (default)
- **`executive`** - High-level summary for management
- **`owasp-summary`** - Findings mapped to OWASP Top 10

## Common Use Cases

### Test Basic HTTP Connectivity
```powershell
$scan = @{
    TargetUrl = "https://example.com"
    Checks = @("reachability", "https-tls")
    Tools = @("http-probe", "ssl-checker")
    ReportType = "technical"
}
```

### Scan Web Application with Login
```powershell
$scan = @{
    TargetUrl = "https://myapp.com/login"
    Checks = @("security-headers", "cookie-security", "authenticated-scan")
    Tools = @("http-probe", "header-analyzer", "cookie-inspector")
    ReportType = "technical"
    Auth = @{
        Type = "form"
        LoginUrl = "https://myapp.com/login"
        Username = "testuser"
        Password = "password"
        UsernameField = "email"
        PasswordField = "password"
        SuccessUrlContains = "dashboard"
    }
}
```

### Full Security Audit
```powershell
$scan = @{
    TargetUrl = "https://example.com"
    Checks = @(
        "reachability",
        "https-tls",
        "security-headers",
        "server-fingerprint",
        "cookie-security",
        "cors-policy",
        "information-disclosure"
    )
    Tools = @(
        "http-probe",
        "ssl-checker",
        "header-analyzer",
        "fingerprint",
        "cookie-inspector",
        "cors-checker"
    )
    ReportType = "technical"
}
```

## Performance Characteristics

| Operation | Typical Time | Notes |
|-----------|-------------|-------|
| User Registration | < 100ms | Creates account + JWT |
| Create Scan | < 200ms | Validates & queues scan |
| Basic HTTP Scan | 100-250ms | Built-in probes only |
| Get Scan Status | < 50ms | Instant retrieval |
| Full Queue to Complete | 3-10s | Depends on target availability |

## Troubleshooting

### Issue: 401 Unauthorized
**Cause:** JWT token expired (default 1 hour TTL)  
**Solution:** Register new user with full_scan_workflow.ps1

### Issue: 403 Forbidden on Scan Retrieval
**Cause:** Missing or invalid X-Scan-Token header  
**Solution:** Use the scan's accessToken in X-Scan-Token header

### Issue: 422 Unprocessable Entity
**Cause:** Invalid request parameters  
**Solution:** Check validation errors in response
- Valid reportType: "executive", "technical", "owasp-summary"
- All checks/tools must be valid IDs
- Auth fields must match the chosen type

### Issue: Scan Returns 0 Findings
**Cause:** Target may be secure or external tools not installed  
**Solution:** 
- Verify target is reachable: test with "reachability" check first
- Check API logs for execution details
- External tools (nuclei, feroxbuster) require binaries on host

### Issue: Timeout Waiting for Scan
**Cause:** Target unreachable or very slow response  
**Solution:**
- Verify target URL is accessible from the API host
- Increase timeout in monitoring loop
- Check if API host has network access

## Integration Examples

### Export Scan Results to JSON
```powershell
$scan = Invoke-RestMethod -Uri "http://localhost/api/v1/scans/$scanId" `
    -Method Get `
    -Headers @{ "X-Scan-Token" = $scanAccessToken }

$scan | ConvertTo-Json -Depth 10 | Out-File "scan-results.json"
```

### Export Findings to CSV
```powershell
$scan.findings | Export-Csv "findings.csv" -NoTypeInformation
```

### Batch Scan Multiple Targets
```powershell
$targets = @("https://site1.com", "https://site2.com", "https://site3.com")
$results = @()

foreach ($target in $targets) {
    # Create scan
    # Monitor to completion
    # Store results
    $results += $scanResult
}

$results | ConvertTo-Json | Out-File "batch-results.json"
```

### Automated Daily Scanning
```powershell
# Schedule this script with Windows Task Scheduler
$targets = @(
    "https://api.example.com",
    "https://admin.example.com",
    "https://app.example.com"
)

$targets | ForEach-Object {
    & .\full_scan_workflow.ps1 -TargetUrl $_
    Start-Sleep -Seconds 5  # Stagger requests
}
```

## API Validation Rules

**HTTP Status Codes:**
- `200` - Request successful
- `400` - Bad request (invalid parameters)
- `401` - Unauthorized (missing/invalid JWT token)
- `403` - Forbidden (insufficient permissions or invalid scan token)
- `404` - Not found (invalid scan ID)
- `422` - Unprocessable entity (validation errors)
- `429` - Rate limited
- `500` - Server error

**Scan Status Values:**
- `Queued` - Waiting to execute
- `Running` - Currently executing
- `Completed` - Finished successfully
- `Failed` - Encountered error

**Finding Severity Levels (descending):**
- `CRITICAL` - Requires immediate attention
- `HIGH` - Significant security risk
- `MEDIUM` - Notable security issue
- `LOW` - Minor security issue
- `INFO` - Informational finding

## Best Practices

1. **Always use X-Scan-Token for retrieval** - Provides hardened access
2. **Store scan IDs and access tokens** - For later result retrieval
3. **Implement retry logic** - For network resilience
4. **Monitor scan completion** - Don't assume immediate completion
5. **Log all API interactions** - For auditing and debugging
6. **Validate target URLs** - Ensure targets are reachable
7. **Handle large response sets** - Paginate if needed
8. **Implement rate limiting** - Space out bulk scanning
9. **Secure credentials** - Use environment variables or vaults
10. **Monitor API usage** - Track quota and performance

## Support & Debugging

### View Recent API Activity
```powershell
# Check API container logs
docker logs securityportal-api-1 | tail -100
```

### Test Specific Endpoint Directly
```powershell
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

$result = Invoke-RestMethod -Uri "http://localhost/api/v1/endpoint" `
    -Method Get `
    -Headers $headers

$result | ConvertTo-Json -Depth 5 | Write-Host
```

### Verify API Health
```powershell
Invoke-RestMethod -Uri "http://localhost/api/v1/health"
```

## Next Steps

1. Run a basic scan: `.\full_scan_workflow.ps1`
2. Review findings and security recommendations
3. Integrate with your CI/CD pipeline
4. Automate regular security scanning
5. Build monitoring dashboard
6. Set up alerts for critical findings

---

**Last Updated:** 2026-08-26  
**API Version:** v1  
**Status:** ✅ Production Ready  
**Tested Targets:** 
- https://example.com ✅
- https://cvmanager.vnm2.vnclever.com ✅  
**Average Scan Time:** 100-250ms (built-in tools)
