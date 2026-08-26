# Security Portal API - Testing & Integration Guide

This directory contains PowerShell scripts for testing and integrating with the Security Portal API.

## Quick Start

### 1. Full Scan Workflow (Recommended)
```powershell
.\full_scan_workflow.ps1
```
**What it does:**
- Registers a new test user
- Creates an authenticated security scan
- Monitors scan progress until completion
- Displays findings with severity levels and recommendations

**Key Features:**
- Automatic user account creation
- JWT-based authentication
- Hardened scan token access
- Real-time progress monitoring
- Structured finding display

**Example Output:**
```
Scan Completed!
  Response Time: 102ms
  HTTP Status Code: 200
  Has HTTPS: True
  Findings Count: 3

Security Findings:
[HIGH] - 1 finding(s)
  • security-headers
    Title: Missing Security Headers
    Detail: X-Content-Type-Options header is missing
    Recommendation: Add X-Content-Type-Options: nosniff

[MEDIUM] - 2 finding(s)
  ...
```

### 2. Public Website Scan
```powershell
.\test_public_scan.ps1
```
Tests the API against a public website (example.com).

### 3. Custom Scan (create_and_monitor_scan.ps1)
Earlier version - works but uses Bearer token which may fail if scan requires access token.

## API Endpoints Reference

### Authentication
```
POST /api/v1/auth/register
  Content-Type: application/json
  
  Request:
  {
    "email": "user@example.com",
    "username": "testuser",
    "password": "Test@123",
    "firstName": "Test",
    "lastName": "User",
    "organizationName": "Org Name"
  }
  
  Response:
  {
    "accessToken": "eyJhbGc...",
    "refreshToken": "...",
    "accessTokenExpiry": "2026-08-26T10:30:00Z",
    "user": {...}
  }
```

### Create Scan
```
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
    ...
  }
```

### Get Scan Status
```
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
    "findings": [
      {
        "checkName": "security-headers",
        "severity": "HIGH",
        "title": "Missing Security Headers",
        "detail": "X-Content-Type-Options header is missing",
        "evidence": "Response headers: Content-Type, Server, ...",
        "recommendation": "Add security headers"
      },
      ...
    ],
    ...
  }
```

## Available Checks

| Check | Description | Category |
|-------|-------------|----------|
| `reachability` | Target connectivity and HTTP response | Baseline HTTP |
| `https-tls` | TLS/SSL certificate and protocol version | Baseline HTTP |
| `security-headers` | HTTP security headers analysis | Baseline HTTP |
| `server-fingerprint` | Server technology detection | Baseline HTTP |
| `cookie-security` | Cookie security attributes | Baseline HTTP |
| `cors-policy` | CORS configuration analysis | Baseline HTTP |
| `information-disclosure` | Information leakage detection | Baseline HTTP |
| `authenticated-scan` | Post-login scan (requires `auth` parameter) | Authenticated |

## Available Tools

| Tool | Type | Description |
|------|------|-------------|
| `http-probe` | Built-in | HTTP connectivity and header analysis |
| `ssl-checker` | Built-in | TLS/SSL certificate analysis |
| `header-analyzer` | Built-in | HTTP security header detection |
| `fingerprint` | Built-in | Server fingerprinting |
| `cookie-inspector` | Built-in | Cookie analysis |
| `cors-checker` | Built-in | CORS policy analysis |
| `nuclei` | External | Vulnerability scanning |
| `naabu` | External | Port scanning |
| `ffuf` | External | Directory discovery |
| `feroxbuster` | External | Directory brute-forcing |
| `dnsx` | External | DNS security |
| `wafw00f` | External | WAF detection |

**Note:** External tools require binaries to be installed on the API host.

## Available Report Types

- `executive` - Summary for management
- `technical` - Detailed technical findings
- `owasp-summary` - OWASP Top 10 focused

## Key Implementation Details

### Authentication Flow
1. User registers via `/api/v1/auth/register` → receives JWT + RefreshToken
2. User creates scan via `POST /api/v1/scans` with Bearer token → receives AccessToken
3. Scan status retrieved via `GET /api/v1/scans/{id}` using X-Scan-Token header

### Access Control
- **Authenticated scans** (created by logged-in user): Accessible with Bearer token
- **Hardened scans** (created by anonymous user): Require X-Scan-Token header
- **Scan ownership**: Enforced via OwnerTokenHash in scan configuration

### Performance
- Basic HTTP probe: ~100-220ms response time
- Scan queuing: Immediate (Queued → Running → Completed)
- Findings format: JSON array with severity, evidence, and recommendations

## Testing Tips

### Test with Different Targets
```powershell
# Modify this line in full_scan_workflow.ps1
$scanRequest.TargetUrl = "https://your-target.com"
```

### Include Authentication
```powershell
# Add Auth block to scan request
$scanRequest.Auth = @{
    Type = "form"
    LoginUrl = "https://your-app.com/login"
    Username = "testuser"
    Password = "testpass"
    UsernameField = "email"
    PasswordField = "password"
    SuccessUrlContains = "dashboard"
}
```

### Add Specific Checks
```powershell
# Select specific security checks
$scanRequest.Checks = @("security-headers", "cookie-security", "cors-policy")
```

## Troubleshooting

### 401 Unauthorized
- JWT token may have expired (1 hour default)
- Solution: Register new user or use RefreshToken endpoint

### 403 Forbidden on Scan Retrieval
- Scan requires AccessToken via X-Scan-Token header
- Solution: Always include X-Scan-Token header when retrieving scans

### 422 Unprocessable Entity
- Invalid request parameters
- Common issues: Invalid `reportType`, missing required fields
- Check API response for validation details

### Scan Returns 0 Findings
- Target may be secure or checks didn't execute
- External tools may not be installed on host
- Authenticated checks may have failed silently

## API Validation Rules

**Scan Checks:**
- Must be valid check IDs (see Available Checks above)
- Empty list defaults to enabled-by-default checks

**Scan Tools:**
- Must be valid tool IDs
- External tools fallback to built-in if binary unavailable

**Report Type:**
- Valid values: "executive", "technical", "owasp-summary"
- Defaults to "technical"

**Auth Configuration (when provided):**
- `type` must be "form", "basic", or "graphql"
- All fields required for chosen type
- Credentials are encrypted before storage

## Integration Examples

### Create Scan and Export Results
```powershell
# Get scan results
$scan = Invoke-RestMethod -Uri "http://localhost/api/v1/scans/$scanId" `
    -Method Get `
    -Headers @{ "X-Scan-Token" = $scanAccessToken }

# Export to JSON
$scan | ConvertTo-Json | Out-File "scan-$scanId.json"

# Export findings to CSV
$scan.findings | Export-Csv "findings-$scanId.csv" -NoTypeInformation
```

### Batch Scanning
```powershell
# Scan multiple targets
$targets = @("https://site1.com", "https://site2.com", "https://site3.com")
$targets | ForEach-Object {
    # Create scan for each target
    # Monitor until complete
    # Log results
}
```

## Support & Debugging

### View API Logs
```powershell
docker logs securityportal-api-1 | Select-Object -Last 100
```

### Test Specific Endpoint
```powershell
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type" = "application/json"
}

$result = Invoke-RestMethod -Uri "http://localhost/api/v1/endpoint" `
    -Method Get `
    -Headers $headers

$result | ConvertTo-Json -Depth 5
```

## Next Steps

1. **Run a scan** with `full_scan_workflow.ps1`
2. **Review findings** for security issues
3. **Integrate** with your CI/CD pipeline
4. **Automate** regular security scanning
5. **Monitor** findings over time

---

**Last Updated:** 2026-08-26  
**API Version:** v1  
**Status:** ✅ Working
