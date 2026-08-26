# Security Portal Scripts - Quick Reference

## 📝 Script Index

### Primary Scripts (Recommended)

#### 1. **full_scan_workflow.ps1** ⭐ RECOMMENDED
- **Best For:** Complete end-to-end testing with all features
- **What It Does:**
  - Register new user account
  - Create authenticated security scan
  - Monitor scan progress in real-time
  - Display findings with severity levels
  - Show execution statistics
- **Run:** `.\full_scan_workflow.ps1`
- **Time:** ~3-6 seconds
- **Output:** Detailed workflow with all steps

#### 2. **test_public_scan.ps1** ⭐ SIMPLEST
- **Best For:** Quick testing against public websites
- **What It Does:**
  - Register user
  - Create scan for example.com
  - Monitor until completion
  - Show basic results
- **Run:** `.\test_public_scan.ps1`
- **Time:** ~2 seconds
- **Output:** Simple status updates

#### 3. **advanced_authenticated_scan.ps1** ⭐ PRODUCTION
- **Best For:** Scanning targets with login credentials
- **What It Does:**
  - Register user
  - Create scan with form-based authentication
  - Monitor execution
  - Display detailed findings with formatting
  - Show severity breakdown
- **Run:** `.\advanced_authenticated_scan.ps1`
- **Time:** ~6 seconds
- **Output:** Formatted finding summary

---

### Legacy Scripts (Alternative Options)

#### 4. create_and_monitor_scan.ps1
- Combined create + monitoring workflow
- Early development version
- Use full_scan_workflow.ps1 instead

#### 5. create_scan.ps1
- Basic scan creation only
- No monitoring or results display
- Use full_scan_workflow.ps1 instead

#### 6. create_scan_auth.ps1
- Authenticated scan creation
- Early iteration
- Use advanced_authenticated_scan.ps1 instead

#### 7. create_scan_clean.ps1
- Simplified scan creation
- Minimal output
- Use test_public_scan.ps1 instead

#### 8. monitor_scan.ps1
- Scan monitoring only
- Requires scan ID as input
- Standalone utility for existing scans

---

## 🎯 Usage Examples

### Example 1: First-Time User
```powershell
# Start with the simplest script
.\test_public_scan.ps1
```
**Expected Output:**
```
[OK] User registered
[OK] Scan created
Status: Queued → Running → Completed
Total Findings: 0
```

### Example 2: Full Workflow
```powershell
# Run the complete workflow
.\full_scan_workflow.ps1
```
**Expected Output:**
```
Step 1: Registering new test user...
Step 2: Creating authenticated scan...
Step 3: Monitoring scan progress...
  [1/120] Status: Queued
  [2/120] Status: Running
  [3/120] Status: Completed
Findings: 0 detected
```

### Example 3: Authenticated Target
```powershell
# Test authenticated scanning
.\advanced_authenticated_scan.ps1
```
**Expected Output:**
```
--- Step 1: User Registration
[OK] User registered

--- Step 2: Scan Creation
[OK] Scan created

--- Step 3: Scan Execution
Status: Queued → Running → Completed

--- Step 4: Scan Results
Summary: [findings displayed]
Statistics: [timing and count info]
```

---

## 📊 Comparison Table

| Feature | full_scan | test_public | advanced |
|---------|-----------|-------------|----------|
| Registration | ✅ | ✅ | ✅ |
| Scan Creation | ✅ | ✅ | ✅ |
| Status Monitoring | ✅ | ✅ | ✅ |
| Finding Display | ✅ | ✅ | ✅ |
| Form Auth | ❌ | ❌ | ✅ |
| Detailed Output | ✅ | ❌ | ✅ |
| Severity Breakdown | ✅ | ❌ | ✅ |
| Structured Format | ✅ | ❌ | ✅ |

---

## 🔧 Customization

### Change Target URL
```powershell
# Edit the script and modify:
$targetUrl = "https://yourtarget.com"
```

### Change Checks
```powershell
$checks = @(
    "reachability",
    "https-tls",
    "security-headers",
    # Add or remove checks here
)
```

### Change Report Type
```powershell
# Valid options:
# "technical"      - Detailed findings
# "executive"      - Summary for management
# "owasp-summary"  - OWASP Top 10 mapping

$reportType = "technical"
```

### Add Login Credentials
```powershell
$auth = @{
    Type = "form"
    LoginUrl = "https://yourtarget.com/login"
    Username = "your_username"
    Password = "your_password"
    UsernameField = "email"
    PasswordField = "password"
    SuccessUrlContains = "dashboard"
}
```

---

## ⚡ Quick Commands

### Run Full Workflow
```powershell
cd "d:\Security Portal"
.\full_scan_workflow.ps1
```

### Run Public Website Test
```powershell
cd "d:\Security Portal"
.\test_public_scan.ps1
```

### Run Advanced Script
```powershell
cd "d:\Security Portal"
.\advanced_authenticated_scan.ps1
```

### Export Results
```powershell
$result | ConvertTo-Json | Out-File "results.json"
```

### Run All Tests
```powershell
cd "d:\Security Portal"
Write-Host "Running basic test..."
.\test_public_scan.ps1
Write-Host "`nRunning full workflow..."
.\full_scan_workflow.ps1
Write-Host "`nRunning advanced test..."
.\advanced_authenticated_scan.ps1
```

---

## 📚 Documentation Files

- **TESTING_README.md** - Comprehensive guide to API and scripts
- **API_TESTING_GUIDE.md** - API reference with examples
- **SESSION_COMPLETION_SUMMARY.md** - This session's results

---

## ✅ Recommended Workflow

1. **First Run:** `.\test_public_scan.ps1` (verify basics)
2. **Full Test:** `.\full_scan_workflow.ps1` (complete workflow)
3. **Production:** `.\advanced_authenticated_scan.ps1` (your target)
4. **Automation:** Schedule any script with Windows Task Scheduler

---

## 🐛 Troubleshooting

### Script Won't Run
```
Error: "File cannot be loaded because running scripts is disabled"
Solution: Run PowerShell as Admin, then:
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
```

### API Connection Error
```
Error: "Unable to connect to http://localhost"
Solution: Verify API is running: docker ps | grep securityportal-api
```

### Authentication Failed
```
Error: "401 Unauthorized"
Solution: User registration failed. Check API logs:
docker logs securityportal-api-1 | tail -50
```

### Scan Not Completing
```
Error: Timeout after 240 seconds
Solution: Target may be slow. Increase timeout in monitoring loop
```

---

## 📈 Next Steps

1. ✅ Run `test_public_scan.ps1` to verify setup
2. ✅ Review findings (if any)
3. ✅ Consult TESTING_README.md for API details
4. ✅ Customize scripts for your targets
5. ✅ Integrate into CI/CD pipeline
6. ✅ Schedule recurring scans

---

**Last Updated:** 2026-08-26  
**Scripts Tested:** ✅ All working  
**Status:** 🟢 Production Ready
