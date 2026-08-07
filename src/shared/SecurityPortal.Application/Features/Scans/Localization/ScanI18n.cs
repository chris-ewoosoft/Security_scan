using SecurityPortal.Application.Features.Scans.DTOs;
using SecurityPortal.Domain.Entities;

namespace SecurityPortal.Application.Features.Scans.Localization;

public static class ScanI18n
{
    public sealed record FindingText(string Title, string Detail, string Recommendation, IReadOnlyList<string>? Steps);

    public static string NormalizeLang(string? lang) =>
        lang?.Trim().Split('-', '_')[0].Equals("en", StringComparison.OrdinalIgnoreCase) == true ? "en" : "vi";

    public static string CheckName(string id, string? lang) => Localize(id, NormalizeLang(lang) == "en", CheckNames);
    public static string CheckDescription(string id, string? lang) => Localize(id, NormalizeLang(lang) == "en", CheckDescriptions);
    public static string ToolName(string id, string? lang) => Localize(id, NormalizeLang(lang) == "en", ToolNames);
    public static string ToolDescription(string id, string? lang) => Localize(id, NormalizeLang(lang) == "en", ToolDescriptions);
    public static string ReportName(string id, string? lang) => Localize(id, NormalizeLang(lang) == "en", ReportNames);
    public static string ReportDescription(string id, string? lang) => Localize(id, NormalizeLang(lang) == "en", ReportDescriptions);

    public static FindingText ResolveFinding(string code, IReadOnlyDictionary<string, string>? parameters, string? lang)
    {
        var en = NormalizeLang(lang) == "en";
        (string Title, string Detail, string Recommendation, IReadOnlyList<string>? Steps) template = code switch
        {
            "reachability.5xx" => ("Server returned a 5xx error", "Observed: {observed}\nImpact: {impact}", "Review server logs, health checks, and error handling; do not expose stack traces.", ["curl -sI \"{targetUrl}\"", "Confirm HTTP {status} or another 5xx response.", "Retry to distinguish transient and persistent failures."]),
            "reachability.4xx" => ("Server returned a 4xx error", "Observed: {observed}\nImpact: {impact}", "Confirm the public URL, path, and access control.", ["curl -sI \"{targetUrl}\"", "Record HTTP {status} and Location headers.", "Compare with the actual user entry point."]),
            "reachability.ok" => ("Website reachable", "Observed: {observed}", "Keep availability monitoring in place.", null),
            "https.missing" => ("HTTPS is not enabled", "Observed: {observed}\nImpact: {impact}", "Require HTTPS, redirect HTTP to HTTPS, and consider HSTS.", ["curl -sI \"{targetUrl}\"", "Confirm that no HTTPS redirect is returned.", "Try {httpsUrl}."]),
            "https.ok" => ("HTTPS is enabled", "The target URL uses HTTPS.", "Maintain a valid certificate and HSTS.", null),
            "header.missing" => ("Missing {header} header", "Observed: {observed}\nImpact: {impact}\nExpected: {expectation}", "{recommendation}", ["curl -sI \"{targetUrl}\"", "Confirm that {header} is absent.", "After fixing, verify: {expectation}."]),
            "header.ok" => ("Baseline security headers present", "All baseline security headers are present on {targetUrl}.", "Review header values periodically against the OWASP baseline.", null),
            "fingerprint.server" => ("Server header disclosed", "Observed: Server: {server}\nImpact: {impact}", "Remove or minimize the Server header at the reverse proxy.", null),
            "fingerprint.powered_by" => ("X-Powered-By header disclosed", "Observed: {observed}\nImpact: {impact}", "Remove X-Powered-By in the application or reverse proxy.", ["curl -sI \"{targetUrl}\"", "Find X-Powered-By and record its value.", "Disable it and verify it is absent."]),
            "fingerprint.ok" => ("Limited server fingerprinting", "No clear Server or X-Powered-By header was observed.", "Continue reducing fingerprinting exposure.", null),
            "cookie.none" => ("No Set-Cookie header", "The target response does not set a cookie.", "No mandatory action.", null),
            "cookie.secure" => ("Cookie missing Secure", "Observed: {observed}\nImpact: {impact}", "Add Secure to every session and authentication cookie.", ["curl -sI \"{targetUrl}\"", "Confirm Set-Cookie lacks Secure.", "Verify the Secure flag in browser storage after fixing."]),
            "cookie.httponly" => ("Cookie missing HttpOnly", "Observed: {observed}\nImpact: {impact}", "Add HttpOnly to cookies that JavaScript does not need.", ["curl -sI \"{targetUrl}\"", "Confirm Set-Cookie lacks HttpOnly.", "Verify the HttpOnly flag after fixing."]),
            "cookie.samesite" => ("Cookie missing SameSite", "Observed: {observed}\nImpact: {impact}", "Set SameSite=Lax or Strict as appropriate.", ["curl -sI \"{targetUrl}\"", "Confirm Set-Cookie lacks SameSite.", "Verify the SameSite setting after fixing."]),
            "cors.none" => ("No ACAO header observed", "No Access-Control-Allow-Origin header was returned for this GET request.", "If this is an API, review preflight responses separately.", null),
            "cors.wildcard" => ("Wildcard CORS policy", "Observed: {observed}\nImpact: {impact}", "Restrict the origin allowlist; do not use * for credentialed requests.", ["curl -sI -H \"Origin: https://evil.example\" \"{targetUrl}\"", "Confirm Access-Control-Allow-Origin: *.", "After fixing, verify that an untrusted origin is not allowed."]),
            "cors.ok" => ("CORS has a restricted origin", "Access-Control-Allow-Origin is not a wildcard: {origin}.", "Review allowed origins for each environment.", null),
            "disclosure.header" => ("Sensitive header disclosed: {key}", "Observed: {key}: {value}\nImpact: {impact}", "Remove or restrict {key} in the web server or application middleware.", ["curl -sI \"{targetUrl}\"", "Find {key}: {value}.", "Remove it and confirm it is absent."]),
            "disclosure.ok" => ("No obvious information disclosure", "No common sensitive headers were observed.", "Continue hardening response headers.", null),
            "port.open" => ("Open ports detected", "Observed: {observed}\nImpact: {impact}", "Expose only required ports through firewall or NSG rules.", ["Test-NetConnection {host} -Port {port}", "Compare open ports with the approved service inventory."]),
            "port.none" => ("No common open ports detected", "Built-in TCP probing found no common open ports.", "Expose only required ports; use Naabu for a full scan.", null),
            "port.accept_all" => ("Unverified accept-all TCP profile", "Observed: {observed}\nImpact: {impact}", "Do not treat silent TCP accepts as confirmed services; verify with banner/service probes from a trusted network path.", ["Re-scan sensitive ports with nmap -sV", "Confirm listeners from an internal jump host"]),
            "port.web_ok" => ("Only common web ports responded", "Observed: {observed}\nImpact: {impact}", "No action if 80/443 (and optional 8080/8443) are expected.", null),
            "port.sensitive_verified" => ("Verified sensitive service port", "Observed: {observed}\nImpact: {impact}", "Restrict management/database ports to private networks and require auth.", ["Confirm the bannered service", "Lock down with firewall / security group rules"]),
            "port.sensitive_unverified" => ("Sensitive port TCP-open without banner", "Observed: {observed}\nImpact: {impact}", "Verify whether a real service is listening; silent accepts are often tarpits.", ["nmap -sV -p {port} {host}", "Compare with the approved service inventory"]),
            "directory.found" => ("Directory discovery paths found", "Observed: {observed}\nImpact: {impact}", "Protect administration panels and disable directory listing.", ["curl -sI \"{url}\"", "Confirm HTTP {status} and that the response is not a fallback page."]),
            "directory.none" => ("No common discovery paths found", "The short built-in wordlist found no paths after soft-404 filtering.", "Use Feroxbuster or FFUF for deeper discovery.", null),
            "directory.tool_warn" => ("Directory discovery tool finished without hits", "Observed: {observed}", "Retry with a larger wordlist or confirm the tool exit code on the scanner host.", null),
            "sensitive.found" => ("Accessible sensitive file or path", "Observed: {observed}\nImpact: {impact}", "Remove the file from web root, block access, and rotate exposed secrets.", ["curl -sI \"{url}\"", "Confirm HTTP {status} and an appropriate content type."]),
            "sensitive.none" => ("No common sensitive paths found", "No validated sensitive files were found in the built-in wordlist.", "Keep Nuclei in CI/CD for deeper scanning.", null),
            "sensitive.nuclei.hits" => ("Nuclei found exposure/config issues", "Observed: {observed}\nImpact: {impact}", "Triage Nuclei template hits, remove exposed artifacts, rotate secrets.", null),
            "sensitive.nuclei.none" => ("Nuclei exposure templates clean", "Observed: {observed}", "Keep templates updated (nuclei -update-templates).", null),
            "vuln.placeholder" => ("Vulnerability scan selected (Nuclei)", "This module requires a Nuclei runner and template pack.", "Deploy a worker with Nuclei CVE and misconfiguration templates.", null),
            "vuln.nuclei.hits" => ("Nuclei reported findings", "Observed: {observed}\nImpact: {impact}", "Triage each template hit, patch or mitigate, and re-run Nuclei.", ["Review Nuclei evidence for {targetUrl}", "Confirm severity and false positives before remediating."]),
            "vuln.nuclei.none" => ("Nuclei found no medium/high/critical hits", "Observed: {observed}", "Keep templates updated and expand tags for deeper coverage.", null),
            "vuln.nuclei.error" => ("Nuclei did not complete", "Observed: {observed}\nImpact: {impact}", "Increase max duration, narrow tags, or check scanner host resources.", null),
            "tech.whatweb" => ("WhatWeb fingerprint", "Observed: {observed}", "Review disclosed stack versions for known CVEs.", null),
            "tech.found" => ("Technology signals detected", "Technology signals inferred from headers: {tech}.", "Reduce fingerprinting and use WhatWeb/Wappalyzer for deeper detection.", null),
            "tech.none" => ("Few technology signals in headers", "Built-in header analysis found few technology signals.", "Use WhatWeb/Wappalyzer for deeper detection.", null),
            "screenshot.placeholder" => ("Screenshot module selected (Gowitness)", "This module requires a Gowitness runner and evidence storage.", "Deploy a screenshot worker and evidence bucket.", null),
            "screenshot.ok" => ("Screenshot captured", "Observed: {observed}", "Retain evidence only as long as needed for the engagement.", null),
            "dns.ok" => ("DNS resolution succeeded", "DNS resolved {host} to {addresses}.", "Monitor DNS changes; use dnsx for a full DNS review.", null),
            "dns.fail" => ("DNS resolution failed", "Observed: {observed}\nImpact: {impact}", "Review DNS records and nameservers.", ["nslookup {host}", "Resolve-DnsName {host}", "Correct the DNS zone and retry resolution."]),
            "waf.found" => ("WAF/CDN fingerprint detected", "Signals detected: {signals}.", "Keep WAF rules current and validate with wafw00f.", null),
            "waf.none" => ("No clear WAF fingerprint", "No clear WAF fingerprint was found in headers.", "Consider deploying a WAF and validate with wafw00f.", null),
            "auth.ok" => ("Authenticated session established", "Observed: {observed}\nAuth type: {authType}.", "Rotate scan credentials regularly and use least-privilege accounts.", ["Open {loginUrl}", "Sign in as the scan user.", "Confirm the post-login URL or session cookie."]),
            "auth.failed" => ("Authentication failed", "Observed: {observed}\nImpact: {impact}", "Verify login URL, credentials, CSRF handling, and success marker; authenticated checks were skipped or limited.", ["Open {loginUrl}", "Attempt the same credentials manually.", "Adjust loginUrl / successUrlContains and rescan."]),
            "auth.skipped" => ("Authenticated scan not requested", "This scan ran anonymously.", "Enable form or basic auth to cover post-login areas.", null),
            "auth.coverage.skipped" => ("Authenticated surface skipped", "Observed: {observed}\nImpact: {impact}", "Fix login first, then rescan to cover post-login APIs and authz diffs.", null),
            "auth.coverage.limited" => ("Limited post-login coverage signal", "Observed: {observed}\nImpact: {impact}", "Add API/GraphQL targets or authenticated crawlers for SPA backends.", null),
            "auth.session.cookie_missing" => ("No session cookies in jar", "Observed: {observed}\nImpact: {impact}", "Confirm whether auth uses HttpOnly cookies or bearer tokens in storage.", ["Sign in manually", "Inspect Application → Cookies / Local Storage"]),
            "auth.session.cookie_insecure" => ("Session cookie missing Secure", "Observed: {observed}\nImpact: {impact}", "Set Secure on all authentication/session cookies.", ["Inspect Set-Cookie after login", "Confirm Secure flag in DevTools"]),
            "auth.session.cookie_no_httponly" => ("Session cookie missing HttpOnly", "Observed: {observed}\nImpact: {impact}", "Set HttpOnly on cookies that JavaScript must not read.", ["Inspect Set-Cookie after login", "Confirm HttpOnly flag in DevTools"]),
            "auth.session.cookie_ok" => ("Session cookies look hardened", "Observed: {observed}", "Keep Secure+HttpOnly and review SameSite separately.", null),
            "auth.surface.api_discovered" => ("Post-login API bases discovered", "Observed: {observed}\nImpact: {impact}", "Include discovered API hosts in authenticated testing and monitoring.", null),
            "auth.surface.api_none" => ("No post-login API base discovered", "Observed: {observed}\nImpact: {impact}", "Configure known GraphQL/REST bases for authenticated scans.", null),
            "auth.surface.authz_diff" => ("Anonymous vs authenticated path difference", "Observed: {observed}\nImpact: {impact}", "Verify role/tenant authorization on unlocked routes; do not rely on obscurity.", ["Open {targetUrl}", "Compare the same paths logged out vs logged in"]),
            "auth.surface.graphql_authz" => ("GraphQL accepts authenticated session", "Observed: {observed}\nImpact: {impact}", "Run authenticated GraphQL tests (introspection, IDOR, dangerous mutations).", ["POST {url} with and without session", "Confirm anonymous access is denied"]),
            "auth.surface.graphql_public" => ("GraphQL reachable anonymously", "Observed: {observed}\nImpact: {impact}", "Enforce authentication on GraphQL and authorize every resolver.", ["POST {url} without credentials", "Confirm sensitive fields are not public"]),
            "auth.surface.graphql_ok" => ("Authenticated GraphQL probe succeeded", "Observed: {observed}", "Continue deeper GraphQL security testing.", null),
            "auth.surface.graphql_error" => ("GraphQL probe error", "Observed: {observed}", "Verify endpoint availability and CORS for scanner traffic.", null),
            "source.clone.failed" => ("Source clone failed", "Observed: {observed}\nImpact: {impact}\nRepository: {repository}", "Verify the https Git URL, branch, and token permissions (contents:read).", ["git clone --depth 1 \"{repository}\"", "Confirm the scanner host can reach the Git server."]),
            "source.clone.too_large" => ("Source worktree too large", "Observed: {observed}\nImpact: {impact}\nRepository: {repository}", "Narrow the repository, use a smaller branch, or raise scanner limits in a dedicated worker.", null),
            "source.routes.none" => ("No routes found in source", "Observed: {observed}\nImpact: {impact}\nRepository: {repository}\nCommit: {commit}", "Add OpenAPI/Swagger or ensure ASP.NET/Next.js/Express route patterns are present.", null),
            "source.routes.found" => ("Source route inventory collected", "Observed: {observed}\nImpact: {impact}\nRepository: {repository}\nCommit: {commit}", "Use the inventory to drive authenticated probes and BOLA packs.", null),
            "source.authz.candidate" => ("Possible missing tenant guard on object route", "Observed: {observed}\nImpact: {impact}\nFile: {file}:{line}\nPath: {path}", "Enforce organization/clinic ownership server-side before returning or mutating the object.", ["Review {file}:{line}", "Call the route with another organization's object id", "Expect 403/404 when ownership fails"]),
            "source.artifact.stored" => ("Route inventory artifact stored", "Observed: {observed}\nImpact: {impact}", "Retain artifacts only as long as needed; avoid storing secrets in Git history.", null),
            "source.inventory.error" => ("Source inventory error", "Observed: {observed}\nImpact: {impact}\nRepository: {repository}", "Retry with a reachable repository and valid credentials.", null),
            "source.route.exposed" => ("Source route anonymously reachable", "Observed: {observed}\nImpact: {impact}", "Confirm each anonymous 2xx route is intentionally public; add authz where needed.", ["curl -sI \"{targetUrl}\"", "Compare with source inventory routes"]),
            "source.route.sensitive_exposed" => ("Sensitive source route anonymously reachable", "Observed: {observed}\nImpact: {impact}", "Lock down auth/admin API routes; require authentication and authorize every action.", ["curl -sI the listed URLs without credentials", "Expect 401/403 for non-public APIs"]),
            "source.route.public_ok" => ("AllowAnonymous routes reachable as designed", "Observed: {observed}\nImpact: {impact}", "Keep the public allowlist reviewed; do not treat these as missing authz.", null),
            "source.route.auth_required" => ("Source routes require authentication", "Observed: {observed}\nImpact: {impact}", "Continue with authenticated scan coverage for these endpoints.", null),
            "source.route.probe_none" => ("Source route probes inconclusive", "Observed: {observed}", "Verify base URL/path prefix matches the deployed API.", null),
            "source.authz.owner_token" => ("Object route uses owner/scan-token guard", "Observed: {observed}\nImpact: {impact}\nFile: {file}:{line}\nPath: {path}", "Confirm token binding cannot be bypassed across owners.", ["Review {file}:{line}", "Call with another owner's object id + token"]),
            _ => (code, "{observed}", "", null)
        };
        var (title, detail, recommendation, steps) = template;
        if (!en) (title, detail, recommendation, steps) = Vietnamese(code, title, detail, recommendation, steps);
        return new FindingText(Format(title, parameters), Format(detail, parameters), Format(recommendation, parameters),
            steps?.Select(s => Format(s, parameters)).ToList());
    }

    public static ScanReportPayloadDto LocalizeReport(ScanReportPayloadDto report, string targetUrl, string? lang)
    {
        var language = NormalizeLang(lang);
        var findings = report.Findings.Select(f =>
        {
            if (string.IsNullOrWhiteSpace(f.Code)) return f;
            var text = ResolveFinding(f.Code, f.Params, language);
            return f with { CheckName = CheckName(f.CheckId, language), Title = text.Title, Detail = text.Detail,
                Recommendation = text.Recommendation, ReproductionSteps = text.Steps };
        }).ToList();
        return report with
        {
            ReportTitle = ReportName(report.ReportType, language),
            Findings = findings,
            ExecutiveSummary = BuildExecutiveSummary(targetUrl, report.RiskLevel,
                findings.Count(f => f.Severity == "High"), findings.Count(f => f.Severity == "Medium"), report.ReportType, language)
        };
    }

    public static string BuildExecutiveSummary(string targetUrl, string riskLevel, int high, int medium, string reportType, string? lang)
    {
        var en = NormalizeLang(lang) == "en";
        var text = en
            ? $"Target {targetUrl}: {riskLevel} risk with {high} high and {medium} medium findings."
            : $"Mục tiêu {targetUrl}: rủi ro {riskLevel} với {high} phát hiện cao và {medium} phát hiện trung bình.";
        return reportType switch
        {
            "executive" => text + (en ? " Prioritize high-risk remediation before release." : " Ưu tiên khắc phục mức cao trước khi phát hành."),
            "owasp-summary" => text + (en ? " Review against the OWASP web security baseline." : " Rà soát theo baseline bảo mật web OWASP."),
            _ => text + (en ? " See technical findings below." : " Xem các phát hiện kỹ thuật bên dưới.")
        };
    }

    public static ScanCatalogDto LocalizeCatalog(string? lang) => new(
        ScanCatalog.Checks.Select(c => new ScanCheckDto(c.Id, CheckName(c.Id, lang), CheckDescription(c.Id, lang), c.Tools, c.EnabledByDefault, c.Category, c.Priority)).ToList(),
        ScanCatalog.Tools.Select(t => new ScanToolDto(t.Id, ToolName(t.Id, lang), t.Kind, ToolDescription(t.Id, lang))).ToList(),
        ScanCatalog.Reports.Select(r => new ScanReportDto(r.Id, ReportName(r.Id, lang), ReportDescription(r.Id, lang))).ToList());

    private static (string, string, string, IReadOnlyList<string>?) Vietnamese(string code, string title, string detail, string recommendation, IReadOnlyList<string>? steps) =>
        code switch
        {
            "reachability.5xx" => ("Máy chủ trả lỗi 5xx", "Quan sát: {observed}\nTác động: {impact}", "Kiểm tra log server, health check và error handling; không lộ stack trace.", ["curl -sI \"{targetUrl}\"", "Xác nhận HTTP {status} hoặc lỗi 5xx khác.", "Thử lại để phân biệt lỗi tạm thời và cố định."]),
            "reachability.4xx" => ("Máy chủ trả lỗi 4xx", "Quan sát: {observed}\nTác động: {impact}", "Xác nhận URL, path công khai và access control.", ["curl -sI \"{targetUrl}\"", "Ghi nhận HTTP {status} và header Location.", "So sánh với entry point thực tế."]),
            "reachability.ok" => ("Website có thể truy cập", "Quan sát: {observed}", "Duy trì giám sát availability.", null),
            "https.missing" => ("Không dùng HTTPS", "Quan sát: {observed}\nTác động: {impact}", "Bắt buộc HTTPS, redirect HTTP sang HTTPS và cân nhắc HSTS.", ["curl -sI \"{targetUrl}\"", "Xác nhận không redirect sang HTTPS.", "Thử {httpsUrl}."]),
            "https.ok" => ("HTTPS được bật", "URL mục tiêu sử dụng HTTPS.", "Duy trì chứng chỉ hợp lệ và HSTS.", null),
            "header.missing" => ("Thiếu header {header}", "Quan sát: {observed}\nTác động: {impact}\nKỳ vọng: {expectation}", "{recommendation}", ["curl -sI \"{targetUrl}\"", "Xác nhận thiếu {header}.", "Sau khi sửa, đối chiếu: {expectation}."]),
            "header.ok" => ("Đã có các header bảo mật cơ bản", "Các header bảo mật cơ bản đều hiện diện trên {targetUrl}.", "Rà soát giá trị header định kỳ theo baseline OWASP.", null),
            "fingerprint.server" => ("Lộ Server header", "Quan sát: Server: {server}\nTác động: {impact}", "Ẩn hoặc làm mờ Server header ở reverse proxy.", null),
            "fingerprint.powered_by" => ("Lộ X-Powered-By", "Quan sát: {observed}\nTác động: {impact}", "Gỡ X-Powered-By trên ứng dụng hoặc reverse proxy.", null),
            "fingerprint.ok" => ("Fingerprint hạn chế", "Không thấy Server hoặc X-Powered-By rõ ràng.", "Tiếp tục giảm fingerprint bề mặt tấn công.", null),
            "cookie.none" => ("Không có Set-Cookie", "Response mục tiêu không đặt cookie.", "Không có hành động bắt buộc.", null),
            "cookie.secure" => ("Cookie thiếu Secure", "Quan sát: {observed}\nTác động: {impact}", "Thêm Secure cho mọi cookie phiên và xác thực.", ["curl -sI \"{targetUrl}\"", "Xác nhận Set-Cookie thiếu Secure."]),
            "cookie.httponly" => ("Cookie thiếu HttpOnly", "Quan sát: {observed}\nTác động: {impact}", "Thêm HttpOnly cho cookie không cần JavaScript đọc.", ["curl -sI \"{targetUrl}\"", "Xác nhận Set-Cookie thiếu HttpOnly."]),
            "cookie.samesite" => ("Cookie thiếu SameSite", "Quan sát: {observed}\nTác động: {impact}", "Đặt SameSite=Lax hoặc Strict khi phù hợp.", ["curl -sI \"{targetUrl}\"", "Xác nhận Set-Cookie thiếu SameSite."]),
            "cors.none" => ("Không thấy ACAO trên response", "Không có Access-Control-Allow-Origin trong response GET.", "Nếu là API, kiểm tra riêng response preflight.", null),
            "cors.wildcard" => ("CORS wildcard", "Quan sát: {observed}\nTác động: {impact}", "Thu hẹp allowlist origin; không dùng * với request có credential.", ["curl -sI -H \"Origin: https://evil.example\" \"{targetUrl}\"", "Xác nhận Access-Control-Allow-Origin: *."]),
            "cors.ok" => ("CORS có giới hạn origin", "Access-Control-Allow-Origin không phải wildcard: {origin}.", "Rà soát allowlist origin theo môi trường.", null),
            "disclosure.header" => ("Lộ header nhạy cảm: {key}", "Quan sát: {key}: {value}\nTác động: {impact}", "Loại bỏ hoặc hạn chế {key} ở web server hoặc middleware.", ["curl -sI \"{targetUrl}\"", "Tìm {key}: {value}."]),
            "disclosure.ok" => ("Không phát hiện disclosure rõ", "Không thấy các header nhạy cảm phổ biến.", "Tiếp tục hardening response headers.", null),
            "port.open" => ("Phát hiện cổng mở", "Quan sát: {observed}\nTác động: {impact}", "Chỉ expose cổng cần thiết qua firewall hoặc NSG.", ["Test-NetConnection {host} -Port {port}", "Đối chiếu với inventory dịch vụ được phép."]),
            "port.none" => ("Không thấy cổng phổ biến mở", "TCP probe tích hợp không tìm thấy cổng phổ biến mở.", "Chỉ expose cổng cần thiết; dùng Naabu để quét đầy đủ.", null),
            "port.accept_all" => ("TCP accept-all chưa xác thực dịch vụ", "Quan sát: {observed}\nTác động: {impact}", "Không coi TCP accept im lặng là dịch vụ thật; xác minh bằng banner/service probe từ mạng tin cậy.", ["Quét lại cổng nhạy cảm bằng nmap -sV", "Xác nhận listener từ jump host nội bộ"]),
            "port.web_ok" => ("Chỉ cổng web phổ biến phản hồi", "Quan sát: {observed}\nTác động: {impact}", "Không cần hành động nếu 80/443 (và tùy chọn 8080/8443) là kỳ vọng.", null),
            "port.sensitive_verified" => ("Xác thực cổng dịch vụ nhạy cảm", "Quan sát: {observed}\nTác động: {impact}", "Thu hẹp cổng quản trị/database về mạng riêng và bắt buộc xác thực.", ["Xác nhận dịch vụ theo banner", "Khóa bằng firewall / security group"]),
            "port.sensitive_unverified" => ("Cổng nhạy cảm TCP-open nhưng không có banner", "Quan sát: {observed}\nTác động: {impact}", "Xác minh có service thật đang lắng nghe; accept im lặng thường là tarpit.", ["nmap -sV -p {port} {host}", "Đối chiếu inventory dịch vụ được phép"]),
            "directory.found" => ("Phát hiện path qua directory discovery", "Quan sát: {observed}\nTác động: {impact}", "Bảo vệ panel quản trị và tắt directory listing.", ["curl -sI \"{url}\"", "Xác nhận HTTP {status} không phải trang fallback."]),
            "directory.none" => ("Không thấy path phổ biến", "Wordlist ngắn tích hợp không tìm thấy path sau khi lọc soft-404.", "Dùng Feroxbuster hoặc FFUF để khám phá sâu.", null),
            "directory.tool_warn" => ("Công cụ directory discovery kết thúc không có hit", "Quan sát: {observed}", "Thử wordlist lớn hơn hoặc kiểm tra exit code trên máy scanner.", null),
            "sensitive.found" => ("File hoặc path nhạy cảm có thể truy cập", "Quan sát: {observed}\nTác động: {impact}", "Gỡ file khỏi web root, chặn truy cập và rotate secret đã lộ.", ["curl -sI \"{url}\"", "Xác nhận HTTP {status} và Content-Type phù hợp."]),
            "sensitive.none" => ("Không thấy sensitive path phổ biến", "Không tìm thấy file nhạy cảm đã xác thực trong wordlist tích hợp.", "Duy trì Nuclei trong CI/CD để quét sâu.", null),
            "sensitive.nuclei.hits" => ("Nuclei phát hiện exposure/config", "Quan sát: {observed}\nTác động: {impact}", "Triage kết quả Nuclei, gỡ artifact lộ, rotate secret.", null),
            "sensitive.nuclei.none" => ("Nuclei exposure templates không hit", "Quan sát: {observed}", "Cập nhật template: nuclei -update-templates.", null),
            "vuln.placeholder" => ("Đã chọn Vulnerability Scan (Nuclei)", "Module này cần Nuclei runner và template pack.", "Triển khai worker với template Nuclei cho CVE và misconfiguration.", null),
            "vuln.nuclei.hits" => ("Nuclei báo cáo phát hiện", "Quan sát: {observed}\nTác động: {impact}", "Triage từng template hit, vá hoặc giảm thiểu, rồi chạy lại Nuclei.", ["Xem evidence Nuclei cho {targetUrl}", "Xác nhận severity và loại trừ false positive trước khi sửa."]),
            "vuln.nuclei.none" => ("Nuclei không thấy hit medium/high/critical", "Quan sát: {observed}", "Giữ template cập nhật và mở rộng tag để phủ sâu hơn.", null),
            "vuln.nuclei.error" => ("Nuclei chưa chạy xong", "Quan sát: {observed}\nTác động: {impact}", "Tăng max duration, thu hẹp tags, hoặc kiểm tra tài nguyên máy scanner.", null),
            "tech.whatweb" => ("WhatWeb fingerprint", "Quan sát: {observed}", "Rà CVE theo stack/version được nhận diện.", null),
            "tech.found" => ("Phát hiện tín hiệu công nghệ", "Suy luận từ header: {tech}.", "Giảm fingerprint và dùng WhatWeb/Wappalyzer để phát hiện sâu.", null),
            "tech.none" => ("Ít tín hiệu công nghệ từ header", "Phân tích header tích hợp tìm thấy ít tín hiệu công nghệ.", "Dùng WhatWeb/Wappalyzer để phát hiện sâu.", null),
            "screenshot.placeholder" => ("Đã chọn Screenshot module (Gowitness)", "Module này cần Gowitness runner và evidence storage.", "Triển khai screenshot worker và evidence bucket.", null),
            "screenshot.ok" => ("Đã chụp screenshot", "Quan sát: {observed}", "Chỉ giữ evidence trong thời gian cần thiết của engagement.", null),
            "dns.ok" => ("DNS resolve thành công", "DNS resolve {host} tới {addresses}.", "Giám sát thay đổi DNS; dùng dnsx để rà soát đầy đủ.", null),
            "dns.fail" => ("DNS resolve thất bại", "Quan sát: {observed}\nTác động: {impact}", "Kiểm tra DNS record và nameserver.", ["nslookup {host}", "Resolve-DnsName {host}"]),
            "waf.found" => ("Phát hiện WAF/CDN fingerprint", "Tín hiệu phát hiện: {signals}.", "Duy trì WAF rules và xác thực bằng wafw00f.", null),
            "waf.none" => ("Không thấy WAF fingerprint rõ", "Không thấy WAF fingerprint rõ trong header.", "Cân nhắc triển khai WAF và xác thực bằng wafw00f.", null),
            "auth.ok" => ("Đã thiết lập phiên đăng nhập", "Quan sát: {observed}\nLoại auth: {authType}.", "Xoay vòng credential scan định kỳ và dùng tài khoản least-privilege.", ["Mở {loginUrl}", "Đăng nhập bằng user scan.", "Xác nhận URL sau login hoặc session cookie."]),
            "auth.failed" => ("Đăng nhập thất bại", "Quan sát: {observed}\nTác động: {impact}", "Kiểm tra login URL, credential, CSRF và success marker; các check sau login bị bỏ qua hoặc hạn chế.", ["Mở {loginUrl}", "Thử đăng nhập thủ công cùng credential.", "Chỉnh loginUrl / successUrlContains rồi scan lại."]),
            "auth.skipped" => ("Không bật authenticated scan", "Scan chạy ẩn danh.", "Bật form hoặc basic auth để phủ khu vực sau login.", null),
            "auth.coverage.skipped" => ("Bỏ qua bề mặt sau login", "Quan sát: {observed}\nTác động: {impact}", "Sửa đăng nhập rồi scan lại để phủ API và authz sau login.", null),
            "auth.coverage.limited" => ("Tín hiệu phủ sau login còn hạn chế", "Quan sát: {observed}\nTác động: {impact}", "Bổ sung target API/GraphQL hoặc crawler authenticated cho SPA.", null),
            "auth.session.cookie_missing" => ("Không thấy session cookie", "Quan sát: {observed}\nTác động: {impact}", "Xác nhận auth dùng HttpOnly cookie hay bearer token trong storage.", ["Đăng nhập thủ công", "Kiểm tra Cookies / Local Storage"]),
            "auth.session.cookie_insecure" => ("Session cookie thiếu Secure", "Quan sát: {observed}\nTác động: {impact}", "Bật Secure cho mọi cookie xác thực/phiên.", ["Xem Set-Cookie sau login", "Xác nhận cờ Secure trong DevTools"]),
            "auth.session.cookie_no_httponly" => ("Session cookie thiếu HttpOnly", "Quan sát: {observed}\nTác động: {impact}", "Bật HttpOnly cho cookie không cần JavaScript đọc.", ["Xem Set-Cookie sau login", "Xác nhận cờ HttpOnly trong DevTools"]),
            "auth.session.cookie_ok" => ("Session cookie trông đã cứng hóa", "Quan sát: {observed}", "Giữ Secure+HttpOnly và rà SameSite riêng.", null),
            "auth.surface.api_discovered" => ("Phát hiện API base sau login", "Quan sát: {observed}\nTác động: {impact}", "Đưa các host API này vào kiểm thử và giám sát authenticated.", null),
            "auth.surface.api_none" => ("Không phát hiện API base sau login", "Quan sát: {observed}\nTác động: {impact}", "Cấu hình GraphQL/REST base đã biết cho authenticated scan.", null),
            "auth.surface.authz_diff" => ("Khác biệt path ẩn danh vs đã login", "Quan sát: {observed}\nTác động: {impact}", "Xác minh phân quyền role/tenant trên route được mở sau login.", ["Mở {targetUrl}", "So sánh cùng path khi logout và login"]),
            "auth.surface.graphql_authz" => ("GraphQL nhận phiên đã đăng nhập", "Quan sát: {observed}\nTác động: {impact}", "Tiếp tục test GraphQL authenticated (introspection, IDOR, mutation nguy hiểm).", ["POST {url} có/không session", "Xác nhận anonymous bị từ chối"]),
            "auth.surface.graphql_public" => ("GraphQL truy cập được khi chưa login", "Quan sát: {observed}\nTác động: {impact}", "Bắt buộc authentication trên GraphQL và authorize từng resolver.", ["POST {url} không credential", "Xác nhận field nhạy cảm không public"]),
            "auth.surface.graphql_ok" => ("Probe GraphQL authenticated thành công", "Quan sát: {observed}", "Tiếp tục kiểm thử GraphQL sâu hơn.", null),
            "auth.surface.graphql_error" => ("Lỗi probe GraphQL", "Quan sát: {observed}", "Kiểm tra endpoint và CORS cho traffic scanner.", null),
            "source.clone.failed" => ("Clone source thất bại", "Quan sát: {observed}\nTác động: {impact}\nRepo: {repository}", "Kiểm tra URL Git https, branch và quyền token (contents:read).", ["git clone --depth 1 \"{repository}\"", "Xác nhận host scanner tới được Git server."]),
            "source.clone.too_large" => ("Source quá lớn", "Quan sát: {observed}\nTác động: {impact}\nRepo: {repository}", "Thu hẹp repo/branch hoặc chuyển clone sang worker có hạn mức riêng.", null),
            "source.routes.none" => ("Không tìm thấy route trong source", "Quan sát: {observed}\nTác động: {impact}\nRepo: {repository}\nCommit: {commit}", "Thêm OpenAPI/Swagger hoặc đảm bảo có pattern route ASP.NET/Next.js/Express.", null),
            "source.routes.found" => ("Đã thu thập inventory route từ source", "Quan sát: {observed}\nTác động: {impact}\nRepo: {repository}\nCommit: {commit}", "Dùng inventory để định hướng probe authenticated và BOLA pack.", null),
            "source.authz.candidate" => ("Nghi ngờ thiếu guard tenant trên route có object id", "Quan sát: {observed}\nTác động: {impact}\nFile: {file}:{line}\nPath: {path}", "Bắt buộc kiểm tra ownership org/clinic phía server trước khi đọc/sửa object.", ["Xem {file}:{line}", "Gọi route với object id của org khác", "Kỳ vọng 403/404 khi ownership sai"]),
            "source.artifact.stored" => ("Đã lưu artifact inventory route", "Quan sát: {observed}\nTác động: {impact}", "Chỉ giữ artifact trong thời gian cần thiết; không commit secret vào Git.", null),
            "source.inventory.error" => ("Lỗi inventory source", "Quan sát: {observed}\nTác động: {impact}\nRepo: {repository}", "Thử lại với repo truy cập được và credential hợp lệ.", null),
            "source.route.exposed" => ("Route từ source truy cập được ẩn danh", "Quan sát: {observed}\nTác động: {impact}", "Xác nhận từng route 2xx ẩn danh là cố ý public; bổ sung authz nếu cần.", ["curl -sI \"{targetUrl}\"", "Đối chiếu với inventory route từ source"]),
            "source.route.sensitive_exposed" => ("Route nhạy cảm từ source truy cập được ẩn danh", "Quan sát: {observed}\nTác động: {impact}", "Khóa API auth/admin; bắt buộc authentication và authorize mọi action.", ["curl -sI các URL đã liệt kê không kèm credential", "Kỳ vọng 401/403 với API không public"]),
            "source.route.public_ok" => ("Route AllowAnonymous truy cập đúng thiết kế", "Quan sát: {observed}\nTác động: {impact}", "Giữ allowlist public được rà soát; không coi đây là thiếu authz.", null),
            "source.route.auth_required" => ("Route từ source yêu cầu xác thực", "Quan sát: {observed}\nTác động: {impact}", "Tiếp tục phủ bằng authenticated scan cho các endpoint này.", null),
            "source.route.probe_none" => ("Probe route từ source chưa có tín hiệu rõ", "Quan sát: {observed}", "Kiểm tra base URL/path prefix khớp API đang deploy.", null),
            "source.authz.owner_token" => ("Route object dùng guard owner/scan-token", "Quan sát: {observed}\nTác động: {impact}\nFile: {file}:{line}\nPath: {path}", "Xác nhận token binding không bypass được giữa các owner.", ["Xem {file}:{line}", "Gọi với object id + token của owner khác"]),
            _ => (title, detail, recommendation, steps)
        };

    private static string Format(string value, IReadOnlyDictionary<string, string>? parameters) =>
        parameters is null ? value : parameters.Aggregate(value, (result, pair) => result.Replace("{" + pair.Key + "}", pair.Value, StringComparison.Ordinal));
    private static string Localize(string id, bool en, IReadOnlyDictionary<string, (string Vi, string En)> values) =>
        values.TryGetValue(id, out var value) ? (en ? value.En : value.Vi) : id;

    private static readonly IReadOnlyDictionary<string, (string Vi, string En)> CheckNames = Pairs(
        ("reachability","Khả năng truy cập","Reachability"),("https-tls","HTTPS / TLS","HTTPS / TLS"),("security-headers","Security Headers","Security Headers"),("server-fingerprint","Server Fingerprint","Server Fingerprint"),("cookie-security","Cookie Security","Cookie Security"),("authenticated-scan","Scan có đăng nhập","Authenticated Scan"),("route-inventory","Inventory route từ source","Source Route Inventory"),("cors-policy","CORS Policy","CORS Policy"),("information-disclosure","Information Disclosure","Information Disclosure"),("port-scan","Quét cổng","Port Scan"),("directory-discovery","Khám phá thư mục","Directory Discovery"),("sensitive-file-scan","Quét file nhạy cảm","Sensitive File Scan"),("vulnerability-scan","Quét lỗ hổng","Vulnerability Scan"),("technology-detection","Nhận diện công nghệ","Technology Detection"),("screenshot","Chụp ảnh","Screenshot"),("dns-security","Bảo mật DNS","DNS Security"),("waf-detection","Phát hiện WAF","WAF Detection"));
    private static readonly IReadOnlyDictionary<string, (string Vi, string En)> CheckDescriptions = Pairs(
        ("reachability","Kiểm tra HTTP response, thời gian phản hồi và mã trạng thái.","Checks HTTP response, latency, and status code."),("https-tls","Xác minh site dùng HTTPS và tín hiệu TLS cơ bản.","Verifies HTTPS use and basic TLS signals."),("security-headers","Phân tích các header bảo mật theo baseline OWASP.","Analyzes security headers against an OWASP baseline."),("server-fingerprint","Thu thập thông tin lộ qua header server.","Collects information exposed by server headers."),("cookie-security","Kiểm tra cờ Secure, HttpOnly, SameSite của cookie.","Checks Secure, HttpOnly, and SameSite cookie flags."),("authenticated-scan","Đăng nhập form/basic rồi quét khu vực sau login.","Logs in with form/basic auth then scans post-login areas."),("route-inventory","Clone Git (shallow) và trích xuất route/API từ source để định hướng scan.","Shallow-clones Git and extracts route/API inventory to guide scanning."),("cors-policy","Đánh giá cấu hình CORS.","Assesses CORS configuration."),("information-disclosure","Phát hiện header nhạy cảm và dấu hiệu lộ thông tin.","Detects sensitive headers and disclosure signals."),("port-scan","Quét cổng mở trên host mục tiêu.","Scans open ports on the target host."),("directory-discovery","Khám phá đường dẫn và thư mục ẩn.","Discovers hidden paths and directories."),("sensitive-file-scan","Tìm file cấu hình, backup và file nhạy cảm.","Searches for configuration, backup, and sensitive files."),("vulnerability-scan","Quét lỗ hổng theo template.","Scans template-based vulnerabilities."),("technology-detection","Nhận diện CMS, framework và tech stack.","Detects CMS, frameworks, and technology stack."),("screenshot","Chụp ảnh trang đích làm chứng cứ.","Captures target screenshots as evidence."),("dns-security","Kiểm tra DNS và tín hiệu cấu hình.","Checks DNS and configuration signals."),("waf-detection","Phát hiện Web Application Firewall.","Detects Web Application Firewalls."));
    private static readonly IReadOnlyDictionary<string, (string Vi, string En)> ToolNames = Pairs(
        ("http-probe","HTTP Probe","HTTP Probe"),("ssl-checker","SSL Checker","SSL Checker"),("header-analyzer","Phân tích Header","Header Analyzer"),("fingerprint","Fingerprint","Fingerprint"),("cookie-inspector","Kiểm tra Cookie","Cookie Inspector"),("cors-checker","Kiểm tra CORS","CORS Checker"),("source-analyzer","Source Analyzer","Source Analyzer"),("naabu","Naabu","Naabu"),("feroxbuster","Feroxbuster","Feroxbuster"),("ffuf","FFUF","FFUF"),("nuclei","Nuclei","Nuclei"),("whatweb","WhatWeb","WhatWeb"),("wappalyzer","Wappalyzer","Wappalyzer"),("gowitness","Gowitness","Gowitness"),("dnsx","dnsx","dnsx"),("wafw00f","wafw00f","wafw00f"));
    private static readonly IReadOnlyDictionary<string, (string Vi, string En)> ToolDescriptions = Pairs(
        ("http-probe","Gửi request HTTP/HTTPS để đo reachability và latency.","Sends HTTP/HTTPS requests to measure reachability and latency."),("ssl-checker","Đánh giá HTTPS và tín hiệu TLS từ URL.","Assesses HTTPS and TLS signals from the URL."),("header-analyzer","Phân tích security headers theo khuyến nghị OWASP.","Analyzes security headers using OWASP recommendations."),("fingerprint","Nhận diện stack từ response headers.","Identifies stack signals from response headers."),("cookie-inspector","Kiểm tra thuộc tính bảo mật cookie.","Checks cookie security attributes."),("cors-checker","Kiểm tra chính sách CORS phản hồi.","Checks returned CORS policy."),("source-analyzer","Shallow Git clone và heuristic inventory route (ASP.NET, Next.js, OpenAPI, Express).","Shallow Git clone and heuristic route inventory (ASP.NET, Next.js, OpenAPI, Express)."),("naabu","Quét cổng nhanh của ProjectDiscovery.","Fast ProjectDiscovery port scanner."),("feroxbuster","Khám phá nội dung và thư mục đa luồng.","Multithreaded directory and content discovery."),("ffuf","Web fuzzer cho directory, vhost và parameter.","Web fuzzer for directories, vhosts, and parameters."),("nuclei","Scanner theo template cho CVE và misconfiguration.","Template-based scanner for CVEs and misconfiguration."),("whatweb","Nhận diện công nghệ web chủ động.","Active web technology fingerprinting."),("wappalyzer","Nhận diện CMS, analytics và framework.","Detects CMS, analytics, and frameworks."),("gowitness","Chụp screenshot website.","Captures website screenshots."),("dnsx","DNS toolkit cho resolve và kiểm tra record.","DNS toolkit for resolution and record checks."),("wafw00f","Phát hiện và nhận diện WAF.","Detects and identifies WAFs."));
    private static readonly IReadOnlyDictionary<string, (string Vi, string En)> ReportNames = Pairs(("executive","Tóm tắt điều hành","Executive Summary"),("technical","Báo cáo kỹ thuật","Technical Report"),("owasp-summary","Tóm tắt theo OWASP","OWASP-oriented Summary"));
    private static readonly IReadOnlyDictionary<string, (string Vi, string En)> ReportDescriptions = Pairs(("executive","Báo cáo ngắn cho quản lý về rủi ro và khuyến nghị.","Short management report of risks and recommendations."),("technical","Chi tiết kỹ thuật theo từng check và evidence.","Technical detail by check and evidence."),("owasp-summary","Nhóm findings theo baseline bảo mật web OWASP.","Groups findings by an OWASP web security baseline."));
    private static IReadOnlyDictionary<string, (string Vi, string En)> Pairs(params (string Id, string Vi, string En)[] items) =>
        items.ToDictionary(x => x.Id, x => (x.Vi, x.En), StringComparer.OrdinalIgnoreCase);
}
