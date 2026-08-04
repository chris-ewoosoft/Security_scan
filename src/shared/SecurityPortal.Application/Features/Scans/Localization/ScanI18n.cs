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
            "directory.found" => ("Directory discovery paths found", "Observed: {observed}\nImpact: {impact}", "Protect administration panels and disable directory listing.", ["curl -sI \"{url}\"", "Confirm HTTP {status} and that the response is not a fallback page."]),
            "directory.none" => ("No common discovery paths found", "The short built-in wordlist found no paths after soft-404 filtering.", "Use Feroxbuster or FFUF for deeper discovery.", null),
            "sensitive.found" => ("Accessible sensitive file or path", "Observed: {observed}\nImpact: {impact}", "Remove the file from web root, block access, and rotate exposed secrets.", ["curl -sI \"{url}\"", "Confirm HTTP {status} and an appropriate content type."]),
            "sensitive.none" => ("No common sensitive paths found", "No validated sensitive files were found in the built-in wordlist.", "Keep Nuclei in CI/CD for deeper scanning.", null),
            "vuln.placeholder" => ("Vulnerability scan selected (Nuclei)", "This module requires a Nuclei runner and template pack.", "Deploy a worker with Nuclei CVE and misconfiguration templates.", null),
            "tech.found" => ("Technology signals detected", "Technology signals inferred from headers: {tech}.", "Reduce fingerprinting and use WhatWeb/Wappalyzer for deeper detection.", null),
            "tech.none" => ("Few technology signals in headers", "Built-in header analysis found few technology signals.", "Use WhatWeb/Wappalyzer for deeper detection.", null),
            "screenshot.placeholder" => ("Screenshot module selected (Gowitness)", "This module requires a Gowitness runner and evidence storage.", "Deploy a screenshot worker and evidence bucket.", null),
            "dns.ok" => ("DNS resolution succeeded", "DNS resolved {host} to {addresses}.", "Monitor DNS changes; use dnsx for a full DNS review.", null),
            "dns.fail" => ("DNS resolution failed", "Observed: {observed}\nImpact: {impact}", "Review DNS records and nameservers.", ["nslookup {host}", "Resolve-DnsName {host}", "Correct the DNS zone and retry resolution."]),
            "waf.found" => ("WAF/CDN fingerprint detected", "Signals detected: {signals}.", "Keep WAF rules current and validate with wafw00f.", null),
            "waf.none" => ("No clear WAF fingerprint", "No clear WAF fingerprint was found in headers.", "Consider deploying a WAF and validate with wafw00f.", null),
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
            "directory.found" => ("Phát hiện path qua directory discovery", "Quan sát: {observed}\nTác động: {impact}", "Bảo vệ panel quản trị và tắt directory listing.", ["curl -sI \"{url}\"", "Xác nhận HTTP {status} không phải trang fallback."]),
            "directory.none" => ("Không thấy path phổ biến", "Wordlist ngắn tích hợp không tìm thấy path sau khi lọc soft-404.", "Dùng Feroxbuster hoặc FFUF để khám phá sâu.", null),
            "sensitive.found" => ("File hoặc path nhạy cảm có thể truy cập", "Quan sát: {observed}\nTác động: {impact}", "Gỡ file khỏi web root, chặn truy cập và rotate secret đã lộ.", ["curl -sI \"{url}\"", "Xác nhận HTTP {status} và Content-Type phù hợp."]),
            "sensitive.none" => ("Không thấy sensitive path phổ biến", "Không tìm thấy file nhạy cảm đã xác thực trong wordlist tích hợp.", "Duy trì Nuclei trong CI/CD để quét sâu.", null),
            "vuln.placeholder" => ("Đã chọn Vulnerability Scan (Nuclei)", "Module này cần Nuclei runner và template pack.", "Triển khai worker với template Nuclei cho CVE và misconfiguration.", null),
            "tech.found" => ("Phát hiện tín hiệu công nghệ", "Suy luận từ header: {tech}.", "Giảm fingerprint và dùng WhatWeb/Wappalyzer để phát hiện sâu.", null),
            "tech.none" => ("Ít tín hiệu công nghệ từ header", "Phân tích header tích hợp tìm thấy ít tín hiệu công nghệ.", "Dùng WhatWeb/Wappalyzer để phát hiện sâu.", null),
            "screenshot.placeholder" => ("Đã chọn Screenshot module (Gowitness)", "Module này cần Gowitness runner và evidence storage.", "Triển khai screenshot worker và evidence bucket.", null),
            "dns.ok" => ("DNS resolve thành công", "DNS resolve {host} tới {addresses}.", "Giám sát thay đổi DNS; dùng dnsx để rà soát đầy đủ.", null),
            "dns.fail" => ("DNS resolve thất bại", "Quan sát: {observed}\nTác động: {impact}", "Kiểm tra DNS record và nameserver.", ["nslookup {host}", "Resolve-DnsName {host}"]),
            "waf.found" => ("Phát hiện WAF/CDN fingerprint", "Tín hiệu phát hiện: {signals}.", "Duy trì WAF rules và xác thực bằng wafw00f.", null),
            "waf.none" => ("Không thấy WAF fingerprint rõ", "Không thấy WAF fingerprint rõ trong header.", "Cân nhắc triển khai WAF và xác thực bằng wafw00f.", null),
            _ => (title, detail, recommendation, steps)
        };

    private static string Format(string value, IReadOnlyDictionary<string, string>? parameters) =>
        parameters is null ? value : parameters.Aggregate(value, (result, pair) => result.Replace("{" + pair.Key + "}", pair.Value, StringComparison.Ordinal));
    private static string Localize(string id, bool en, IReadOnlyDictionary<string, (string Vi, string En)> values) =>
        values.TryGetValue(id, out var value) ? (en ? value.En : value.Vi) : id;

    private static readonly IReadOnlyDictionary<string, (string Vi, string En)> CheckNames = Pairs(
        ("reachability","Khả năng truy cập","Reachability"),("https-tls","HTTPS / TLS","HTTPS / TLS"),("security-headers","Security Headers","Security Headers"),("server-fingerprint","Server Fingerprint","Server Fingerprint"),("cookie-security","Cookie Security","Cookie Security"),("cors-policy","CORS Policy","CORS Policy"),("information-disclosure","Information Disclosure","Information Disclosure"),("port-scan","Quét cổng","Port Scan"),("directory-discovery","Khám phá thư mục","Directory Discovery"),("sensitive-file-scan","Quét file nhạy cảm","Sensitive File Scan"),("vulnerability-scan","Quét lỗ hổng","Vulnerability Scan"),("technology-detection","Nhận diện công nghệ","Technology Detection"),("screenshot","Chụp ảnh","Screenshot"),("dns-security","Bảo mật DNS","DNS Security"),("waf-detection","Phát hiện WAF","WAF Detection"));
    private static readonly IReadOnlyDictionary<string, (string Vi, string En)> CheckDescriptions = Pairs(
        ("reachability","Kiểm tra HTTP response, thời gian phản hồi và mã trạng thái.","Checks HTTP response, latency, and status code."),("https-tls","Xác minh site dùng HTTPS và tín hiệu TLS cơ bản.","Verifies HTTPS use and basic TLS signals."),("security-headers","Phân tích các header bảo mật theo baseline OWASP.","Analyzes security headers against an OWASP baseline."),("server-fingerprint","Thu thập thông tin lộ qua header server.","Collects information exposed by server headers."),("cookie-security","Kiểm tra cờ Secure, HttpOnly, SameSite của cookie.","Checks Secure, HttpOnly, and SameSite cookie flags."),("cors-policy","Đánh giá cấu hình CORS.","Assesses CORS configuration."),("information-disclosure","Phát hiện header nhạy cảm và dấu hiệu lộ thông tin.","Detects sensitive headers and disclosure signals."),("port-scan","Quét cổng mở trên host mục tiêu.","Scans open ports on the target host."),("directory-discovery","Khám phá đường dẫn và thư mục ẩn.","Discovers hidden paths and directories."),("sensitive-file-scan","Tìm file cấu hình, backup và file nhạy cảm.","Searches for configuration, backup, and sensitive files."),("vulnerability-scan","Quét lỗ hổng theo template.","Scans template-based vulnerabilities."),("technology-detection","Nhận diện CMS, framework và tech stack.","Detects CMS, frameworks, and technology stack."),("screenshot","Chụp ảnh trang đích làm chứng cứ.","Captures target screenshots as evidence."),("dns-security","Kiểm tra DNS và tín hiệu cấu hình.","Checks DNS and configuration signals."),("waf-detection","Phát hiện Web Application Firewall.","Detects Web Application Firewalls."));
    private static readonly IReadOnlyDictionary<string, (string Vi, string En)> ToolNames = Pairs(
        ("http-probe","HTTP Probe","HTTP Probe"),("ssl-checker","SSL Checker","SSL Checker"),("header-analyzer","Phân tích Header","Header Analyzer"),("fingerprint","Fingerprint","Fingerprint"),("cookie-inspector","Kiểm tra Cookie","Cookie Inspector"),("cors-checker","Kiểm tra CORS","CORS Checker"),("naabu","Naabu","Naabu"),("feroxbuster","Feroxbuster","Feroxbuster"),("ffuf","FFUF","FFUF"),("nuclei","Nuclei","Nuclei"),("whatweb","WhatWeb","WhatWeb"),("wappalyzer","Wappalyzer","Wappalyzer"),("gowitness","Gowitness","Gowitness"),("dnsx","dnsx","dnsx"),("wafw00f","wafw00f","wafw00f"));
    private static readonly IReadOnlyDictionary<string, (string Vi, string En)> ToolDescriptions = Pairs(
        ("http-probe","Gửi request HTTP/HTTPS để đo reachability và latency.","Sends HTTP/HTTPS requests to measure reachability and latency."),("ssl-checker","Đánh giá HTTPS và tín hiệu TLS từ URL.","Assesses HTTPS and TLS signals from the URL."),("header-analyzer","Phân tích security headers theo khuyến nghị OWASP.","Analyzes security headers using OWASP recommendations."),("fingerprint","Nhận diện stack từ response headers.","Identifies stack signals from response headers."),("cookie-inspector","Kiểm tra thuộc tính bảo mật cookie.","Checks cookie security attributes."),("cors-checker","Kiểm tra chính sách CORS phản hồi.","Checks returned CORS policy."),("naabu","Quét cổng nhanh của ProjectDiscovery.","Fast ProjectDiscovery port scanner."),("feroxbuster","Khám phá nội dung và thư mục đa luồng.","Multithreaded directory and content discovery."),("ffuf","Web fuzzer cho directory, vhost và parameter.","Web fuzzer for directories, vhosts, and parameters."),("nuclei","Scanner theo template cho CVE và misconfiguration.","Template-based scanner for CVEs and misconfiguration."),("whatweb","Nhận diện công nghệ web chủ động.","Active web technology fingerprinting."),("wappalyzer","Nhận diện CMS, analytics và framework.","Detects CMS, analytics, and frameworks."),("gowitness","Chụp screenshot website.","Captures website screenshots."),("dnsx","DNS toolkit cho resolve và kiểm tra record.","DNS toolkit for resolution and record checks."),("wafw00f","Phát hiện và nhận diện WAF.","Detects and identifies WAFs."));
    private static readonly IReadOnlyDictionary<string, (string Vi, string En)> ReportNames = Pairs(("executive","Tóm tắt điều hành","Executive Summary"),("technical","Báo cáo kỹ thuật","Technical Report"),("owasp-summary","Tóm tắt theo OWASP","OWASP-oriented Summary"));
    private static readonly IReadOnlyDictionary<string, (string Vi, string En)> ReportDescriptions = Pairs(("executive","Báo cáo ngắn cho quản lý về rủi ro và khuyến nghị.","Short management report of risks and recommendations."),("technical","Chi tiết kỹ thuật theo từng check và evidence.","Technical detail by check and evidence."),("owasp-summary","Nhóm findings theo baseline bảo mật web OWASP.","Groups findings by an OWASP web security baseline."));
    private static IReadOnlyDictionary<string, (string Vi, string En)> Pairs(params (string Id, string Vi, string En)[] items) =>
        items.ToDictionary(x => x.Id, x => (x.Vi, x.En), StringComparer.OrdinalIgnoreCase);
}
