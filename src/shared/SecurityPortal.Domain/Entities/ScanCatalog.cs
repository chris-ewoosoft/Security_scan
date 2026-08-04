namespace SecurityPortal.Domain.Entities;

/// <summary>Catalog of scan modules, tools, and report templates available in the portal.</summary>
public static class ScanCatalog
{
    public static IReadOnlyList<ScanCheckDefinition> Checks { get; } =
    [
        // ── Baseline (built-in HTTP probe) ───────────────────────────────
        new("reachability", "Khả năng truy cập", "Kiểm tra HTTP response, thời gian phản hồi và mã trạng thái.",
            ["http-probe"], true, "basic", 4),
        new("https-tls", "HTTPS / TLS", "Xác minh site dùng HTTPS và tín hiệu cấu hình TLS cơ bản.",
            ["ssl-checker", "http-probe"], true, "basic", 4),
        new("security-headers", "Security Headers", "Phân tích các header bảo mật (CSP, HSTS, X-Frame-Options, …).",
            ["header-analyzer"], true, "owasp", 4),
        new("server-fingerprint", "Server Fingerprint", "Thu thập thông tin lộ qua Server / X-Powered-By.",
            ["fingerprint"], true, "recon", 3),
        new("cookie-security", "Cookie Security", "Kiểm tra cờ Secure, HttpOnly, SameSite trên Set-Cookie.",
            ["cookie-inspector"], false, "owasp", 3),
        new("cors-policy", "CORS Policy", "Đánh giá Access-Control-Allow-Origin và cấu hình CORS lộ ra.",
            ["cors-checker"], false, "owasp", 3),
        new("information-disclosure", "Information Disclosure", "Phát hiện header nhạy cảm và dấu hiệu lộ thông tin.",
            ["header-analyzer", "fingerprint"], false, "recon", 3),

        // ── High-value external modules ──────────────────────────────────
        new("port-scan", "Port Scan",
            "Quét cổng mở trên host mục tiêu. Tool chính: Naabu (full). Portal có probe TCP nhanh cho cổng phổ biến.",
            ["naabu"], false, "network", 5),
        new("directory-discovery", "Directory Discovery",
            "Khám phá đường dẫn / thư mục ẩn. Tool: Feroxbuster hoặc FFUF. Portal probe wordlist ngắn các path nhạy cảm.",
            ["feroxbuster", "ffuf"], false, "recon", 5),
        new("sensitive-file-scan", "Sensitive File Scan",
            "Tìm file nhạy cảm (.env, backup, git, config). Tool: Nuclei templates. Portal probe danh sách path cơ bản.",
            ["nuclei"], false, "vuln", 5),
        new("vulnerability-scan", "Vulnerability Scan",
            "Quét lỗ hổng theo template (CVE, misconfig, exposures). Tool: Nuclei.",
            ["nuclei"], false, "vuln", 5),
        new("technology-detection", "Technology Detection",
            "Nhận diện CMS/framework/JS stack. Tool: WhatWeb / Wappalyzer. Portal suy luận từ header + tín hiệu HTML.",
            ["whatweb", "wappalyzer", "fingerprint"], false, "recon", 5),
        new("screenshot", "Screenshot",
            "Chụp ảnh trang đích để lưu chứng cứ. Tool: Gowitness (cần runner + MinIO).",
            ["gowitness"], false, "recon", 4),
        new("dns-security", "DNS Security",
            "Kiểm tra bản ghi DNS (A/AAAA/CNAME) và tín hiệu cấu hình. Tool: dnsx.",
            ["dnsx"], false, "network", 4),
        new("waf-detection", "WAF Detection",
            "Phát hiện Web Application Firewall. Tool: wafw00f. Portal nhận diện qua header/fingerprint phổ biến.",
            ["wafw00f"], false, "recon", 4),
    ];

    public static IReadOnlyList<ScanToolDefinition> Tools { get; } =
    [
        // Built-in
        new("http-probe", "HTTP Probe", "Built-in", "Gửi request HTTP/HTTPS để đo reachability và latency."),
        new("ssl-checker", "SSL Checker", "Built-in", "Đánh giá HTTPS và tín hiệu TLS từ URL/scheme."),
        new("header-analyzer", "Header Analyzer", "Built-in", "Phân tích security headers theo khuyến nghị OWASP."),
        new("fingerprint", "Fingerprint", "Built-in", "Nhận diện stack từ response headers."),
        new("cookie-inspector", "Cookie Inspector", "Built-in", "Kiểm tra thuộc tính bảo mật của cookie."),
        new("cors-checker", "CORS Checker", "Built-in", "Kiểm tra chính sách CORS phản hồi."),

        // External high-value
        new("naabu", "Naabu", "External", "Port scanner nhanh (ProjectDiscovery) — quét cổng mở trên host."),
        new("feroxbuster", "Feroxbuster", "External", "Directory / content discovery đa luồng, hỗ trợ đệ quy."),
        new("ffuf", "FFUF", "External", "Web fuzzer linh hoạt cho directory, vhost, parameter discovery."),
        new("nuclei", "Nuclei", "External", "Template-based scanner cho sensitive files, CVE, misconfiguration."),
        new("whatweb", "WhatWeb", "External", "Nhận diện công nghệ web từ fingerprint chủ động."),
        new("wappalyzer", "Wappalyzer", "External", "Nhận diện tech stack (CMS, analytics, frameworks)."),
        new("gowitness", "Gowitness", "External", "Chụp screenshot website hàng loạt, lưu chứng cứ visual."),
        new("dnsx", "dnsx", "External", "DNS toolkit — resolve, wildcard, bản ghi bảo mật."),
        new("wafw00f", "wafw00f", "External", "Phát hiện và nhận diện WAF đang bảo vệ mục tiêu."),
    ];

    public static IReadOnlyList<ScanReportDefinition> Reports { get; } =
    [
        new("executive", "Executive Summary", "Báo cáo ngắn cho quản lý: rủi ro tổng quan và khuyến nghị."),
        new("technical", "Technical Report", "Chi tiết kỹ thuật theo từng check và evidence."),
        new("owasp-summary", "OWASP-oriented Summary", "Nhóm findings theo góc nhìn OWASP / baseline web."),
    ];

    public static HashSet<string> ValidCheckIds { get; } = Checks.Select(c => c.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
    public static HashSet<string> ValidToolIds { get; } = Tools.Select(t => t.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
    public static HashSet<string> ValidReportIds { get; } = Reports.Select(r => r.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyList<string> DefaultCheckIds { get; } =
        Checks.Where(c => c.EnabledByDefault).Select(c => c.Id).ToList();

    public static string DefaultReportType => "technical";
}

public sealed record ScanCheckDefinition(
    string Id,
    string Name,
    string Description,
    IReadOnlyList<string> Tools,
    bool EnabledByDefault,
    string Category,
    int Priority);

public sealed record ScanToolDefinition(
    string Id,
    string Name,
    string Kind,
    string Description);

public sealed record ScanReportDefinition(string Id, string Name, string Description);
