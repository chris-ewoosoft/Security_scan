namespace SecurityPortal.Domain.Entities;

/// <summary>Catalog of scan modules, tools, and report templates available in the portal.</summary>
public static class ScanCatalog
{
    public static IReadOnlyList<ScanCheckDefinition> Checks { get; } =
    [
        new("reachability", "Khả năng truy cập", "Kiểm tra HTTP response, thời gian phản hồi và mã trạng thái.",
            ["http-probe"], true, "basic"),
        new("https-tls", "HTTPS / TLS", "Xác minh site dùng HTTPS và tín hiệu cấu hình TLS cơ bản.",
            ["ssl-checker", "http-probe"], true, "basic"),
        new("security-headers", "Security Headers", "Phân tích các header bảo mật (CSP, HSTS, X-Frame-Options, …).",
            ["header-analyzer"], true, "owasp"),
        new("server-fingerprint", "Server Fingerprint", "Thu thập thông tin lộ qua Server / X-Powered-By.",
            ["fingerprint"], true, "recon"),
        new("cookie-security", "Cookie Security", "Kiểm tra cờ Secure, HttpOnly, SameSite trên Set-Cookie.",
            ["cookie-inspector"], false, "owasp"),
        new("cors-policy", "CORS Policy", "Đánh giá Access-Control-Allow-Origin và cấu hình CORS lộ ra.",
            ["cors-checker"], false, "owasp"),
        new("information-disclosure", "Information Disclosure", "Phát hiện header nhạy cảm và dấu hiệu lộ thông tin.",
            ["header-analyzer", "fingerprint"], false, "recon"),
    ];

    public static IReadOnlyList<ScanToolDefinition> Tools { get; } =
    [
        new("http-probe", "HTTP Probe", "Gửi request HTTP/HTTPS để đo reachability và latency."),
        new("ssl-checker", "SSL Checker", "Đánh giá HTTPS và tín hiệu TLS từ URL/scheme."),
        new("header-analyzer", "Header Analyzer", "Phân tích security headers theo khuyến nghị OWASP."),
        new("fingerprint", "Fingerprint", "Nhận diện stack từ response headers."),
        new("cookie-inspector", "Cookie Inspector", "Kiểm tra thuộc tính bảo mật của cookie."),
        new("cors-checker", "CORS Checker", "Kiểm tra chính sách CORS phản hồi."),
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
    string Category);

public sealed record ScanToolDefinition(string Id, string Name, string Description);

public sealed record ScanReportDefinition(string Id, string Name, string Description);
