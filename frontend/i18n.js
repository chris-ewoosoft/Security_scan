window.SecurityPortalI18n = (() => {
  const STORAGE_KEY = "sp.locale.v1";

  const dict = {
    vi: {
      "nav.home": "Trang chủ",
      "nav.functions": "Chức năng",
      "nav.config": "Cấu hình",
      "nav.history": "Lịch sử",
      "home.title": "Quét bảo mật website",
      "home.urlLabel": "Địa chỉ website cần scan",
      "home.scan": "Bắt đầu scan",
      "home.scanning": "Đang scan…",
      "home.stop": "Dừng scan",
      "home.stopping": "Đang dừng…",
      "home.stopFailed": "Không dừng được scan",
      "auth.enable": "Scan với đăng nhập",
      "auth.type": "Loại đăng nhập",
      "auth.typeForm": "Form login",
      "auth.typeBasic": "HTTP Basic",
      "auth.typeGraphql": "GraphQL API",
      "auth.loginUrl": "Login URL (tuỳ chọn)",
      "auth.graphqlHint": "GraphQL: có thể để trống hoặc dán …/graphql. Clever Manager: portal tự tìm cvmanager-backend…/graphql.",
      "auth.username": "Username",
      "auth.clinicId": "Clinic / Hospital ID",
      "auth.password": "Password",
      "auth.success": "URL sau đăng nhập chứa (tuỳ chọn)",
      "auth.required": "Nhập username và password để scan có đăng nhập.",
      "auth.graphqlLoginRequired": "GraphQL cần Login URL trỏ tới endpoint API (/graphql).",
      "source.enable": "Phân tích source code (Git)",
      "source.repo": "Git repository URL (https)",
      "source.branch": "Branch (tuỳ chọn)",
      "source.token": "Token / PAT (tuỳ chọn)",
      "source.hint": "Shallow clone để lấy inventory route/API và gợi ý thiếu tenant guard. Không dùng SSH git@.",
      "source.repoRequired": "Nhập Git repository URL (https) khi bật phân tích source.",
      "home.configLabel": "Cấu hình đang dùng",
      "home.configLoading": "Đang tải…",
      "home.openConfig": "Chỉnh cấu hình",
      "home.openHistory": "Lịch sử",
      "home.urlRequired": "Vui lòng nhập địa chỉ website cần scan.",
      "home.genericError": "Có lỗi xảy ra.",
      "home.scanFailed": "Scan thất bại.",
      "home.reportFailed": "Không tạo được Security Report.",
      "home.scanStartFailed": "Không thể bắt đầu scan",
      "placeholder.eyebrow": "Cột phải",
      "placeholder.title": "Chưa có báo cáo",
      "placeholder.body": "Mở Cấu hình, Lịch sử, hoặc bắt đầu scan để xem Technical Report tại đây.",
      "report.eyebrow": "Technical Report",
      "report.risk": "Risk",
      "report.export": "Export Report",
      "report.statusTitle": "Trạng thái scan",
      "report.metricHttp": "HTTP",
      "report.metricTime": "Thời gian",
      "report.metricHttps": "HTTPS",
      "report.metricServer": "Server",
      "report.yes": "Có",
      "report.no": "Không",
      "report.findings": "Findings",
      "report.noFindings": "Không có finding.",
      "report.findingsPending": "Findings sẽ hiển thị khi scan hoàn tất.",
      "report.historyNote": "Xem lại trong",
      "report.historyLink": "Lịch sử",
      "report.processing": "Đang xử lý Security Report…",
      "report.creating": "Security Report đang được tạo — vui lòng chờ trong giây lát.",
      "report.queued": "Đang xếp hàng…",
      "report.scanning": "Đang scan…",
      "report.execLabel": "Executive summary",
      "report.execWaiting": "Đang chờ kết quả…",
      "risk.legendTitle": "Cách đọc Risk",
      "risk.high": "≥ 70: High",
      "risk.medium": "40–69: Medium",
      "risk.low": "< 40: Low",
      "risk.formula": "Điểm = tổng finding (High +25, Medium +12, Low +5, Info +0), tối đa 100. Điểm càng thấp càng tốt — 0/100 là an toàn nhất, 100/100 là rủi ro cao nhất.",
      "table.index": "Index",
      "table.function": "Function",
      "table.tool": "Tool",
      "table.result": "Result",
      "table.recommend": "Recommend",
      "table.reproduce": "Tái tạo",
      "config.eyebrow": "Cấu hình scan",
      "config.title": "Chọn checks · tools · report",
      "config.lede": "Tích chọn sẽ tự lưu và áp dụng cho mọi lần scan trên cột trái.",
      "config.close": "Đóng",
      "config.back": "Về báo cáo / trống",
      "config.save": "Lưu cấu hình",
      "config.loading": "Đang tải cấu hình…",
      "config.checks": "Vấn đề security",
      "config.defaults": "Chọn mặc định",
      "config.tools": "Tools",
      "config.toolsHint": "Tự gợi ý theo checks · Built-in / External",
      "config.reports": "Security report",
      "config.storeMissing": "Không tải được bộ nhớ cấu hình.",
      "config.catalogError": "Không tải được catalog cấu hình.",
      "config.savedAt": "Cấu hình hiện tại đã lưu lúc {when}. Tích chọn sẽ tự lưu.",
      "config.notSaved": "Chưa có cấu hình lưu. Tích chọn sẽ tự lưu ngay trên trình duyệt.",
      "config.saved": "Đã lưu cấu hình",
      "config.savedDefaults": "Đã lưu cấu hình mặc định",
      "config.autosaved": "Đã tự lưu khi chọn",
      "config.savedShort": "Đã lưu",
      "config.needChecks": "Chọn ít nhất một vấn đề security.",
      "config.needTools": "Chọn ít nhất một tool.",
      "config.needReport": "Chọn loại security report.",
      "config.saveBlocked": "Lưu cấu hình thất bại (trình duyệt chặn localStorage).",
      "config.saveFailed": "Không lưu được cấu hình vào trình duyệt.",
      "config.bannerSaved": "{reason}: {checks} checks · {tools} tools · {report}. Cập nhật: {when}",
      "config.loadError": "Lỗi tải cấu hình.",
      "report.loadFailed": "Không tải được báo cáo",
      "export.exportedAt": "Xuất lúc",
      "history.eyebrow": "Lịch sử",
      "history.title": "Scan & báo cáo trước đây",
      "history.delete": "Xóa",
      "history.close": "Đóng",
      "history.listTitle": "Danh sách scan",
      "history.refresh": "Làm mới",
      "history.selectAll": "Chọn tất cả",
      "history.when": "Thời gian scan",
      "history.url": "URL",
      "history.status": "Trạng thái",
      "history.empty": "Chưa có scan nào trong lịch sử",
      "history.loadError": "Không tải được lịch sử",
      "history.deleteConfirmOne": "Xóa 1 scan đã chọn khỏi lịch sử? Thao tác không hoàn tác.",
      "history.deleteConfirmMany": "Xóa {count} scan đã chọn khỏi lịch sử? Thao tác không hoàn tác.",
      "history.deleting": "Đang xóa…",
      "history.deleted": "Đã xóa {count} scan.",
      "history.deleteError": "Không xóa được",
      "history.selectToDelete": "Chọn để xóa",
      "snapshot.checks": "checks",
      "snapshot.tools": "tools",
      "snapshot.updated": "cập nhật",
      "snapshot.default": "mặc định hệ thống",
      "nav.introduce": "Giới thiệu",
      "introduce.eyebrow": "Hướng dẫn sử dụng",
      "introduce.title": "Security Portal",
      "introduce.subtitle": "Nền tảng quét bảo mật website tự động cho đội ngũ kỹ thuật và kỹ sư bảo mật.",
      "introduce.close": "Đóng",
      "introduce.s1.title": "Tổng quan",
      "introduce.s1.body": "Security Portal phân tích rủi ro bảo mật website theo chuẩn OWASP, hỗ trợ scan HTTP, đăng nhập tự động, phân tích source Git và tạo Technical Report với findings, bằng chứng và khuyến nghị khắc phục.",
      "introduce.s2.title": "Các kiểm tra bảo mật (Security Checks)",
      "introduce.s3.title": "Loại báo cáo và điểm rủi ro",
      "introduce.s4.title": "Hướng dẫn sử dụng",
      "introduce.s5.title": "Vai trò người dùng",
      "introduce.s6.title": "Bảo mật và quyền riêng tư",
      "lang.vi": "VI",
      "lang.en": "EN",
      "api.unreachable": "Không kết nối được API.",
    },
    en: {
      "nav.home": "Home",
      "nav.functions": "Functions",
      "nav.config": "Configure",
      "nav.history": "History",
      "home.title": "Website security scan",
      "home.urlLabel": "Website URL to scan",
      "home.scan": "Start scan",
      "home.scanning": "Scanning…",
      "home.stop": "Stop scan",
      "home.stopping": "Stopping…",
      "home.stopFailed": "Could not stop the scan",
      "auth.enable": "Scan with login",
      "auth.type": "Login type",
      "auth.typeForm": "Form login",
      "auth.typeBasic": "HTTP Basic",
      "auth.typeGraphql": "GraphQL API",
      "auth.loginUrl": "Login URL (optional)",
      "auth.graphqlHint": "GraphQL: leave blank or paste …/graphql. Clever Manager: portal discovers cvmanager-backend…/graphql.",
      "auth.username": "Username",
      "auth.clinicId": "Clinic / Hospital ID",
      "auth.password": "Password",
      "auth.success": "Post-login URL contains (optional)",
      "auth.required": "Enter username and password for authenticated scan.",
      "auth.graphqlLoginRequired": "GraphQL requires Login URL pointing at the API endpoint (/graphql).",
      "source.enable": "Analyze source code (Git)",
      "source.repo": "Git repository URL (https)",
      "source.branch": "Branch (optional)",
      "source.token": "Token / PAT (optional)",
      "source.hint": "Shallow clone to collect route/API inventory and tenant-guard hints. SSH git@ is not supported.",
      "source.repoRequired": "Enter an https Git repository URL when source analysis is enabled.",
      "home.configLabel": "Active configuration",
      "home.configLoading": "Loading…",
      "home.openConfig": "Edit configuration",
      "home.openHistory": "History",
      "home.urlRequired": "Please enter a website URL to scan.",
      "home.genericError": "Something went wrong.",
      "home.scanFailed": "Scan failed.",
      "home.reportFailed": "Could not create the Security Report.",
      "home.scanStartFailed": "Unable to start scan",
      "placeholder.eyebrow": "Right panel",
      "placeholder.title": "No report yet",
      "placeholder.body": "Open Configure, History, or start a scan to view the Technical Report here.",
      "report.eyebrow": "Technical Report",
      "report.risk": "Risk",
      "report.export": "Export Report",
      "report.statusTitle": "Scan status",
      "report.metricHttp": "HTTP",
      "report.metricTime": "Time",
      "report.metricHttps": "HTTPS",
      "report.metricServer": "Server",
      "report.yes": "Yes",
      "report.no": "No",
      "report.findings": "Findings",
      "report.noFindings": "No findings.",
      "report.findingsPending": "Findings will appear when the scan completes.",
      "report.historyNote": "Review later in",
      "report.historyLink": "History",
      "report.processing": "Generating Security Report…",
      "report.creating": "Security Report is being created — please wait.",
      "report.queued": "Queued…",
      "report.scanning": "Scanning…",
      "report.execLabel": "Executive summary",
      "report.execWaiting": "Waiting for results…",
      "risk.legendTitle": "How to read Risk",
      "risk.high": "≥ 70: High",
      "risk.medium": "40–69: Medium",
      "risk.low": "< 40: Low",
      "risk.formula": "Score = sum of findings (High +25, Medium +12, Low +5, Info +0), capped at 100. Lower is better — 0/100 is safest, 100/100 is highest risk.",
      "table.index": "Index",
      "table.function": "Function",
      "table.tool": "Tool",
      "table.result": "Result",
      "table.recommend": "Recommend",
      "table.reproduce": "Reproduce",
      "config.eyebrow": "Scan configuration",
      "config.title": "Choose checks · tools · report",
      "config.lede": "Selections are saved automatically and applied to every scan on the left.",
      "config.close": "Close",
      "config.back": "Back to report / empty",
      "config.save": "Save configuration",
      "config.loading": "Loading configuration…",
      "config.checks": "Security checks",
      "config.defaults": "Select defaults",
      "config.tools": "Tools",
      "config.toolsHint": "Suggested from checks · Built-in / External",
      "config.reports": "Security report",
      "config.storeMissing": "Could not load configuration storage.",
      "config.catalogError": "Could not load configuration catalog.",
      "config.savedAt": "Configuration last saved at {when}. Changes auto-save.",
      "config.notSaved": "No saved configuration yet. Changes auto-save in this browser.",
      "config.saved": "Configuration saved",
      "config.savedDefaults": "Default configuration saved",
      "config.autosaved": "Auto-saved on change",
      "config.savedShort": "Saved",
      "config.needChecks": "Select at least one security check.",
      "config.needTools": "Select at least one tool.",
      "config.needReport": "Select a security report type.",
      "config.saveBlocked": "Could not save configuration (browser blocked localStorage).",
      "config.saveFailed": "Could not save configuration in this browser.",
      "config.bannerSaved": "{reason}: {checks} checks · {tools} tools · {report}. Updated: {when}",
      "config.loadError": "Failed to load configuration.",
      "report.loadFailed": "Could not load report",
      "export.exportedAt": "Exported at",
      "history.eyebrow": "History",
      "history.title": "Previous scans & reports",
      "history.delete": "Delete",
      "history.close": "Close",
      "history.listTitle": "Scan list",
      "history.refresh": "Refresh",
      "history.selectAll": "Select all",
      "history.when": "Scan time",
      "history.url": "URL",
      "history.status": "Status",
      "history.empty": "No scans in history yet",
      "history.loadError": "Could not load history",
      "history.deleteConfirmOne": "Delete 1 selected scan from history? This cannot be undone.",
      "history.deleteConfirmMany": "Delete {count} selected scans from history? This cannot be undone.",
      "history.deleting": "Deleting…",
      "history.deleted": "Deleted {count} scan(s).",
      "history.deleteError": "Could not delete",
      "history.selectToDelete": "Select to delete",
      "snapshot.checks": "checks",
      "snapshot.tools": "tools",
      "snapshot.updated": "updated",
      "snapshot.default": "system defaults",
      "nav.introduce": "Introduce",
      "introduce.eyebrow": "User Guide",
      "introduce.title": "Security Portal",
      "introduce.subtitle": "Automated website security scanning platform for engineering and security teams.",
      "introduce.close": "Close",
      "introduce.s1.title": "Overview",
      "introduce.s1.body": "Security Portal analyses website security risks against OWASP standards, with HTTP scanning, automated login, Git source analysis and Technical Reports with findings, evidence and remediation guidance.",
      "introduce.s2.title": "Security Checks",
      "introduce.s3.title": "Report types & risk score",
      "introduce.s4.title": "How to use",
      "introduce.s5.title": "User roles",
      "introduce.s6.title": "Security & privacy",
      "lang.vi": "VI",
      "lang.en": "EN",
      "api.unreachable": "Could not reach the API.",
    },
  };

  let locale = loadLocale();
  const listeners = new Set();

  function loadLocale() {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved === "en" || saved === "vi") return saved;
    } catch { /* ignore */ }
    return "vi";
  }

  function getLocale() {
    return locale;
  }

  function t(key, vars) {
    const table = dict[locale] || dict.vi;
    let text = table[key] ?? dict.en[key] ?? key;
    if (vars) {
      for (const [k, v] of Object.entries(vars)) {
        text = text.replaceAll(`{${k}}`, String(v));
      }
    }
    return text;
  }

  function setLocale(next) {
    const normalized = next === "en" ? "en" : "vi";
    if (normalized === locale) return;
    locale = normalized;
    try { localStorage.setItem(STORAGE_KEY, locale); } catch { /* ignore */ }
    applyDom();
    document.documentElement.lang = locale;
    listeners.forEach((fn) => {
      try { fn(locale); } catch { /* ignore */ }
    });
  }

  function onChange(fn) {
    listeners.add(fn);
    return () => listeners.delete(fn);
  }

  function applyDom(root = document) {
    root.querySelectorAll("[data-i18n]").forEach((el) => {
      const key = el.getAttribute("data-i18n");
      if (!key) return;
      el.textContent = t(key);
    });
    root.querySelectorAll("[data-i18n-html]").forEach((el) => {
      const key = el.getAttribute("data-i18n-html");
      if (!key) return;
      el.innerHTML = t(key);
    });
    root.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
      const key = el.getAttribute("data-i18n-placeholder");
      if (!key) return;
      el.setAttribute("placeholder", t(key));
    });
    root.querySelectorAll("[data-i18n-title]").forEach((el) => {
      const key = el.getAttribute("data-i18n-title");
      if (!key) return;
      el.setAttribute("title", t(key));
    });
    root.querySelectorAll("[data-lang]").forEach((el) => {
      el.classList.toggle("is-active", el.getAttribute("data-lang") === locale);
    });
  }

  document.documentElement.lang = locale;

  return { getLocale, setLocale, t, onChange, applyDom, STORAGE_KEY };
})();
