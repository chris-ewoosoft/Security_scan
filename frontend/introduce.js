window.SecurityPortalIntroduce = (() => {
  const { escapeHtml } = window.SecurityPortalApi;
  const I18n = window.SecurityPortalI18n;
  const t = (key, vars) => (I18n ? I18n.t(key, vars) : key);

  function renderContent() {
    const locale = I18n?.getLocale?.() ?? "vi";
    return locale === "en" ? renderEn() : renderVi();
  }

  function renderVi() {
    return `
<div class="introduce-body">
  <section class="introduce-section">
    <h3>${escapeHtml(t("introduce.s1.title"))}</h3>
    <p>${escapeHtml(t("introduce.s1.body"))}</p>
  </section>

  <section class="introduce-section">
    <h3>${escapeHtml(t("introduce.s2.title"))}</h3>
    <div class="introduce-checks-grid">
      <div class="introduce-check-group">
        <p class="introduce-check-group-label">Cơ bản (Built-in)</p>
        <ul>
          <li><strong>Khả năng truy cập</strong> — HTTP response, thời gian phản hồi, mã trạng thái</li>
          <li><strong>HTTPS / TLS</strong> — Xác minh HTTPS và cấu hình TLS cơ bản</li>
          <li><strong>Security Headers</strong> — CSP, HSTS, X-Frame-Options và các header bảo mật</li>
          <li><strong>Server Fingerprint</strong> — Thông tin lộ qua <code>Server</code> / <code>X-Powered-By</code></li>
          <li><strong>Cookie Security</strong> — Cờ <code>Secure</code>, <code>HttpOnly</code>, <code>SameSite</code></li>
          <li><strong>CORS Policy</strong> — Cấu hình <code>Access-Control-Allow-Origin</code></li>
          <li><strong>Information Disclosure</strong> — Header nhạy cảm và dấu hiệu lộ thông tin</li>
          <li><strong>Authenticated Scan</strong> — Quét khu vực sau đăng nhập (form / Basic / GraphQL)</li>
          <li><strong>Source Route Inventory</strong> — Clone Git, inventory route/API, gợi ý thiếu tenant guard</li>
        </ul>
      </div>
      <div class="introduce-check-group">
        <p class="introduce-check-group-label">Mạng &amp; Hạ tầng</p>
        <ul>
          <li><strong>Port Scan</strong> — Quét cổng (Naabu nếu có trên PATH, không thì TCP probe)</li>
          <li><strong>DNS Security</strong> — Resolve DNS (dnsx nếu có)</li>
          <li><strong>WAF Detection</strong> — Fingerprint WAF (wafw00f nếu có)</li>
        </ul>
        <p class="introduce-check-group-label">Khám phá &amp; Tình báo</p>
        <ul>
          <li><strong>Directory Discovery</strong> — Wordlist tích hợp; Feroxbuster / FFUF nếu có</li>
          <li><strong>Sensitive File Scan</strong> — File <code>.env</code>, backup, git</li>
          <li><strong>Technology Detection</strong> — Suy luận stack từ header</li>
          <li><strong>Screenshot</strong> — Gowitness nếu có trên PATH</li>
          <li><strong>Vulnerability Scan</strong> — Nuclei nếu có; không thì placeholder</li>
        </ul>
        <p class="introduce-check-group-label">Server nội bộ (SSH)</p>
        <ul>
          <li><strong>SSH Connectivity</strong> — Kết nối server Linux bằng password hoặc private key</li>
          <li><strong>Host Triage</strong> — Thu thập thông tin hệ thống và các dấu hiệu cấu hình cần chú ý</li>
          <li><strong>Server Findings</strong> — Hiển thị trạng thái, summary và findings trong báo cáo bên phải</li>
        </ul>
      </div>
    </div>
  </section>

  <section class="introduce-section">
    <h3>${escapeHtml(t("introduce.sshGoals.title"))}</h3>
    <p>${escapeHtml(t("introduce.sshGoals.body"))}</p>
    <ul>
      <li><strong>Malware &amp; Reverse Shell</strong> — Tìm payload trong thư mục tạm, miner, lệnh tải và thực thi mã, process bất thường hoặc binary đã bị xóa nhưng vẫn chạy.</li>
      <li><strong>Sniffer &amp; Raw Socket</strong> — Đối chiếu promiscuous mode, raw socket với process capture như <code>tcpdump</code>, <code>tshark</code>, <code>bettercap</code> và các công cụ tương tự.</li>
      <li><strong>Persistence</strong> — Kiểm tra cron, systemd, shell startup, <code>LD_PRELOAD</code>, SSH key và cơ chế tự khởi động lại.</li>
      <li><strong>Account Compromise</strong> — Phân tích SSH authentication events, invalid user, login failure và dấu hiệu truy cập bất thường.</li>
      <li><strong>Data Exfiltration</strong> — Tìm dấu hiệu dump database, đóng gói dữ liệu, upload/copy file và kết nối outbound đáng ngờ.</li>
      <li><strong>Read-only evidence</strong> — Chỉ thu thập và lưu evidence; không tự động kill process, xóa file, quarantine hoặc block IP.</li>
    </ul>
  </section>

  <section class="introduce-section">
    <h3>${escapeHtml(t("introduce.s3.title"))}</h3>
    <table class="introduce-table">
      <thead><tr><th>Loại báo cáo</th><th>Dành cho</th></tr></thead>
      <tbody>
        <tr><td><strong>Technical Report</strong></td><td>Kỹ sư bảo mật — chi tiết kỹ thuật từng check và bằng chứng</td></tr>
        <tr><td><strong>Executive Summary</strong></td><td>Quản lý — rủi ro tổng quan và khuyến nghị ưu tiên</td></tr>
        <tr><td><strong>OWASP-oriented Summary</strong></td><td>Nhóm findings theo góc nhìn OWASP / baseline web</td></tr>
      </tbody>
    </table>
    <div class="introduce-risk-note">
      <strong>Điểm rủi ro (Risk Score):</strong> 0–100 · điểm giảm dần theo số finding cùng severity; có High → tối thiểu 55.
      <br><span class="introduce-risk-scale">
        <span class="sev-low">Low &lt; 40</span>
        <span class="sev-medium">Medium 40–69</span>
        <span class="sev-high">High ≥ 70</span>
      </span>
    </div>
  </section>

  <section class="introduce-section">
    <h3>${escapeHtml(t("introduce.s4.title"))}</h3>
    <ol class="introduce-steps">
      <li>
        <span class="introduce-step-num">1</span>
        <div>
          <strong>Nhập URL</strong> — Gõ địa chỉ website cần quét vào ô ở bên trái, ví dụ
          <code>https://example.com</code>.
        </div>
      </li>
      <li>
        <span class="introduce-step-num">2</span>
        <div>
          <strong>Cấu hình scan (tuỳ chọn)</strong> — Mở <em>Chức năng → Cấu hình</em> để tích chọn
          Security Checks, Tools và loại báo cáo. Cấu hình tự lưu vào trình duyệt.
        </div>
      </li>
      <li>
        <span class="introduce-step-num">3</span>
        <div>
          <strong>Scan có đăng nhập (tuỳ chọn)</strong> — Bật <em>Scan với đăng nhập</em>, chọn
          Form / HTTP Basic / GraphQL. Với GraphQL, dán endpoint API (<code>…/graphql</code>).
          Có thể điền Clinic ID cho hệ multi-tenant. Sau login, portal so sánh path ẩn danh vs đã đăng nhập
          và probe API/GraphQL phát hiện được.
        </div>
      </li>
      <li>
        <span class="introduce-step-num">4</span>
        <div>
          <strong>Phân tích source code (tuỳ chọn)</strong> — Bật <em>Phân tích source code (Git)</em>,
          nhập URL repo <code>https://…</code>, branch và PAT (repo private). PAT chỉ điền vào ô Token —
          không dán vào ô URL. Portal shallow-clone repo, liệt kê route và gợi ý route có object id
          thiếu guard org/clinic.
        </div>
      </li>
      <li>
        <span class="introduce-step-num">5</span>
        <div>
          <strong>Bắt đầu scan</strong> — Nhấn <em>Bắt đầu scan</em>. Trình duyệt lưu access token để xem lại / dừng / xóa.
          Trạng thái cập nhật ở cột phải; nhấn <em>Dừng scan</em> để hủy.
        </div>
      </li>
      <li>
        <span class="introduce-step-num">6</span>
        <div>
          <strong>Quét server nội bộ qua SSH</strong> — Chọn tab <em>Quét server SSH</em> ở cột trái,
          nhập IP hoặc hostname, port SSH, username và chọn Password hoặc Private Key. Nhấn
          <em>Bắt đầu scan</em>; kết quả server và findings hiển thị ở cột phải. Có thể nhấn
          <em>Dừng scan</em> để hủy request đang chạy.
        </div>
      </li>
      <li>
        <span class="introduce-step-num">7</span>
        <div>
          <strong>Đọc Security Report</strong> — Điểm rủi ro, executive summary, bảng findings
          (kể cả <code>auth.*</code>, <code>source.*</code> và findings từ SSH). <em>Export Report</em> để xuất PDF.
        </div>
      </li>
      <li>
        <span class="introduce-step-num">8</span>
        <div>
          <strong>Xem lịch sử &amp; hướng dẫn</strong> — <em>Chức năng → Lịch sử</em> để mở lại scan cũ;
          <em>Chức năng → Giới thiệu</em> để xem hướng dẫn này.
        </div>
      </li>
    </ol>
  </section>

  <section class="introduce-section">
    <h3>${escapeHtml(t("introduce.s5.title"))}</h3>
    <table class="introduce-table">
      <thead><tr><th>Vai trò</th><th>Quyền hạn</th></tr></thead>
      <tbody>
        <tr><td><span class="introduce-role introduce-role-admin">Admin</span></td><td>Quản trị người dùng, tổ chức, phân quyền, xem audit log</td></tr>
        <tr><td><span class="introduce-role introduce-role-engineer">SecurityEngineer</span></td><td>Tạo và chạy quét, xem và xuất báo cáo, quản lý findings</td></tr>
        <tr><td><span class="introduce-role introduce-role-viewer">Viewer</span></td><td>Chỉ đọc — xem kết quả scan và báo cáo</td></tr>
      </tbody>
    </table>
  </section>

  <section class="introduce-section introduce-section-last">
    <h3>${escapeHtml(t("introduce.s6.title"))}</h3>
    <ul class="introduce-security-list">
      <li>Mật khẩu băm bằng <strong>BCrypt</strong> — không lưu plaintext.</li>
      <li>JWT Bearer + Refresh Token quản lý server-side, có thể thu hồi bất cứ lúc nào.</li>
      <li>Mọi thao tác quan trọng ghi <strong>Audit Log</strong> kèm IP, UserAgent và dữ liệu thay đổi.</li>
      <li>Thông tin xác thực scan (password, clinic ID) và <strong>PAT Git</strong> được mã hóa — API không trả plaintext; lỗi scan được sanitize để không lộ token.</li>
      <li>Giao tiếp Frontend ↔ API qua Nginx reverse proxy (HTTPS).</li>
    </ul>
  </section>
</div>`;
  }

  function renderEn() {
    return `
<div class="introduce-body">
  <section class="introduce-section">
    <h3>${escapeHtml(t("introduce.s1.title"))}</h3>
    <p>${escapeHtml(t("introduce.s1.body"))}</p>
  </section>

  <section class="introduce-section">
    <h3>${escapeHtml(t("introduce.s2.title"))}</h3>
    <div class="introduce-checks-grid">
      <div class="introduce-check-group">
        <p class="introduce-check-group-label">Basic (Built-in)</p>
        <ul>
          <li><strong>Reachability</strong> — HTTP response, latency, status code</li>
          <li><strong>HTTPS / TLS</strong> — Verify HTTPS and basic TLS configuration</li>
          <li><strong>Security Headers</strong> — CSP, HSTS, X-Frame-Options and more</li>
          <li><strong>Server Fingerprint</strong> — Info leaked via <code>Server</code> / <code>X-Powered-By</code></li>
          <li><strong>Cookie Security</strong> — <code>Secure</code>, <code>HttpOnly</code>, <code>SameSite</code> flags</li>
          <li><strong>CORS Policy</strong> — <code>Access-Control-Allow-Origin</code> configuration</li>
          <li><strong>Information Disclosure</strong> — Sensitive headers and data leakage signals</li>
          <li><strong>Authenticated Scan</strong> — Scan behind login (form / Basic / GraphQL)</li>
          <li><strong>Source Route Inventory</strong> — Git clone, route/API inventory, tenant-guard hints</li>
        </ul>
      </div>
      <div class="introduce-check-group">
        <p class="introduce-check-group-label">Network &amp; Infrastructure</p>
        <ul>
          <li><strong>Port Scan</strong> — Open ports (Naabu if on PATH, else TCP probe)</li>
          <li><strong>DNS Security</strong> — DNS resolve (dnsx if available)</li>
          <li><strong>WAF Detection</strong> — WAF fingerprint (wafw00f if available)</li>
        </ul>
        <p class="introduce-check-group-label">Discovery &amp; Reconnaissance</p>
        <ul>
          <li><strong>Directory Discovery</strong> — Built-in wordlist; Feroxbuster / FFUF if available</li>
          <li><strong>Sensitive File Scan</strong> — <code>.env</code>, backup, git files</li>
          <li><strong>Technology Detection</strong> — Stack signals from headers</li>
          <li><strong>Screenshot</strong> — Gowitness if on PATH</li>
          <li><strong>Vulnerability Scan</strong> — Nuclei if available; otherwise placeholder</li>
        </ul>
        <p class="introduce-check-group-label">Internal server (SSH)</p>
        <ul>
          <li><strong>SSH Connectivity</strong> — Connect to Linux servers with a password or private key</li>
          <li><strong>Host Triage</strong> — Collect system information and configuration signals</li>
          <li><strong>Server Findings</strong> — Show status, summary and findings in the right report panel</li>
        </ul>
      </div>
    </div>
  </section>

  <section class="introduce-section">
    <h3>${escapeHtml(t("introduce.sshGoals.title"))}</h3>
    <p>${escapeHtml(t("introduce.sshGoals.body"))}</p>
    <ul>
      <li><strong>Malware &amp; Reverse Shell</strong> — Detect payloads in temporary paths, miners, download-and-execute commands, abnormal processes, and deleted binaries still running.</li>
      <li><strong>Sniffers &amp; Raw Sockets</strong> — Correlate promiscuous mode and raw sockets with capture processes such as <code>tcpdump</code>, <code>tshark</code>, and <code>bettercap</code>.</li>
      <li><strong>Persistence</strong> — Check cron, systemd, shell startup, <code>LD_PRELOAD</code>, SSH keys, and relaunch mechanisms.</li>
      <li><strong>Account Compromise</strong> — Analyse SSH authentication events, invalid users, login failures, and unusual access signals.</li>
      <li><strong>Data Exfiltration</strong> — Look for database dumps, data archiving, upload/copy commands, and suspicious outbound connections.</li>
      <li><strong>Read-only evidence</strong> — Collect and retain evidence only; never automatically kill processes, delete files, quarantine artifacts, or block IPs.</li>
    </ul>
  </section>

  <section class="introduce-section">
    <h3>${escapeHtml(t("introduce.s3.title"))}</h3>
    <table class="introduce-table">
      <thead><tr><th>Report type</th><th>For</th></tr></thead>
      <tbody>
        <tr><td><strong>Technical Report</strong></td><td>Security engineers — full technical detail per check with evidence</td></tr>
        <tr><td><strong>Executive Summary</strong></td><td>Management — risk overview and priority recommendations</td></tr>
        <tr><td><strong>OWASP-oriented Summary</strong></td><td>Findings grouped by OWASP / web baseline categories</td></tr>
      </tbody>
    </table>
    <div class="introduce-risk-note">
      <strong>Risk Score:</strong> 0–100 · diminishing returns per severity; any High floors at 55.
      <br><span class="introduce-risk-scale">
        <span class="sev-low">Low &lt; 40</span>
        <span class="sev-medium">Medium 40–69</span>
        <span class="sev-high">High ≥ 70</span>
      </span>
    </div>
  </section>

  <section class="introduce-section">
    <h3>${escapeHtml(t("introduce.s4.title"))}</h3>
    <ol class="introduce-steps">
      <li>
        <span class="introduce-step-num">1</span>
        <div>
          <strong>Enter URL</strong> — Type the target website in the left column,
          e.g. <code>https://example.com</code>.
        </div>
      </li>
      <li>
        <span class="introduce-step-num">2</span>
        <div>
          <strong>Configure scan (optional)</strong> — Open <em>Functions → Configure</em> to select
          Security Checks, Tools and report type. Settings auto-save in the browser.
        </div>
      </li>
      <li>
        <span class="introduce-step-num">3</span>
        <div>
          <strong>Authenticated scan (optional)</strong> — Enable <em>Scan with login</em>, choose
          Form / HTTP Basic / GraphQL. For GraphQL, paste the API endpoint (<code>…/graphql</code>).
          Clinic ID is available for multi-tenant apps. After login, the portal compares anonymous vs
          authenticated paths and probes discovered API/GraphQL bases.
        </div>
      </li>
      <li>
        <span class="introduce-step-num">4</span>
        <div>
          <strong>Source analysis (optional)</strong> — Enable <em>Analyze source code (Git)</em>,
          enter an <code>https://</code> repo URL, branch and PAT (private repos). Put the PAT only in
          the Token field — never in the URL box. The portal shallow-clones the repo, inventories routes
          and flags object-id routes that may lack tenant/org guards.
        </div>
      </li>
      <li>
        <span class="introduce-step-num">5</span>
        <div>
          <strong>Start scan</strong> — Click <em>Start scan</em>. The browser stores an access token for view / stop / delete.
        </div>
      </li>
      <li>
        <span class="introduce-step-num">6</span>
        <div>
          <strong>Scan an internal server over SSH</strong> — Select <em>SSH server scan</em> in the left column,
          enter the IP or hostname, SSH port, username, and choose Password or Private Key. Press
          <em>Start scan</em>; the server result and findings appear in the right column. Press
          <em>Stop scan</em> to cancel the active request.
        </div>
      </li>
      <li>
        <span class="introduce-step-num">7</span>
        <div>
          <strong>Read the Security Report</strong> — Risk score, executive summary and findings
          (including <code>auth.*</code>, <code>source.*</code> and SSH findings). Use <em>Export Report</em> to export PDF.
        </div>
      </li>
      <li>
        <span class="introduce-step-num">8</span>
        <div>
          <strong>History &amp; guide</strong> — <em>Functions → History</em> to reopen past scans;
          <em>Functions → Introduce</em> for this guide.
        </div>
      </li>
    </ol>
  </section>

  <section class="introduce-section">
    <h3>${escapeHtml(t("introduce.s5.title"))}</h3>
    <table class="introduce-table">
      <thead><tr><th>Role</th><th>Access</th></tr></thead>
      <tbody>
        <tr><td><span class="introduce-role introduce-role-admin">Admin</span></td><td>Manage users, organizations, permissions, audit log</td></tr>
        <tr><td><span class="introduce-role introduce-role-engineer">SecurityEngineer</span></td><td>Create and run scans, view and export reports, manage findings</td></tr>
        <tr><td><span class="introduce-role introduce-role-viewer">Viewer</span></td><td>Read-only — view scan results and reports</td></tr>
      </tbody>
    </table>
  </section>

  <section class="introduce-section introduce-section-last">
    <h3>${escapeHtml(t("introduce.s6.title"))}</h3>
    <ul class="introduce-security-list">
      <li>Passwords hashed with <strong>BCrypt</strong> — never stored in plaintext.</li>
      <li>JWT Bearer + server-managed Refresh Tokens, revocable at any time.</li>
      <li>All important actions logged in <strong>Audit Log</strong> with IP, UserAgent and diff.</li>
      <li>Scan credentials (password, clinic ID) and <strong>Git PATs</strong> are encrypted — the API never returns plaintext; scan errors are sanitized to avoid token leakage.</li>
      <li>Frontend ↔ API communication via Nginx reverse proxy (HTTPS).</li>
    </ul>
  </section>
</div>`;
  }

  function mount(root, options = {}) {
    const { onClose } = options;

    root.innerHTML = `
      <div class="introduce-panel-inner">
        <div class="report-hero">
          <div>
            <p class="eyebrow" data-i18n="introduce.eyebrow"></p>
            <h2 class="page-title" data-i18n="introduce.title"></h2>
            <p class="lede introduce-lede" data-i18n="introduce.subtitle"></p>
          </div>
          <button type="button" class="ghost-btn" data-action="close-introduce"
            data-i18n="introduce.close"></button>
        </div>
        <div class="introduce-content"></div>
      </div>
    `;

    I18n?.applyDom(root);

    const content = root.querySelector(".introduce-content");
    content.innerHTML = renderContent();

    const closeBtn = root.querySelector('[data-action="close-introduce"]');
    closeBtn?.addEventListener("click", () => onClose?.());

    let unlisten;
    if (I18n?.onChange) {
      unlisten = I18n.onChange(() => {
        I18n.applyDom(root);
        content.innerHTML = renderContent();
      });
    }

    return {
      destroy() {
        unlisten?.();
      },
    };
  }

  return { mount };
})();
