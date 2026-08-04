(() => {
  const {
    apiFetch,
    extractError,
    normalizeUrl,
    statusClass,
    severityClass,
    escapeHtml,
    formatWhen,
  } = window.SecurityPortalApi;
  const ConfigStore = window.SecurityPortalConfig;

  const form = document.getElementById("scan-form");
  const input = document.getElementById("target-url");
  const scanBtn = document.getElementById("scan-btn");
  const formError = document.getElementById("form-error");
  const configSummary = document.getElementById("config-summary");
  const reportPanel = document.getElementById("report-panel");

  let catalog = null;
  let pollTimer = null;
  let activeScanId = null;

  function getScanConfig() {
    const loaded = ConfigStore.load();
    const allowedChecks = new Set((catalog?.checks || []).map((c) => c.id));
    const allowedTools = new Set((catalog?.tools || []).map((t) => t.id));
    const allowedReports = new Set((catalog?.reports || []).map((r) => r.id));

    let checks = (loaded.checks || []).filter((id) => !allowedChecks.size || allowedChecks.has(id));
    let tools = (loaded.tools || []).filter((id) => !allowedTools.size || allowedTools.has(id));
    let reportType = loaded.reportType;

    if (!checks.length) checks = [...ConfigStore.FALLBACK.checks];
    if (!tools.length) tools = [...ConfigStore.FALLBACK.tools];
    if (!reportType || (allowedReports.size && !allowedReports.has(reportType))) {
      reportType = ConfigStore.FALLBACK.reportType;
    }

    return { checks, tools, reportType, updatedAt: loaded.updatedAt || null };
  }

  async function loadCatalog() {
    try {
      const res = await apiFetch("/scans/catalog", { headers: { Accept: "application/json" } });
      if (res.ok) catalog = await res.json();
    } catch {
      catalog = null;
    }
    renderConfigSnapshot();
  }

  function renderConfigSnapshot() {
    const config = getScanConfig();
    const summary = ConfigStore.summarize(config, catalog);
    const updated = summary.updatedAt
      ? ` · cập nhật ${formatWhen(summary.updatedAt)}`
      : " · mặc định hệ thống";
    configSummary.textContent =
      `${summary.checkCount} checks · ${summary.toolCount} tools · ${summary.reportName}${updated}`;
  }

  function openReportPanel(scan) {
    activeScanId = scan.id;
    const placeholder = document.getElementById("report-placeholder");
    if (placeholder) placeholder.hidden = true;
    reportPanel.hidden = false;
    renderReport(scan);
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    formError.hidden = true;

    const targetUrl = normalizeUrl(input.value);
    if (!targetUrl) {
      formError.hidden = false;
      formError.textContent = "Vui lòng nhập địa chỉ website cần scan.";
      input.focus();
      return;
    }

    const config = getScanConfig();
    scanBtn.disabled = true;
    scanBtn.textContent = "Đang scan…";

    openReportPanel({
      id: "pending",
      targetUrl,
      status: "Queued",
      summary: "Đang khởi tạo Security Report…",
      reportType: config.reportType,
      configuration: config,
      report: null,
    });

    try {
      const res = await apiFetch("/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({
          targetUrl,
          checks: config.checks,
          tools: config.tools,
          reportType: config.reportType,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(extractError(data) || `Không thể bắt đầu scan (HTTP ${res.status}).`);
      }

      history.replaceState(null, "", `/?id=${encodeURIComponent(data.id)}`);
      openReportPanel(data);
      startPolling(data.id);

      const historyNote = document.querySelector(".history-link-note a");
      if (historyNote) historyNote.href = `/history.html?id=${encodeURIComponent(data.id)}`;
    } catch (err) {
      formError.hidden = false;
      formError.textContent = err.message || "Có lỗi xảy ra.";
      document.getElementById("status-badge").textContent = "Failed";
      document.getElementById("status-badge").className = "badge is-failed";
      document.getElementById("status-summary").textContent = err.message || "Scan thất bại.";
      document.getElementById("executive-summary").textContent = err.message || "Không tạo được Security Report.";
      stopPolling();
    } finally {
      scanBtn.disabled = false;
      scanBtn.textContent = "Bắt đầu scan";
    }
  });

  async function refreshReport() {
    if (!activeScanId || activeScanId === "pending") return;
    const res = await apiFetch(`/scans/${activeScanId}`, { headers: { Accept: "application/json" } });
    if (!res.ok) throw new Error(`Không tải được báo cáo (HTTP ${res.status}).`);
    const scan = await res.json();
    renderReport(scan);
    if (scan.status === "Completed" || scan.status === "Failed" || scan.status === "Cancelled") {
      stopPolling();
    }
  }

  function renderReport(scan) {
    document.getElementById("report-title").textContent = scan.report?.reportTitle || "Security Report";
    document.getElementById("report-target").textContent = scan.targetUrl || "";

    const badge = document.getElementById("status-badge");
    badge.textContent = scan.status || "Queued";
    badge.className = "badge " + statusClass(scan.status);
    document.getElementById("status-summary").textContent =
      scan.errorMessage || scan.summary || "Đang xử lý Security Report…";
    document.getElementById("metric-http").textContent = scan.httpStatusCode ?? "—";
    document.getElementById("metric-time").textContent =
      scan.responseTimeMs != null ? `${scan.responseTimeMs} ms` : "—";
    document.getElementById("metric-https").textContent =
      scan.hasHttps == null ? "—" : (scan.hasHttps ? "Có" : "Không");
    document.getElementById("metric-server").textContent = scan.serverHeader || "—";

    const report = scan.report;
    if (!report) {
      document.getElementById("risk-level").textContent = "—";
      document.getElementById("risk-level").className = "";
      document.getElementById("risk-score").textContent = "—/100";
      document.getElementById("executive-summary").textContent =
        "Security Report đang được tạo theo cấu hình đã lưu…";
      document.getElementById("findings-list").innerHTML =
        "<p class='muted'>Findings sẽ hiển thị khi scan hoàn tất.</p>";
      return;
    }

    document.getElementById("risk-level").textContent = report.riskLevel;
    document.getElementById("risk-level").className = severityClass(report.riskLevel);
    document.getElementById("risk-score").textContent = `${report.riskScore}/100`;
    document.getElementById("executive-summary").textContent = report.executiveSummary;

    const findings = report.findings || [];
    if (!findings.length) {
      document.getElementById("findings-list").innerHTML = "<p class='muted'>Không có finding.</p>";
      return;
    }

    document.getElementById("findings-list").innerHTML = `
      <table class="findings-table">
        <thead>
          <tr>
            <th scope="col">Index</th>
            <th scope="col">Function</th>
            <th scope="col">Tool</th>
            <th scope="col">Result</th>
            <th scope="col">Recommend</th>
          </tr>
        </thead>
        <tbody>
          ${findings.map((f, index) => `
            <tr class="${severityClass(f.severity)}">
              <td class="col-index">${index + 1}</td>
              <td class="col-function">${escapeHtml(f.checkName || f.checkId || "—")}</td>
              <td class="col-tool">${escapeHtml((f.tools || []).join(", ") || "—")}</td>
              <td class="col-result">
                <span class="badge ${severityClass(f.severity)}">${escapeHtml(f.severity || "Info")}</span>
                <strong>${escapeHtml(f.title || "—")}</strong>
                <p>${escapeHtml(f.detail || "")}</p>
                ${f.evidence ? `<pre>${escapeHtml(f.evidence)}</pre>` : ""}
              </td>
              <td class="col-recommend">${escapeHtml(f.recommendation || "—")}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function startPolling(scanId) {
    activeScanId = scanId;
    stopPolling();
    pollTimer = setInterval(() => {
      refreshReport().catch(() => {});
    }, 2000);
  }

  async function showReport(scanId) {
    openReportPanel({
      id: scanId,
      targetUrl: "",
      status: "Queued",
      summary: "Đang tải Security Report…",
      report: null,
    });
    startPolling(scanId);
    try {
      await refreshReport();
    } catch (err) {
      document.getElementById("status-summary").textContent = err.message;
    }
  }

  const params = new URLSearchParams(window.location.search);
  const initialId = params.get("id");

  loadCatalog().then(async () => {
    if (initialId) await showReport(initialId);
  });

  input.focus();
})();
