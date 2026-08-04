(() => {
  const { apiFetch, statusClass, severityClass, escapeHtml } = window.SecurityPortalApi;

  const params = new URLSearchParams(window.location.search);
  const scanId = params.get("id");
  if (!scanId) {
    document.getElementById("report-title").textContent = "Thiếu mã scan";
    return;
  }

  const reconfig = document.getElementById("reconfig-link");
  let pollTimer = null;

  async function refresh() {
    const res = await apiFetch(`/scans/${scanId}`, { headers: { Accept: "application/json" } });
    if (!res.ok) throw new Error(`Không tải được scan (HTTP ${res.status}).`);
    const scan = await res.json();
    render(scan);

    if (scan.status === "Completed" || scan.status === "Failed" || scan.status === "Cancelled") {
      stopPolling();
    }
  }

  function render(scan) {
    document.title = `Report · ${scan.normalizedHost} — Security Portal`;
    document.getElementById("report-title").textContent = scan.report?.reportTitle || "Security Report";
    document.getElementById("report-target").textContent = scan.targetUrl;
    reconfig.href = `/configure.html?url=${encodeURIComponent(scan.targetUrl)}`;

    const badge = document.getElementById("status-badge");
    badge.textContent = scan.status;
    badge.className = "badge " + statusClass(scan.status);
    document.getElementById("status-summary").textContent = scan.errorMessage || scan.summary || "Đang xử lý…";
    document.getElementById("metric-http").textContent = scan.httpStatusCode ?? "—";
    document.getElementById("metric-time").textContent = scan.responseTimeMs != null ? `${scan.responseTimeMs} ms` : "—";
    document.getElementById("metric-https").textContent = scan.hasHttps == null ? "—" : (scan.hasHttps ? "Có" : "Không");
    document.getElementById("metric-server").textContent = scan.serverHeader || "—";

    const checks = scan.configuration?.checks || [];
    const tools = scan.configuration?.tools || [];
    document.getElementById("selected-checks").innerHTML = checks.map((c) => `<span class="chip">${escapeHtml(c)}</span>`).join("") || "<span class='muted'>—</span>";
    document.getElementById("selected-tools").innerHTML = tools.map((t) => `<span class="chip tool">${escapeHtml(t)}</span>`).join("") || "<span class='muted'>—</span>";
    document.getElementById("selected-report").textContent = `Report type: ${scan.reportType || "—"}`;

    const report = scan.report;
    if (!report) {
      document.getElementById("risk-level").textContent = "—";
      document.getElementById("risk-score").textContent = "—/100";
      document.getElementById("executive-summary").textContent = "Đang chạy các check đã chọn…";
      document.getElementById("findings-list").innerHTML = "<p class='muted'>Chưa có findings.</p>";
      return;
    }

    document.getElementById("risk-level").textContent = report.riskLevel;
    document.getElementById("risk-level").className = severityClass(report.riskLevel);
    document.getElementById("risk-score").textContent = `${report.riskScore}/100`;
    document.getElementById("executive-summary").textContent = report.executiveSummary;

    const findings = report.findings || [];
    document.getElementById("findings-list").innerHTML = findings.map((f) => `
      <article class="finding ${severityClass(f.severity)}">
        <header>
          <span class="badge ${severityClass(f.severity)}">${escapeHtml(f.severity)}</span>
          <strong>${escapeHtml(f.title)}</strong>
        </header>
        <p>${escapeHtml(f.detail)}</p>
        <p class="muted">Check: ${escapeHtml(f.checkName)} · Tools: ${escapeHtml((f.tools || []).join(", "))}</p>
        ${f.evidence ? `<pre>${escapeHtml(f.evidence)}</pre>` : ""}
        ${f.recommendation ? `<p class="reco"><span>Khuyến nghị:</span> ${escapeHtml(f.recommendation)}</p>` : ""}
      </article>
    `).join("") || "<p class='muted'>Không có finding.</p>";
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function startPolling() {
    stopPolling();
    pollTimer = setInterval(() => {
      refresh().catch(() => {});
    }, 2000);
  }

  refresh()
    .then(() => startPolling())
    .catch((err) => {
      document.getElementById("report-title").textContent = "Không tải được báo cáo";
      document.getElementById("executive-summary").textContent = err.message;
    });
})();
