(() => {
  const {
    apiFetch,
    statusClass,
    severityClass,
    escapeHtml,
    formatWhen,
  } = window.SecurityPortalApi;

  const historyList = document.getElementById("history-list");
  const historyError = document.getElementById("history-error");
  const refreshBtn = document.getElementById("refresh-btn");
  const reportPanel = document.getElementById("report-panel");

  let activeScanId = null;
  let pollTimer = null;

  function renderFindingsTable(findings) {
    if (!findings.length) {
      return "<p class='muted'>Không có finding.</p>";
    }
    return `
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

  function renderReport(scan) {
    document.getElementById("report-title").textContent = scan.report?.reportTitle || "Security Report";
    document.getElementById("report-target").textContent = scan.targetUrl || "";

    const badge = document.getElementById("status-badge");
    badge.textContent = scan.status || "—";
    badge.className = "badge " + statusClass(scan.status);
    document.getElementById("status-summary").textContent =
      scan.errorMessage || scan.summary || "—";
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
        scan.status === "Queued" || scan.status === "Running"
          ? "Scan đang chạy — báo cáo sẽ cập nhật khi hoàn tất."
          : "Chưa có báo cáo cho scan này.";
      document.getElementById("findings-list").innerHTML = "<p class='muted'>Chưa có findings.</p>";
      return;
    }

    document.getElementById("risk-level").textContent = report.riskLevel;
    document.getElementById("risk-level").className = severityClass(report.riskLevel);
    document.getElementById("risk-score").textContent = `${report.riskScore}/100`;
    document.getElementById("executive-summary").textContent = report.executiveSummary;
    document.getElementById("findings-list").innerHTML = renderFindingsTable(report.findings || []);
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  async function refreshReport() {
    if (!activeScanId) return;
    const res = await apiFetch(`/scans/${activeScanId}`, { headers: { Accept: "application/json" } });
    if (!res.ok) throw new Error(`Không tải được báo cáo (HTTP ${res.status}).`);
    const scan = await res.json();
    renderReport(scan);
    if (scan.status === "Completed" || scan.status === "Failed" || scan.status === "Cancelled") {
      stopPolling();
      await loadHistory();
    }
  }

  async function showReport(scanId) {
    activeScanId = scanId;
    reportPanel.hidden = false;
    history.replaceState(null, "", `/history.html?id=${encodeURIComponent(scanId)}`);
    [...historyList.children].forEach((el) => {
      el.classList.toggle("is-active", el.dataset.id === scanId);
    });
    reportPanel.scrollIntoView({ behavior: "smooth", block: "start" });

    stopPolling();
    try {
      await refreshReport();
      pollTimer = setInterval(() => {
        refreshReport().catch(() => {});
      }, 2000);
    } catch (err) {
      document.getElementById("status-summary").textContent = err.message;
    }
  }

  async function loadHistory() {
    historyError.hidden = true;
    try {
      const res = await apiFetch("/scans?take=50", { headers: { Accept: "application/json" } });
      if (!res.ok) throw new Error(`Không tải được lịch sử (HTTP ${res.status}).`);
      const items = await res.json();
      historyList.innerHTML = "";

      if (!items.length) {
        historyList.innerHTML = "<li><span class=\"url\">Chưa có scan nào trong lịch sử</span></li>";
        return;
      }

      for (const item of items) {
        const li = document.createElement("li");
        li.dataset.id = item.id;
        if (item.id === activeScanId) li.classList.add("is-active");
        const risk = item.report?.riskLevel ? ` · Risk ${item.report.riskLevel}` : "";
        li.innerHTML = `
          <span class="url">${escapeHtml(item.targetUrl)}</span>
          <span class="badge ${statusClass(item.status)}">${escapeHtml(item.status)}${escapeHtml(risk)}</span>
          <span class="when">${formatWhen(item.createdAt)}</span>
        `;
        li.addEventListener("click", () => showReport(item.id));
        historyList.appendChild(li);
      }
    } catch (err) {
      historyError.hidden = false;
      historyError.textContent = err.message || "Lỗi tải lịch sử.";
    }
  }

  refreshBtn.addEventListener("click", () => {
    loadHistory();
  });

  const params = new URLSearchParams(window.location.search);
  const initialId = params.get("id");

  loadHistory().then(() => {
    if (initialId) showReport(initialId);
  });
})();
