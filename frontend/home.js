(() => {
  const {
    apiFetch,
    extractError,
    normalizeUrl,
    statusClass,
    severityClass,
    escapeHtml,
    wrapReportLines,
    formatWhen,
  } = window.SecurityPortalApi;
  const ConfigStore = window.SecurityPortalConfig;
  const Configure = window.SecurityPortalConfigure;
  const HistoryPanel = window.SecurityPortalHistory;
  const I18n = window.SecurityPortalI18n;
  const t = (key, vars) => (I18n ? I18n.t(key, vars) : key);

  I18n?.applyDom();

  const form = document.getElementById("scan-form");
  const input = document.getElementById("target-url");
  const scanBtn = document.getElementById("scan-btn");
  const stopScanBtn = document.getElementById("stop-scan-btn");
  const stopScanReportBtn = document.getElementById("stop-scan-report-btn");
  const formError = document.getElementById("form-error");
  const configSummary = document.getElementById("config-summary");
  const reportPanel = document.getElementById("report-panel");
  const configPanel = document.getElementById("config-panel");
  const historyPanel = document.getElementById("history-panel");
  const placeholder = document.getElementById("report-placeholder");
  const openConfigBtn = document.getElementById("open-config-btn");
  const openHistoryBtn = document.getElementById("open-history-btn");
  const exportReportBtn = document.getElementById("export-report-btn");
  const navHome = document.querySelector('[data-nav="home"]');
  const navConfig = document.querySelector('[data-nav="config"]');
  const navHistory = document.querySelector('[data-nav="history"]');

  let catalog = null;
  let pollTimer = null;
  let progressTimer = null;
  let activeScanId = null;
  let lastScan = null;
  let scanProgressStartedAt = null;
  let configMount = null;
  let historyMount = null;
  let rightView = "placeholder"; // placeholder | report | config | history

  document.querySelectorAll("[data-lang]").forEach((btn) => {
    btn.addEventListener("click", () => I18n?.setLocale(btn.getAttribute("data-lang")));
  });

  function setStopVisible(visible) {
    const show = !!visible;
    if (stopScanBtn) stopScanBtn.hidden = !show;
    if (stopScanReportBtn) stopScanReportBtn.hidden = !show;
    if (!show) {
      if (stopScanBtn) {
        stopScanBtn.disabled = false;
        stopScanBtn.textContent = t("home.stop");
      }
      if (stopScanReportBtn) {
        stopScanReportBtn.disabled = false;
        stopScanReportBtn.textContent = t("home.stop");
      }
    }
  }

  async function stopActiveScan() {
    const id = (activeScanId && activeScanId !== "pending" ? activeScanId : null)
      || (lastScan?.id && lastScan.id !== "pending" ? lastScan.id : null);
    if (!id) {
      formError.hidden = false;
      formError.textContent = t("home.stopFailed");
      return;
    }

    if (stopScanBtn) {
      stopScanBtn.disabled = true;
      stopScanBtn.textContent = t("home.stopping");
    }
    if (stopScanReportBtn) {
      stopScanReportBtn.disabled = true;
      stopScanReportBtn.textContent = t("home.stopping");
    }

    try {
      const res = await apiFetch(`/scans/${encodeURIComponent(id)}/cancel`, {
        method: "POST",
        headers: { Accept: "application/json" },
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(extractError(data) || `${t("home.stopFailed")} (HTTP ${res.status}).`);
      }

      stopPolling();
      activeScanId = data.id || id;
      lastScan = data;
      scanBtn.disabled = false;
      scanBtn.textContent = t("home.scan");
      setStopVisible(false);
      renderReport(data);
    } catch (err) {
      formError.hidden = false;
      formError.textContent = err.message || t("home.stopFailed");
      setStopVisible(true);
      if (stopScanBtn) {
        stopScanBtn.disabled = false;
        stopScanBtn.textContent = t("home.stop");
      }
      if (stopScanReportBtn) {
        stopScanReportBtn.disabled = false;
        stopScanReportBtn.textContent = t("home.stop");
      }
    }
  }

  stopScanBtn?.addEventListener("click", () => stopActiveScan());
  stopScanReportBtn?.addEventListener("click", () => stopActiveScan());

  function leavePanelUrl() {
    const id = activeScanId && activeScanId !== "pending" ? activeScanId : null;
    return id ? `/?id=${encodeURIComponent(id)}` : "/";
  }

  function setNavActive(view) {
    navHome?.classList.toggle("is-active", view === "placeholder" || view === "report");
    navConfig?.classList.toggle("is-active", view === "config");
    navHistory?.classList.toggle("is-active", view === "history");
  }

  function showRight(view) {
    rightView = view;
    placeholder.hidden = view !== "placeholder";
    reportPanel.hidden = view !== "report";
    configPanel.hidden = view !== "config";
    historyPanel.hidden = view !== "history";
    setNavActive(view);

    if (view === "config") {
      history.replaceState(null, "", "/?view=config");
      if (configMount) {
        configMount.destroy?.();
        configMount = null;
      }
      if (Configure) {
        configMount = Configure.mount(configPanel, {
          onSaved() {
            renderConfigSnapshot();
          },
          onClose() {
            if (lastScan) showRight("report");
            else showRight("placeholder");
            history.replaceState(null, "", leavePanelUrl());
          },
        });
      }
    } else if (view === "history") {
      history.replaceState(null, "", "/?view=history");
      if (historyMount) {
        historyMount.destroy?.();
        historyMount = null;
      }
      if (HistoryPanel) {
        historyMount = HistoryPanel.mount(historyPanel, {
          activeScanId: activeScanId && activeScanId !== "pending" ? activeScanId : null,
          onSelect(scanId) {
            showReport(scanId);
          },
          onDeleted(ids) {
            const removedActive = ids.some((id) => id === activeScanId);
            if (removedActive) {
              stopPolling();
              activeScanId = null;
              lastScan = null;
            }
          },
          onClose() {
            if (lastScan) showRight("report");
            else showRight("placeholder");
            history.replaceState(null, "", leavePanelUrl());
          },
        });
      }
    } else if (view === "report" && lastScan) {
      const id = lastScan.id && lastScan.id !== "pending" ? lastScan.id : null;
      history.replaceState(null, "", id ? `/?id=${encodeURIComponent(id)}` : "/");
    } else if (view === "placeholder") {
      history.replaceState(null, "", "/");
    }
  }

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
      ? ` · ${t("snapshot.updated")} ${formatWhen(summary.updatedAt)}`
      : ` · ${t("snapshot.default")}`;
    configSummary.textContent =
      `${summary.checkCount} ${t("snapshot.checks")} · ${summary.toolCount} ${t("snapshot.tools")} · ${summary.reportName}${updated}`;
  }

  function openReportPanel(scan) {
    activeScanId = scan.id;
    lastScan = scan;
    if (isScanInProgress(scan.status)) {
      scanProgressStartedAt = Date.now();
    } else {
      scanProgressStartedAt = null;
    }
    showRight("report");
    renderReport(scan);
  }

  openConfigBtn?.addEventListener("click", () => showRight("config"));
  openHistoryBtn?.addEventListener("click", () => showRight("history"));
  exportReportBtn?.addEventListener("click", () => exportReportHtml());
  navConfig?.addEventListener("click", (event) => {
    event.preventDefault();
    showRight("config");
  });
  navHistory?.addEventListener("click", (event) => {
    event.preventDefault();
    showRight("history");
  });
  navHome?.addEventListener("click", (event) => {
    if (rightView === "config" || rightView === "history") {
      event.preventDefault();
      if (lastScan) showRight("report");
      else showRight("placeholder");
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    formError.hidden = true;

    const targetUrl = normalizeUrl(input.value);
    if (!targetUrl) {
      formError.hidden = false;
      formError.textContent = t("home.urlRequired");
      input.focus();
      return;
    }

    const config = getScanConfig();
    scanBtn.disabled = true;
    scanBtn.textContent = t("home.scanning");
    setStopVisible(false);

    openReportPanel({
      id: "pending",
      targetUrl,
      status: "Queued",
      summary: t("report.processing"),
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
        throw new Error(extractError(data) || `${t("home.scanStartFailed")} (HTTP ${res.status}).`);
      }

      openReportPanel(data);
      startPolling(data.id);
      setStopVisible(true);

      const historyNote = document.querySelector(".history-link-note a");
      if (historyNote) historyNote.href = `/?view=history`;
    } catch (err) {
      formError.hidden = false;
      formError.textContent = err.message || t("home.genericError");
      document.getElementById("status-badge").textContent = "Failed";
      document.getElementById("status-badge").className = "badge is-failed";
      document.getElementById("status-summary").textContent = err.message || t("home.scanFailed");
      document.getElementById("executive-summary").textContent = err.message || t("home.reportFailed");
      stopPolling();
      scanBtn.disabled = false;
      scanBtn.textContent = t("home.scan");
      setStopVisible(false);
      updateScanProgressUi({ status: "Failed" });
    } finally {
      if (!isScanInProgress(lastScan?.status)) {
        scanBtn.disabled = false;
        scanBtn.textContent = t("home.scan");
      }
    }
  });

  async function refreshReport() {
    if (!activeScanId || activeScanId === "pending") return;
    const res = await apiFetch(`/scans/${activeScanId}`, { headers: { Accept: "application/json" } });
    if (!res.ok) throw new Error(`${t("report.loadFailed")} (HTTP ${res.status}).`);
    const scan = await res.json();
    lastScan = scan;
    if (rightView === "report") renderReport(scan);
    if (scan.status === "Completed" || scan.status === "Failed" || scan.status === "Cancelled") {
      stopPolling();
      scanProgressStartedAt = null;
      scanBtn.disabled = false;
      scanBtn.textContent = t("home.scan");
      setStopVisible(false);
    }
  }

  function formatFindingResult(f) {
    const detailHtml = f.detail
      ? `<p class="finding-detail">${escapeHtml(wrapReportLines(f.detail, 140))}</p>`
      : "";
    const evidenceHtml = f.evidence
      ? `<pre class="finding-evidence">${escapeHtml(wrapReportLines(f.evidence, 120))}</pre>`
      : "";
    const steps = Array.isArray(f.reproductionSteps) ? f.reproductionSteps.filter(Boolean) : [];
    const reproduceHtml = steps.length
      ? `<div class="finding-reproduce">
          <p class="finding-reproduce-label">${escapeHtml(t("table.reproduce"))}</p>
          <ol>${steps.map((s) => `<li><code>${escapeHtml(wrapReportLines(s, 120))}</code></li>`).join("")}</ol>
        </div>`
      : "";
    return `
      <div class="finding-head">
        <span class="badge ${severityClass(f.severity)}">${escapeHtml(f.severity || "Info")}</span>
        <strong class="finding-title">${escapeHtml(wrapReportLines(f.title || "—", 100))}</strong>
      </div>
      ${detailHtml}
      ${evidenceHtml}
      ${reproduceHtml}
    `;
  }

  function sanitizeFilePart(value) {
    return String(value || "report")
      .trim()
      .replace(/^https?:\/\//i, "")
      .replace(/[<>:"/\\|?*\u0000-\u001f]+/g, "-")
      .replace(/\s+/g, "-")
      .replace(/-+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 120) || "report";
  }

  function formatExportDate(iso) {
    const d = iso ? new Date(iso) : new Date();
    if (Number.isNaN(d.getTime())) return formatExportDate(null);
    const dd = String(d.getDate()).padStart(2, "0");
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const yyyy = String(d.getFullYear());
    return `${dd}${mm}${yyyy}`;
  }

  function buildExportFilename(scan) {
    const reportName = sanitizeFilePart(scan.report?.reportTitle || "Technical-Report");
    const datePart = formatExportDate(scan.completedAt || scan.createdAt);
    const urlPart = sanitizeFilePart(scan.targetUrl || scan.normalizedHost || "target");
    return `${reportName}-${datePart}-${urlPart}.html`;
  }

  function buildExportHtml(scan) {
    const report = scan.report;
    const findings = report?.findings || [];
    const findingsRows = findings.length
      ? findings.map((f, index) => `
          <tr class="${severityClass(f.severity)}">
            <td class="col-index">${index + 1}</td>
            <td class="col-function">${escapeHtml(wrapReportLines(f.checkName || f.checkId || "—", 40))}</td>
            <td class="col-tool">${escapeHtml(wrapReportLines((f.tools || []).join(", ") || "—", 36))}</td>
            <td class="col-result">${formatFindingResult(f)}</td>
            <td class="col-recommend">${escapeHtml(wrapReportLines(f.recommendation || "—", 72))}</td>
          </tr>`).join("")
      : `<tr><td colspan="5">${escapeHtml(t("report.noFindings"))}</td></tr>`;

    const when = formatWhen(scan.completedAt || scan.createdAt || new Date().toISOString());
    const httpsText = scan.hasHttps == null ? "—" : (scan.hasHttps ? t("report.yes") : t("report.no"));
    const lang = I18n?.getLocale?.() || "vi";

    return `<!DOCTYPE html>
<html lang="${escapeHtml(lang)}">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(report?.reportTitle || "Technical Report")} — ${escapeHtml(scan.targetUrl || "")}</title>
  <style>
    :root { color-scheme: light; --ink:#12202b; --muted:#5b6b76; --line:#d7e0e7; --bg:#f7fafc; --card:#fff; --high:#b42318; --medium:#b54708; --low:#027a48; --info:#175cd3; }
    * { box-sizing: border-box; }
    body { margin: 0; font: 15px/1.5 system-ui, Segoe UI, sans-serif; color: var(--ink); background: var(--bg); }
    main { max-width: 1100px; margin: 0 auto; padding: 2rem 1.25rem 3rem; }
    h1 { margin: 0.2rem 0 0.35rem; font-size: 1.75rem; letter-spacing: -0.03em; }
    h2 { margin: 0 0 0.75rem; font-size: 1.1rem; }
    .lede, .muted { color: var(--muted); }
    .hero { display: flex; justify-content: space-between; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.25rem; }
    .risk { min-width: 140px; padding: 0.85rem 1rem; border: 1px solid var(--line); background: var(--card); }
    .risk strong { display: block; font-size: 1.5rem; }
    .block { margin: 1rem 0; padding: 1rem 1.1rem; border: 1px solid var(--line); background: var(--card); }
    .metrics { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 0.75rem; margin: 0; }
    .metrics div { margin: 0; }
    .metrics dt { color: var(--muted); font-size: 0.8rem; }
    .metrics dd { margin: 0.15rem 0 0; font-weight: 600; }
    table { width: 100%; table-layout: fixed; border-collapse: collapse; font-size: 0.92rem; }
    th, td { border-bottom: 1px solid var(--line); padding: 0.7rem 0.55rem; vertical-align: top; text-align: left; overflow-wrap: anywhere; word-break: break-word; white-space: pre-line; }
    .col-index { width: 3.25rem; white-space: nowrap; }
    .col-function { width: 11%; }
    .col-tool { width: 10%; }
    .col-result { width: 52%; }
    .col-recommend { width: 20%; }
    .finding-head { display: flex; align-items: center; flex-wrap: wrap; gap: 0.4rem 0.5rem; margin: 0; }
    .finding-title { margin: 0; }
    th { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }
    .badge { display: inline-block; padding: 0.12rem 0.45rem; border: 1px solid var(--line); font-size: 0.75rem; margin-right: 0.35rem; }
    .sev-high .badge, .sev-high { color: var(--high); }
    .sev-medium .badge, .sev-medium { color: var(--medium); }
    .sev-low .badge, .sev-low { color: var(--low); }
    .sev-info .badge, .sev-info { color: var(--info); }
    .finding-detail { white-space: pre-line; color: var(--muted); margin: 0.4rem 0 0; }
    .finding-evidence { margin: 0.5rem 0 0; padding: 0.55rem 0.65rem; background: #eef3f7; overflow: auto; font-size: 0.8rem; }
    .finding-reproduce { margin-top: 0.55rem; padding-top: 0.45rem; border-top: 1px dashed var(--line); }
    .finding-reproduce-label { margin: 0 0 0.3rem; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--medium); }
    .finding-reproduce ol { margin: 0; padding-left: 1.1rem; }
    .finding-reproduce code { font-size: 0.8rem; word-break: break-word; }
    .executive-summary-line { margin: 0; width: 100%; line-height: 1.55; color: var(--muted); }
    .executive-summary-line strong { margin-right: 0.45rem; color: var(--ink); }
    .risk-legend { margin: 0.55rem 0 0; display: grid; gap: 0.3rem; color: var(--muted); font-size: 0.84rem; line-height: 1.45; }
    .risk-legend-title { font-weight: 600; color: var(--ink); }
    .risk-legend-scale { display: flex; flex-wrap: wrap; gap: 0.55rem 1rem; font-weight: 600; }
    .footer { margin-top: 1.5rem; color: var(--muted); font-size: 0.85rem; }
    @media (max-width: 720px) { .metrics { grid-template-columns: 1fr 1fr; } }
  </style>
</head>
<body>
  <main>
    <header class="hero">
      <div>
        <p class="muted">Security Portal</p>
        <h1>${escapeHtml(report?.reportTitle || "Technical Report")}</h1>
        <p class="lede">${escapeHtml(wrapReportLines(scan.targetUrl || "", 100))}</p>
        <p class="risk-legend">
          <span class="risk-legend-title">${escapeHtml(t("risk.legendTitle"))}</span>
          <span class="risk-legend-scale">
            <span class="sev-high">${escapeHtml(t("risk.high"))}</span>
            <span class="sev-medium">${escapeHtml(t("risk.medium"))}</span>
            <span class="sev-low">${escapeHtml(t("risk.low"))}</span>
          </span>
          <span>${escapeHtml(t("risk.formula"))}</span>
        </p>
        <p class="muted">${escapeHtml(t("export.exportedAt"))} ${escapeHtml(when)} · Status: ${escapeHtml(scan.status || "—")}</p>
      </div>
      <div class="risk">
        <span class="muted">${escapeHtml(t("report.risk"))}</span>
        <strong class="${severityClass(report?.riskLevel)}">${escapeHtml(report?.riskLevel || "—")}</strong>
        <span class="muted">${escapeHtml(String(report?.riskScore ?? "—"))}/100</span>
      </div>
    </header>

    <section class="block">
      <h2>${escapeHtml(t("report.statusTitle"))}</h2>
      <p>${escapeHtml(wrapReportLines(scan.errorMessage || scan.summary || "—", 110))}</p>
      <dl class="metrics">
        <div><dt>${escapeHtml(t("report.metricHttp"))}</dt><dd>${escapeHtml(String(scan.httpStatusCode ?? "—"))}</dd></div>
        <div><dt>${escapeHtml(t("report.metricTime"))}</dt><dd>${escapeHtml(scan.responseTimeMs != null ? `${scan.responseTimeMs} ms` : "—")}</dd></div>
        <div><dt>${escapeHtml(t("report.metricHttps"))}</dt><dd>${escapeHtml(httpsText)}</dd></div>
        <div><dt>${escapeHtml(t("report.metricServer"))}</dt><dd>${escapeHtml(wrapReportLines(scan.serverHeader || "—", 40))}</dd></div>
      </dl>
    </section>

    <section class="block">
      <p class="executive-summary-line"><strong>${escapeHtml(t("report.execLabel"))}</strong> ${escapeHtml(wrapReportLines(report?.executiveSummary || "—", 120))}</p>
    </section>

    <section class="block">
      <h2>${escapeHtml(t("report.findings"))}</h2>
      <table>
        <thead>
          <tr>
            <th class="col-index">${escapeHtml(t("table.index"))}</th>
            <th class="col-function">${escapeHtml(t("table.function"))}</th>
            <th class="col-tool">${escapeHtml(t("table.tool"))}</th>
            <th class="col-result">${escapeHtml(t("table.result"))}</th>
            <th class="col-recommend">${escapeHtml(t("table.recommend"))}</th>
          </tr>
        </thead>
        <tbody>${findingsRows}</tbody>
      </table>
    </section>

    <p class="footer">Generated by Security Portal · file standalone HTML</p>
  </main>
</body>
</html>`;
  }

  function exportReportHtml() {
    if (!lastScan?.report) return;
    const filename = buildExportFilename(lastScan);
    const html = buildExportHtml(lastScan);
    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function setExportEnabled(enabled) {
    if (!exportReportBtn) return;
    exportReportBtn.disabled = !enabled;
  }

  function isScanInProgress(status) {
    return status === "Queued" || status === "Running" || status === "pending";
  }

  function estimateScanProgress(scan) {
    const status = scan?.status || "Queued";
    if (status === "Completed") return 100;
    if (status === "Failed" || status === "Cancelled") return 100;

    const started = scanProgressStartedAt
      || (scan.startedAt ? new Date(scan.startedAt).getTime() : null)
      || (scan.createdAt ? new Date(scan.createdAt).getTime() : Date.now());
    const elapsedSec = Math.max(0, (Date.now() - started) / 1000);

    if (status === "Queued" || status === "pending") {
      return Math.min(12, 4 + elapsedSec * 1.5);
    }

    // Running: asymptotic toward 92% until API completes
    const expectedSec = 18;
    const ratio = 1 - Math.exp(-elapsedSec / expectedSec);
    let pct = 12 + ratio * 80;
    if (scan.httpStatusCode != null) pct = Math.max(pct, 55);
    if (scan.serverHeader) pct = Math.max(pct, 68);
    if (scan.report) pct = Math.max(pct, 88);
    return Math.min(92, Math.round(pct));
  }

  function stopProgressTicker() {
    if (progressTimer) {
      clearInterval(progressTimer);
      progressTimer = null;
    }
  }

  function startProgressTicker() {
    stopProgressTicker();
    progressTimer = setInterval(() => {
      if (!lastScan || !isScanInProgress(lastScan.status) || lastScan.status === "pending") {
        if (lastScan) updateScanProgressUi(lastScan);
        return;
      }
      updateScanProgressUi(lastScan);
    }, 400);
  }

  function updateScanProgressUi(scan) {
    const progressEl = document.getElementById("scan-progress");
    const trackEl = document.getElementById("scan-progress-track");
    const fillEl = document.getElementById("scan-progress-fill");
    const labelEl = document.getElementById("scan-progress-label");
    const pctEl = document.getElementById("scan-progress-pct");
    const summaryEl = document.getElementById("executive-summary");
    if (!progressEl || !trackEl || !fillEl || !labelEl || !pctEl || !summaryEl) return;

    const status = scan?.status || "";
    const inProgress = isScanInProgress(status);

    if (!inProgress) {
      progressEl.hidden = true;
      trackEl.hidden = true;
      fillEl.style.width = status === "Completed" ? "100%" : "0%";
      stopProgressTicker();
      return;
    }

    if (!scanProgressStartedAt) {
      scanProgressStartedAt = scan.startedAt
        ? new Date(scan.startedAt).getTime()
        : (scan.createdAt ? new Date(scan.createdAt).getTime() : Date.now());
    }

    const pct = estimateScanProgress(scan);
    progressEl.hidden = false;
    trackEl.hidden = false;
    fillEl.style.width = `${pct}%`;
    pctEl.textContent = `${pct}%`;
    labelEl.textContent = status === "Queued" || status === "pending"
      ? t("report.queued")
      : t("report.scanning");
    summaryEl.textContent = scan.report?.executiveSummary
      ? wrapReportLines(scan.report.executiveSummary, 120)
      : t("report.creating");
  }

  function renderReport(scan) {
    document.getElementById("report-title").textContent = scan.report?.reportTitle || "Technical Report";
    document.getElementById("report-target").textContent = wrapReportLines(scan.targetUrl || "", 100);

    const badge = document.getElementById("status-badge");
    badge.textContent = scan.status === "pending" ? "Queued" : (scan.status || "Queued");
    badge.className = "badge " + statusClass(scan.status === "pending" ? "Queued" : scan.status);
    document.getElementById("status-summary").textContent =
      wrapReportLines(scan.errorMessage || scan.summary || t("report.processing"), 110);
    document.getElementById("metric-http").textContent = scan.httpStatusCode ?? "—";
    document.getElementById("metric-time").textContent =
      scan.responseTimeMs != null ? `${scan.responseTimeMs} ms` : "—";
    document.getElementById("metric-https").textContent =
      scan.hasHttps == null ? "—" : (scan.hasHttps ? t("report.yes") : t("report.no"));
    document.getElementById("metric-server").textContent = wrapReportLines(scan.serverHeader || "—", 40);

    updateScanProgressUi(scan);
    if (isScanInProgress(scan.status)) startProgressTicker();
    setStopVisible(isScanInProgress(scan.status) && activeScanId && activeScanId !== "pending");
    if (isScanInProgress(scan.status)) {
      scanBtn.disabled = true;
      scanBtn.textContent = t("home.scanning");
    } else {
      scanBtn.disabled = false;
      scanBtn.textContent = t("home.scan");
    }

    const report = scan.report;
    if (!report) {
      document.getElementById("risk-level").textContent = "—";
      document.getElementById("risk-level").className = "";
      document.getElementById("risk-score").textContent = "—/100";
      if (!isScanInProgress(scan.status)) {
        document.getElementById("executive-summary").textContent = t("report.creating");
      }
      document.getElementById("findings-list").innerHTML =
        `<p class='muted'>${escapeHtml(t("report.findingsPending"))}</p>`;
      setExportEnabled(false);
      return;
    }

    document.getElementById("risk-level").textContent = report.riskLevel;
    document.getElementById("risk-level").className = severityClass(report.riskLevel);
    document.getElementById("risk-score").textContent = `${report.riskScore}/100`;
    if (!isScanInProgress(scan.status)) {
      document.getElementById("executive-summary").textContent = wrapReportLines(report.executiveSummary || "", 120);
    }
    setExportEnabled(!isScanInProgress(scan.status));

    const findings = report.findings || [];
    if (!findings.length) {
      document.getElementById("findings-list").innerHTML = `<p class='muted'>${escapeHtml(t("report.noFindings"))}</p>`;
      return;
    }

    document.getElementById("findings-list").innerHTML = `
      <table class="findings-table">
        <thead>
          <tr>
            <th scope="col" class="col-index">${escapeHtml(t("table.index"))}</th>
            <th scope="col" class="col-function">${escapeHtml(t("table.function"))}</th>
            <th scope="col" class="col-tool">${escapeHtml(t("table.tool"))}</th>
            <th scope="col" class="col-result">${escapeHtml(t("table.result"))}</th>
            <th scope="col" class="col-recommend">${escapeHtml(t("table.recommend"))}</th>
          </tr>
        </thead>
        <tbody>
          ${findings.map((f, index) => `
            <tr class="${severityClass(f.severity)}">
              <td class="col-index">${index + 1}</td>
              <td class="col-function">${escapeHtml(wrapReportLines(f.checkName || f.checkId || "—", 40))}</td>
              <td class="col-tool">${escapeHtml(wrapReportLines((f.tools || []).join(", ") || "—", 36))}</td>
              <td class="col-result">${formatFindingResult(f)}</td>
              <td class="col-recommend">${escapeHtml(wrapReportLines(f.recommendation || "—", 72))}</td>
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
    stopProgressTicker();
  }

  function startPolling(scanId) {
    activeScanId = scanId;
    if (!scanProgressStartedAt) scanProgressStartedAt = Date.now();
    stopPolling();
    startProgressTicker();
    pollTimer = setInterval(() => {
      refreshReport().catch(() => {});
    }, 2000);
  }

  async function showReport(scanId) {
    openReportPanel({
      id: scanId,
      targetUrl: "",
      status: "Queued",
      summary: t("report.processing"),
      report: null,
    });
    startPolling(scanId);
    try {
      await refreshReport();
    } catch (err) {
      document.getElementById("status-summary").textContent = err.message;
    }
  }

  document.querySelector(".history-link-note")?.addEventListener("click", (event) => {
    const link = event.target.closest("a");
    if (!link) return;
    event.preventDefault();
    showRight("history");
  });

  I18n?.onChange(async () => {
    I18n.applyDom();
    await loadCatalog();
    if (rightView === "config") showRight("config");
    else if (rightView === "history") showRight("history");
    else if (rightView === "report" && activeScanId && activeScanId !== "pending") {
      try { await refreshReport(); } catch { /* ignore */ }
    } else if (lastScan) {
      renderReport(lastScan);
    }
  });

  const params = new URLSearchParams(window.location.search);
  const initialId = params.get("id");
  const initialView = params.get("view");

  loadCatalog().then(async () => {
    if (initialView === "config") showRight("config");
    else if (initialView === "history") showRight("history");
    else if (initialId) await showReport(initialId);
    else showRight("placeholder");
  });

  input.focus();
})();
