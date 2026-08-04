(() => {
  const { apiFetch, extractError, normalizeUrl, escapeHtml } = window.SecurityPortalApi;

  const form = document.getElementById("config-form");
  const targetInput = document.getElementById("target-url");
  const checksList = document.getElementById("checks-list");
  const toolsList = document.getElementById("tools-list");
  const reportsList = document.getElementById("reports-list");
  const formError = document.getElementById("form-error");
  const startBtn = document.getElementById("start-btn");
  const selectDefaultBtn = document.getElementById("select-default-checks");

  let catalog = null;
  const params = new URLSearchParams(window.location.search);
  if (params.get("url")) targetInput.value = params.get("url");

  function selectedValues(name) {
    return [...form.querySelectorAll(`input[name="${name}"]:checked`)].map((el) => el.value);
  }

  function renderCatalog() {
    checksList.innerHTML = catalog.checks.map((check) => `
      <label class="option">
        <input type="checkbox" name="checks" value="${escapeHtml(check.id)}" data-tools="${escapeHtml(check.tools.join(","))}" ${check.enabledByDefault ? "checked" : ""} />
        <span>
          <strong>${escapeHtml(check.name)}</strong>
          <small>${escapeHtml(check.description)}</small>
          <em>Tools: ${escapeHtml(check.tools.join(", "))}</em>
        </span>
      </label>
    `).join("");

    toolsList.innerHTML = catalog.tools.map((tool) => `
      <label class="option">
        <input type="checkbox" name="tools" value="${escapeHtml(tool.id)}" />
        <span>
          <strong>${escapeHtml(tool.name)}</strong>
          <small>${escapeHtml(tool.description)}</small>
        </span>
      </label>
    `).join("");

    reportsList.innerHTML = catalog.reports.map((report, index) => `
      <label class="option report">
        <input type="radio" name="reportType" value="${escapeHtml(report.id)}" ${index === 1 || report.id === "technical" ? "checked" : ""} />
        <span>
          <strong>${escapeHtml(report.name)}</strong>
          <small>${escapeHtml(report.description)}</small>
        </span>
      </label>
    `).join("");

    // ensure only one default report radio checked
    const technical = form.querySelector('input[name="reportType"][value="technical"]');
    if (technical) {
      form.querySelectorAll('input[name="reportType"]').forEach((el) => { el.checked = false; });
      technical.checked = true;
    }

    syncToolsFromChecks();
    checksList.addEventListener("change", syncToolsFromChecks);
  }

  function syncToolsFromChecks() {
    const suggested = new Set();
    form.querySelectorAll('input[name="checks"]:checked').forEach((el) => {
      (el.dataset.tools || "").split(",").filter(Boolean).forEach((t) => suggested.add(t));
    });
    form.querySelectorAll('input[name="tools"]').forEach((el) => {
      el.checked = suggested.has(el.value);
    });
  }

  selectDefaultBtn.addEventListener("click", () => {
    form.querySelectorAll('input[name="checks"]').forEach((el) => {
      const def = catalog.checks.find((c) => c.id === el.value);
      el.checked = !!(def && def.enabledByDefault);
    });
    syncToolsFromChecks();
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    formError.hidden = true;

    const targetUrl = normalizeUrl(targetInput.value);
    const checks = selectedValues("checks");
    const tools = selectedValues("tools");
    const reportType = (form.querySelector('input[name="reportType"]:checked') || {}).value;

    if (!targetUrl) {
      formError.hidden = false;
      formError.textContent = "Nhập địa chỉ website.";
      return;
    }
    if (!checks.length) {
      formError.hidden = false;
      formError.textContent = "Chọn ít nhất một vấn đề security.";
      return;
    }
    if (!tools.length) {
      formError.hidden = false;
      formError.textContent = "Chọn ít nhất một tool.";
      return;
    }
    if (!reportType) {
      formError.hidden = false;
      formError.textContent = "Chọn loại security report.";
      return;
    }

    startBtn.disabled = true;
    startBtn.textContent = "Đang khởi tạo…";

    try {
      const res = await apiFetch("/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ targetUrl, checks, tools, reportType }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(extractError(data) || `Không thể bắt đầu scan (HTTP ${res.status}).`);
      window.location.href = `/report.html?id=${encodeURIComponent(data.id)}`;
    } catch (err) {
      formError.hidden = false;
      formError.textContent = err.message || "Có lỗi xảy ra.";
      startBtn.disabled = false;
      startBtn.textContent = "Bắt đầu scan";
    }
  });

  async function init() {
    const res = await apiFetch("/scans/catalog", { headers: { Accept: "application/json" } });
    if (!res.ok) throw new Error("Không tải được catalog cấu hình.");
    catalog = await res.json();
    renderCatalog();
  }

  init().catch((err) => {
    formError.hidden = false;
    formError.textContent = err.message || "Lỗi tải trang cấu hình.";
  });
})();
