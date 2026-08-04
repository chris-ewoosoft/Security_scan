(() => {
  const { apiFetch, escapeHtml, formatWhen } = window.SecurityPortalApi;
  const ConfigStore = window.SecurityPortalConfig;

  if (!ConfigStore) {
    const el = document.getElementById("form-error");
    if (el) {
      el.hidden = false;
      el.textContent = "Không tải được bộ nhớ cấu hình (config-store.js).";
    }
    return;
  }

  const form = document.getElementById("config-form");
  const checksList = document.getElementById("checks-list");
  const toolsList = document.getElementById("tools-list");
  const reportsList = document.getElementById("reports-list");
  const formError = document.getElementById("form-error");
  const saveBtn = document.getElementById("save-btn");
  const saveBanner = document.getElementById("save-banner");
  const selectDefaultBtn = document.getElementById("select-default-checks");

  let catalog = null;
  let suppressToolSync = false;
  let saveTimer = null;

  function selectedValues(name) {
    return [...form.querySelectorAll(`input[name="${name}"]:checked`)].map((el) => el.value);
  }

  function currentConfig() {
    return {
      checks: selectedValues("checks"),
      tools: selectedValues("tools"),
      reportType: (form.querySelector('input[name="reportType"]:checked') || {}).value || ConfigStore.FALLBACK.reportType,
    };
  }

  function showError(message) {
    formError.hidden = false;
    formError.textContent = message;
    saveBanner.hidden = true;
  }

  function clearError() {
    formError.hidden = true;
    formError.textContent = "";
  }

  function persist(reason = "Đã lưu cấu hình") {
    clearError();
    const config = currentConfig();

    if (!config.checks.length) {
      showError("Chọn ít nhất một vấn đề security.");
      return false;
    }
    if (!config.tools.length) {
      // Auto-fill tools from selected checks so save never blocks after sync race
      const suggested = new Set();
      form.querySelectorAll('input[name="checks"]:checked').forEach((el) => {
        (el.dataset.tools || "").split(",").filter(Boolean).forEach((t) => suggested.add(t));
      });
      form.querySelectorAll('input[name="tools"]').forEach((el) => {
        el.checked = suggested.has(el.value);
      });
      config.tools = selectedValues("tools");
    }
    if (!config.tools.length) {
      showError("Chọn ít nhất một tool.");
      return false;
    }
    if (!config.reportType) {
      showError("Chọn loại security report.");
      return false;
    }

    try {
      const saved = ConfigStore.save(config);
      // Verify round-trip
      const loaded = ConfigStore.load();
      const ok =
        loaded.checks.length === saved.checks.length &&
        loaded.reportType === saved.reportType;

      if (!ok) {
        showError("Lưu cấu hình thất bại (trình duyệt chặn localStorage).");
        return false;
      }

      saveBanner.hidden = false;
      saveBanner.textContent =
        `${reason}: ${saved.checks.length} checks · ${saved.tools.length} tools · ${saved.reportType}. ` +
        `Áp dụng cho mọi lần scan trên Trang chủ. Cập nhật: ${formatWhen(saved.updatedAt)}`;
      saveBtn.textContent = "Đã lưu";
      setTimeout(() => { saveBtn.textContent = "Lưu cấu hình"; }, 1200);
      return true;
    } catch (err) {
      showError(err.message || "Không lưu được cấu hình vào trình duyệt.");
      return false;
    }
  }

  function schedulePersist() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => persist("Đã tự lưu khi chọn"), 250);
  }

  function applySavedSelection(saved) {
    form.querySelectorAll('input[name="checks"]').forEach((el) => {
      el.checked = saved.checks.includes(el.value);
    });
    form.querySelectorAll('input[name="tools"]').forEach((el) => {
      el.checked = saved.tools.includes(el.value);
    });
    let reportMatched = false;
    form.querySelectorAll('input[name="reportType"]').forEach((el) => {
      el.checked = el.value === saved.reportType;
      if (el.checked) reportMatched = true;
    });
    if (!reportMatched) {
      const technical = form.querySelector('input[name="reportType"][value="technical"]');
      if (technical) technical.checked = true;
    }
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

  function renderCatalog(saved) {
    checksList.innerHTML = catalog.checks.map((check) => `
      <label class="option">
        <input type="checkbox" name="checks" value="${escapeHtml(check.id)}" data-tools="${escapeHtml(check.tools.join(","))}" />
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

    reportsList.innerHTML = catalog.reports.map((report) => `
      <label class="option report">
        <input type="radio" name="reportType" value="${escapeHtml(report.id)}" />
        <span>
          <strong>${escapeHtml(report.name)}</strong>
          <small>${escapeHtml(report.description)}</small>
        </span>
      </label>
    `).join("");

    applySavedSelection(saved);

    // Single delegated listener — auto-save on every change
    form.addEventListener("change", (event) => {
      const target = event.target;
      if (!(target instanceof HTMLInputElement)) return;

      if (target.name === "checks" && !suppressToolSync) {
        syncToolsFromChecks();
      }
      schedulePersist();
    });
  }

  selectDefaultBtn.addEventListener("click", () => {
    suppressToolSync = true;
    form.querySelectorAll('input[name="checks"]').forEach((el) => {
      const def = catalog.checks.find((c) => c.id === el.value);
      el.checked = !!(def && def.enabledByDefault);
    });
    suppressToolSync = false;
    syncToolsFromChecks();
    const technical = form.querySelector('input[name="reportType"][value="technical"]');
    if (technical) {
      form.querySelectorAll('input[name="reportType"]').forEach((el) => { el.checked = false; });
      technical.checked = true;
    }
    persist("Đã lưu cấu hình mặc định");
  });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    persist("Đã lưu cấu hình");
  });

  saveBtn.addEventListener("click", (event) => {
    // Ensure click always persists even if form submit is interrupted
    event.preventDefault();
    persist("Đã lưu cấu hình");
  });

  async function init() {
    const res = await apiFetch("/scans/catalog", { headers: { Accept: "application/json" } });
    if (!res.ok) throw new Error("Không tải được catalog cấu hình.");
    catalog = await res.json();
    const saved = ConfigStore.load();
    renderCatalog(saved);

    saveBanner.hidden = false;
    saveBanner.textContent = saved.updatedAt
      ? `Cấu hình hiện tại đã lưu lúc ${formatWhen(saved.updatedAt)}. Tích chọn sẽ tự lưu.`
      : "Chưa có cấu hình lưu. Tích chọn sẽ tự lưu ngay trên trình duyệt.";
  }

  init().catch((err) => {
    showError(err.message || "Lỗi tải trang cấu hình.");
  });
})();
