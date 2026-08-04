window.SecurityPortalConfigure = (() => {
  const { apiFetch, escapeHtml, formatWhen } = window.SecurityPortalApi;
  const ConfigStore = window.SecurityPortalConfig;

  function mount(root, options = {}) {
    if (!ConfigStore) {
      root.innerHTML = "<p class='form-error'>Không tải được bộ nhớ cấu hình.</p>";
      return { destroy() {} };
    }

    root.innerHTML = `
      <div class="config-panel-inner">
        <div class="report-hero">
          <div>
            <p class="eyebrow">Cấu hình scan</p>
            <h2 class="page-title">Chọn checks · tools · report</h2>
            <p class="lede">Tích chọn sẽ tự lưu và áp dụng cho mọi lần scan trên cột trái.</p>
          </div>
          <button type="button" class="ghost-btn" data-action="close-config">Đóng</button>
        </div>

        <div data-role="save-banner" class="save-banner">Đang tải cấu hình…</div>
        <p data-role="form-error" class="form-error" hidden></p>

        <form data-role="config-form" class="config-form">
          <section class="config-block">
            <div class="block-head">
              <h2>Vấn đề security</h2>
              <button type="button" class="linkish" data-action="defaults">Chọn mặc định</button>
            </div>
            <div data-role="checks-list" class="option-grid"></div>
          </section>

          <section class="config-block">
            <div class="block-head">
              <h2>Tools</h2>
              <span class="muted">Tự gợi ý theo checks · Built-in / External</span>
            </div>
            <div data-role="tools-list" class="option-grid"></div>
          </section>

          <section class="config-block">
            <h2>Security report</h2>
            <div data-role="reports-list" class="report-list"></div>
          </section>

          <div class="actions">
            <button type="button" class="ghost-btn" data-action="close-config">Về báo cáo / trống</button>
            <button type="button" data-action="save">Lưu cấu hình</button>
          </div>
        </form>
      </div>
    `;

    const form = root.querySelector('[data-role="config-form"]');
    const checksList = root.querySelector('[data-role="checks-list"]');
    const toolsList = root.querySelector('[data-role="tools-list"]');
    const reportsList = root.querySelector('[data-role="reports-list"]');
    const formError = root.querySelector('[data-role="form-error"]');
    const saveBanner = root.querySelector('[data-role="save-banner"]');
    const saveBtn = root.querySelector('[data-action="save"]');

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
        const loaded = ConfigStore.load();
        if (loaded.checks.length !== saved.checks.length || loaded.reportType !== saved.reportType) {
          showError("Lưu cấu hình thất bại (trình duyệt chặn localStorage).");
          return false;
        }

        saveBanner.hidden = false;
        saveBanner.textContent =
          `${reason}: ${saved.checks.length} checks · ${saved.tools.length} tools · ${saved.reportType}. ` +
          `Cập nhật: ${formatWhen(saved.updatedAt)}`;
        saveBtn.textContent = "Đã lưu";
        setTimeout(() => { saveBtn.textContent = "Lưu cấu hình"; }, 1200);
        options.onSaved?.(saved);
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
            <strong>${escapeHtml(check.name)} <span class="priority">${"★".repeat(check.priority || 0)}</span></strong>
            <small>${escapeHtml(check.description)}</small>
            <em>${escapeHtml(check.category || "")} · Tools: ${escapeHtml(check.tools.join(", "))}</em>
          </span>
        </label>
      `).join("");

      toolsList.innerHTML = catalog.tools.map((tool) => `
        <label class="option">
          <input type="checkbox" name="tools" value="${escapeHtml(tool.id)}" />
          <span>
            <strong>${escapeHtml(tool.name)} <span class="tool-kind">${escapeHtml(tool.kind || "")}</span></strong>
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
    }

    const onChange = (event) => {
      const target = event.target;
      if (!(target instanceof HTMLInputElement)) return;
      if (target.name === "checks" && !suppressToolSync) syncToolsFromChecks();
      schedulePersist();
    };

    const onClick = (event) => {
      const action = event.target.closest("[data-action]")?.getAttribute("data-action");
      if (!action) return;

      if (action === "close-config") {
        options.onClose?.();
        return;
      }
      if (action === "defaults") {
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
        return;
      }
      if (action === "save") {
        persist("Đã lưu cấu hình");
      }
    };

    form.addEventListener("change", onChange);
    root.addEventListener("click", onClick);

    apiFetch("/scans/catalog", { headers: { Accept: "application/json" } })
      .then(async (res) => {
        if (!res.ok) throw new Error("Không tải được catalog cấu hình.");
        catalog = await res.json();
        const saved = ConfigStore.load();
        renderCatalog(saved);
        saveBanner.hidden = false;
        saveBanner.textContent = saved.updatedAt
          ? `Cấu hình hiện tại đã lưu lúc ${formatWhen(saved.updatedAt)}. Tích chọn sẽ tự lưu.`
          : "Chưa có cấu hình lưu. Tích chọn sẽ tự lưu ngay trên trình duyệt.";
      })
      .catch((err) => showError(err.message || "Lỗi tải cấu hình."));

    return {
      destroy() {
        clearTimeout(saveTimer);
        form.removeEventListener("change", onChange);
        root.removeEventListener("click", onClick);
        root.innerHTML = "";
      },
    };
  }

  return { mount };
})();
