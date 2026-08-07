window.SecurityPortalConfigure = (() => {
  const { apiFetch, escapeHtml, formatWhen } = window.SecurityPortalApi;
  const ConfigStore = window.SecurityPortalConfig;
  const I18n = window.SecurityPortalI18n;
  const t = (key, vars) => (I18n ? I18n.t(key, vars) : key);

  function mount(root, options = {}) {
    if (!ConfigStore) {
      root.innerHTML = `<p class='form-error'>${escapeHtml(t("config.storeMissing"))}</p>`;
      return { destroy() {} };
    }

    root.innerHTML = `
      <div class="config-panel-inner">
        <div class="report-hero">
          <div>
            <p class="eyebrow">${escapeHtml(t("config.eyebrow"))}</p>
            <h2 class="page-title">${escapeHtml(t("config.title"))}</h2>
            <p class="lede">${escapeHtml(t("config.lede"))}</p>
          </div>
          <button type="button" class="ghost-btn" data-action="close-config">${escapeHtml(t("config.close"))}</button>
        </div>

        <div data-role="save-banner" class="save-banner">${escapeHtml(t("config.loading"))}</div>
        <p data-role="form-error" class="form-error" hidden></p>

        <form data-role="config-form" class="config-form">
          <section class="config-block">
            <div class="block-head">
              <h2>${escapeHtml(t("config.checks"))}</h2>
              <div class="preset-actions">
                <button type="button" class="linkish" data-action="preset-baseline">${escapeHtml(t("config.presetBaseline"))}</button>
                <button type="button" class="linkish" data-action="preset-max">${escapeHtml(t("config.presetMax"))}</button>
                <button type="button" class="linkish" data-action="preset-all">${escapeHtml(t("config.presetAll"))}</button>
                <button type="button" class="linkish" data-action="defaults">${escapeHtml(t("config.defaults"))}</button>
              </div>
            </div>
            <p class="muted config-preset-hint">${escapeHtml(t("config.presetHint"))}</p>
            <div data-role="tools-status" class="tools-status muted" hidden></div>
            <div data-role="checks-list" class="option-grid"></div>
          </section>

          <section class="config-block">
            <div class="block-head">
              <h2>${escapeHtml(t("config.tools"))}</h2>
              <span class="muted">${escapeHtml(t("config.toolsHint"))}</span>
            </div>
            <div data-role="tools-list" class="option-grid"></div>
          </section>

          <section class="config-block">
            <h2>${escapeHtml(t("config.reports"))}</h2>
            <div data-role="reports-list" class="report-list"></div>
          </section>

          <div class="actions">
            <button type="button" class="ghost-btn" data-action="close-config">${escapeHtml(t("config.back"))}</button>
            <button type="button" data-action="save">${escapeHtml(t("config.save"))}</button>
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
    const toolsStatus = root.querySelector('[data-role="tools-status"]');

    let catalog = null;
    let suppressToolSync = false;
    let saveTimer = null;
    let toolAvailability = null;

    function applyCheckIds(ids) {
      const set = new Set(ids);
      suppressToolSync = true;
      form.querySelectorAll('input[name="checks"]').forEach((el) => {
        el.checked = set.has(el.value);
      });
      suppressToolSync = false;
      syncToolsFromChecks();
    }

    function refreshToolsStatus() {
      if (!toolsStatus) return;
      apiFetch("/scans/tools-status", { headers: { Accept: "application/json" } })
        .then((r) => (r.ok ? r.json() : null))
        .then((data) => {
          toolAvailability = data;
          if (!data?.tools) {
            toolsStatus.hidden = true;
            return;
          }
          const ready = data.tools.filter((t) => t.available).map((t) => t.id);
          const missing = data.tools.filter((t) => !t.available && t.kind === "External").map((t) => t.id);
          toolsStatus.hidden = false;
          toolsStatus.innerHTML = [
            `<strong>${escapeHtml(t("config.toolsStatusTitle"))}</strong>`,
            ready.length
              ? `${escapeHtml(t("config.toolsReady"))}: ${escapeHtml(ready.join(", "))}`
              : escapeHtml(t("config.toolsNoneReady")),
            missing.length
              ? `${escapeHtml(t("config.toolsMissing"))}: ${escapeHtml(missing.join(", "))} — ${escapeHtml(t("config.toolsInstallHint"))}`
              : "",
          ].filter(Boolean).join(" · ");
          // Refresh tool badges without losing current selection
          if (catalog) renderCatalog(currentConfig());
        })
        .catch(() => { toolsStatus.hidden = true; });
    }

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

    function persist(reason = t("config.saved")) {
      clearError();
      const config = currentConfig();

      if (!config.checks.length) {
        showError(t("config.needChecks"));
        return false;
      }
      if (!config.tools.length) {
        const suggested = new Set();
        form.querySelectorAll('input[name="checks"]:checked').forEach((el) => {
          (el.dataset.tools || "").split(",").filter(Boolean).forEach((toolId) => suggested.add(toolId));
        });
        form.querySelectorAll('input[name="tools"]').forEach((el) => {
          el.checked = suggested.has(el.value);
        });
        config.tools = selectedValues("tools");
      }
      if (!config.tools.length) {
        showError(t("config.needTools"));
        return false;
      }
      if (!config.reportType) {
        showError(t("config.needReport"));
        return false;
      }

      try {
        const saved = ConfigStore.save(config);
        const loaded = ConfigStore.load();
        if (loaded.checks.length !== saved.checks.length || loaded.reportType !== saved.reportType) {
          showError(t("config.saveBlocked"));
          return false;
        }

        saveBanner.hidden = false;
        saveBanner.textContent = t("config.bannerSaved", {
          reason,
          checks: saved.checks.length,
          tools: saved.tools.length,
          report: saved.reportType,
          when: formatWhen(saved.updatedAt),
        });
        saveBtn.textContent = t("config.savedShort");
        setTimeout(() => { saveBtn.textContent = t("config.save"); }, 1200);
        options.onSaved?.(saved);
        return true;
      } catch (err) {
        showError(err.message || t("config.saveFailed"));
        return false;
      }
    }

    function schedulePersist() {
      clearTimeout(saveTimer);
      saveTimer = setTimeout(() => persist(t("config.autosaved")), 250);
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
        (el.dataset.tools || "").split(",").filter(Boolean).forEach((toolId) => suggested.add(toolId));
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

      toolsList.innerHTML = catalog.tools.map((tool) => {
        const avail = toolAvailability?.tools?.find((x) => x.id === tool.id);
        const badge = tool.kind === "External"
          ? (avail
            ? (avail.available
              ? `<span class="tool-avail is-ready">${escapeHtml(t("config.toolReady"))}</span>`
              : `<span class="tool-avail is-missing">${escapeHtml(t("config.toolMissing"))}</span>`)
            : `<span class="tool-avail">${escapeHtml(tool.kind || "")}</span>`)
          : `<span class="tool-kind">${escapeHtml(tool.kind || "")}</span>`;
        return `
        <label class="option">
          <input type="checkbox" name="tools" value="${escapeHtml(tool.id)}" />
          <span>
            <strong>${escapeHtml(tool.name)} ${badge}</strong>
            <small>${escapeHtml(tool.description)}</small>
          </span>
        </label>`;
      }).join("");

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
      if (action === "defaults" || action === "preset-max") {
        applyCheckIds(ConfigStore.MAX_DETECTION_CHECKS || catalog.checks.filter((c) => c.enabledByDefault).map((c) => c.id));
        const technical = form.querySelector('input[name="reportType"][value="technical"]');
        if (technical) {
          form.querySelectorAll('input[name="reportType"]').forEach((el) => { el.checked = false; });
          technical.checked = true;
        }
        persist(t("config.savedMax"));
        return;
      }
      if (action === "preset-baseline") {
        applyCheckIds(ConfigStore.BASELINE_CHECKS || ["reachability", "https-tls", "security-headers", "server-fingerprint"]);
        persist(t("config.savedBaseline"));
        return;
      }
      if (action === "preset-all") {
        applyCheckIds((catalog.checks || []).map((c) => c.id));
        persist(t("config.savedAll"));
        return;
      }
      if (action === "save") {
        persist(t("config.saved"));
      }
    };

    form.addEventListener("change", onChange);
    root.addEventListener("click", onClick);

    apiFetch("/scans/catalog", { headers: { Accept: "application/json" } })
      .then(async (res) => {
        if (!res.ok) throw new Error(t("config.catalogError"));
        catalog = await res.json();
        const saved = ConfigStore.load();
        renderCatalog(saved);
        refreshToolsStatus();
        saveBanner.hidden = false;
        saveBanner.textContent = saved.updatedAt
          ? t("config.savedAt", { when: formatWhen(saved.updatedAt) })
          : t("config.notSaved");
      })
      .catch((err) => showError(err.message || t("config.loadError")));

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
