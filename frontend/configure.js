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

          <section class="config-block" data-role="depth-block" hidden>
            <div class="block-head">
              <h2>${escapeHtml(t("config.depth"))}</h2>
              <div class="preset-actions">
                <button type="button" class="linkish" data-action="depth-quick">${escapeHtml(t("config.depthQuick"))}</button>
                <button type="button" class="linkish" data-action="depth-balanced">${escapeHtml(t("config.depthBalanced"))}</button>
                <button type="button" class="linkish" data-action="depth-deep">${escapeHtml(t("config.depthDeep"))}</button>
                <button type="button" class="linkish" data-action="depth-close">${escapeHtml(t("config.depthClose"))}</button>
              </div>
            </div>
            <p class="muted config-preset-hint">${escapeHtml(t("config.depthHint"))}</p>
            <div data-role="depth-panels" class="depth-panels"></div>
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
    const depthBlock = root.querySelector('[data-role="depth-block"]');
    const depthPanels = root.querySelector('[data-role="depth-panels"]');
    const reportsList = root.querySelector('[data-role="reports-list"]');
    const formError = root.querySelector('[data-role="form-error"]');
    const saveBanner = root.querySelector('[data-role="save-banner"]');
    const saveBtn = root.querySelector('[data-action="save"]');
    const toolsStatus = root.querySelector('[data-role="tools-status"]');

    const DEPTH_TOOLS = new Set(["nuclei", "naabu", "feroxbuster", "ffuf"]);
    let catalog = null;
    let suppressToolSync = false;
    let saveTimer = null;
    let toolAvailability = null;
    let toolOptionsState = ConfigStore.mergeToolOptions(ConfigStore.load().toolOptions);
    /** @type {string|null} tool id whose depth panel is open */
    let openDepthTool = null;

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
      readDepthFromForm();
      return {
        checks: selectedValues("checks"),
        tools: selectedValues("tools"),
        reportType: (form.querySelector('input[name="reportType"]:checked') || {}).value || ConfigStore.FALLBACK.reportType,
        toolOptions: toolOptionsState,
      };
    }

    function readDepthFromForm() {
      if (!depthPanels) return;
      const g = (name) => depthPanels.querySelector(`[name="${name}"]`);
      const num = (name, fallback) => {
        const el = g(name);
        const n = el ? Number(el.value) : NaN;
        return Number.isFinite(n) ? n : fallback;
      };
      const str = (name, fallback) => {
        const el = g(name);
        return el ? String(el.value || "").trim() : fallback;
      };
      toolOptionsState = ConfigStore.mergeToolOptions({
        nuclei: {
          profile: str("nuclei.profile", "balanced"),
          severity: str("nuclei.severity", "medium,high,critical"),
          tags: str("nuclei.tags", ""),
          exposureTags: str("nuclei.exposureTags", "exposure,config,backup,token,key,file"),
          concurrency: num("nuclei.concurrency", 25),
          rateLimit: num("nuclei.rateLimit", 150),
          timeoutSeconds: num("nuclei.timeoutSeconds", 8),
          retries: num("nuclei.retries", 1),
          maxDurationSeconds: num("nuclei.maxDurationSeconds", 120),
        },
        naabu: {
          ports: str("naabu.ports", ConfigStore.DEFAULT_TOOL_OPTIONS.naabu.ports),
          rate: num("naabu.rate", 200),
        },
        feroxbuster: {
          depth: num("feroxbuster.depth", 1),
          threads: num("feroxbuster.threads", 20),
          timeoutSeconds: num("feroxbuster.timeoutSeconds", 5),
          maxDurationSeconds: num("feroxbuster.maxDurationSeconds", 90),
        },
        ffuf: {
          threads: num("ffuf.threads", 20),
          timeoutSeconds: num("ffuf.timeoutSeconds", 5),
          maxDurationSeconds: num("ffuf.maxDurationSeconds", 90),
          matchCodes: str("ffuf.matchCodes", "200,204,301,401,403"),
        },
      });
    }

    function selectedToolsSet() {
      return new Set(selectedValues("tools"));
    }

    function syncDetailButtons() {
      toolsList?.querySelectorAll("[data-action='tool-detail']").forEach((btn) => {
        const id = btn.getAttribute("data-tool");
        const active = id && id === openDepthTool;
        btn.classList.toggle("is-active", !!active);
        btn.setAttribute("aria-expanded", active ? "true" : "false");
        btn.textContent = active ? t("config.depthHide") : t("config.toolDetail");
      });
    }

    function renderDepthPanels() {
      if (!depthPanels || !depthBlock) return;

      if (!openDepthTool || !DEPTH_TOOLS.has(openDepthTool)) {
        depthBlock.hidden = true;
        depthPanels.innerHTML = "";
        syncDetailButtons();
        return;
      }

      // Keep depth values if the tool is still selected; otherwise close.
      const selected = selectedToolsSet();
      if (!selected.has(openDepthTool)) {
        openDepthTool = null;
        depthBlock.hidden = true;
        depthPanels.innerHTML = "";
        syncDetailButtons();
        return;
      }

      depthBlock.hidden = false;
      const o = toolOptionsState;
      const toolId = openDepthTool;

      const field = (label, name, value, attrs = "") => `
        <label class="depth-field">
          <span class="depth-field-label">${escapeHtml(label)}</span>
          <input name="${escapeHtml(name)}" value="${escapeHtml(String(value ?? ""))}" ${attrs} />
        </label>`;

      const select = (label, name, value, options) => `
        <label class="depth-field">
          <span class="depth-field-label">${escapeHtml(label)}</span>
          <select name="${escapeHtml(name)}">
            ${options.map(([v, lab]) =>
              `<option value="${escapeHtml(v)}"${v === value ? " selected" : ""}>${escapeHtml(lab)}</option>`).join("")}
          </select>
        </label>`;

      let panel = "";
      if (toolId === "nuclei") {
        panel = `
          <div class="depth-panel">
            <h3 class="depth-panel-title">Nuclei <span class="depth-panel-sub">${escapeHtml(t("config.depthNucleiSummary"))}</span></h3>
            <div class="depth-grid">
              ${select(t("config.nucleiProfile"), "nuclei.profile", o.nuclei.profile, [
                ["quick", t("config.depthQuick")],
                ["balanced", t("config.depthBalanced")],
                ["deep", t("config.depthDeep")],
              ])}
              ${field(t("config.nucleiSeverity"), "nuclei.severity", o.nuclei.severity)}
              ${field(t("config.nucleiTags"), "nuclei.tags", o.nuclei.tags, `placeholder="cve,misconfig,xss"`)}
              ${field(t("config.nucleiExposureTags"), "nuclei.exposureTags", o.nuclei.exposureTags)}
              ${field(t("config.nucleiConcurrency"), "nuclei.concurrency", o.nuclei.concurrency, `type="number" min="1" max="100"`)}
              ${field(t("config.nucleiRate"), "nuclei.rateLimit", o.nuclei.rateLimit, `type="number" min="10" max="1000"`)}
              ${field(t("config.nucleiTimeout"), "nuclei.timeoutSeconds", o.nuclei.timeoutSeconds, `type="number" min="3" max="30"`)}
              ${field(t("config.nucleiRetries"), "nuclei.retries", o.nuclei.retries, `type="number" min="0" max="3"`)}
              ${field(t("config.nucleiMaxDuration"), "nuclei.maxDurationSeconds", o.nuclei.maxDurationSeconds, `type="number" min="30" max="900"`)}
            </div>
            <p class="depth-note">${escapeHtml(t("config.nucleiNote"))}</p>
          </div>`;
      } else if (toolId === "naabu") {
        panel = `
          <div class="depth-panel">
            <h3 class="depth-panel-title">Naabu <span class="depth-panel-sub">${escapeHtml(t("config.depthNaabuSummary"))}</span></h3>
            <div class="depth-grid">
              ${field(t("config.naabuPorts"), "naabu.ports", o.naabu.ports)}
              ${field(t("config.naabuRate"), "naabu.rate", o.naabu.rate, `type="number" min="10" max="5000"`)}
            </div>
          </div>`;
      } else if (toolId === "feroxbuster") {
        panel = `
          <div class="depth-panel">
            <h3 class="depth-panel-title">Feroxbuster <span class="depth-panel-sub">${escapeHtml(t("config.depthFeroxSummary"))}</span></h3>
            <div class="depth-grid">
              ${field(t("config.feroxDepth"), "feroxbuster.depth", o.feroxbuster.depth, `type="number" min="0" max="4"`)}
              ${field(t("config.feroxThreads"), "feroxbuster.threads", o.feroxbuster.threads, `type="number" min="1" max="100"`)}
              ${field(t("config.feroxTimeout"), "feroxbuster.timeoutSeconds", o.feroxbuster.timeoutSeconds, `type="number" min="2" max="30"`)}
              ${field(t("config.feroxMaxDuration"), "feroxbuster.maxDurationSeconds", o.feroxbuster.maxDurationSeconds, `type="number" min="30" max="600"`)}
            </div>
          </div>`;
      } else if (toolId === "ffuf") {
        panel = `
          <div class="depth-panel">
            <h3 class="depth-panel-title">FFUF <span class="depth-panel-sub">${escapeHtml(t("config.depthFfufSummary"))}</span></h3>
            <div class="depth-grid">
              ${field(t("config.ffufThreads"), "ffuf.threads", o.ffuf.threads, `type="number" min="1" max="100"`)}
              ${field(t("config.ffufTimeout"), "ffuf.timeoutSeconds", o.ffuf.timeoutSeconds, `type="number" min="2" max="30"`)}
              ${field(t("config.ffufMaxDuration"), "ffuf.maxDurationSeconds", o.ffuf.maxDurationSeconds, `type="number" min="30" max="600"`)}
              ${field(t("config.ffufMatchCodes"), "ffuf.matchCodes", o.ffuf.matchCodes)}
            </div>
          </div>`;
      }

      depthPanels.innerHTML = panel;
      syncDetailButtons();
      depthBlock.scrollIntoView({ behavior: "smooth", block: "nearest" });
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
        const hasDepth = DEPTH_TOOLS.has(tool.id);
        const detailBtn = hasDepth
          ? `<button type="button" class="tool-detail-btn" data-action="tool-detail" data-tool="${escapeHtml(tool.id)}" aria-expanded="false">${escapeHtml(t("config.toolDetail"))}</button>`
          : "";
        return `
        <div class="tool-option${hasDepth ? " has-depth" : ""}">
          <label class="tool-option-main">
            <input type="checkbox" name="tools" value="${escapeHtml(tool.id)}" />
            <span>
              <strong>${escapeHtml(tool.name)} ${badge}</strong>
              <small>${escapeHtml(tool.description)}</small>
            </span>
          </label>
          ${detailBtn}
        </div>`;
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
      renderDepthPanels();
    }

    const onChange = (event) => {
      const target = event.target;
      if (!(target instanceof HTMLInputElement) && !(target instanceof HTMLSelectElement)) return;
      if (target.name === "checks" && !suppressToolSync) {
        syncToolsFromChecks();
        renderDepthPanels();
      }
      if (target.name === "tools") {
        // Closing depth if the open tool was unchecked
        if (openDepthTool && target instanceof HTMLInputElement && target.value === openDepthTool && !target.checked) {
          openDepthTool = null;
        }
        renderDepthPanels();
      }
      if (target.name === "nuclei.profile") {
        readDepthFromForm();
        toolOptionsState = ConfigStore.applyDepthProfile(target.value, toolOptionsState);
        renderDepthPanels();
      }
      schedulePersist();
    };

    const onClick = (event) => {
      const actionEl = event.target.closest("[data-action]");
      const action = actionEl?.getAttribute("data-action");
      if (!action) return;

      if (action === "tool-detail") {
        event.preventDefault();
        event.stopPropagation();
        const toolId = actionEl.getAttribute("data-tool");
        if (!toolId || !DEPTH_TOOLS.has(toolId)) return;
        // Ensure tool is selected when opening depth
        const checkbox = form.querySelector(`input[name="tools"][value="${CSS.escape(toolId)}"]`);
        if (checkbox instanceof HTMLInputElement && !checkbox.checked) {
          checkbox.checked = true;
        }
        readDepthFromForm();
        openDepthTool = openDepthTool === toolId ? null : toolId;
        renderDepthPanels();
        if (openDepthTool) schedulePersist();
        return;
      }

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
        toolOptionsState = ConfigStore.applyDepthProfile("balanced", toolOptionsState);
        renderDepthPanels();
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
      if (action === "depth-close") {
        readDepthFromForm();
        openDepthTool = null;
        renderDepthPanels();
        schedulePersist();
        return;
      }
      if (action === "depth-quick" || action === "depth-balanced" || action === "depth-deep") {
        const profile = action.replace("depth-", "");
        readDepthFromForm();
        toolOptionsState = ConfigStore.applyDepthProfile(profile, toolOptionsState);
        renderDepthPanels();
        persist(t("config.savedDepth", { profile }));
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
        toolOptionsState = ConfigStore.mergeToolOptions(saved.toolOptions);
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
