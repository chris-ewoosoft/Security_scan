window.SecurityPortalHistory = (() => {
  const { apiFetch, statusClass, escapeHtml, formatWhen } = window.SecurityPortalApi;
  const I18n = window.SecurityPortalI18n;
  const t = (key, vars) => (I18n ? I18n.t(key, vars) : key);

  function mount(root, options = {}) {
    root.innerHTML = `
      <div class="history-panel-inner">
        <div class="report-hero">
          <div>
            <p class="eyebrow">${escapeHtml(t("history.eyebrow"))}</p>
            <h2 class="page-title">${escapeHtml(t("history.title"))}</h2>
          </div>
          <div class="history-hero-actions">
            <button type="button" class="ghost-btn danger-btn" data-action="delete-selected" disabled>
              ${escapeHtml(t("history.delete"))}
            </button>
            <button type="button" class="ghost-btn" data-action="close-history">${escapeHtml(t("history.close"))}</button>
          </div>
        </div>

        <section class="config-block history-list-block">
          <div class="block-head">
            <h2>${escapeHtml(t("history.listTitle"))}</h2>
            <button type="button" class="linkish" data-action="refresh">${escapeHtml(t("history.refresh"))}</button>
          </div>
          <p data-role="history-error" class="form-error" hidden></p>
          <p data-role="history-status" class="muted history-status" hidden></p>
          <div class="history-table-wrap">
            <table class="history-table">
              <thead>
                <tr>
                  <th scope="col" class="col-select">
                    <label class="history-select-all" title="${escapeHtml(t("history.selectAll"))}">
                      <input type="checkbox" data-role="select-all" />
                      <span>${escapeHtml(t("history.selectAll"))}</span>
                    </label>
                  </th>
                  <th scope="col" class="col-when">${escapeHtml(t("history.when"))}</th>
                  <th scope="col" class="col-url">${escapeHtml(t("history.url"))}</th>
                  <th scope="col" class="col-status">${escapeHtml(t("history.status"))}</th>
                </tr>
              </thead>
              <tbody data-role="history-list"></tbody>
            </table>
          </div>
        </section>
      </div>
    `;

    const historyList = root.querySelector('[data-role="history-list"]');
    const historyError = root.querySelector('[data-role="history-error"]');
    const historyStatus = root.querySelector('[data-role="history-status"]');
    const selectAll = root.querySelector('[data-role="select-all"]');
    const deleteBtn = root.querySelector('[data-action="delete-selected"]');
    let activeScanId = options.activeScanId || null;

    function selectedIds() {
      return [...historyList.querySelectorAll('input[data-role="row-check"]:checked')]
        .map((el) => el.value)
        .filter(Boolean);
    }

    function syncSelectionUi() {
      const checks = [...historyList.querySelectorAll('input[data-role="row-check"]')];
      const selected = checks.filter((el) => el.checked);
      if (deleteBtn) deleteBtn.disabled = selected.length === 0;
      if (selectAll) {
        selectAll.disabled = checks.length === 0;
        selectAll.checked = checks.length > 0 && selected.length === checks.length;
        selectAll.indeterminate = selected.length > 0 && selected.length < checks.length;
      }
    }

    function showStatus(message) {
      if (!historyStatus) return;
      historyStatus.hidden = !message;
      historyStatus.textContent = message || "";
    }

    function markActiveRows() {
      [...historyList.querySelectorAll("tr[data-id]")].forEach((el) => {
        el.classList.toggle("is-active", el.dataset.id === activeScanId);
      });
    }

    async function loadHistory() {
      historyError.hidden = true;
      showStatus("");
      try {
        const res = await apiFetch("/scans?take=50", { headers: { Accept: "application/json" } });
        if (!res.ok) throw new Error(`${t("history.loadError")} (HTTP ${res.status}).`);
        const items = await res.json();
        historyList.innerHTML = "";

        if (!items.length) {
          historyList.innerHTML = `
            <tr class="history-empty">
              <td colspan="4">${escapeHtml(t("history.empty"))}</td>
            </tr>`;
          syncSelectionUi();
          return;
        }

        for (const item of items) {
          const tr = document.createElement("tr");
          tr.dataset.id = item.id;
          if (item.id === activeScanId) tr.classList.add("is-active");
          const risk = item.report?.riskLevel ? ` · Risk ${item.report.riskLevel}` : "";
          tr.innerHTML = `
            <td class="col-select">
              <label class="history-check" title="${escapeHtml(t("history.selectToDelete"))}">
                <input type="checkbox" data-role="row-check" value="${escapeHtml(item.id)}" />
              </label>
            </td>
            <td class="col-when">${formatWhen(item.createdAt)}</td>
            <td class="col-url"><span class="url">${escapeHtml(item.targetUrl)}</span></td>
            <td class="col-status">
              <span class="badge ${statusClass(item.status)}">${escapeHtml(item.status)}${escapeHtml(risk)}</span>
            </td>
          `;

          const check = tr.querySelector('input[data-role="row-check"]');
          check?.addEventListener("click", (event) => event.stopPropagation());
          check?.addEventListener("change", () => syncSelectionUi());

          tr.addEventListener("click", (event) => {
            if (event.target.closest(".history-check")) return;
            activeScanId = item.id;
            markActiveRows();
            options.onSelect?.(item.id);
          });
          historyList.appendChild(tr);
        }
        syncSelectionUi();
      } catch (err) {
        historyError.hidden = false;
        historyError.textContent = err.message || t("history.loadError");
        syncSelectionUi();
      }
    }

    async function deleteSelected() {
      const ids = selectedIds();
      if (!ids.length) return;

      const ok = window.confirm(
        ids.length === 1
          ? t("history.deleteConfirmOne")
          : t("history.deleteConfirmMany", { count: ids.length })
      );
      if (!ok) return;

      if (deleteBtn) deleteBtn.disabled = true;
      historyError.hidden = true;
      showStatus(t("history.deleting"));

      try {
        const res = await apiFetch("/scans", {
          method: "DELETE",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify({ ids }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          throw new Error(data.detail || `${t("history.deleteError")} (HTTP ${res.status}).`);
        }

        const deleted = data.deleted ?? ids.length;
        showStatus(t("history.deleted", { count: deleted }));
        options.onDeleted?.(ids);
        if (ids.includes(activeScanId)) activeScanId = null;
        await loadHistory();
      } catch (err) {
        historyError.hidden = false;
        historyError.textContent = err.message || t("history.deleteError");
        syncSelectionUi();
      } finally {
        showStatus("");
      }
    }

    const onClick = (event) => {
      const action = event.target.closest("[data-action]")?.getAttribute("data-action");
      if (!action) return;
      if (action === "close-history") {
        options.onClose?.();
        return;
      }
      if (action === "refresh") loadHistory();
      if (action === "delete-selected") deleteSelected();
    };

    selectAll?.addEventListener("click", (event) => event.stopPropagation());
    selectAll?.addEventListener("change", () => {
      const checked = !!selectAll.checked;
      historyList.querySelectorAll('input[data-role="row-check"]').forEach((el) => {
        el.checked = checked;
      });
      syncSelectionUi();
    });

    root.addEventListener("click", onClick);
    loadHistory();

    return {
      refresh: loadHistory,
      setActive(id) {
        activeScanId = id;
        markActiveRows();
      },
      destroy() {
        root.removeEventListener("click", onClick);
        root.innerHTML = "";
      },
    };
  }

  return { mount };
})();
