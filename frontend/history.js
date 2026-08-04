window.SecurityPortalHistory = (() => {
  const { apiFetch, statusClass, escapeHtml, formatWhen } = window.SecurityPortalApi;

  function mount(root, options = {}) {
    root.innerHTML = `
      <div class="history-panel-inner">
        <div class="report-hero">
          <div>
            <p class="eyebrow">Lịch sử</p>
            <h2 class="page-title">Scan &amp; báo cáo trước đây</h2>
            <p class="lede">Chọn một mục để mở Technical Report ở cột phải.</p>
          </div>
          <button type="button" class="ghost-btn" data-action="close-history">Đóng</button>
        </div>

        <section class="config-block history-list-block">
          <div class="block-head">
            <h2>Danh sách scan</h2>
            <button type="button" class="linkish" data-action="refresh">Làm mới</button>
          </div>
          <p data-role="history-error" class="form-error" hidden></p>
          <ul data-role="history-list" class="recent-list history-list"></ul>
        </section>
      </div>
    `;

    const historyList = root.querySelector('[data-role="history-list"]');
    const historyError = root.querySelector('[data-role="history-error"]');
    let activeScanId = options.activeScanId || null;

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
          li.addEventListener("click", () => {
            activeScanId = item.id;
            [...historyList.children].forEach((el) => {
              el.classList.toggle("is-active", el.dataset.id === item.id);
            });
            options.onSelect?.(item.id);
          });
          historyList.appendChild(li);
        }
      } catch (err) {
        historyError.hidden = false;
        historyError.textContent = err.message || "Lỗi tải lịch sử.";
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
    };

    root.addEventListener("click", onClick);
    loadHistory();

    return {
      refresh: loadHistory,
      setActive(id) {
        activeScanId = id;
        [...historyList.children].forEach((el) => {
          el.classList.toggle("is-active", el.dataset.id === id);
        });
      },
      destroy() {
        root.removeEventListener("click", onClick);
        root.innerHTML = "";
      },
    };
  }

  return { mount };
})();
