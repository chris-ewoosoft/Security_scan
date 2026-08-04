(() => {
  const { apiFetch, extractError, normalizeUrl, statusClass, escapeHtml, formatWhen } = window.SecurityPortalApi;

  const form = document.getElementById("scan-form");
  const input = document.getElementById("target-url");
  const formError = document.getElementById("form-error");
  const recentList = document.getElementById("recent-list");

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    formError.hidden = true;

    const targetUrl = normalizeUrl(input.value);
    if (!targetUrl) {
      formError.hidden = false;
      formError.textContent = "Vui lòng nhập địa chỉ website cần scan.";
      input.focus();
      return;
    }

    const params = new URLSearchParams({ url: targetUrl });
    window.location.href = `/configure.html?${params.toString()}`;
  });

  async function loadRecent() {
    try {
      const res = await apiFetch("/scans?take=8", { headers: { Accept: "application/json" } });
      if (!res.ok) return;
      const items = await res.json();
      recentList.innerHTML = "";
      if (!items.length) {
        recentList.innerHTML = "<li><span class=\"url\">Chưa có scan nào</span></li>";
        return;
      }

      for (const item of items) {
        const li = document.createElement("li");
        li.innerHTML = `
          <span class="url">${escapeHtml(item.targetUrl)}</span>
          <span class="badge ${statusClass(item.status)}">${escapeHtml(item.status)}</span>
          <span class="when">${formatWhen(item.createdAt)}</span>
        `;
        li.addEventListener("click", () => {
          window.location.href = `/report.html?id=${encodeURIComponent(item.id)}`;
        });
        recentList.appendChild(li);
      }
    } catch {
      // ignore
    }
  }

  void extractError;
  loadRecent();
  input.focus();
})();
