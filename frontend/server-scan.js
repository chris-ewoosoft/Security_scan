window.SecurityPortalServerScan = (() => {
  const { apiFetch, escapeHtml, extractError } = window.SecurityPortalApi;
  const I18n = window.SecurityPortalI18n;
  const t = (key, vars) => (I18n ? I18n.t(key, vars) : key);

  const STORE_KEY = "sp.serverScanAccess.v1";

  function rememberAccess(id, token) {
    try {
      const raw = localStorage.getItem(STORE_KEY);
      const map = raw ? JSON.parse(raw) : {};
      map[id] = token;
      localStorage.setItem(STORE_KEY, JSON.stringify(map));
    } catch { /* ignore */ }
  }

  function severityClass(sev) {
    const s = (sev || "").toLowerCase();
    if (s === "high") return "sev-high";
    if (s === "medium") return "sev-medium";
    if (s === "unknown" || s === "error") return "sev-medium";
    return "sev-low";
  }

  function renderFindings(findings) {
    if (!findings || findings.length === 0) {
      return `<p class="muted">${escapeHtml(t("serverScan.noFindings"))}</p>`;
    }
    return findings
      .map(
        (f) => `
        <div class="server-scan-finding">
          <div class="server-scan-finding-head">
            <strong>${escapeHtml(f.name)}</strong>
            <span class="${severityClass(f.severity)}">${escapeHtml((f.severity || "").toUpperCase())}</span>
          </div>
          <p class="server-scan-finding-meta">${escapeHtml(f.category || "host-triage")} · ${escapeHtml(f.confidence || "unknown")}</p>
          <div class="server-scan-finding-analysis">
            <strong>${escapeHtml(t("serverScan.analysis"))}</strong>
            <pre class="server-scan-finding-detail">${escapeHtml(f.analysis || f.detail || "—")}</pre>
          </div>
          ${String(f.severity || "").toLowerCase() === "high" ? `
            <div class="server-scan-finding-recommendation">
              <strong>${escapeHtml(t("serverScan.recommendation"))}</strong>
              <p>${escapeHtml(f.recommendation || t("serverScan.defaultRecommendation"))}</p>
            </div>` : ""}
        </div>`
      )
      .join("");
  }

  function renderResult(dto) {
    rememberAccess(dto.id, dto.accessToken);
    return `
      <div class="server-scan-result">
        <p><strong>${escapeHtml(t("serverScan.status"))}:</strong> ${escapeHtml(dto.status)}</p>
        <p>${escapeHtml(dto.summary || dto.errorMessage || "")}</p>
        ${renderFindings(dto.findings)}
      </div>`;
  }

  function mount(root, options = {}) {
    const { onStarted, onProgress, onResult, onError, onBusyChange } = options;
    root.innerHTML = `
      <div class="server-scan-panel-inner">
        <form id="server-scan-form" class="server-scan-form" autocomplete="off">
          <div class="auth-row auth-row-2">
            <div>
              <label for="ss-host" data-i18n="serverScan.host"></label>
              <input id="ss-host" type="text" placeholder="10.0.0.5" required autocomplete="off" spellcheck="false" />
            </div>
            <div>
              <label for="ss-port" data-i18n="serverScan.port"></label>
              <input id="ss-port" type="number" value="22" min="1" max="65535" />
            </div>
          </div>
          <div class="auth-row">
            <label for="ss-username" data-i18n="serverScan.username"></label>
            <input id="ss-username" type="text" placeholder="root" required autocomplete="off" />
          </div>
          <div class="auth-row">
            <label for="ss-auth-type" data-i18n="serverScan.authType"></label>
            <select id="ss-auth-type">
              <option value="password" data-i18n="serverScan.authPassword"></option>
              <option value="privatekey" data-i18n="serverScan.authPrivateKey"></option>
            </select>
          </div>
          <div class="auth-row" id="ss-password-row">
            <label for="ss-password" data-i18n="serverScan.password"></label>
            <input id="ss-password" type="password" autocomplete="off" />
          </div>
          <div class="auth-row" id="ss-key-row" hidden>
            <label for="ss-private-key" data-i18n="serverScan.privateKey"></label>
            <textarea id="ss-private-key" rows="5" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" spellcheck="false"></textarea>
          </div>
          <div class="auth-row" id="ss-passphrase-row" hidden>
            <label for="ss-passphrase" data-i18n="serverScan.passphrase"></label>
            <input id="ss-passphrase" type="password" autocomplete="off" />
          </div>
          <div class="scan-actions">
            <button type="submit" id="ss-submit-btn" class="server-scan-action-btn" data-i18n="serverScan.start"></button>
            <button type="button" id="ss-stop-btn" class="server-scan-action-btn" hidden data-i18n="home.stop"></button>
          </div>
          <p id="ss-form-error" class="form-error" hidden></p>
        </form>

        <div id="ss-result"></div>
      </div>
    `;

    I18n?.applyDom(root);

    const closeBtn = root.querySelector('[data-action="close-server-scan"]');
    closeBtn?.addEventListener("click", () => onClose?.());

    const form = root.querySelector("#server-scan-form");
    const authTypeSelect = root.querySelector("#ss-auth-type");
    const passwordRow = root.querySelector("#ss-password-row");
    const keyRow = root.querySelector("#ss-key-row");
    const passphraseRow = root.querySelector("#ss-passphrase-row");
    const errorEl = root.querySelector("#ss-form-error");
    const resultEl = root.querySelector("#ss-result");
    const submitBtn = root.querySelector("#ss-submit-btn");
    const stopBtn = root.querySelector("#ss-stop-btn");
    let requestController = null;
    let progressTimer = null;
    let progressStartedAt = null;

    function progressSnapshot() {
      const elapsedSeconds = Math.floor((Date.now() - progressStartedAt) / 1000);
      const phase = elapsedSeconds < 3
        ? "serverScan.phaseConnect"
        : elapsedSeconds < 15
          ? "serverScan.phaseCollect"
          : "serverScan.phaseAnalyze";
      return { phase, elapsedSeconds };
    }

    authTypeSelect.addEventListener("change", () => {
      const isKey = authTypeSelect.value === "privatekey";
      passwordRow.hidden = isKey;
      keyRow.hidden = !isKey;
      passphraseRow.hidden = !isKey;
    });

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      errorEl.hidden = true;
      resultEl.innerHTML = "";

      const authType = authTypeSelect.value;
      const payload = {
        host: root.querySelector("#ss-host").value.trim(),
        port: Number(root.querySelector("#ss-port").value) || 22,
        username: root.querySelector("#ss-username").value.trim(),
        authType,
        password: authType === "password" ? root.querySelector("#ss-password").value : null,
        privateKey: authType === "privatekey" ? root.querySelector("#ss-private-key").value : null,
        passphrase: authType === "privatekey" ? root.querySelector("#ss-passphrase").value : null,
      };

      submitBtn.disabled = true;
      submitBtn.textContent = t("serverScan.scanning");
      stopBtn.hidden = false;
      requestController = new AbortController();
      progressStartedAt = Date.now();
      progressTimer = setInterval(() => onProgress?.(progressSnapshot()), 500);
      onBusyChange?.(true);
      onStarted?.({
        host: payload.host,
        port: payload.port,
        username: payload.username,
        status: "Running",
        summary: t("serverScan.scanning"),
        findings: [],
      });
      try {
        const res = await apiFetch("/server-scans", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          signal: requestController.signal,
        });
        const data = await res.json().catch(() => null);
        if (!res.ok) {
          throw new Error(extractError(data) || t("serverScan.failed"));
        }
        rememberAccess(data.id, data.accessToken);
        onResult?.(data);
      } catch (err) {
        if (err.name !== "AbortError") {
          errorEl.textContent = err.message || t("serverScan.failed");
          errorEl.hidden = false;
          onError?.(err);
        }
      } finally {
        if (progressTimer) clearInterval(progressTimer);
        progressTimer = null;
        progressStartedAt = null;
        requestController = null;
        submitBtn.disabled = false;
        submitBtn.textContent = t("serverScan.start");
        stopBtn.hidden = true;
        onBusyChange?.(false);
      }
    });

    stopBtn.addEventListener("click", () => requestController?.abort());

    let unlisten;
    if (I18n?.onChange) {
      unlisten = I18n.onChange(() => I18n.applyDom(root));
    }

    return {
      destroy() {
        unlisten?.();
      },
    };
  }

  return { mount };
})();
