window.SecurityPortalApi = (() => {
  const candidates = window.location.port === "3000"
    ? ["http://localhost:5000/api/v1", "/api/v1"]
    : ["/api/v1", "http://localhost:5000/api/v1"];
  const TOKEN_STORE_KEY = "sp.scanAccess.v1";
  const AUTH_STORE_KEY = "sp.auth.v1";

  function currentLang() {
    return window.SecurityPortalI18n?.getLocale?.() || "vi";
  }

  function loadTokenMap() {
    try {
      const raw = localStorage.getItem(TOKEN_STORE_KEY);
      if (!raw) return {};
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === "object" ? parsed : {};
    } catch {
      return {};
    }
  }

  function saveTokenMap(map) {
    try {
      localStorage.setItem(TOKEN_STORE_KEY, JSON.stringify(map));
    } catch { /* ignore */ }
  }

  function rememberScanAccess(scanId, accessToken) {
    if (!scanId || !accessToken) return;
    const map = loadTokenMap();
    map[scanId] = accessToken;
    const ids = Object.keys(map);
    if (ids.length > 80) {
      ids.slice(0, ids.length - 80).forEach((id) => delete map[id]);
    }
    saveTokenMap(map);
  }

  function getScanAccessToken(scanId) {
    return loadTokenMap()[scanId] || null;
  }

  function getAllScanAccessTokens() {
    return loadTokenMap();
  }

  function forgetScanAccess(ids) {
    const map = loadTokenMap();
    (ids || []).forEach((id) => delete map[id]);
    saveTokenMap(map);
  }

  function loadAuth() {
    try {
      const raw = localStorage.getItem(AUTH_STORE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed === "object" ? parsed : null;
    } catch {
      return null;
    }
  }

  function saveAuth(auth) {
    try {
      if (auth) localStorage.setItem(AUTH_STORE_KEY, JSON.stringify(auth));
      else localStorage.removeItem(AUTH_STORE_KEY);
    } catch { /* ignore */ }
  }

  function authHeaders(headers) {
    const auth = loadAuth();
    if (auth?.accessToken && !headers.has("Authorization")) {
      headers.set("Authorization", `Bearer ${auth.accessToken}`);
    }
  }

  async function authenticate(email, password) {
    const res = await apiFetch("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ email, password }),
      skipAuth: true,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(extractError(data) || `Login failed (HTTP ${res.status}).`);
    saveAuth(data);
    return data;
  }

  async function refreshAuth() {
    const auth = loadAuth();
    if (!auth?.refreshToken) return false;
    const res = await apiFetch("/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ refreshToken: auth.refreshToken }),
      skipAuth: true,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      saveAuth(null);
      return false;
    }
    saveAuth(data);
    return true;
  }

  async function logout() {
    const auth = loadAuth();
    saveAuth(null);
    if (!auth?.refreshToken) return;
    await apiFetch("/auth/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ refreshToken: auth.refreshToken }),
      skipAuth: true,
    }).catch(() => {});
  }

  async function apiFetch(path, options = {}) {
    let lastError = null;
    const headers = new Headers(options.headers || {});
    if (!headers.has("Accept-Language")) {
      headers.set("Accept-Language", currentLang());
    }
    if (!options.skipAuth) authHeaders(headers);
    const nextOptions = { ...options, headers };

    for (const base of candidates) {
      try {
        const res = await fetch(`${base}${path}`, nextOptions);
        const contentType = res.headers.get("content-type") || "";
        const looksLikeApiResponse = contentType.includes("json");
        // A gateway error, or a non-JSON response (e.g. this candidate has no
        // reverse proxy for /api and served a static-server error page instead),
        // means this base isn't actually serving the API — try the next one.
        if (res.status === 501 || res.status === 502 || res.status === 503 || res.status === 504 || (!res.ok && !looksLikeApiResponse)) {
          lastError = new Error(`API gateway error (${res.status})`);
          continue;
        }
        if (res.status === 401 && !options.skipAuth && !options._retried) {
          const refreshed = await refreshAuth();
          if (refreshed) return apiFetch(path, { ...options, _retried: true });
        }
        return res;
      } catch (err) {
        lastError = err;
      }
    }
    const unreachable = window.SecurityPortalI18n?.t?.("api.unreachable") || "Could not reach the API.";
    throw lastError || new Error(unreachable);
  }

  function extractError(data) {
    if (!data) return null;
    if (data.detail) return data.detail;
    if (data.errors) {
      const first = Object.values(data.errors).flat()[0];
      if (first) return first;
    }
    return null;
  }

  function normalizeUrl(value) {
    const trimmed = (value || "").trim();
    if (!trimmed) return "";
    return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  }

  function statusClass(status) {
    if (status === "Running" || status === "Queued") return "is-running";
    if (status === "Completed") return "is-completed";
    if (status === "Failed") return "is-failed";
    if (status === "Cancelled") return "is-cancelled";
    return "";
  }

  function severityClass(severity) {
    const s = (severity || "").toLowerCase();
    if (s === "high") return "sev-high";
    if (s === "medium") return "sev-medium";
    if (s === "low") return "sev-low";
    return "sev-info";
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  }

  function wrapReportLines(value, maxChars = 96) {
    const text = String(value ?? "");
    if (!text || maxChars < 24) return text;

    return text.split(/\r?\n/).map((line) => {
      if (line.length <= maxChars) return line;
      const parts = [];
      let rest = line;
      while (rest.length > maxChars) {
        const windowSlice = rest.slice(0, maxChars + 1);
        const breakAt = Math.max(
          windowSlice.lastIndexOf(" "),
          windowSlice.lastIndexOf("\t"),
          windowSlice.lastIndexOf(";"),
          windowSlice.lastIndexOf(","),
          windowSlice.lastIndexOf("|"),
          windowSlice.lastIndexOf("/"),
          windowSlice.lastIndexOf("?"),
          windowSlice.lastIndexOf("&"),
          windowSlice.lastIndexOf("="),
          windowSlice.lastIndexOf(":")
        );
        const cut = breakAt > maxChars * 0.45 ? breakAt + 1 : maxChars;
        parts.push(rest.slice(0, cut).trimEnd());
        rest = rest.slice(cut).trimStart();
      }
      if (rest) parts.push(rest);
      return parts.join("\n");
    }).join("\n");
  }

  function formatWhen(iso) {
    try {
      const locale = currentLang() === "en" ? "en-US" : "vi-VN";
      return new Date(iso).toLocaleString(locale);
    } catch {
      return iso;
    }
  }

  return {
    apiFetch,
    authenticate,
    refreshAuth,
    logout,
    getAuth: loadAuth,
    extractError,
    normalizeUrl,
    statusClass,
    severityClass,
    escapeHtml,
    wrapReportLines,
    formatWhen,
    rememberScanAccess,
    getScanAccessToken,
    getAllScanAccessTokens,
    forgetScanAccess,
  };
})();
