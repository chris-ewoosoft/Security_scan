window.SecurityPortalApi = (() => {
  const candidates = ["/api/v1", "http://localhost:5000/api/v1"];
  const TOKEN_STORE_KEY = "sp.scanAccess.v1";

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

  async function apiFetch(path, options = {}) {
    let lastError = null;
    const headers = new Headers(options.headers || {});
    if (!headers.has("Accept-Language")) {
      headers.set("Accept-Language", currentLang());
    }
    const nextOptions = { ...options, headers };

    for (const base of candidates) {
      try {
        const res = await fetch(`${base}${path}`, nextOptions);
        if (res.status === 502 || res.status === 503 || res.status === 504) {
          lastError = new Error(`API gateway error (${res.status})`);
          continue;
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
