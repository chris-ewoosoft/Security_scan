window.SecurityPortalConfig = (() => {
  const STORAGE_KEY = "sp.scanConfig.v1";

  const FALLBACK = {
    checks: ["reachability", "https-tls", "security-headers", "server-fingerprint"],
    tools: ["http-probe", "ssl-checker", "header-analyzer", "fingerprint"],
    reportType: "technical",
  };

  function load() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return { ...FALLBACK, checks: [...FALLBACK.checks], tools: [...FALLBACK.tools] };
      const parsed = JSON.parse(raw);
      return {
        checks: Array.isArray(parsed.checks) && parsed.checks.length ? parsed.checks : [...FALLBACK.checks],
        tools: Array.isArray(parsed.tools) && parsed.tools.length ? parsed.tools : [...FALLBACK.tools],
        reportType: parsed.reportType || FALLBACK.reportType,
        updatedAt: parsed.updatedAt || null,
      };
    } catch {
      return { ...FALLBACK, checks: [...FALLBACK.checks], tools: [...FALLBACK.tools] };
    }
  }

  function save(config) {
    const payload = {
      checks: [...new Set(config.checks || [])],
      tools: [...new Set(config.tools || [])],
      reportType: config.reportType || FALLBACK.reportType,
      updatedAt: new Date().toISOString(),
    };
    if (!payload.checks.length) throw new Error("Checks trống — không lưu.");
    if (!payload.tools.length) throw new Error("Tools trống — không lưu.");
    localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
    const verify = localStorage.getItem(STORAGE_KEY);
    if (!verify) throw new Error("localStorage không ghi được dữ liệu.");
    return payload;
  }

  function summarize(config, catalog) {
    const checkNames = (config.checks || []).map((id) => {
      const found = catalog?.checks?.find((c) => c.id === id);
      return found?.name || id;
    });
    const report = catalog?.reports?.find((r) => r.id === config.reportType);
    return {
      checkCount: config.checks?.length || 0,
      toolCount: config.tools?.length || 0,
      checkNames,
      reportName: report?.name || config.reportType,
      updatedAt: config.updatedAt,
    };
  }

  return { load, save, summarize, FALLBACK };
})();
