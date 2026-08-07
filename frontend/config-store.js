window.SecurityPortalConfig = (() => {
  const STORAGE_KEY = "sp.scanConfig.v2";
  const LEGACY_KEY = "sp.scanConfig.v1";

  /** Max-detection profile — mirrors ScanCatalog EnabledByDefault / MaxDetectionCheckIds */
  const MAX_DETECTION_CHECKS = [
    "reachability",
    "https-tls",
    "security-headers",
    "server-fingerprint",
    "cookie-security",
    "cors-policy",
    "information-disclosure",
    "port-scan",
    "directory-discovery",
    "sensitive-file-scan",
    "vulnerability-scan",
    "technology-detection",
    "dns-security",
    "waf-detection",
  ];

  const MAX_DETECTION_TOOLS = [
    "http-probe",
    "ssl-checker",
    "header-analyzer",
    "fingerprint",
    "cookie-inspector",
    "cors-checker",
    "naabu",
    "feroxbuster",
    "ffuf",
    "nuclei",
    "whatweb",
    "wappalyzer",
    "dnsx",
    "wafw00f",
  ];

  const BASELINE_CHECKS = [
    "reachability",
    "https-tls",
    "security-headers",
    "server-fingerprint",
  ];

  const BASELINE_TOOLS = [
    "http-probe",
    "ssl-checker",
    "header-analyzer",
    "fingerprint",
  ];

  const FALLBACK = {
    checks: [...MAX_DETECTION_CHECKS],
    tools: [...MAX_DETECTION_TOOLS],
    reportType: "technical",
  };

  function migrateLegacy() {
    try {
      if (localStorage.getItem(STORAGE_KEY)) return;
      const legacy = localStorage.getItem(LEGACY_KEY);
      if (!legacy) return;
      const parsed = JSON.parse(legacy);
      // Upgrade old baseline-only configs to max detection once.
      const onlyBaseline =
        Array.isArray(parsed.checks) &&
        parsed.checks.length <= 4 &&
        parsed.checks.every((id) => BASELINE_CHECKS.includes(id));
      const next = onlyBaseline
        ? { ...FALLBACK, updatedAt: new Date().toISOString() }
        : {
            checks: parsed.checks?.length ? parsed.checks : [...FALLBACK.checks],
            tools: parsed.tools?.length ? parsed.tools : [...FALLBACK.tools],
            reportType: parsed.reportType || FALLBACK.reportType,
            updatedAt: parsed.updatedAt || new Date().toISOString(),
          };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      /* ignore */
    }
  }

  function load() {
    migrateLegacy();
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

  return {
    load,
    save,
    summarize,
    FALLBACK,
    BASELINE_CHECKS,
    BASELINE_TOOLS,
    MAX_DETECTION_CHECKS,
    MAX_DETECTION_TOOLS,
  };
})();
