window.SecurityPortalConfig = (() => {
  const STORAGE_KEY = "sp.scanConfig.v3";
  const LEGACY_V2 = "sp.scanConfig.v2";
  const LEGACY_V1 = "sp.scanConfig.v1";

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

  const DEFAULT_TOOL_OPTIONS = {
    nuclei: {
      profile: "balanced",
      severity: "medium,high,critical",
      tags: "cve,misconfig",
      exposureTags: "exposure,config,backup,token,key,file",
      concurrency: 25,
      rateLimit: 150,
      timeoutSeconds: 8,
      retries: 1,
      maxDurationSeconds: 180,
    },
    naabu: {
      ports: "21,22,25,53,80,110,143,443,445,993,995,3306,3389,5432,6379,8080,8443",
      rate: 200,
    },
    feroxbuster: {
      depth: 1,
      threads: 20,
      timeoutSeconds: 5,
      maxDurationSeconds: 90,
    },
    ffuf: {
      threads: 20,
      timeoutSeconds: 5,
      maxDurationSeconds: 90,
      matchCodes: "200,204,301,401,403",
    },
  };

  const PROFILE_PRESETS = {
    quick: {
      nuclei: {
        profile: "quick",
        severity: "high,critical",
        tags: "cve,misconfig",
        exposureTags: "exposure,config,backup",
        concurrency: 15,
        rateLimit: 100,
        timeoutSeconds: 5,
        retries: 1,
        maxDurationSeconds: 90,
      },
      feroxbuster: { depth: 0, threads: 15, timeoutSeconds: 4, maxDurationSeconds: 45 },
      ffuf: { threads: 15, timeoutSeconds: 4, maxDurationSeconds: 45, matchCodes: "200,301,403" },
    },
    balanced: {
      nuclei: { ...DEFAULT_TOOL_OPTIONS.nuclei },
      feroxbuster: { ...DEFAULT_TOOL_OPTIONS.feroxbuster },
      ffuf: { ...DEFAULT_TOOL_OPTIONS.ffuf },
    },
    deep: {
      nuclei: {
        profile: "deep",
        severity: "low,medium,high,critical",
        tags: "cve,misconfig,exposure,vuln,default-login",
        exposureTags: "exposure,config,backup,token,key,file",
        concurrency: 30,
        rateLimit: 180,
        timeoutSeconds: 10,
        retries: 1,
        maxDurationSeconds: 240,
      },
      feroxbuster: { depth: 2, threads: 30, timeoutSeconds: 8, maxDurationSeconds: 120 },
      ffuf: { threads: 30, timeoutSeconds: 8, maxDurationSeconds: 120, matchCodes: "200,204,301,302,401,403" },
      naabu: {
        ports: "22,80,443,3306,3389,5432,6379,8080,8443",
        rate: 300,
      },
    },
  };

  const FALLBACK = {
    checks: [...MAX_DETECTION_CHECKS],
    tools: [...MAX_DETECTION_TOOLS],
    reportType: "technical",
    toolOptions: structuredClone(DEFAULT_TOOL_OPTIONS),
  };

  function mergeToolOptions(raw) {
    const base = structuredClone(DEFAULT_TOOL_OPTIONS);
    if (!raw || typeof raw !== "object") return base;
    for (const key of Object.keys(base)) {
      if (raw[key] && typeof raw[key] === "object") {
        base[key] = { ...base[key], ...raw[key] };
      }
    }
    return base;
  }

  function applyDepthProfile(profile, current) {
    const p = PROFILE_PRESETS[profile] || PROFILE_PRESETS.balanced;
    const next = mergeToolOptions(current);
    if (p.nuclei) next.nuclei = { ...next.nuclei, ...p.nuclei };
    if (p.naabu) next.naabu = { ...next.naabu, ...p.naabu };
    if (p.feroxbuster) next.feroxbuster = { ...next.feroxbuster, ...p.feroxbuster };
    if (p.ffuf) next.ffuf = { ...next.ffuf, ...p.ffuf };
    return next;
  }

  function migrateLegacy() {
    try {
      if (localStorage.getItem(STORAGE_KEY)) return;
      const v2 = localStorage.getItem(LEGACY_V2) || localStorage.getItem(LEGACY_V1);
      if (!v2) return;
      const parsed = JSON.parse(v2);
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
            toolOptions: mergeToolOptions(parsed.toolOptions),
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
      if (!raw) {
        return {
          ...FALLBACK,
          checks: [...FALLBACK.checks],
          tools: [...FALLBACK.tools],
          toolOptions: structuredClone(DEFAULT_TOOL_OPTIONS),
        };
      }
      const parsed = JSON.parse(raw);
      return {
        checks: Array.isArray(parsed.checks) && parsed.checks.length ? parsed.checks : [...FALLBACK.checks],
        tools: Array.isArray(parsed.tools) && parsed.tools.length ? parsed.tools : [...FALLBACK.tools],
        reportType: parsed.reportType || FALLBACK.reportType,
        toolOptions: mergeToolOptions(parsed.toolOptions),
        updatedAt: parsed.updatedAt || null,
      };
    } catch {
      return {
        ...FALLBACK,
        checks: [...FALLBACK.checks],
        tools: [...FALLBACK.tools],
        toolOptions: structuredClone(DEFAULT_TOOL_OPTIONS),
      };
    }
  }

  function save(config) {
    const payload = {
      checks: [...new Set(config.checks || [])],
      tools: [...new Set(config.tools || [])],
      reportType: config.reportType || FALLBACK.reportType,
      toolOptions: mergeToolOptions(config.toolOptions),
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
    const profile = config.toolOptions?.nuclei?.profile || "balanced";
    return {
      checkCount: config.checks?.length || 0,
      toolCount: config.tools?.length || 0,
      checkNames,
      reportName: report?.name || config.reportType,
      depthProfile: profile,
      updatedAt: config.updatedAt,
    };
  }

  /** Shape expected by API StartWebsiteScanRequest.toolOptions */
  function toApiToolOptions(toolOptions) {
    const o = mergeToolOptions(toolOptions);
    return {
      nuclei: {
        profile: o.nuclei.profile,
        severity: o.nuclei.severity,
        tags: o.nuclei.tags || null,
        exposureTags: o.nuclei.exposureTags,
        concurrency: Number(o.nuclei.concurrency) || 25,
        rateLimit: Number(o.nuclei.rateLimit) || 150,
        timeoutSeconds: Number(o.nuclei.timeoutSeconds) || 8,
        retries: Number(o.nuclei.retries) || 1,
        maxDurationSeconds: Number(o.nuclei.maxDurationSeconds) || 120,
      },
      naabu: {
        ports: o.naabu.ports,
        rate: Number(o.naabu.rate) || 200,
      },
      feroxbuster: {
        depth: Number(o.feroxbuster.depth) || 0,
        threads: Number(o.feroxbuster.threads) || 20,
        timeoutSeconds: Number(o.feroxbuster.timeoutSeconds) || 5,
        maxDurationSeconds: Number(o.feroxbuster.maxDurationSeconds) || 90,
      },
      ffuf: {
        threads: Number(o.ffuf.threads) || 20,
        timeoutSeconds: Number(o.ffuf.timeoutSeconds) || 5,
        maxDurationSeconds: Number(o.ffuf.maxDurationSeconds) || 90,
        matchCodes: o.ffuf.matchCodes,
      },
    };
  }

  return {
    load,
    save,
    summarize,
    mergeToolOptions,
    applyDepthProfile,
    toApiToolOptions,
    FALLBACK,
    DEFAULT_TOOL_OPTIONS,
    BASELINE_CHECKS,
    BASELINE_TOOLS,
    MAX_DETECTION_CHECKS,
    MAX_DETECTION_TOOLS,
  };
})();
