"use strict";

function shellQuote(arg) {
  const s = String(arg);
  if (/^[a-zA-Z0-9_./:@=,-]+$/.test(s)) return s;
  return `'${s.replace(/'/g, "'\\''")}'`;
}

function parsePort(val, fallback) {
  const raw = String(val || "").trim();
  if (!/^\d+$/.test(raw)) return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 65535) return fallback;
  return n;
}

function detectMode(low) {
  const negatedMonitor = /\b(?:don'?t|do not|not|never)\s+(?:just\s+)?(?:monitor|watch|observe|audit)\b/.test(low);
  const negatedBlock = /\b(?:don'?t|do not|never|no|without)\s+block(?:ing)?\b/.test(low);
  const explicitMonitor =
    !negatedMonitor &&
    (negatedBlock ||
      /\b(without blocking|monitor only|log only|watch only|observe only|audit only|dry run|(?:monitor|observe|audit|watch|passive|shadow)\s+mode)\b/.test(
        low
      ));
  const plainMonitor =
    !negatedMonitor &&
    !/\b(block|deny|stop|prevent|strict|balanced|gentle|relaxed|mobile)\b/.test(low) &&
    /\b(monitor(?:ing)?|watch(?:ing)?|observ(?:e|ing)|audit(?:ing)?)\b/.test(low);

  if (explicitMonitor || plainMonitor) return "monitor";
  if (/\b(balanced|gentle|relaxed|mobile)\b/.test(low)) return "balanced";
  const offPattern = /\b(mode[\s=]+off|(?:turn off|disable)\s+(?:proxysnare|protection|blocking|shield|defense))\b/g;
  const strippedOff = low
    .replace(/\b(?:don'?t|do not|never)\s+block(?:ing)?\b/g, "")
    .replace(offPattern, "");
  if (offPattern.test(low) && !/\b(block|protect|shield)\b/.test(strippedOff)) {
    return "off";
  }
  return "strict";
}

/**
 * Plain-English Natural-Language CLI compiler for beginners (`node bin/proxysnare.js ask "..."`).
 */
function compileNaturalLanguage(sentence) {
  const input = String(sentence || "").trim();
  if (!input) {
    throw new Error(
      'Describe what you want in plain English, e.g.:\n  node bin/proxysnare.js ask "block caido and burp repeater on http://localhost:3000 on port 8080"'
    );
  }
  const low = input.toLowerCase();

  const explicitPortMatch = input.match(/\bport\s*[:=]?\s*(\d+)\b/i);
  const mode = detectMode(low);

  // Detect explicit URLs (any scheme so ftp:// or ws:// triggers an explicit error instead of silent fallback)
  const schemeUrlMatch = input.match(/[a-z][a-z0-9+.-]*:\/\/[^\s"'`;|&<>()[\]]+/i);
  const bareLocalMatch = !schemeUrlMatch
    ? input.match(/\b(localhost|127\.0\.0\.1):(\d{1,5})(?:\/[^\s"'`;|&<>()[\]]*)?\b/i)
    : null;

  // Avoid mistaking "/demo" path or "example.com" domain for demo intent
  const hasDemoWord =
    /(?:^|[\s,'"`(])(?:demo|sandbox|try it|playground)\b/i.test(low) ||
    (/\bexample\b/i.test(low) && !/\bexample\.(?:com|org|net|io|dev|local)\b/i.test(low));

  if (hasDemoWord && !schemeUrlMatch && !bareLocalMatch) {
    let demoPort = 8088;
    if (explicitPortMatch) {
      const p = parsePort(explicitPortMatch[1], null);
      if (!p) throw new Error(`Invalid port number '${explicitPortMatch[1]}' (expected 1-65535)`);
      demoPort = p;
    }
    return {
      input,
      intent: "demo",
      goal: `Start the interactive ProxySnare local demo (${mode} mode)`,
      options: { port: demoPort, mode },
      command: `node bin/proxysnare.js demo --port ${demoPort} --mode ${mode}`,
      reasons: [
        "Spins up a sample web app shielded by ProxySnare (PS_ECDH_V2 + PoW + rotating canary) so you can test normal browser traffic vs. curl and Caido/Burp Repeater immediately",
      ],
    };
  }

  let target = "http://127.0.0.1:3000";
  if (schemeUrlMatch) {
    const candidate = schemeUrlMatch[0].replace(/[.,;!?)\]:]+$/, "");
    let parsed;
    try {
      parsed = new URL(candidate);
    } catch {
      throw new Error(`Invalid target URL in prompt: '${candidate}'`);
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error(`Unsupported URL scheme '${parsed.protocol}': expected http:// or https://`);
    }
    target = parsed.toString().replace(/\/$/, "");
  } else if (bareLocalMatch) {
    const candidate = `http://${bareLocalMatch[0].replace(/[.,;!?)\]:]+$/, "")}`;
    let parsed;
    try {
      parsed = new URL(candidate);
    } catch {
      throw new Error(`Invalid target URL in prompt: '${bareLocalMatch[0]}'`);
    }
    target = parsed.toString().replace(/\/$/, "");
  }

  let listenPort = 8080;
  if (explicitPortMatch) {
    const p = parsePort(explicitPortMatch[1], null);
    if (!p) throw new Error(`Invalid port number '${explicitPortMatch[1]}' (expected 1-65535)`);
    listenPort = p;
  }

  const reasons = [];
  if (mode === "monitor") {
    reasons.push("--mode monitor: scores and logs Repeater activity via X-ProxySnare-Score without blocking requests");
  } else if (mode === "balanced") {
    reasons.push("--mode balanced: blocks Repeater/proxy replays (score >= 6) with a 15s freshness window and ECDH + PoW handshake");
  } else if (mode === "off") {
    reasons.push("--mode off: disables blocking for local development");
  } else {
    reasons.push("--mode strict: blocks curl & Repeater immediately (score >= 4, 8s freshness window, PS_ECDH_V2 + PoW + rotating canary)");
  }

  const withoutUrls = input
    .replace(/[a-z][a-z0-9+.-]*:\/\/[^\s"'`,;|<>()[\]]+/gi, " ")
    .replace(/\b(?:localhost|127\.0\.0\.1):\d{1,5}(?:\/[^\s"'`,;|<>()[\]]*)?/gi, " ");
  const wantsAllRoutes =
    /\b(all routes|all paths|entire site|every route|everything)\b/.test(low) ||
    /(?:^|[\s,'"`(\[])(\/|\*)(?=$|[\s,.)\]])/.test(withoutUrls);
  const pathMatches = [...withoutUrls.matchAll(/(?:^|[\s,'"`(\[])(\/[a-z0-9._~/-]+)/gi)]
    .map((m) => m[1].replace(/[.,;!?)\]]+$/, ""))
    .filter((p) => p !== "/" && !p.startsWith("//"));
  const protectedPaths = pathMatches.length > 0 ? [...new Set(pathMatches)] : ["/api"];
  if (wantsAllRoutes && pathMatches.length === 0) {
    reasons.push("Defaulted protected API prefix to /api so initial HTML pages can load /__proxysnare/guard.js (pass --paths '*' explicitly for API-only deployments with --no-inject)");
  } else {
    reasons.push(`Protects routes matching ${protectedPaths.join(", ")} and auto-injects /__proxysnare/guard.js into HTML pages`);
  }

  const negatedProxy =
    /\b(?:no|not|without)\s+(?:behind\s+)?(?:a\s+)?(?:nginx|caddy|haproxy|traefik|envoy|(?:reverse\s+)?proxy)\b|\bblock(?:ing)?\s+(?:a\s+)?(?:nginx|caddy|haproxy|traefik|envoy|reverse\s+proxy)\b/.test(
      low
    );
  const explicitProxyMatch = !negatedProxy
    ? input.match(/\b(?:trust[- ]proxy|behind\s+(?:nginx|caddy|haproxy|traefik|envoy|(?:a\s+)?(?:reverse\s+)?proxy)(?:\s+(?:at|on|ip))?)\s+((?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.]*)(?:\/\d{1,3})?)(?=$|[\s,.)\]])/i)
    : null;
  let trustProxy = "";
  if (explicitProxyMatch) {
    trustProxy = explicitProxyMatch[1];
    reasons.push(`--trust-proxy ${trustProxy}: trusts X-Forwarded-For appended by your configured ingress proxy`);
  } else if (!negatedProxy && /\b(behind\s+(?:a\s+)?(?:reverse\s+)?proxy|nginx|caddy|haproxy|traefik|envoy)\b/.test(low)) {
    trustProxy = "127.0.0.1";
    reasons.push("--trust-proxy 127.0.0.1: trusts X-Forwarded-For appended by your local reverse proxy");
  }
  if (/\bcloudflare\b/.test(low)) {
    reasons.push("Behind Cloudflare: pass --trust-proxy <your-ingress-proxy-ip-or-cidr> explicitly so X-Forwarded-For is trusted only from your ingress proxy");
  }

  const cmdParts = [
    "node bin/proxysnare.js protect",
    `--target ${shellQuote(target)}`,
    `--port ${listenPort}`,
    `--mode ${mode}`,
    `--paths ${shellQuote(protectedPaths.join(","))}`,
  ];
  if (trustProxy) cmdParts.push(`--trust-proxy ${shellQuote(trustProxy)}`);

  return {
    input,
    intent: "protect",
    goal: `Shield ${target} against curl & Repeater tampering on http://127.0.0.1:${listenPort}`,
    options: { target, port: listenPort, mode, protectedPaths, trustProxy },
    command: cmdParts.join(" "),
    reasons,
  };
}

module.exports = { compileNaturalLanguage };
