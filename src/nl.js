"use strict";

/**
 * Plain-English Natural-Language CLI compiler for beginners (`proxysnare ask "..."`).
 */
function compileNaturalLanguage(sentence) {
  const input = String(sentence || "").trim();
  if (!input) {
    throw new Error('Describe what you want in plain English, e.g.:\n  proxysnare ask "block caido and burp repeater on http://localhost:3000 on port 8080"');
  }
  const low = input.toLowerCase();

  if (/\b(demo|sandbox|try it|playground|example)\b/.test(low) && !/https?:\/\//.test(low)) {
    return {
      input,
      intent: "demo",
      goal: "Start the interactive ProxySnare local demo (protected app + live Repeater tester)",
      options: { port: 8088, mode: "strict" },
      command: "proxysnare demo --port 8088",
      reasons: ["Spins up a sample web app shielded by ProxySnare so you can test normal browser traffic vs. Caido/Burp Repeater immediately"],
    };
  }

  const urlMatch = input.match(/https?:\/\/[^\s"'`]+/i);
  const target = urlMatch ? urlMatch[0].replace(/[.,;!?]+$/, "") : "http://127.0.0.1:3000";

  const portMatch = input.match(/(?:\b(?:on|at)\s+port\s+|\bport\s+|:)(\d{2,5})\b/i);
  let listenPort = 8080;
  if (portMatch) {
    const p = Number(portMatch[1]);
    // Avoid picking the target URL's own port unless it's explicitly prefixed with "port "
    if (!urlMatch || !urlMatch[0].includes(`:${p}`) || /\bport\s+\d+/.test(portMatch[0])) {
      listenPort = p;
    }
  }
  const explicitPort = input.match(/\bport\s+(\d{2,5})\b/i);
  if (explicitPort) listenPort = Number(explicitPort[1]);

  let mode = "strict";
  const reasons = [];
  if (/\b(monitor|watch|log only|observe|without blocking|dry|audit)\b/.test(low)) {
    mode = "monitor";
    reasons.push("--mode monitor: scores and logs Caido/Burp Repeater activity via X-ProxySnare-Score without blocking requests");
  } else if (/\b(balanced|gentle|relaxed)\b/.test(low)) {
    mode = "balanced";
    reasons.push("--mode balanced: blocks clear Repeater/proxy replays (score >= 6) with a generous 15s freshness window");
  } else {
    mode = "strict";
    reasons.push("--mode strict: blocks Caido Repeater, Burp Repeater, and mitmproxy tampering immediately (score >= 4, 8s freshness window, mandatory PoF + rotating canary)");
  }

  const pathMatches = [...input.matchAll(/(\/[a-z0-9_/-]+)/gi)]
    .map((m) => m[1])
    .filter((p) => !urlMatch || !urlMatch[0].endsWith(p))
    .filter((p) => p !== "/" && !p.startsWith("//"));
  const protectedPaths = pathMatches.length > 0 ? [...new Set(pathMatches)] : ["/api"];
  reasons.push(`Protects routes matching ${protectedPaths.join(", ")} and auto-injects /__proxysnare/guard.js into HTML pages`);

  const trustProxy = /\b(nginx|caddy|cloudflare|behind proxy|reverse proxy)\b/.test(low) ? "127.0.0.1" : "";
  if (trustProxy) {
    reasons.push("--trust-proxy 127.0.0.1: trusts X-Forwarded-For from your upstream reverse proxy");
  }

  const cmdParts = [
    "proxysnare protect",
    `--target ${target}`,
    `--port ${listenPort}`,
    `--mode ${mode}`,
    `--paths ${protectedPaths.join(",")}`,
  ];
  if (trustProxy) cmdParts.push(`--trust-proxy ${trustProxy}`);

  return {
    input,
    intent: "protect",
    goal: `Shield ${target} against Caido/Burp Repeater & proxy tampering on http://127.0.0.1:${listenPort}`,
    options: { target, port: listenPort, mode, protectedPaths, trustProxy },
    command: cmdParts.join(" "),
    reasons,
  };
}

module.exports = { compileNaturalLanguage };
