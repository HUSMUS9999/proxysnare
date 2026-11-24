"use strict";

function shellQuote(arg) {
  const s = String(arg);
  if (/^[a-zA-Z0-9_./:@=,-]+$/.test(s)) return s;
  return `'${s.replace(/'/g, "'\\''")}'`;
}

function parsePort(val, fallback) {
  const n = Number(val);
  if (!Number.isInteger(n) || n < 1 || n > 65535) return fallback;
  return n;
}

/**
 * Plain-English Natural-Language CLI compiler for beginners (`node bin/proxysnare.js ask "..."`).
 */
function compileNaturalLanguage(sentence) {
  const input = String(sentence || "").trim();
  if (!input) {
    throw new Error('Describe what you want in plain English, e.g.:\n  node bin/proxysnare.js ask "block caido and burp repeater on http://localhost:3000 on port 8080"');
  }
  const low = input.toLowerCase();

  const explicitPortMatch = input.match(/\bport\s+(\d{1,5})\b/i);

  if (/\b(demo|sandbox|try it|playground|example)\b/.test(low) && !/https?:\/\//.test(low)) {
    const demoPort = explicitPortMatch ? parsePort(explicitPortMatch[1], 8088) : 8088;
    return {
      input,
      intent: "demo",
      goal: "Start the interactive ProxySnare local demo (protected app + live Repeater tester)",
      options: { port: demoPort, mode: "strict" },
      command: `node bin/proxysnare.js demo --port ${demoPort}`,
      reasons: ["Spins up a sample web app shielded by ProxySnare so you can test normal browser traffic vs. Caido/Burp Repeater immediately"],
    };
  }

  const urlMatch = input.match(/https?:\/\/[^\s"'`;|&<>]+/i);
  let target = "http://127.0.0.1:3000";
  if (urlMatch) {
    const candidate = urlMatch[0].replace(/[.,;!?]+$/, "");
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
  }

  let listenPort = 8080;
  if (explicitPortMatch) {
    const p = parsePort(explicitPortMatch[1], null);
    if (!p) throw new Error(`Invalid port number '${explicitPortMatch[1]}' (expected 1-65535)`);
    listenPort = p;
  }

  let mode = "strict";
  const reasons = [];
  const negatedMonitor = /\b(?:don'?t|do not|not)\s+(?:just\s+)?(?:monitor|watch|observe)\b/.test(low);
  const explicitMonitor =
    !negatedMonitor &&
    /\b(without blocking|monitor only|log only|watch only|observe only|dry run|monitor mode)\b/.test(low);
  const plainMonitor =
    !negatedMonitor &&
    !/\b(block|deny|stop|prevent|strict)\b/.test(low) &&
    /\b(monitor|watch|observe|audit)\b/.test(low);

  if (explicitMonitor || plainMonitor) {
    mode = "monitor";
    reasons.push("--mode monitor: scores and logs Repeater activity via X-ProxySnare-Score without blocking requests");
  } else if (/\b(balanced|gentle|relaxed|mobile)\b/.test(low)) {
    mode = "balanced";
    reasons.push("--mode balanced: blocks Repeater/proxy replays (score >= 6) with a 15s freshness window");
  } else {
    mode = "strict";
    reasons.push("--mode strict: blocks Repeater & proxy tampering immediately (score >= 4, 8s freshness window, mandatory PoF + rotating canary)");
  }

  // Strip the target URL before extracting route prefixes so words like "caido/burp" or "http/1.1" never match!
  const withoutUrls = input.replace(/https?:\/\/[^\s"'`]+/gi, " ");
  const pathMatches = [...withoutUrls.matchAll(/(?:^|[\s,'"`])(\/[a-z0-9._~/-]+)/gi)]
    .map((m) => m[1].replace(/[.,;!?]+$/, ""))
    .filter((p) => p !== "/" && !p.startsWith("//"));
  const protectedPaths = pathMatches.length > 0 ? [...new Set(pathMatches)] : ["/api"];
  reasons.push(`Protects routes matching ${protectedPaths.join(", ")} and auto-injects /__proxysnare/guard.js into HTML pages`);

  const trustProxy = /\b(nginx|caddy|behind proxy|reverse proxy)\b/.test(low) ? "127.0.0.1" : "";
  if (trustProxy) {
    reasons.push("--trust-proxy 127.0.0.1: trusts X-Forwarded-For appended by your local Nginx/Caddy reverse proxy");
  } else if (/\bcloudflare\b/.test(low)) {
    reasons.push("Behind Cloudflare: pass --trust-proxy <your-ingress-proxy-ip> explicitly so X-Forwarded-For is trusted only from your ingress proxy");
  }

  const cmdParts = [
    "node bin/proxysnare.js protect",
    `--target ${shellQuote(target)}`,
    `--port ${listenPort}`,
    `--mode ${mode}`,
    `--paths ${shellQuote(protectedPaths.join(","))}`,
  ];
  if (trustProxy) cmdParts.push(`--trust-proxy ${trustProxy}`);

  return {
    input,
    intent: "protect",
    goal: `Shield ${target} against Repeater & proxy tampering on http://127.0.0.1:${listenPort}`,
    options: { target, port: listenPort, mode, protectedPaths, trustProxy },
    command: cmdParts.join(" "),
    reasons,
  };
}

module.exports = { compileNaturalLanguage };
