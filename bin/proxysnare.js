#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const http = require("node:http");
const { createProxySnareServer, compileNaturalLanguage, normalizeMode } = require("../src/index.js");

const pkgVersion = (() => {
  try {
    return require("../package.json").version || "2.0.0";
  } catch {
    return "2.0.0";
  }
})();

function printHelp() {
  console.log(`ProxySnare v${pkgVersion} — HTTP Repeater & Intercepting Proxy Defense (PS_ECDH_V2)

Natural-Language Mode:
  node bin/proxysnare.js ask "block caido and burp repeater on http://localhost:3000 on port 8080"
  node bin/proxysnare.js explain "watch for burp repeater without blocking on http://localhost:3000"

Commands:
  node bin/proxysnare.js protect --target <url> [--port 8080] [--host 127.0.0.1]
                         [--mode strict|balanced|monitor|observe|off] [--paths /api,/auth]
                         [--freshness-ms 8000] [--threshold 4] [--pow-bits 12]
                         [--trust-proxy 127.0.0.1,10.0.0.0/8] [--secret-file <path>]
                         [--no-inject] [--no-debug-headers]
  node bin/proxysnare.js demo [--port 8088] [--host 127.0.0.1] [--mode strict|balanced|monitor|observe|off]
  node bin/proxysnare.js ask|do "<plain English>" [--dry-run] [--json]
  node bin/proxysnare.js explain "<plain English>" [--json]

Environment:
  PROXYSNARE_SECRET      HMAC secret (>= 16 bytes; preferred over --secret argv)
`);
}

function parsePortStrict(raw) {
  const s = String(raw ?? "").trim();
  if (!/^\d{1,5}$/.test(s)) {
    throw new Error(`Invalid --port value '${raw}': expected decimal integer 0-65535`);
  }
  const n = Number(s);
  if (!Number.isInteger(n) || n < 0 || n > 65535) {
    throw new Error(`Invalid --port value '${raw}': expected integer 0-65535`);
  }
  return n;
}

function parsePositiveIntFlag(flag, raw) {
  const s = String(raw ?? "").trim();
  if (!/^\d+$/.test(s)) {
    throw new Error(`Invalid ${flag} value '${raw}': expected a positive integer`);
  }
  const n = Number(s);
  if (!Number.isSafeInteger(n) || n <= 0) {
    throw new Error(`Invalid ${flag} value '${raw}': expected a positive integer`);
  }
  return n;
}

function parseNonNegIntFlag(flag, raw, maxVal = 22) {
  const s = String(raw ?? "").trim();
  if (!/^\d+$/.test(s)) {
    throw new Error(`Invalid ${flag} value '${raw}': expected an integer 0-${maxVal}`);
  }
  const n = Number(s);
  if (!Number.isInteger(n) || n < 0 || n > maxVal) {
    throw new Error(`Invalid ${flag} value '${raw}': expected an integer 0-${maxVal}`);
  }
  return n;
}

function parseFlags(args, { allowPositional = false, allowedFlags = null } = {}) {
  const opts = { positionals: [] };
  const valueFlags = new Set([
    "--target",
    "--port",
    "--host",
    "--mode",
    "--paths",
    "--freshness-ms",
    "--threshold",
    "--pow-bits",
    "--trust-proxy",
    "--secret",
    "--secret-file",
  ]);
  const boolFlags = new Set(["--dry-run", "--json", "--no-inject", "--no-debug-headers"]);
  let endOfFlags = false;

  for (let i = 0; i < args.length; i++) {
    let a = args[i];
    if (!endOfFlags && a === "--") {
      endOfFlags = true;
      continue;
    }
    if (!endOfFlags && (a === "--help" || a === "-h")) {
      opts.help = true;
      return opts;
    }
    if (endOfFlags) {
      if (!allowPositional) throw new Error(`Unexpected argument '${a}'. Run with --help for usage.`);
      opts.positionals.push(a);
      continue;
    }

    let inlineVal = null;
    if (a.startsWith("--") && a.includes("=")) {
      const eq = a.indexOf("=");
      inlineVal = a.slice(eq + 1);
      a = a.slice(0, eq);
    }

    if (boolFlags.has(a)) {
      if (allowedFlags && !allowedFlags.has(a)) {
        throw new Error(`Flag '${a}' is not supported for this command. Run with --help for usage.`);
      }
      if (inlineVal !== null) {
        throw new Error(`Flag '${a}' does not accept a value`);
      }
      if (a === "--dry-run") opts.dryRun = true;
      else if (a === "--json") opts.json = true;
      else if (a === "--no-inject") opts.injectGuard = false;
      else if (a === "--no-debug-headers") opts.exposeDebugHeaders = false;
      continue;
    }

    if (valueFlags.has(a)) {
      if (allowedFlags && !allowedFlags.has(a)) {
        throw new Error(`Flag '${a}' is not supported for this command. Run with --help for usage.`);
      }
      const val = inlineVal !== null ? inlineVal : args[++i];
      if (val === undefined || (inlineVal === null && val.startsWith("--"))) {
        throw new Error(`Flag '${a}' requires a value`);
      }
      if (a === "--target") {
        if (!val.trim()) throw new Error("Flag '--target' cannot be empty");
        opts.target = val.trim();
      } else if (a === "--port") {
        opts.port = parsePortStrict(val);
      } else if (a === "--host") {
        if (!val.trim()) throw new Error("Flag '--host' cannot be empty");
        opts.host = val.trim();
      } else if (a === "--mode") {
        opts.mode = normalizeMode(val);
      } else if (a === "--paths") {
        const list = val.split(",").map((s) => s.trim()).filter(Boolean);
        if (list.length === 0) throw new Error("Flag '--paths' must include at least one route prefix");
        opts.protectedPaths = list;
      } else if (a === "--freshness-ms") {
        opts.freshnessMs = parsePositiveIntFlag("--freshness-ms", val);
      } else if (a === "--threshold") {
        opts.threshold = parsePositiveIntFlag("--threshold", val);
      } else if (a === "--pow-bits") {
        opts.handshakePowBits = parseNonNegIntFlag("--pow-bits", val, 22);
      } else if (a === "--trust-proxy") {
        if (!val.trim()) throw new Error("Flag '--trust-proxy' cannot be empty");
        opts.trustProxy = val.trim();
      } else if (a === "--secret") {
        console.error("[proxysnare] Warning: passing --secret on argv exposes it to process listings; prefer PROXYSNARE_SECRET or --secret-file.");
        opts.secret = val;
      } else if (a === "--secret-file") {
        if (!val.trim()) throw new Error("Flag '--secret-file' cannot be empty");
        opts.secret = fs.readFileSync(val.trim(), "utf8").trim();
      }
      continue;
    }

    if (a.startsWith("-")) {
      throw new Error(`Unknown flag '${a}'. Run with --help to see supported flags.`);
    }
    if (!allowPositional) {
      throw new Error(`Unexpected argument '${a}'. Run with --help for usage.`);
    }
    opts.positionals.push(a);
  }
  return opts;
}

function resolveSecret(cliSecret) {
  if (cliSecret !== undefined) return cliSecret;
  if (typeof process.env.PROXYSNARE_SECRET === "string" && process.env.PROXYSNARE_SECRET.length > 0) {
    return process.env.PROXYSNARE_SECRET;
  }
  return undefined;
}

function attachGracefulShutdown(closers) {
  let closing = false;
  const shutdown = () => {
    if (closing) {
      process.exit(130);
    }
    closing = true;
    const deadline = setTimeout(() => process.exit(0), 3000);
    if (typeof deadline.unref === "function") deadline.unref();
    Promise.all(closers.map((fn) => Promise.resolve().then(fn).catch(() => {}))).finally(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

async function runDemo(port = 8088, mode = "strict", host = "127.0.0.1", quietStdout = false) {
  const safeMode = normalizeMode(mode);
  const backend = http.createServer((req, res) => {
    const pathname = String(req.url || "/").split("?")[0];
    if (pathname === "/api/transfer" && req.method === "POST") {
      const chunks = [];
      let total = 0;
      const MAX_DEMO_BODY = 64 * 1024;
      let aborted = false;
      req.on("error", () => {
        aborted = true;
        if (!res.headersSent) res.destroy();
      });
      req.on("data", (c) => {
        if (aborted) return;
        total += c.length;
        if (total > MAX_DEMO_BODY) {
          aborted = true;
          req.pause();
          const errPayload = JSON.stringify({ ok: false, error: "BODY_TOO_LARGE" });
          res.writeHead(413, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(errPayload) });
          res.end(errPayload);
          return;
        }
        chunks.push(c);
      });
      req.on("end", () => {
        if (aborted) return;
        const body = Buffer.concat(chunks).toString("utf8");
        const payload = JSON.stringify({ ok: true, message: "Authorized browser API call accepted", echo: body });
        res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) });
        res.end(payload);
      });
      return;
    }
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>ProxySnare Live Demo</title></head>
<body style="background:#090d16;color:#e2e8f0;font-family:system-ui;padding:32px;max-width:760px;">
  <h1>ProxySnare Live Repeater Defense Demo (${safeMode})</h1>
  <p>Click the button below from a real browser (passes with <code>score=0</code> over ephemeral <code>PS_ECDH_V2</code>), then capture the POST in <b>Caido</b> or <b>Burp Suite</b>, send it to <b>Repeater</b>, and click Send — ProxySnare blocks it with <code>403 REPEATER_OR_PROXY_BLOCKED</code>.</p>
  <button id="send-btn" style="padding:10px 18px;font-size:16px;cursor:pointer;">Send Signed POST /api/transfer</button>
  <pre id="out" style="margin-top:16px;padding:16px;background:#111827;border-radius:8px;">Ready.</pre>
  <script>
    document.getElementById("send-btn").onclick = async () => {
      const r = await fetch("/api/transfer", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ amount: 42, currency: "USD" }) });
      document.getElementById("out").textContent = r.status + " (X-ProxySnare-Score=" + r.headers.get("X-ProxySnare-Score") + ")\\n" + await r.text();
    };
  </script>
</body></html>`;
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Content-Length": Buffer.byteLength(html) });
    res.end(html);
  });
  await new Promise((resolve, reject) => {
    backend.once("error", reject);
    backend.listen(0, "127.0.0.1", () => {
      backend.removeListener("error", reject);
      resolve();
    });
  });
  const bPort = backend.address().port;
  const closeBackend = () =>
    new Promise((r) => {
      if (typeof backend.closeAllConnections === "function") backend.closeAllConnections();
      backend.close(r);
    });

  let shield;
  let url;
  try {
    shield = createProxySnareServer({
      target: `http://127.0.0.1:${bPort}`,
      mode: safeMode,
      protectedPaths: ["/api"],
      onDetect: (ev) => {
        console.error(
          `[proxysnare] ${ev.blocked ? "BLOCKED" : "FLAGGED"} ${ev.method} ${ev.path} score=${ev.score}/${ev.threshold} reasons=${ev.reasons.map((r) => r.code).join(",")}`
        );
      },
    });
    url = await shield.listen(port, host);
  } catch (err) {
    await closeBackend();
    throw err;
  }
  attachGracefulShutdown([() => shield.close(), closeBackend]);
  if (!quietStdout) {
    console.log(`[proxysnare] Demo active at ${url} (mode=${safeMode}, protected=/api)`);
  }
}

const PROTECT_FLAGS = new Set([
  "--target",
  "--port",
  "--host",
  "--mode",
  "--paths",
  "--freshness-ms",
  "--threshold",
  "--pow-bits",
  "--trust-proxy",
  "--secret",
  "--secret-file",
  "--no-inject",
  "--no-debug-headers",
]);
const DEMO_FLAGS = new Set(["--port", "--host", "--mode"]);
const ASK_FLAGS = new Set([...PROTECT_FLAGS, "--dry-run", "--json"]);
const EXPLAIN_FLAGS = new Set(["--json", "--port", "--mode", "--target", "--paths", "--trust-proxy"]);

async function main() {
  const [, , cmd, ...rest] = process.argv;
  if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") {
    printHelp();
    return;
  }

  if (cmd === "ask" || cmd === "do" || cmd === "explain") {
    const forceDry = cmd === "explain";
    const flags = parseFlags(rest, {
      allowPositional: true,
      allowedFlags: forceDry ? EXPLAIN_FLAGS : ASK_FLAGS,
    });
    if (flags.help) {
      printHelp();
      return;
    }
    const plan = compileNaturalLanguage(flags.positionals.join(" "));
    if (flags.port !== undefined) plan.options.port = flags.port;
    if (flags.mode !== undefined) plan.options.mode = flags.mode;
    if (flags.target !== undefined && plan.intent === "protect") plan.options.target = flags.target;
    if (flags.protectedPaths !== undefined && plan.intent === "protect") plan.options.protectedPaths = flags.protectedPaths;
    if (flags.trustProxy !== undefined && plan.intent === "protect") plan.options.trustProxy = flags.trustProxy;

    const dryRun = forceDry || Boolean(flags.dryRun);
    if (flags.json) {
      console.log(JSON.stringify({ ok: true, dryRun, ...plan }, null, 2));
      if (dryRun) return;
    } else {
      console.log("[proxysnare natural language]");
      console.log(`  You asked: "${plan.input}"`);
      console.log(`  Goal:      ${plan.goal}`);
      console.log(`  Command:   ${plan.command}`);
      console.log("  Why:");
      for (const r of plan.reasons) console.log(`    - ${r}`);
      if (dryRun) {
        console.log('  Mode:      DRY-RUN (run with "node bin/proxysnare.js ask ..." to execute)');
        return;
      }
    }
    if (plan.intent === "demo") {
      await runDemo(plan.options.port, plan.options.mode, flags.host || "127.0.0.1", Boolean(flags.json));
      return;
    }
    const shield = createProxySnareServer({
      ...plan.options,
      freshnessMs: flags.freshnessMs,
      threshold: flags.threshold,
      handshakePowBits: flags.handshakePowBits,
      secret: resolveSecret(flags.secret),
      injectGuard: flags.injectGuard,
      exposeDebugHeaders: flags.exposeDebugHeaders,
      onDetect: (ev) => {
        console.error(
          `[proxysnare] ${ev.blocked ? "BLOCKED" : "FLAGGED"} ${ev.method} ${ev.path} score=${ev.score}/${ev.threshold} reasons=${ev.reasons.map((r) => r.code).join(",")}`
        );
      },
    });
    const url = await shield.listen(plan.options.port, flags.host || "127.0.0.1");
    attachGracefulShutdown([() => shield.close()]);
    if (!flags.json) {
      console.log(`[proxysnare] Shield listening at ${url} -> ${plan.options.target} (mode=${shield.engine.mode})`);
    }
    return;
  }

  if (cmd === "demo") {
    const f = parseFlags(rest, { allowedFlags: DEMO_FLAGS });
    if (f.help) {
      printHelp();
      return;
    }
    await runDemo(f.port ?? 8088, f.mode || "strict", f.host || "127.0.0.1");
    return;
  }

  if (cmd === "protect") {
    const f = parseFlags(rest, { allowedFlags: PROTECT_FLAGS });
    if (f.help) {
      printHelp();
      return;
    }
    if (!f.target) {
      console.error("Missing --target <url> (example: node bin/proxysnare.js protect --target http://127.0.0.1:3000 --port 8080)");
      process.exit(1);
    }
    const shield = createProxySnareServer({
      target: f.target,
      mode: f.mode || "strict",
      protectedPaths: f.protectedPaths || ["/api"],
      freshnessMs: f.freshnessMs,
      threshold: f.threshold,
      handshakePowBits: f.handshakePowBits,
      trustProxy: f.trustProxy,
      secret: resolveSecret(f.secret),
      injectGuard: f.injectGuard,
      exposeDebugHeaders: f.exposeDebugHeaders,
      onDetect: (ev) => {
        console.error(
          `[proxysnare] ${ev.blocked ? "BLOCKED" : "FLAGGED"} ${ev.method} ${ev.path} score=${ev.score}/${ev.threshold} reasons=${ev.reasons.map((r) => r.code).join(",")}`
        );
      },
    });
    const url = await shield.listen(f.port ?? 8080, f.host || "127.0.0.1");
    attachGracefulShutdown([() => shield.close()]);
    console.log(`[proxysnare] Shield active at ${url} -> ${f.target} (mode=${shield.engine.mode})`);
    return;
  }

  console.error(`Unknown command: ${cmd}`);
  printHelp();
  process.exit(1);
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
