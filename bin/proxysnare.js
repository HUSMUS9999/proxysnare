#!/usr/bin/env node
"use strict";

const http = require("node:http");
const { createProxySnareServer, compileNaturalLanguage } = require("../src/index.js");

function printHelp() {
  console.log(`ProxySnare v1.0.0 — HTTP Repeater & Intercepting Proxy Defense

Natural-Language Mode:
  node bin/proxysnare.js ask "block caido and burp repeater on http://localhost:3000 on port 8080"
  node bin/proxysnare.js explain "watch for burp repeater without blocking on http://localhost:3000"

Commands:
  node bin/proxysnare.js protect --target <url> [--port 8080] [--host 127.0.0.1]
                         [--mode strict|balanced|monitor|off] [--paths /api,/auth]
                         [--freshness-ms 8000] [--threshold 4] [--trust-proxy 127.0.0.1]
                         [--no-inject] [--no-debug-headers]
  node bin/proxysnare.js demo [--port 8088] [--host 127.0.0.1] [--mode strict]
  node bin/proxysnare.js ask "<plain English>" [--dry-run] [--json]
  node bin/proxysnare.js explain "<plain English>" [--json]
`);
}

function parsePortStrict(raw) {
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0 || n > 65535) {
    throw new Error(`Invalid --port value '${raw}': expected integer 0-65535`);
  }
  return n;
}

function parseFlags(args, { allowPositional = false } = {}) {
  const opts = { positionals: [] };
  const valueFlags = new Set(["--target", "--port", "--host", "--mode", "--paths", "--freshness-ms", "--threshold", "--trust-proxy", "--secret"]);
  const boolFlags = new Set(["--dry-run", "--json", "--no-inject", "--no-debug-headers"]);

  for (let i = 0; i < args.length; i++) {
    let a = args[i];
    let inlineVal = null;
    if (a.startsWith("--") && a.includes("=")) {
      const eq = a.indexOf("=");
      inlineVal = a.slice(eq + 1);
      a = a.slice(0, eq);
    }

    if (boolFlags.has(a)) {
      if (a === "--dry-run") opts.dryRun = true;
      else if (a === "--json") opts.json = true;
      else if (a === "--no-inject") opts.injectGuard = false;
      else if (a === "--no-debug-headers") opts.exposeDebugHeaders = false;
      continue;
    }

    if (valueFlags.has(a)) {
      const val = inlineVal !== null ? inlineVal : args[++i];
      if (val === undefined || (inlineVal === null && val.startsWith("--"))) {
        throw new Error(`Flag '${a}' requires a value`);
      }
      if (a === "--target") opts.target = val;
      else if (a === "--port") opts.port = parsePortStrict(val);
      else if (a === "--host") opts.host = val;
      else if (a === "--mode") opts.mode = val;
      else if (a === "--paths") opts.protectedPaths = val.split(",").map((s) => s.trim()).filter(Boolean);
      else if (a === "--freshness-ms") opts.freshnessMs = Number(val);
      else if (a === "--threshold") opts.threshold = Number(val);
      else if (a === "--trust-proxy") opts.trustProxy = val;
      else if (a === "--secret") opts.secret = val;
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

function attachGracefulShutdown(closers) {
  let closing = false;
  const shutdown = () => {
    if (closing) return;
    closing = true;
    Promise.all(closers.map((fn) => Promise.resolve().then(fn).catch(() => {}))).finally(() => process.exit(0));
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

async function runDemo(port = 8088, mode = "strict", host = "127.0.0.1") {
  const backend = http.createServer((req, res) => {
    if (req.url === "/api/transfer" && req.method === "POST") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const payload = JSON.stringify({ ok: true, message: "Authorized browser API call accepted", echo: body });
        res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) });
        res.end(payload);
      });
      return;
    }
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>ProxySnare Live Demo</title></head>
<body style="background:#090d16;color:#e2e8f0;font-family:system-ui;padding:32px;max-width:760px;">
  <h1>ProxySnare Live Repeater Defense Demo</h1>
  <p>Click the button below from a real browser (passes with <code>score=0</code>), then capture the POST in <b>Caido</b> or <b>Burp Suite</b>, send it to <b>Repeater</b>, and click Send — ProxySnare blocks it with <code>403 REPEATER_OR_PROXY_BLOCKED</code>.</p>
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
  await new Promise((r) => backend.listen(0, "127.0.0.1", r));
  const bPort = backend.address().port;

  const shield = createProxySnareServer({
    target: `http://127.0.0.1:${bPort}`,
    mode,
    protectedPaths: ["/api"],
    onDetect: (ev) => {
      console.log(`[proxysnare] ${ev.blocked ? "BLOCKED" : "FLAGGED"} ${ev.method} ${ev.path} score=${ev.score}/${ev.threshold} reasons=${ev.reasons.map((r) => r.code).join(",")}`);
    },
  });
  const url = await shield.listen(port, host);
  attachGracefulShutdown([() => shield.close(), () => new Promise((r) => backend.close(r))]);
  console.log(`[proxysnare] Demo active at ${url} (mode=${mode}, protected=/api)`);
}

async function main() {
  const [, , cmd, ...rest] = process.argv;
  if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") {
    printHelp();
    return;
  }

  if (cmd === "ask" || cmd === "do" || cmd === "explain") {
    const forceDry = cmd === "explain";
    const flags = parseFlags(rest, { allowPositional: true });
    const plan = compileNaturalLanguage(flags.positionals.join(" "));
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
      await runDemo(flags.port ?? plan.options.port, flags.mode || plan.options.mode, flags.host || "127.0.0.1");
      return;
    }
    const shield = createProxySnareServer({
      ...plan.options,
      injectGuard: flags.injectGuard,
      exposeDebugHeaders: flags.exposeDebugHeaders,
      onDetect: (ev) => {
        console.log(`[proxysnare] ${ev.blocked ? "BLOCKED" : "FLAGGED"} ${ev.method} ${ev.path} score=${ev.score}/${ev.threshold} reasons=${ev.reasons.map((r) => r.code).join(",")}`);
      },
    });
    const url = await shield.listen(flags.port ?? plan.options.port, flags.host || "127.0.0.1");
    attachGracefulShutdown([() => shield.close()]);
    console.log(`[proxysnare] Shield listening at ${url} -> ${plan.options.target} (mode=${plan.options.mode})`);
    return;
  }

  if (cmd === "demo") {
    const f = parseFlags(rest);
    await runDemo(f.port ?? 8088, f.mode || "strict", f.host || "127.0.0.1");
    return;
  }

  if (cmd === "protect") {
    const f = parseFlags(rest);
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
      trustProxy: f.trustProxy,
      secret: f.secret,
      injectGuard: f.injectGuard,
      exposeDebugHeaders: f.exposeDebugHeaders,
      onDetect: (ev) => {
        console.log(`[proxysnare] ${ev.blocked ? "BLOCKED" : "FLAGGED"} ${ev.method} ${ev.path} score=${ev.score}/${ev.threshold} reasons=${ev.reasons.map((r) => r.code).join(",")}`);
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
