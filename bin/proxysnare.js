#!/usr/bin/env node
"use strict";

const http = require("node:http");
const { createProxySnareServer, compileNaturalLanguage } = require("../src/index.js");

function printHelp() {
  console.log(`ProxySnare v1.0.0 — Detect & Block Caido Repeater, Burp Suite Repeater & Intercepting Proxies

Beginner Natural-Language Mode (Plain English):
  proxysnare ask "block caido and burp repeater on http://localhost:3000 on port 8080"
  proxysnare explain "watch for burp repeater without blocking on http://localhost:3000"

Commands:
  proxysnare protect --target <url> [--port 8080] [--mode strict|balanced|monitor]
                     [--paths /api,/auth] [--freshness-ms 8000] [--trust-proxy 127.0.0.1]
  proxysnare demo [--port 8088] [--mode strict]
  proxysnare ask "<plain English>" [--dry-run] [--json]
  proxysnare explain "<plain English>" [--json]
`);
}

function parseFlags(args) {
  const opts = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--target" && args[i + 1]) opts.target = args[++i];
    else if (a === "--port" && args[i + 1]) opts.port = Number(args[++i]);
    else if (a === "--host" && args[i + 1]) opts.host = args[++i];
    else if (a === "--mode" && args[i + 1]) opts.mode = args[++i];
    else if (a === "--paths" && args[i + 1]) opts.protectedPaths = args[++i].split(",").map((s) => s.trim()).filter(Boolean);
    else if (a === "--freshness-ms" && args[i + 1]) opts.freshnessMs = Number(args[++i]);
    else if (a === "--trust-proxy" && args[i + 1]) opts.trustProxy = args[++i];
    else if (a === "--dry-run") opts.dryRun = true;
    else if (a === "--json") opts.json = true;
  }
  return opts;
}

async function runDemo(port = 8088, mode = "strict") {
  // Spin up an embedded sample target backend
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
  const url = await shield.listen(port, "127.0.0.1");
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
    const flags = parseFlags(rest);
    const words = rest.filter((w) => !["--dry-run", "--json"].includes(w));
    const plan = compileNaturalLanguage(words.join(" "));
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
        console.log('  Mode:      DRY-RUN (run with "proxysnare ask ..." to execute)');
        return;
      }
    }
    if (plan.intent === "demo") {
      await runDemo(plan.options.port, plan.options.mode);
      return;
    }
    const shield = createProxySnareServer({
      ...plan.options,
      onDetect: (ev) => {
        console.log(`[proxysnare] ${ev.blocked ? "BLOCKED" : "FLAGGED"} ${ev.method} ${ev.path} score=${ev.score}/${ev.threshold} reasons=${ev.reasons.map((r) => r.code).join(",")}`);
      },
    });
    const url = await shield.listen(plan.options.port, "127.0.0.1");
    console.log(`[proxysnare] Shield listening at ${url} -> ${plan.options.target} (mode=${plan.options.mode})`);
    return;
  }

  if (cmd === "demo") {
    const f = parseFlags(rest);
    await runDemo(f.port || 8088, f.mode || "strict");
    return;
  }

  if (cmd === "protect") {
    const f = parseFlags(rest);
    if (!f.target) {
      console.error("Missing --target <url> (example: proxysnare protect --target http://127.0.0.1:3000 --port 8080)");
      process.exit(1);
    }
    const shield = createProxySnareServer({
      target: f.target,
      mode: f.mode || "strict",
      protectedPaths: f.protectedPaths || ["/api"],
      freshnessMs: f.freshnessMs,
      trustProxy: f.trustProxy,
      onDetect: (ev) => {
        console.log(`[proxysnare] ${ev.blocked ? "BLOCKED" : "FLAGGED"} ${ev.method} ${ev.path} score=${ev.score}/${ev.threshold} reasons=${ev.reasons.map((r) => r.code).join(",")}`);
      },
    });
    const url = await shield.listen(f.port || 8080, f.host || "127.0.0.1");
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
