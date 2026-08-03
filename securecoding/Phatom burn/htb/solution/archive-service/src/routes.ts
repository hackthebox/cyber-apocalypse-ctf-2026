import express from "express";
import type { ArchiveConfig } from "./config.js";
import { verifyReceipt, type ChainReceipt, type Principal } from "./chainReceipt.js";
import { markConsumed } from "./receiptStore.js";

function principalFromRequest(req: express.Request): Principal {
  return {
    address: String(req.header("x-archive-principal") ?? "0x0000000000000000000000000000000000000000"),
    role: req.header("x-archive-role") === "keeper" ? "keeper" : "visitor"
  };
}

export function routes(config: ArchiveConfig) {
  const router = express.Router();
  router.use(express.json());

  router.get("/", (_req, res) => {
    res.type("html").send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>Archive Gate - The Phantom Burn</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Saira+Condensed:wght@500;600;700&family=Public+Sans:wght@400;500&family=Martian+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      color-scheme: dark;
      --bg: #06080a; --bg-2: #080b0d;
      --panel: rgba(12, 16, 19, .85);
      --line: rgba(150, 168, 176, .13); --line-2: rgba(160, 180, 190, .26);
      --ink: #bcc6ca; --ink-dim: #7b868b; --ink-faint: #515b5a; --salt: #eef3f1;
      --amber: #f0a338; --amber-d: #7a531a;
      --cyan: #6fc9ff; --cyan-d: #23516f;
      --red: #e0644f; --red-l: #ff9c88; --red-d: #7d2a20;
      --green: #4bb98a; --green-l: #8fe3bd; --green-d: #1f5943;
      --f-display: "Space Grotesk", ui-sans-serif, system-ui, sans-serif;
      --f-mono: "Martian Mono", ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
      --f-body: "Public Sans", system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      --f-label: "Saira Condensed", Oswald, ui-sans-serif, sans-serif;
    }
    * { box-sizing: border-box; }
    html { background: var(--bg); }
    body {
      margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 28px;
      font-family: var(--f-body); color: var(--ink); line-height: 1.6;
      background: linear-gradient(180deg, var(--bg) 0%, var(--bg-2) 55%, #090c0d 100%);
      -webkit-font-smoothing: antialiased;
    }
    #fire { position: fixed; left: 0; bottom: 0; width: 100vw; height: 40vh; z-index: 0; pointer-events: none; opacity: .38; mix-blend-mode: screen; filter: blur(1.2px); }
    body::after {
      content: ""; position: fixed; inset: 0; z-index: 0; pointer-events: none;
      background:
        linear-gradient(180deg, rgba(6,8,10,.82), transparent 26%, transparent 66%, rgba(6,8,10,.46)),
        radial-gradient(140% 76% at 50% 114%, transparent 52%, rgba(6,8,10,.6));
    }
    @media (prefers-reduced-motion: reduce) { #fire { opacity: .3; } }

    main {
      position: relative; z-index: 1; width: min(760px, 100%);
      border: 1px solid var(--line); background: var(--panel);
      box-shadow: 0 28px 80px rgba(0, 0, 0, .6);
      padding: clamp(26px, 5vw, 44px);
    }
    main::before, main::after { content: ""; position: absolute; width: 9px; height: 9px; }
    main::before { top: -1px; left: -1px; border-top: 1px solid var(--amber); border-left: 1px solid var(--amber); }
    main::after { bottom: -1px; right: -1px; border-bottom: 1px solid var(--red-d); border-right: 1px solid var(--red-d); }

    a { color: var(--cyan); text-decoration: none; }
    a:hover { color: #a9e0ff; }

    .eyebrow { margin: 0 0 14px; font-family: var(--f-mono); font-size: .74rem; letter-spacing: .02em; color: var(--amber); }
    h1 { margin: 0; font-family: var(--f-display); font-weight: 700; font-size: clamp(2rem, 5.5vw, 3.1rem); line-height: 1; letter-spacing: -.02em; color: var(--salt); }
    p.sub { max-width: 60ch; color: var(--ink-dim); font-size: .97rem; margin: 16px 0 0; }

    .chips { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 26px; }
    .chip { display: inline-flex; align-items: center; gap: 8px; font-family: var(--f-mono); font-size: .72rem; letter-spacing: -.01em; padding: 5px 11px; border: 1px solid var(--line-2); color: var(--ink); background: rgba(6,8,10,.4); }
    .chip .b { width: 6px; height: 6px; }
    .chip--on { color: var(--green-l); border-color: var(--green-d); background: rgba(31,89,67,.18); }
    .chip--on .b { border-radius: 50%; background: var(--green); }
    .chip--sealed { color: var(--red-l); border-color: var(--red-d); background: rgba(125,42,32,.16); }
    .chip--sealed .b { background: var(--red); }
    .chip--cool { color: var(--cyan); border-color: var(--cyan-d); background: rgba(35,81,111,.2); }
    .chip--cool .b { border-radius: 50%; background: var(--cyan); }
    .chip code { font-family: var(--f-mono); color: inherit; }
  </style>
</head>
<body>
  <canvas id="fire" aria-hidden="true"></canvas>
  <main>
    <p class="eyebrow">// lower-vault service</p>
    <h1>Archive Gate</h1>
    <p class="sub">This service accepts archive-open requests from the Phantom Burn runtime and reviews receipt material against the configured chain context before returning a lower-vault grant.</p>
    <div class="chips" aria-label="Service status">
      <span class="chip chip--on"><span class="b"></span>online</span>
      <span class="chip chip--sealed"><span class="b"></span><code>POST /archive/archive/open</code></span>
      <a class="chip chip--cool" href="/app/"><span class="b"></span>back to phantom_burn</a>
    </div>
  </main>
  <script>
  (function () {
    var cv = document.getElementById("fire");
    if (!cv || !cv.getContext) return;
    var ctx = cv.getContext("2d");
    var FW = 220, FH = 108;
    var off = document.createElement("canvas"); off.width = FW; off.height = FH;
    var octx = off.getContext("2d");
    var img = octx.createImageData(FW, FH);
    var fire = new Uint8Array(FW * FH);
    var stops = [[6,8,10],[59,14,11],[122,30,23],[166,48,31],[214,83,66],[230,108,47],[241,154,44],[246,184,74],[251,214,122],[255,243,201],[255,247,231],[234,244,255],[216,236,255]];
    var N = 37, pal = [];
    for (var i = 0; i < N; i++) {
      var t = i / (N - 1) * (stops.length - 1);
      var a = Math.floor(t), b = Math.min(a + 1, stops.length - 1), f = t - a;
      pal.push([(stops[a][0]+(stops[b][0]-stops[a][0])*f)|0,(stops[a][1]+(stops[b][1]-stops[a][1])*f)|0,(stops[a][2]+(stops[b][2]-stops[a][2])*f)|0, i===0?0:Math.min(230,14+i*9)]);
    }
    for (var x = 0; x < FW; x++) fire[(FH - 1) * FW + x] = N - 1;
    function spread() {
      for (var x = 0; x < FW; x++) for (var y = 1; y < FH; y++) {
        var from = y * FW + x, v = fire[from];
        if (v === 0) { fire[from - FW] = 0; continue; }
        var rand = (Math.random() * 3) | 0, to = from - FW - rand + 1;
        if (to >= 0) fire[to] = v - (rand & 1);
      }
    }
    function render() {
      var d = img.data;
      for (var i = 0; i < FW * FH; i++) { var c = pal[fire[i]], j = i * 4; d[j]=c[0]; d[j+1]=c[1]; d[j+2]=c[2]; d[j+3]=c[3]; }
      octx.putImageData(img, 0, 0);
      ctx.clearRect(0, 0, cv.width, cv.height);
      ctx.imageSmoothingEnabled = true;
      ctx.drawImage(off, 0, 0, FW, FH, 0, 0, cv.width, cv.height);
    }
    function size() { cv.width = Math.max(320, window.innerWidth); cv.height = Math.max(180, Math.round(window.innerHeight * 0.40)); }
    size();
    window.addEventListener("resize", size, { passive: true });
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) { for (var k = 0; k < 90; k++) spread(); render(); }
    else { var last = 0; (function frame(now){ if (now - last > 40) { spread(); render(); last = now; } requestAnimationFrame(frame); })(0); }
  })();
  </script>
</body>
</html>`);
  });

  router.post("/archive/open", async (req, res, next) => {
    try {
      const principal = principalFromRequest(req);
      const receipt = req.body.receipt as ChainReceipt;
      const verdict = await verifyReceipt(config, principal, receipt);
      if (!verdict.ok) {
        res.status(403).json({ error: verdict.reason });
        return;
      }

      // The grant is bound to the shard proven by the verified log. A caller may
      // name a target shard, but it is only a locator: it must equal the shard
      // decoded from the on-chain event, and it never overrides it.
      if (receipt.shardId && receipt.shardId.toLowerCase() !== verdict.shardId.toLowerCase()) {
        res.status(403).json({ error: "shard does not match verified filing" });
        return;
      }

      if (!markConsumed(verdict.receiptId)) {
        res.status(409).json({ error: "receipt already consumed" });
        return;
      }

      // Every value returned to the caller comes from the verified event, not
      // from the submitted receipt.
      res.json({
        opened: true,
        shardId: verdict.shardId,
        owner: verdict.owner,
        archive: "crown-source-ledger",
        grants: ["source:read", "decree:audit"]
      });
    } catch (error) {
      next(error);
    }
  });

  return router;
}
