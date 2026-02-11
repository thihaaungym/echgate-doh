// ===================== ECHGate :: DoH DNS Console (Worker + KV GET Toggle + Health HTML/JSON (single endpoint) + DPI Badge+Sound + Public/Admin Health + Security Harden) =====================
//
// PUBLIC:
//  - /dns-query            (AUTO fallback)      GET ?dns=  | POST application/dns-message | HEAD (204)
//  - /dns-query/cf         (Cloudflare only)    GET/POST/HEAD
//  - /dns-query/cf-sec     (CF Security only)  GET/POST/HEAD
//  - /dns-query/gg         (Google only)       GET/POST/HEAD
//  - /health               Single endpoint:
//                          - Browser (Accept: text/html) => HTML
//                          - curl/clients (default)      => JSON (public-safe)
//                          - Admin full JSON: /health?admin=1 AND (logged-in cookie OR x-ech-admin-key header)
//
// UI (login required):
//  - /                     console
//  - /login  POST
//  - /logout
//  - /api/status
//  - /api/echrr
//  - /api/config           GET/POST (KV) allow_get on/off
//
// Bindings:
//  - KV   (KV namespace binding name must be exactly "KV")
//
// Secrets:
//  - UI_USER
//  - UI_PASS
//  - ADMIN_KEY   (optional)  -> allow /health?admin=1 JSON full detail if header matches
//
// Notes:
//  - DoH endpoints are public.
//  - GET can be toggled from UI and persisted in KV.
//  - /health JSON is PUBLIC by default; admin details only when authed or valid admin key.
//  - /health HTML shows GET toggle switch when authed.
//  - DPI indicator is heuristic (best-effort).
//  - Security harden: CSP + nosniff + frame deny + origin check on POST /api/config

const VERSION = "2026.02.10-health-single-endpoint-sec";

// ---- DPI-friendly timeouts (ms) ----
const UPSTREAM_TIMEOUT_MS = 2200;
const PROBE_TIMEOUT_MS = 1400;
const MAX_COOLDOWN_MS = 60000;

// ---- Slow threshold (ms) ----
const SLOW_MS_THRESHOLD = 900;

// ---- Default GET policy (when KV empty/unbound) ----
const DEFAULT_ALLOW_GET = true;

// ---- DPI indicator thresholds (heuristic) ----
const DPI_SLOW_RATIO_WARN = 0.15;     // >= 15% slow in last 60s
const DPI_SLOW_RATIO_BAD  = 0.30;     // >= 30% slow
const DPI_ERR_RATIO_WARN  = 0.03;     // >= 3% err
const DPI_ERR_RATIO_BAD   = 0.08;     // >= 8% err
const DPI_PROBE_JUMP_MS   = 600;      // probe latency jump suggests throttling/routing change
const DPI_EWMA_BAD_MS     = 900;      // ewma above this is suspicious

// Upstreams
const UPSTREAMS = [
  { tag: "cf",     url: "https://cloudflare-dns.com/dns-query" },
  { tag: "cf-sec", url: "https://security.cloudflare-dns.com/dns-query" },
  { tag: "gg",     url: "https://dns.google/dns-query" },
];

// Probe wire: example.com A
const PROBE_WIRE = Uint8Array.from(
  atob("AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE="),
  c => c.charCodeAt(0)
);

// in-memory config cache (reduce KV reads)
let _cfgCache = { at: 0, allowGet: DEFAULT_ALLOW_GET, kvBound: false };

async function getAllowGet(env) {
  const now = Date.now();
  if (now - _cfgCache.at < 5000) return _cfgCache.allowGet; // 5s cache

  const kvBound = !!env.KV;
  if (!kvBound) {
    _cfgCache = { at: now, allowGet: DEFAULT_ALLOW_GET, kvBound: false };
    return _cfgCache.allowGet;
  }

  const v = await env.KV.get("cfg:allow_get");
  const allow = (v === null) ? DEFAULT_ALLOW_GET : (v === "1");
  _cfgCache = { at: now, allowGet: allow, kvBound: true };
  return allow;
}

async function setAllowGet(env, allow) {
  if (!env.KV) throw new Error("KV not bound");
  await env.KV.put("cfg:allow_get", allow ? "1" : "0");
  _cfgCache = { at: Date.now(), allowGet: !!allow, kvBound: true };
}

function isAuthedFromCookie(req) {
  const cookie = req.headers.get("cookie") || "";
  return cookie.includes("echgate=1");
}

function isAdmin(req, env, isAuthed) {
  // Admin if logged-in OR valid admin key header
  const key = (req.headers.get("x-ech-admin-key") || "").trim();
  const hasKey = typeof env.ADMIN_KEY === "string" && env.ADMIN_KEY.length >= 8;
  if (isAuthed) return true;
  if (hasKey && key && key === env.ADMIN_KEY) return true;
  return false;
}

// ---------- security headers ----------
function secHeaders(extra = {}) {
  return {
    ...extra,
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "permissions-policy": "geolocation=(), microphone=(), camera=()",
    // Inline scripts/styles are used in UI/health; keep tight otherwise.
    "content-security-policy":
      "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  };
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;

    const NO_CACHE = {
      "cache-control": "no-store, no-cache, must-revalidate",
      "pragma": "no-cache",
      "expires": "0",
    };

    const isAuthed = isAuthedFromCookie(req);
    const isAdminMode = isAdmin(req, env, isAuthed);

    const authOK = (u, p) =>
      typeof env.UI_USER === "string" &&
      typeof env.UI_PASS === "string" &&
      u === env.UI_USER &&
      p === env.UI_PASS;

    const setAuthCookie = () =>
      "echgate=1; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=43200";
    const clearAuthCookie = () =>
      "echgate=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";

    // state
    if (!globalThis.__ECH_STATE__) globalThis.__ECH_STATE__ = makeState();
    const S = globalThis.__ECH_STATE__;

    // health (single endpoint): HTML when browser, JSON otherwise
    if (path === "/health") {
      const allowGet = await getAllowGet(env);
      const probe = await getProbeSnapshot(S);
      const dpi = computeDpiIndicator(S, probe);

      const accept = (req.headers.get("accept") || "").toLowerCase();
      const wantHtml = accept.includes("text/html"); // ✅ single endpoint (no ?html=1)

      const full = (url.searchParams.get("admin") === "1") && isAdminMode; // admin details only
      const payload = buildHealthJson(req, env, url, S, probe, allowGet, dpi, full, isAuthed, isAdminMode);

      if (wantHtml) {
        return new Response(renderHealthHTML(payload), {
          status: 200,
          headers: secHeaders({ ...NO_CACHE, "content-type": "text/html; charset=utf-8" }),
        });
      }

      return new Response(JSON.stringify(payload), {
        status: 200,
        headers: secHeaders({ ...NO_CACHE, "content-type": "application/json; charset=utf-8" }),
      });
    }

    // DoH (public)
    if (path.startsWith("/dns-query")) {
      const allowGet = await getAllowGet(env);
      const pin = parsePinned(path);
      return handleDoH(req, url, S, secHeaders(NO_CACHE), pin, allowGet);
    }

    // login
    if (path === "/login" && req.method.toUpperCase() === "POST") {
      const form = await req.formData();
      const u = String(form.get("u") || "");
      const p = String(form.get("p") || "");
      if (authOK(u, p)) {
        return new Response("ok", {
          status: 200,
          headers: secHeaders({ ...NO_CACHE, "set-cookie": setAuthCookie() })
        });
      }
      return new Response("denied", { status: 401, headers: secHeaders(NO_CACHE) });
    }

    if (path === "/logout") {
      return new Response("bye", {
        status: 200,
        headers: secHeaders({ ...NO_CACHE, "set-cookie": clearAuthCookie() })
      });
    }

    // UI APIs
    if (path === "/api/status") {
      if (!isAuthed) return new Response("forbidden", { status: 403, headers: secHeaders(NO_CACHE) });

      decayPulse(S);
      const now = Date.now();
      const probe = await getProbeSnapshot(S);
      const dpi = computeDpiIndicator(S, probe);

      return new Response(JSON.stringify({
        ok: true,
        version: VERSION,
        origin: url.origin,
        uptime_s: Math.floor((now - S.start) / 1000),
        counters: { ok: S.ok, err: S.err, slow: S.slow, get: S.get, post: S.post },
        slow_threshold_ms: SLOW_MS_THRESHOLD,
        series: S.series,
        err_series: S.errSeries,
        slow_series: S.slowSeries,
        pulse: S.pulse,
        dpi,
        upstreams: Object.entries(S.ups).map(([tag, v]) => ({
          tag,
          ewma_ms: v.ewma,
          fails: v.fails,
          cooldown_s: v.cdUntil > now ? Math.ceil((v.cdUntil - now) / 1000) : 0,
          state: v.cdUntil > now ? "COOLDOWN" : "READY",
        })),
        last: S.last,
      }), {
        status: 200,
        headers: secHeaders({ ...NO_CACHE, "content-type": "application/json; charset=utf-8" })
      });
    }

    if (path === "/api/config") {
      if (!isAuthed) return new Response("forbidden", { status: 403, headers: secHeaders(NO_CACHE) });

      if (req.method.toUpperCase() === "GET") {
        const allowGet = await getAllowGet(env);
        return new Response(JSON.stringify({
          ok: true,
          allow_get: allowGet,
          kv_bound: !!env.KV,
          default_allow_get: DEFAULT_ALLOW_GET
        }), {
          status: 200,
          headers: secHeaders({ ...NO_CACHE, "content-type": "application/json; charset=utf-8" })
        });
      }

      if (req.method.toUpperCase() === "POST") {
        // CSRF harden: origin check
        const origin = req.headers.get("origin") || "";
        if (origin && origin !== url.origin) {
          return new Response("forbidden", { status: 403, headers: secHeaders(NO_CACHE) });
        }

        const ct = (req.headers.get("content-type") || "").toLowerCase();
        if (!ct.includes("application/json")) return new Response("Unsupported Media Type", { status: 415, headers: secHeaders(NO_CACHE) });
        try {
          const body = await req.json();
          await setAllowGet(env, !!body.allow_get);
          const allowGet = await getAllowGet(env);
          return new Response(JSON.stringify({ ok: true, allow_get: allowGet, kv_bound: !!env.KV }), {
            status: 200,
            headers: secHeaders({ ...NO_CACHE, "content-type": "application/json; charset=utf-8" })
          });
        } catch (e) {
          return new Response(JSON.stringify({ ok: false, error: String(e) }), {
            status: 400,
            headers: secHeaders({ ...NO_CACHE, "content-type": "application/json; charset=utf-8" })
          });
        }
      }

      return new Response("Method Not Allowed", { status: 405, headers: secHeaders({ ...NO_CACHE, allow: "GET, POST" }) });
    }

    if (path === "/api/echrr") {
      if (!isAuthed) return new Response("forbidden", { status: 403, headers: secHeaders(NO_CACHE) });

      const name = url.searchParams.get("name") || "cloudflare-ech.com";
      const api = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=HTTPS`;
      try {
        const r = await fetch(api, { headers: { accept: "application/json" } });
        const j = await r.json();
        const ans = Array.isArray(j.Answer) ? j.Answer : [];
        const hasHTTPS = ans.some(x => x && (x.type === 65 || String(x.type) === "65"));
        return new Response(JSON.stringify({
          ok: true,
          query: { name, type: "HTTPS" },
          status: j.Status,
          has_https_rr: hasHTTPS,
          answer_count: ans.length
        }), {
          status: 200,
          headers: secHeaders({ ...NO_CACHE, "content-type": "application/json; charset=utf-8" })
        });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: String(e) }), {
          status: 502,
          headers: secHeaders({ ...NO_CACHE, "content-type": "application/json; charset=utf-8" })
        });
      }
    }

    // UI page
    if (path === "/") {
      return new Response(renderUI(isAuthed, url.origin), {
        status: 200,
        headers: secHeaders({ ...NO_CACHE, "content-type": "text/html; charset=utf-8" }),
      });
    }

    return new Response("Not Found", { status: 404, headers: secHeaders(NO_CACHE) });
  },
};

// ---------------------- state ----------------------

function makeState() {
  const ups = Object.fromEntries(UPSTREAMS.map(u => [u.tag, { ewma: 320, fails: 0, cdUntil: 0 }]));
  return {
    start: Date.now(),
    ok: 0, err: 0, slow: 0, get: 0, post: 0,

    // per-second windows (60s)
    series: new Array(60).fill(0),       // total rps
    errSeries: new Array(60).fill(0),    // errors per second
    slowSeries: new Array(60).fill(0),   // slow per second

    lastTick: Date.now(),
    pulse: 0,
    lastHit: 0,
    ups,
    last: { method: "n/a", upstream: "n/a", ms: "n/a", http: "n/a", at: "n/a", mode: "AUTO" },

    // probe snapshot cache
    probe: { at: 0, results: null },

    // for DPI heuristics
    probeHistory: { at: 0, last: null, prev: null }
  };
}

function decayPulse(S) {
  const now = Date.now();
  const dt = now - (S.lastHit || now);
  const decay = Math.max(0, 1 - Math.min(1, dt / 2200));
  S.pulse = Math.min(1, S.pulse * decay);
}

function rollSecondWindows(S) {
  const now = Date.now();
  if (now - S.lastTick >= 1000) {
    const steps = Math.min(10, Math.floor((now - S.lastTick) / 1000));
    for (let i = 0; i < steps; i++) {
      S.series.shift(); S.series.push(0);
      S.errSeries.shift(); S.errSeries.push(0);
      S.slowSeries.shift(); S.slowSeries.push(0);
    }
    S.lastTick += steps * 1000;
  }
}

function bumpWindows(S, kind /* "ok"|"err"|"slow" */) {
  rollSecondWindows(S);
  S.series[S.series.length - 1] += 1;
  if (kind === "err") S.errSeries[S.errSeries.length - 1] += 1;
  if (kind === "slow") S.slowSeries[S.slowSeries.length - 1] += 1;

  const now = Date.now();
  S.lastHit = now;
  const bump = (kind === "err") ? 0.65 : 0.22;
  S.pulse = Math.min(1, S.pulse + bump);
}

// ---------------------- probe ----------------------

async function getProbeSnapshot(S) {
  const now = Date.now();
  const maxAgeMs = 6000;

  if (S.probe.results && (now - S.probe.at) < maxAgeMs) {
    return { cached_s: Math.max(0, Math.floor((now - S.probe.at) / 1000)), results: S.probe.results };
  }

  const results = {};
  for (const u of UPSTREAMS) results[u.tag] = await probeUpstream(u);

  S.probeHistory.prev = S.probeHistory.last;
  S.probeHistory.last = results;
  S.probeHistory.at = now;

  S.probe = { at: now, results };
  return { cached_s: 0, results };
}

async function probeUpstream(u) {
  const t0 = performance.now();
  try {
    const r = await fetchWithTimeout(
      u.url,
      {
        method: "POST",
        headers: { "content-type": "application/dns-message", accept: "application/dns-message", "cache-control": "no-store" },
        body: PROBE_WIRE,
      },
      PROBE_TIMEOUT_MS
    );
    const ms = Math.round(performance.now() - t0);
    if (!r.ok) return { ok: false, http: r.status, ms };
    await r.arrayBuffer();
    return { ok: true, http: 200, ms };
  } catch (e) {
    const ms = Math.round(performance.now() - t0);
    return { ok: false, http: 0, ms, error: String(e) };
  }
}

// ---------------------- DPI indicator (heuristic) ----------------------

function sum(arr) { return arr.reduce((a, b) => a + b, 0); }
function clamp(n, a, b) { return Math.max(a, Math.min(b, n)); }

function computeDpiIndicator(S, probe) {
  const total60 = Math.max(0, sum(S.series));
  const err60 = Math.max(0, sum(S.errSeries));
  const slow60 = Math.max(0, sum(S.slowSeries));

  const errRatio = total60 ? err60 / total60 : 0;
  const slowRatio = total60 ? slow60 / total60 : 0;

  const prev = S.probeHistory.prev;
  const last = S.probeHistory.last;

  let maxJump = 0;
  if (prev && last) {
    for (const u of UPSTREAMS) {
      const a = prev[u.tag]?.ms;
      const b = last[u.tag]?.ms;
      if (typeof a === "number" && typeof b === "number") {
        maxJump = Math.max(maxJump, b - a);
      }
    }
  }

  const now = Date.now();
  let cooldownCount = 0;
  let ewmaBadCount = 0;
  for (const u of UPSTREAMS) {
    const st = S.ups[u.tag];
    if (st.cdUntil > now) cooldownCount++;
    if ((st.ewma || 0) >= DPI_EWMA_BAD_MS) ewmaBadCount++;
  }

  const reasons = [];
  let score = 0;

  if (slowRatio >= DPI_SLOW_RATIO_BAD) { score += 45; reasons.push(`SLOW ratio မြင့် (${Math.round(slowRatio * 100)}%)`); }
  else if (slowRatio >= DPI_SLOW_RATIO_WARN) { score += 25; reasons.push(`SLOW ratio တက်နေ (${Math.round(slowRatio * 100)}%)`); }

  if (errRatio >= DPI_ERR_RATIO_BAD) { score += 35; reasons.push(`ERR ratio မြင့် (${Math.round(errRatio * 100)}%)`); }
  else if (errRatio >= DPI_ERR_RATIO_WARN) { score += 18; reasons.push(`ERR ratio တက်နေ (${Math.round(errRatio * 100)}%)`); }

  if (maxJump >= DPI_PROBE_JUMP_MS) { score += 22; reasons.push(`Upstream probe latency jump +${Math.round(maxJump)}ms`); }

  if (cooldownCount >= 1) { score += 12; reasons.push(`Upstream cooldown ဖြစ်နေ (${cooldownCount})`); }
  if (ewmaBadCount >= 1) { score += 10; reasons.push(`EWMA နှေးနေ (${ewmaBadCount})`); }

  score = clamp(score, 0, 100);

  let level = "OK";
  if (score >= 70) level = "HIGH";
  else if (score >= 45) level = "MED";
  else if (score >= 25) level = "LOW";

  const suspected = score >= 45;

  return {
    suspected,
    score,
    level,
    reasons,
    window_60s: {
      total: total60,
      ok: Math.max(0, total60 - err60),
      err: err60,
      slow: slow60,
      err_ratio: +errRatio.toFixed(4),
      slow_ratio: +slowRatio.toFixed(4),
    },
    probe_jump_ms_max: Math.round(maxJump),
  };
}

// ---------------------- Health payload: public/admin ----------------------

function buildHealthJson(req, env, url, S, probe, allowGet, dpi, full, isAuthed, isAdminMode) {
  const endpoints = {
    auto: `${url.origin}/dns-query`,
    pinned: {
      cf: `${url.origin}/dns-query/cf`,
      "cf-sec": `${url.origin}/dns-query/cf-sec`,
      gg: `${url.origin}/dns-query/gg`,
    },
    health: `${url.origin}/health`,
    // single endpoint; browser will render HTML based on Accept header:
    health_html: `${url.origin}/health`,
  };

  const headEnabled = true;

  const base = {
    ok: true,
    service: "ECHGate DoH",
    version: VERSION,
    now_iso: new Date().toISOString(),
    cache_mode: "no-store",
    doh: {
      allow_get: allowGet,
      head_enabled: headEnabled,
      get_policy: allowGet ? "ENABLED" : "DISABLED",
      accepted_methods: allowGet ? ["POST", "GET", "HEAD"] : ["POST", "HEAD"],
      endpoints,
      usage_tip_mm: allowGet
        ? "Remote DNS (URL ထည့်တဲ့ app) သုံးမယ်ဆို GET=ON ထားပါ။"
        : "GET=OFF (POST-only) ဖြစ်နေပါတယ်။ URL field only app တချို့မှာ မလုပ်နိုင်နိုင်ပါ။",
    },
    runtime: {
      uptime_s: Math.floor((Date.now() - S.start) / 1000),
      slow_threshold_ms: SLOW_MS_THRESHOLD,
      counters: { ok: S.ok, err: S.err, slow: S.slow, get: S.get, post: S.post },
      window_60s: {
        total: sum(S.series),
        err: sum(S.errSeries),
        slow: sum(S.slowSeries),
      },
      dpi: {
        suspected: dpi.suspected,
        score: dpi.score,
        level: dpi.level,
        reasons: dpi.reasons,
        window_60s: dpi.window_60s,
        probe_jump_ms_max: dpi.probe_jump_ms_max,
      },
    },
    ui: {
      authed: !!isAuthed,
      admin: !!isAdminMode,
      admin_hint: "Admin JSON အပြည့် (/health?admin=1) ကို login (cookie) သို့ x-ech-admin-key header နဲ့သာ ရနိုင်ပါတယ်။",
    }
  };

  if (!full) {
    // PUBLIC SAFE: do NOT expose ray_id, last request details, upstream probe breakdown, ewma list
    return base;
  }

  // ADMIN FULL
  return {
    ...base,
    colo: (req.cf?.colo || req.headers.get("cf-colo") || "n/a"),
    ray_id: (req.headers.get("cf-ray") || "n/a"),
    kv: {
      bound: !!env.KV,
      cfg_allow_get_key: "cfg:allow_get",
      default_allow_get: DEFAULT_ALLOW_GET,
      cache_ttl_s: 5,
      source: env.KV ? "KV" : "DEFAULT"
    },
    runtime: {
      ...base.runtime,
      last: S.last,
      upstreams: UPSTREAMS.map(u => {
        const st = S.ups[u.tag];
        const now = Date.now();
        return {
          tag: u.tag,
          ewma_ms: st.ewma,
          fails: st.fails,
          cooldown_s: st.cdUntil > now ? Math.ceil((st.cdUntil - now) / 1000) : 0,
          state: st.cdUntil > now ? "COOLDOWN" : "READY",
        };
      }),
      probe_cached_s: probe.cached_s,
      upstream_probe: probe.results,
    }
  };
}

function renderHealthHTML(H) {
  const dpi = H.runtime?.dpi || { suspected:false, score:0, level:"OK", reasons:[] };
  const pill = (txt, cls) => `<span class="pill ${cls||""}">${escapeHtml(txt)}</span>`;
  const row = (k, v) => `<tr><td class="k">${escapeHtml(k)}</td><td class="v">${v}</td></tr>`;

  const dpiPill =
    dpi.level === "HIGH" ? pill(`DPI: HIGH (${dpi.score})`, "bad") :
    dpi.level === "MED"  ? pill(`DPI: MED (${dpi.score})`, "warn") :
    dpi.level === "LOW"  ? pill(`DPI: LOW (${dpi.score})`, "low") :
                           pill(`DPI: OK (${dpi.score})`, "ok");

  const headBadge = H.doh?.head_enabled ? pill("HEAD: ON", "ok") : pill("HEAD: OFF", "warn");
  const getBadge = H.doh?.allow_get ? pill("GET: ON", "ok") : pill("GET: OFF", "warn");

  const reasons = (dpi.reasons && dpi.reasons.length)
    ? `<ul>${dpi.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join("")}</ul>`
    : `<div class="muted">DPI သံသယအင်အားကြီး signal မတွေ့ပါ (last 60s).</div>`;

  const isAuthed = !!H.ui?.authed;
  const rawJson = escapeHtml(JSON.stringify(H, null, 2)); // safe payload only (public-safe unless admin view requested)

  return `<!doctype html>
<html lang="my">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="color-scheme" content="dark"/>
<title>ECHGate Health</title>
<style>
:root{
  --bg:#05080c; --panel:rgba(11,22,34,.92);
  --txt:rgba(231,246,255,.94); --muted:rgba(150,170,185,.82);
  --ok:#3fffc7; --warn:#ffd66b; --bad:#ff6b6b;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  --sans: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Noto Sans Myanmar", "Pyidaungsu", "Myanmar Text", sans-serif;
}
*{box-sizing:border-box}
body{margin:0;font-family:var(--sans);color:var(--txt);
  background:
    radial-gradient(1100px 560px at 20% -10%, rgba(63,255,199,.15), transparent 60%),
    radial-gradient(900px 520px at 90% 10%, rgba(70,164,255,.10), transparent 60%),
    linear-gradient(180deg, var(--bg), #07121b);
}
.wrap{max-width:980px;margin:18px auto;padding:14px}
.head{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;
  padding:14px;border-radius:18px;border:1px solid rgba(63,255,199,.14);
  background:linear-gradient(180deg, rgba(11,22,34,.78), rgba(11,22,34,.40));
}
.h1{font-weight:900;font-size:18px}
.sub{margin-top:6px;font-size:12px;color:var(--muted)}
.card{margin-top:12px;background:var(--panel);border:1px solid rgba(63,255,199,.12);border-radius:18px;padding:14px;}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media (max-width:860px){.grid{grid-template-columns:1fr}}
.table{width:100%;border-collapse:collapse;margin-top:10px}
.table td{padding:8px 8px;border-bottom:1px solid rgba(63,255,199,.10);vertical-align:top}
.k{font-size:12px;color:rgba(180,205,220,.9);letter-spacing:.12em;text-transform:uppercase}
.v{font-family:var(--mono);font-size:12px}
.muted{color:var(--muted);font-size:12px;line-height:1.6}
.pill{display:inline-block;padding:6px 10px;border-radius:999px;border:1px solid rgba(63,255,199,.16);
  background:rgba(0,0,0,.12);font-size:12px}
.mono{font-family:var(--mono)}
.right{text-align:right}
.pill.ok{border-color:rgba(63,255,199,.45);color:rgba(200,255,240,.98)}
.pill.low{border-color:rgba(70,164,255,.35);color:rgba(210,235,255,.95)}
.pill.warn{border-color:rgba(255,214,107,.60);color:rgba(255,240,190,.95)}
.pill.bad{border-color:rgba(255,107,107,.55);color:rgba(255,200,200,.95)}
ul{margin:8px 0 0 18px;padding:0}
li{margin:6px 0;color:rgba(230,245,255,.92);font-size:12px}
a{color:rgba(180,235,255,.95);text-decoration:none}
a:hover{text-decoration:underline}
.btn{display:inline-flex;gap:8px;align-items:center;justify-content:center;cursor:pointer;
  padding:10px 12px;border-radius:14px;border:1px solid rgba(63,255,199,.16);background:rgba(0,0,0,.12);
  font-weight:800;color:rgba(231,246,255,.94); user-select:none;
}
.btn:disabled{opacity:.5; cursor:not-allowed}
.switch{width:46px;height:26px;border-radius:999px;border:1px solid rgba(63,255,199,.18);background:rgba(255,255,255,.06);position:relative;flex:0 0 auto;display:inline-block;vertical-align:middle;margin-left:10px}
.knob{width:20px;height:20px;border-radius:999px;position:absolute;top:2px;left:2px;background:rgba(63,255,199,.75);transition:all .18s ease;}
.switch.on .knob{left:22px;background:rgba(63,255,199,.95)}
.note{margin-top:10px}
</style>
</head>
<body>
<div class="wrap">
  <div class="head">
    <div>
      <div class="h1">ECHGate // Health</div>
      <div class="sub">${escapeHtml(H.service)} • v${escapeHtml(H.version)} • ${escapeHtml(H.now_iso)}</div>
      <div class="sub">cache: <span class="mono">${escapeHtml(H.cache_mode||"no-store")}</span> • ${escapeHtml(H.doh?.usage_tip_mm || "")}</div>
    </div>
    <div style="display:flex;gap:8px;align-items:flex-start;flex-wrap:wrap;justify-content:flex-end">
      ${dpiPill}
      ${getBadge}
      ${headBadge}
      ${pill(isAuthed ? "AUTH: YES" : "AUTH: NO", isAuthed ? "ok" : "warn")}
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <div class="k">DoH Summary</div>
      <table class="table">
        <tbody>
          ${row("Auto endpoint", `<span class="mono">${escapeHtml(H.doh?.endpoints?.auto || "")}</span>`)}
          ${row("Health", `<a class="mono" href="${escapeHtml(H.doh?.endpoints?.health || "/health")}">${escapeHtml(H.doh?.endpoints?.health || "/health")}</a>`)}
          ${row("Slow threshold", `<span class="mono">≥ ${escapeHtml(String(H.runtime?.slow_threshold_ms ?? 900))}ms</span>`)}
          ${row("Uptime", `<span class="mono">${escapeHtml(String(H.runtime?.uptime_s ?? 0))}s</span>`)}
        </tbody>
      </table>

      <div class="note muted">
        <b>GET Toggle (Health Page)</b> — login လုပ်ထားရင် ဒီနေရာကနေ တိုက်ရိုက် ဖွင့်/ပိတ် လို့ရပါတယ်။
      </div>

      <div class="note">
        <span class="btn" id="togBtn" ${isAuthed ? "" : "disabled"}>TOGGLE GET</span>
        <span class="switch ${H.doh?.allow_get ? "on" : ""}" id="sw"><span class="knob"></span></span>
        <div class="muted" id="togMsg" style="margin-top:8px">
          ${isAuthed ? "Ready." : "Login မလုပ်ထားလို့ toggle မရပါ။ Console မှာ login ဝင်ပြီး ပြန်လာပါ။"}
        </div>
      </div>
    </div>

    <div class="card">
      <div class="k">DPI Indicator (Heuristic)</div>
      <table class="table">
        <tbody>
          ${row("Suspected", dpi.suspected ? pill("YES", "bad") : pill("NO", "ok"))}
          ${row("Score / Level", `<span class="mono">${escapeHtml(String(dpi.score))}</span> • ${escapeHtml(String(dpi.level))}`)}
          ${row("Window 60s", `<span class="mono">total=${escapeHtml(String(dpi.window_60s?.total ?? 0))} err=${escapeHtml(String(dpi.window_60s?.err ?? 0))} slow=${escapeHtml(String(dpi.window_60s?.slow ?? 0))}</span>`)}
          ${row("Ratios", `<span class="mono">err=${escapeHtml(String(dpi.window_60s?.err_ratio ?? 0))} slow=${escapeHtml(String(dpi.window_60s?.slow_ratio ?? 0))}</span>`)}
          ${row("Probe jump", `<span class="mono">max +${escapeHtml(String(dpi.probe_jump_ms_max ?? 0))}ms</span>`)}
        </tbody>
      </table>
      <div class="muted">${reasons}</div>
      <div class="muted" style="margin-top:10px">
        DPI အလားအလာကို “သေချာအတည်ပြု” မဟုတ်ပဲ slow/err ratio + probe jump + cooldown လက္ခဏာတွေကနေ ခန့်မှန်းထားတာပါ။
      </div>
    </div>
  </div>

  <div class="card">
    <div class="k">Runtime Counters</div>
    <table class="table">
      <tbody>
        ${row("OK / ERR / SLOW", `<span class="mono">${escapeHtml(String(H.runtime?.counters?.ok ?? 0))} / ${escapeHtml(String(H.runtime?.counters?.err ?? 0))} / ${escapeHtml(String(H.runtime?.counters?.slow ?? 0))}</span>`)}
        ${row("GET / POST", `<span class="mono">${escapeHtml(String(H.runtime?.counters?.get ?? 0))} / ${escapeHtml(String(H.runtime?.counters?.post ?? 0))}</span>`)}
        ${row("60s window", `<span class="mono">total=${escapeHtml(String(H.runtime?.window_60s?.total ?? 0))} err=${escapeHtml(String(H.runtime?.window_60s?.err ?? 0))} slow=${escapeHtml(String(H.runtime?.window_60s?.slow ?? 0))}</span>`)}
      </tbody>
    </table>
    <div class="muted">
      Public JSON က summary ပဲ ထုတ်ပါတယ်။ Admin JSON အပြည့်လိုရင် login (cookie) သို့ <span class="mono">x-ech-admin-key</span> header နဲ့ <span class="mono">/health?admin=1</span> ကိုခေါ်ပါ။
    </div>
  </div>

  ${isAuthed ? `
  <div class="card">
    <div class="k">Raw JSON (this view)</div>
    <pre class="mono" style="white-space:pre-wrap;color:rgba(220,238,248,.92);font-size:12px;margin:10px 0 0">${rawJson}</pre>
  </div>` : ``}

  <div class="muted" style="text-align:center;margin:14px 0 4px">© 2026 Thiha Aung (Yone Man)</div>
</div>

<script>
(() => {
  const authed = ${JSON.stringify(isAuthed)};
  const sw = document.getElementById('sw');
  const btn = document.getElementById('togBtn');
  const msg = document.getElementById('togMsg');

  let allowGet = ${JSON.stringify(!!H.doh?.allow_get)};

  function render(){ sw.classList.toggle('on', !!allowGet); }
  render();

  async function toggle(){
    if(!authed) return;
    btn.setAttribute('disabled', 'disabled');
    msg.textContent = 'saving...';
    try{
      const r = await fetch('/api/config', {
        method:'POST',
        headers:{'content-type':'application/json'},
        body: JSON.stringify({ allow_get: !allowGet })
      });
      if(!r.ok){
        msg.textContent = 'toggle failed (403 ဆို login မရှိတာ / origin mismatch / KV bind မရှိတာ ဖြစ်နိုင်)';
        return;
      }
      const j = await r.json();
      if(!j.ok){
        msg.textContent = 'toggle failed: ' + (j.error || 'unknown');
        return;
      }
      allowGet = !!j.allow_get;
      msg.textContent = allowGet ? 'GET is ON (Remote DNS compatibility)' : 'GET is OFF (POST-only)';
      render();
    }catch(e){
      msg.textContent = 'toggle failed: ' + String(e);
    }finally{
      btn.removeAttribute('disabled');
    }
  }

  btn && btn.addEventListener('click', (e)=>{ e.preventDefault(); toggle(); });
  sw && sw.addEventListener('click', (e)=>{ e.preventDefault(); toggle(); });
})();
</script>

</body>
</html>`;
}

// ---------------------- DoH ----------------------

function parsePinned(pathname) {
  const parts = pathname.split("/").filter(Boolean);
  if (parts.length <= 1) return null;
  const pin = parts[1];
  if (UPSTREAMS.some(u => u.tag === pin)) return pin;
  return null;
}

function base64urlToBytes(b64u) {
  let s = String(b64u).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function markOK(S, tag, ms) {
  const u = S.ups[tag];
  const a = 0.25;
  u.ewma = Math.round((u.ewma || ms) * (1 - a) + ms * a);
  u.fails = 0;
  u.cdUntil = 0;
}

function markFail(S, tag, ms) {
  const u = S.ups[tag];
  u.fails = (u.fails || 0) + 1;
  const cd = Math.min(MAX_COOLDOWN_MS, 2000 + u.fails * u.fails * 1000);
  u.cdUntil = Date.now() + cd;
  const m = Math.min(2000, ms || 2000);
  u.ewma = Math.round((u.ewma || m) * 0.8 + m * 0.2);
}

function pickUpstreams(S) {
  const now = Date.now();
  return [...UPSTREAMS].sort((a, b) => {
    const A = S.ups[a.tag], B = S.ups[b.tag];
    const ac = A.cdUntil > now ? 1 : 0;
    const bc = B.cdUntil > now ? 1 : 0;
    if (ac !== bc) return ac - bc;
    return (A.ewma || 9999) - (B.ewma || 9999);
  });
}

async function fetchWithTimeout(url, init, timeoutMs) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort("timeout"), timeoutMs);
  try { return await fetch(url, { ...init, signal: controller.signal }); }
  finally { clearTimeout(t); }
}

async function handleDoH(req, url, S, NO_CACHE, pinnedTag, allowGet) {
  const m = req.method.toUpperCase();

  // HEAD: always allowed, returns 204 with allow header. (No DNS processing)
  if (m === "HEAD") {
    const allow = allowGet ? "GET, POST, HEAD" : "POST, HEAD";
    return new Response(null, {
      status: 204,
      headers: { ...NO_CACHE, allow, "x-allow-get": allowGet ? "1" : "0" }
    });
  }

  if (m === "GET") {
    if (!allowGet) return new Response("Method Not Allowed", { status: 405, headers: { ...NO_CACHE, allow: "POST, HEAD" } });
    S.get++;
  } else if (m === "POST") {
    S.post++;
  } else {
    return new Response("Method Not Allowed", {
      status: 405,
      headers: { ...NO_CACHE, allow: allowGet ? "GET, POST, HEAD" : "POST, HEAD" }
    });
  }

  let wire;
  if (m === "GET") {
    const q = url.searchParams.get("dns");
    if (!q) return new Response("Bad Request", { status: 400, headers: NO_CACHE });
    try { wire = base64urlToBytes(q); }
    catch { return new Response("Bad dns param", { status: 400, headers: NO_CACHE }); }
  } else {
    const ct = (req.headers.get("content-type") || "").toLowerCase();
    if (!ct.includes("application/dns-message")) return new Response("Unsupported Media Type", { status: 415, headers: NO_CACHE });
    wire = new Uint8Array(await req.arrayBuffer());
    if (!wire || wire.length < 12) return new Response("Bad Request", { status: 400, headers: NO_CACHE });
  }

  let attempts;
  let modeLabel = "AUTO";
  if (pinnedTag) {
    const up = UPSTREAMS.find(u => u.tag === pinnedTag);
    attempts = up ? [up] : pickUpstreams(S);
    modeLabel = pinnedTag.toUpperCase();
  } else {
    attempts = pickUpstreams(S);
  }

  let lastErr = null;

  for (const up of attempts) {
    const t0 = performance.now();
    try {
      const r = await fetchWithTimeout(
        up.url,
        {
          method: "POST",
          headers: { "content-type": "application/dns-message", accept: "application/dns-message", "cache-control": "no-store" },
          body: wire,
        },
        UPSTREAM_TIMEOUT_MS
      );

      const ms = Math.round(performance.now() - t0);

      if (!r.ok) {
        markFail(S, up.tag, ms);
        lastErr = `HTTP ${r.status}`;
        continue;
      }

      const out = await r.arrayBuffer();
      markOK(S, up.tag, ms);

      S.ok++;
      const isSlow = ms >= SLOW_MS_THRESHOLD;
      if (isSlow) S.slow++;

      bumpWindows(S, isSlow ? "slow" : "ok");
      S.last = { method: m, upstream: up.tag, ms, http: 200, at: new Date().toISOString(), mode: modeLabel };

      return new Response(out, {
        status: 200,
        headers: {
          ...NO_CACHE,
          "content-type": "application/dns-message",
          "x-upstream": up.tag,
          "x-ms": String(ms),
          "x-mode": modeLabel,
          "x-slow": isSlow ? "1" : "0",
          "x-allow-get": allowGet ? "1" : "0",
        },
      });
    } catch (e) {
      const ms = Math.round(performance.now() - t0);
      markFail(S, up.tag, ms);
      lastErr = String(e);
    }
  }

  S.err++;
  bumpWindows(S, "err");
  S.last = { method: m, upstream: "n/a", ms: "n/a", http: 502, at: new Date().toISOString(), mode: modeLabel };
  return new Response(`Upstream failed: ${String(lastErr || "n/a")}`, { status: 502, headers: NO_CACHE });
}

// ---------------------- UI (Console) ----------------------

function renderUI(authed, origin) {
  return `<!doctype html>
<html lang="my">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="color-scheme" content="dark"/>
<title>ECHGate // DoH DNS</title>
<style>
:root{
  --panel:rgba(11,22,34,.92);
  --txt:rgba(231,246,255,.94);
  --muted:rgba(150,170,185,.82);
  --err:#ff6b6b;
  --warn:#ffd66b;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  --sans: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Noto Sans Myanmar", "Pyidaungsu", "Myanmar Text", sans-serif;
}
*{box-sizing:border-box}
body{
  margin:0;font-family:var(--sans);color:var(--txt);
  background:
    radial-gradient(1100px 560px at 20% -10%, rgba(63,255,199,.15), transparent 60%),
    radial-gradient(900px 520px at 90% 10%, rgba(70,164,255,.10), transparent 60%),
    linear-gradient(180deg, #05080c, #07121b);
}
.wrap{max-width:1040px;margin:18px auto;padding:14px}
.top{
  display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap;
  padding:14px 14px;border-radius:18px;border:1px solid rgba(63,255,199,.14);
  background:linear-gradient(180deg, rgba(11,22,34,.78), rgba(11,22,34,.40));
}
.brand{display:flex;gap:12px;align-items:center;min-width:0}
.logo{
  width:40px;height:40px;border-radius:14px;border:1px solid rgba(63,255,199,.22);
  background:linear-gradient(180deg, rgba(255,255,255,.07), rgba(0,0,0,.10));
  position:relative; overflow:hidden;
  box-shadow:0 0 0 2px rgba(63,255,199,.06), 0 18px 40px rgba(0,0,0,.55);
}
.logo::before{
  content:""; position:absolute; inset:8px 9px 9px 9px; border-radius:10px;
  background:
    linear-gradient(180deg, rgba(63,255,199,.08), rgba(70,164,255,.06)),
    repeating-linear-gradient(180deg, rgba(255,255,255,.10) 0px, rgba(255,255,255,.10) 1px, transparent 1px, transparent 6px);
  border:1px solid rgba(63,255,199,.14);
}
.logo::after{
  content:""; position:absolute; left:12px; top:12px; width:16px; height:16px; border-radius:8px;
  background:
    radial-gradient(circle at 30% 35%, rgba(63,255,199,.95), rgba(63,255,199,.20) 55%, transparent 60%),
    radial-gradient(circle at 70% 70%, rgba(70,164,255,.70), transparent 58%);
  box-shadow:
    18px 0 0 0 rgba(255,255,255,.06),
    18px 0 18px rgba(70,164,255,.18),
    0 18px 0 0 rgba(255,255,255,.06),
    0 18px 18px rgba(63,255,199,.14),
    18px 18px 0 0 rgba(255,255,255,.06),
    18px 18px 18px rgba(63,255,199,.10);
  animation:rackBlink 1.8s ease-in-out infinite;
}
@keyframes rackBlink{0%,100%{opacity:.45; transform:translateY(0)}50%{opacity:1; transform:translateY(-1px)}}
.h1{font-weight:900;font-size:18px;letter-spacing:.2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sub{margin-top:4px;font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.pill{font-family:var(--mono); font-size:12px; padding:6px 10px; border-radius:999px; border:1px solid rgba(63,255,199,.16); background:rgba(0,0,0,.12);}
.pill.bad{border-color:rgba(255,107,107,.45);color:rgba(255,200,200,.95)}
.pill.warn{border-color:rgba(255,214,107,.60);color:rgba(255,240,190,.95)}
.pill.low{border-color:rgba(70,164,255,.35);color:rgba(210,235,255,.95)}
.grid{margin-top:12px;display:grid;grid-template-columns:1.35fr .65fr;gap:12px}
@media (max-width:940px){.grid{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid rgba(63,255,199,.12);border-radius:18px;padding:14px;}
.k{font-family:var(--mono);font-size:12px;letter-spacing:.12em;color:rgba(180,205,220,.9);text-transform:uppercase}
input,button,select{
  width:100%; padding:11px 12px; border-radius:14px;
  border:1px solid rgba(63,255,199,.12); background:rgba(0,0,0,.16); color:var(--txt); outline:none;
}
button{cursor:pointer;font-weight:800;background:linear-gradient(180deg, rgba(63,255,199,.18), rgba(63,255,199,.04));}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:10px}
.badge{font-family:var(--mono);font-size:12px;padding:6px 10px;border-radius:999px;border:1px solid rgba(63,255,199,.16);background:rgba(0,0,0,.12)}
.badge.bad{border-color:rgba(255,107,107,.55);color:rgba(255,180,180,.95)}
.badge.warn{border-color:rgba(255,214,107,.60);color:rgba(255,240,190,.95)}
.badge.low{border-color:rgba(70,164,255,.35);color:rgba(210,235,255,.95)}
.ledGrid{display:grid;grid-template-columns:repeat(18,1fr);gap:6px;margin-top:10px}
@media (max-width:940px){.ledGrid{grid-template-columns:repeat(14,1fr)}}
.led{height:10px;border-radius:8px;border:1px solid rgba(63,255,199,.08);background:rgba(255,255,255,.04)}
.led.on{background:radial-gradient(circle at 30% 40%, rgba(63,255,199,.9), rgba(63,255,199,.16) 60%, rgba(0,0,0,.05) 76%);border-color:rgba(63,255,199,.22);box-shadow:0 0 18px rgba(63,255,199,.14)}
.led.err.on{background:radial-gradient(circle at 30% 40%, rgba(255,107,107,.9), rgba(255,107,107,.16) 60%, rgba(0,0,0,.05) 76%);border-color:rgba(255,107,107,.22);box-shadow:0 0 18px rgba(255,107,107,.12)}
.led.slow.on{background:radial-gradient(circle at 30% 40%, rgba(255,214,107,.95), rgba(255,214,107,.18) 60%, rgba(0,0,0,.05) 76%);border-color:rgba(255,214,107,.25);box-shadow:0 0 18px rgba(255,214,107,.10)}
.canvasBox{margin-top:10px;border-radius:16px;border:1px solid rgba(63,255,199,.10);background:rgba(0,0,0,.14);overflow:hidden}
canvas{display:block;width:100%;height:170px}
@media (max-width:940px){canvas{height:180px}}
.table{width:100%;border-collapse:collapse;margin-top:10px;font-family:var(--mono);font-size:12px}
.table td{padding:8px 8px;border-bottom:1px solid rgba(63,255,199,.10);color:rgba(220,238,248,.92)}
.right{text-align:right}
.small{font-size:12px;color:var(--muted);line-height:1.55;margin-top:8px}
.footer{margin-top:12px;text-align:center;font-family:var(--mono);font-size:12px;color:rgba(150,170,185,.70)}
.toggle{display:flex;gap:10px;align-items:center;justify-content:space-between;padding:10px 12px;border-radius:14px;border:1px solid rgba(63,255,199,.12);background:rgba(0,0,0,.12);}
.switch{width:46px;height:26px;border-radius:999px;border:1px solid rgba(63,255,199,.18);background:rgba(255,255,255,.06);position:relative;flex:0 0 auto;}
.knob{width:20px;height:20px;border-radius:999px;position:absolute;top:2px;left:2px;background:rgba(63,255,199,.75);box-shadow:0 0 18px rgba(63,255,199,.15);transition:all .18s ease;}
.switch.on .knob{left:22px;background:rgba(63,255,199,.95)}
.banner{
  display:none;margin-top:10px;padding:10px 12px;border-radius:14px;
  border:1px solid rgba(255,214,107,.40); background:rgba(255,214,107,.08);
  color:rgba(255,240,200,.95); font-size:12px; line-height:1.5;
}
.banner.show{display:block}
.banner b{font-family:var(--mono)}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div class="brand">
      <div class="logo" aria-hidden="true"></div>
      <div style="min-width:0">
        <div class="h1">ECHGate // DoH DNS Console</div>
        <div class="sub">Thiha Aung (Yone Man) • v${VERSION}</div>
      </div>
    </div>
    <div class="actions">
      ${authed ? `<span class="pill" id="pill">IDLE</span><span class="pill low" id="dpiPill">DPI: OK</span><a class="pill" href="/logout">LOGOUT</a>` : `<span class="pill">LOGIN</span>`}
    </div>
  </div>

  ${authed ? consoleHTML(origin) : loginHTML()}

  <div class="footer">© 2026 Thiha Aung (Yone Man)</div>
</div>

<script>
${authed ? consoleJS() : loginJS()}
</script>
</body>
</html>`;
}

function loginHTML() {
  return `
  <div class="grid">
    <div class="card">
      <div class="k">LOGIN</div>
      <div class="small">DoH DNS Console ထဲဝင်ရန် login လိုအပ်ပါသည်။</div>
      <form id="f" class="row" style="flex-direction:column; align-items:stretch; margin-top:12px">
        <input name="u" placeholder="Username" autocomplete="username" required />
        <input name="p" placeholder="Password" type="password" autocomplete="current-password" required />
        <button type="submit">ENTER CONSOLE</button>
      </form>
    </div>
    <div class="card">
      <div class="k">STATUS</div>
      <div class="small">Login မဝင်ခင်မှာ endpoint/info မပြထားပါဘူး။</div>
    </div>
  </div>`;
}

function loginJS() {
  return `
const f = document.getElementById('f');
f.onsubmit = async (e) => {
  e.preventDefault();
  const r = await fetch('/login', { method:'POST', body: new FormData(f), cache:'no-store' });
  if (r.ok) location.reload();
  else alert('login failed');
};`;
}

function consoleHTML(origin) {
  const auto = `${origin}/dns-query`;
  const cf = `${origin}/dns-query/cf`;
  const cfsec = `${origin}/dns-query/cf-sec`;
  const gg = `${origin}/dns-query/gg`;
  const health = `${origin}/health`;

  return `
  <div class="grid">
    <div class="card">
      <div class="k">DOH ENDPOINT</div>
      <div class="row">
        <select id="mode">
          <option value="AUTO">AUTO (fallback)</option>
          <option value="CF">Cloudflare only</option>
          <option value="CF-SEC">CF Security only</option>
          <option value="GG">Google only</option>
        </select>
        <span class="badge" id="modeBadge">saved</span>
      </div>

      <div class="row">
        <input id="doh" readonly value="${escapeHtml(auto)}" />
        <button id="copy">COPY</button>
      </div>

      <div class="k" style="margin-top:12px">GET MODE (KV)</div>
      <div class="toggle">
        <div style="min-width:0">
          <div class="k" style="letter-spacing:.08em">ALLOW GET</div>
          <div class="small" id="getHint">loading...</div>
        </div>
        <div class="switch" id="sw"><div class="knob"></div></div>
      </div>

      <div class="banner" id="warn">
        ⚠️ <b>GET = OFF</b> ဖြစ်နေပါတယ်။ Remote DNS ကို “URL တစ်ကြောင်းထည့်တဲ့ app” မျိုးမှာ GET လိုနိုင်ပါတယ်။
        အဲ့ဒီအခါ <b>GET = ON</b> ပြန်ဖွင့်ပါ (သို့) DNS ကို config ထဲကနေ <b>POST + detour=proxy</b> နဲ့သုံးပါ။
      </div>

      <div class="k" style="margin-top:12px">ECH INDICATOR</div>
      <div class="row">
        <button id="ech1">Check HTTPS RR: cloudflare-ech.com</button>
        <span class="badge" id="echRes">—</span>
      </div>

      <div class="k" style="margin-top:12px">SYSTEM :: LED RACK</div>
      <div class="row">
        <label class="pill" style="display:flex;gap:8px;align-items:center">
          <input id="snd" type="checkbox" style="width:auto; margin:0" />
          sound
        </label>
        <span class="badge" id="qres">—</span>
        <a class="pill" href="${escapeHtml(health)}" target="_blank" rel="noreferrer">/health</a>
      </div>

      <div class="ledGrid" id="rack"></div>

      <div class="k" style="margin-top:12px">PER-SECOND GRAPH</div>
      <div class="canvasBox"><canvas id="g"></canvas></div>

      <div class="small">
        ✅ Heartbeat tick (always) + ✅ Traffic double tick (OK). <br/>
        ⚠️ DPI throttle က “200 but slow” ဖြစ်နိုင်လို့ SLOW counter + DPI badge ကိုကြည့်ပါ။
      </div>
    </div>

    <div class="card">
      <div class="k">LIVE COUNTERS</div>
      <table class="table">
        <tbody>
          <tr><td>OK</td><td class="right" id="ok">0</td></tr>
          <tr><td>ERR</td><td class="right" id="er">0</td></tr>
          <tr><td>SLOW</td><td class="right" id="sl">0</td></tr>
          <tr><td>GET / POST</td><td class="right" id="gp">0 / 0</td></tr>
          <tr><td>uptime</td><td class="right" id="up">0s</td></tr>
          <tr><td>DPI</td><td class="right" id="dpi">OK</td></tr>
          <tr><td>last mode</td><td class="right" id="lm2">AUTO</td></tr>
          <tr><td>last upstream</td><td class="right" id="lu">n/a</td></tr>
          <tr><td>last ms</td><td class="right" id="lm">n/a</td></tr>
          <tr><td>last http</td><td class="right" id="lc">n/a</td></tr>
          <tr><td>last at</td><td class="right" id="la">n/a</td></tr>
        </tbody>
      </table>

      <div class="row" style="margin-top:12px">
        <button id="qt">QUICK TEST (DoH POST)</button>
      </div>

      <div class="k" style="margin-top:14px">UPSTREAMS (AUTO HEALTH)</div>
      <table class="table" id="ut">
        <thead>
          <tr><td>tag</td><td class="right">ewma</td><td class="right">fails</td><td class="right">cd(s)</td><td class="right">state</td></tr>
        </thead>
        <tbody></tbody>
      </table>

      <div class="small" id="cfgLine">
        Hard timeout: ${UPSTREAM_TIMEOUT_MS}ms • Probe: ${PROBE_TIMEOUT_MS}ms • Slow ≥ ${SLOW_MS_THRESHOLD}ms
      </div>

      <div style="display:none" id="urls"
        data-auto="${escapeHtml(auto)}"
        data-cf="${escapeHtml(cf)}"
        data-cfsec="${escapeHtml(cfsec)}"
        data-gg="${escapeHtml(gg)}"></div>
    </div>
  </div>`;
}

function consoleJS() {
  return `
const $ = (id)=>document.getElementById(id);
const urls = $('urls').dataset;

function modeToUrl(mode){
  if(mode === 'CF') return urls.cf;
  if(mode === 'CF-SEC') return urls.cfsec;
  if(mode === 'GG') return urls.gg;
  return urls.auto;
}
function loadMode(){ return localStorage.getItem('ech_mode') || 'AUTO'; }
function saveMode(m){ localStorage.setItem('ech_mode', m); }

const modeSel = $('mode');
const modeBadge = $('modeBadge');
modeSel.value = loadMode();

function applyMode(){
  const m = modeSel.value;
  $('doh').value = modeToUrl(m);
  modeBadge.textContent = 'saved';
  setTimeout(()=>modeBadge.textContent='saved', 600);
}
applyMode();
modeSel.onchange = ()=>{ saveMode(modeSel.value); applyMode(); };

$('copy').onclick = async (e)=>{
  e.preventDefault();
  try{ await navigator.clipboard.writeText($('doh').value); $('qres').textContent='copied'; }
  catch{ $('qres').textContent='copy failed'; }
  setTimeout(()=>$('qres').textContent='—', 900);
};

// KV GET toggle UI + banner
const sw = $('sw');
const getHint = $('getHint');
const warn = $('warn');
let allowGet = null;
let kvBound = null;

function renderSwitch(){
  if (allowGet === null) { sw.classList.remove('on'); warn.classList.remove('show'); return; }
  sw.classList.toggle('on', !!allowGet);
  warn.classList.toggle('show', allowGet === false);
}

async function loadConfig(){
  try{
    const r = await fetch('/api/config', { cache:'no-store' });
    const j = await r.json();
    if(!j.ok) throw new Error('bad');
    allowGet = !!j.allow_get;
    kvBound = !!j.kv_bound;

    if(!kvBound){
      getHint.textContent = 'KV မချိတ်ထားသေးပါ (fallback default).';
    } else {
      getHint.textContent = allowGet ? 'GET ဖွင့်ထားပါတယ် (Remote DNS compatibility).' : 'POST-only (GET ပိတ်ထား).';
    }
    renderSwitch();
  }catch{
    getHint.textContent = 'config load failed';
    allowGet = null; kvBound = null;
    renderSwitch();
  }
}

async function saveConfig(next){
  try{
    getHint.textContent = 'saving...';
    const r = await fetch('/api/config', {
      method:'POST',
      headers:{'content-type':'application/json'},
      body: JSON.stringify({ allow_get: !!next })
    });
    const j = await r.json();
    if(!j.ok) throw new Error(j.error || 'bad');
    allowGet = !!j.allow_get;
    kvBound = !!j.kv_bound;
    getHint.textContent = allowGet ? 'GET ဖွင့်ထားပါတယ် (Remote DNS compatibility).' : 'POST-only (GET ပိတ်ထား).';
    renderSwitch();
  }catch{
    getHint.textContent = 'save failed (KV bind / origin check စစ်ပါ)';
  }
}

sw.onclick = async (e)=>{
  e.preventDefault();
  if(kvBound === false){
    getHint.textContent = 'KV မချိတ်ထားသေးလို့ toggle မလုပ်နိုင်ပါ။';
    return;
  }
  const next = !(allowGet === true);
  await saveConfig(next);
};

loadConfig();

// LED rack
const rack = $('rack');
const LED_N = 18*4;
for(let i=0;i<LED_N;i++){
  const d=document.createElement('div');
  d.className='led';
  rack.appendChild(d);
}
const leds=[...rack.children];

const pill=$('pill');
const qres=$('qres');
const snd=$('snd');
const echRes=$('echRes');

const dpiPill = document.getElementById('dpiPill');
const dpiCell = document.getElementById('dpi');

// audio
const audio = (() => {
  const C = window.AudioContext || window.webkitAudioContext;
  let ctx = null;
  function ensure(){ if(!ctx) ctx = new C(); return ctx; }
  return {
    beep(freq=880, dur=0.08){
      if(!snd.checked) return;
      try{
        const A = ensure();
        const o=A.createOscillator();
        const g=A.createGain();
        o.type='sine'; o.frequency.value=freq;
        g.gain.value=0.05;
        o.connect(g); g.connect(A.destination);
        o.start();
        setTimeout(()=>o.stop(), dur*1000);
      }catch{}
    },
    dpiLow(){ this.beep(780,0.05); setTimeout(()=>this.beep(820,0.05), 110); },
    dpiMed(){ this.beep(520,0.08); setTimeout(()=>this.beep(460,0.08), 120); setTimeout(()=>this.beep(520,0.08), 240); },
    dpiHigh(){ this.beep(360,0.10); setTimeout(()=>this.beep(320,0.10), 140); setTimeout(()=>this.beep(280,0.10), 280); }
  };
})();

// Heartbeat tick (always)
let hbTimer = null;
function startHeartbeat(){
  if(hbTimer) clearInterval(hbTimer);
  hbTimer = setInterval(()=>{
    if(!snd.checked) return;
    audio.beep(900, 0.02);
  }, 900);
}
startHeartbeat();

// graph canvas
const cv = $('g');
const ctx = cv.getContext('2d');
function resizeCanvas(){
  const r = cv.getBoundingClientRect();
  const dpr = Math.max(1, window.devicePixelRatio || 1);
  cv.width = Math.floor(r.width * dpr);
  cv.height = Math.floor(r.height * dpr);
}
window.addEventListener('resize', resizeCanvas);
resizeCanvas();

function drawSeries(series){
  const w=cv.width, h=cv.height;
  ctx.clearRect(0,0,w,h);

  ctx.globalAlpha=0.22;
  ctx.strokeStyle='rgba(63,255,199,0.35)';
  for(let i=0;i<=10;i++){
    const y=Math.round(i*h/10);
    ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(w,y); ctx.stroke();
  }
  ctx.globalAlpha=1;

  const max = Math.max(2, ...series);
  ctx.strokeStyle='rgba(63,255,199,0.9)';
  ctx.lineWidth = Math.max(2, Math.floor(w/600));
  ctx.beginPath();
  series.forEach((v,i)=>{
    const x = i*(w/(series.length-1));
    const y = h - (v/max)*(h-18) - 9;
    if(i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
  });
  ctx.stroke();
}

function fmtUptime(s){
  s = Math.max(0, s|0);
  const h=Math.floor(s/3600), m=Math.floor((s%3600)/60), ss=s%60;
  if(h) return h+'h '+m+'m '+ss+'s';
  if(m) return m+'m '+ss+'s';
  return ss+'s';
}

let pulse=0;
let phase=0;
let errBlink=0;
let slowBlink=0;

function animRack(){
  const speed = 0.05 + pulse*0.55;
  phase += speed;

  const dens = Math.min(1, 0.08 + pulse*0.88);
  const head = (Math.sin(phase) * 0.5 + 0.5) * (leds.length-1);

  leds.forEach((el,i)=>{
    el.classList.remove('on','err','slow');
    const d = Math.abs(i - head);
    const wave = d < (2.2 + pulse*3.2);
    const rnd = Math.random() < dens*0.55;
    if (wave || rnd) el.classList.add('on');
  });

  if(slowBlink > 0){
    const k = Math.min(10, Math.floor(slowBlink*14));
    for(let i=0;i<k;i++){
      const idx = (Math.floor(head) + i*3) % leds.length;
      leds[idx].classList.add('on','slow');
    }
    slowBlink = Math.max(0, slowBlink - 0.05);
  }

  if(errBlink > 0){
    const k = Math.min(14, Math.floor(errBlink*18));
    for(let i=0;i<k;i++){
      const idx = (Math.floor(head) + i*2) % leds.length;
      leds[idx].classList.add('on','err');
    }
    errBlink = Math.max(0, errBlink - 0.04);
  }

  requestAnimationFrame(animRack);
}
requestAnimationFrame(animRack);

function fillUpstreams(list){
  const tb = $('ut').querySelector('tbody');
  tb.innerHTML = '';
  list.forEach(u=>{
    const tr=document.createElement('tr');
    tr.innerHTML = \`
      <td>\${u.tag}</td>
      <td class="right">\${u.ewma_ms}</td>
      <td class="right">\${u.fails}</td>
      <td class="right">\${u.cooldown_s}</td>
      <td class="right">\${u.state}</td>\`;
    tb.appendChild(tr);
  });
}

let lastErr = 0;
let lastOk = 0;
let lastSlow = 0;
let lastDpiLevel = "OK";

function setDpiUI(dpi){
  const level = dpi?.level || "OK";
  const score = dpi?.score ?? 0;

  if (dpiCell) dpiCell.textContent = level + " (" + score + ")";

  if (dpiPill){
    dpiPill.classList.remove('bad','warn','low');
    if(level === "HIGH"){ dpiPill.textContent = "DPI: HIGH"; dpiPill.classList.add('bad'); }
    else if(level === "MED"){ dpiPill.textContent = "DPI: MED"; dpiPill.classList.add('warn'); }
    else if(level === "LOW"){ dpiPill.textContent = "DPI: LOW"; dpiPill.classList.add('low'); }
    else { dpiPill.textContent = "DPI: OK"; dpiPill.classList.add('low'); }
  }

  // sound only on "level change up"
  if(level !== lastDpiLevel){
    if(level === "HIGH"){ audio.dpiHigh(); }
    else if(level === "MED"){ audio.dpiMed(); }
    else if(level === "LOW"){ audio.dpiLow(); }
    lastDpiLevel = level;
  }
}

async function poll(){
  try{
    const r = await fetch('/api/status', { cache:'no-store' });
    if(!r.ok) return;
    const j = await r.json();
    if(!j.ok) return;

    pulse = j.pulse || 0;

    $('ok').textContent = j.counters.ok;
    $('er').textContent = j.counters.err;
    $('sl').textContent = j.counters.slow;
    $('gp').textContent = j.counters.get + ' / ' + j.counters.post;
    $('up').textContent = fmtUptime(j.uptime_s);

    $('lm2').textContent = j.last.mode || 'AUTO';
    $('lu').textContent = j.last.upstream;
    $('lm').textContent = j.last.ms;
    $('lc').textContent = j.last.http;
    $('la').textContent = j.last.at;

    setDpiUI(j.dpi);

    const lastMs = (j.last && j.last.ms && j.last.ms !== 'n/a') ? Number(j.last.ms) : 0;
    if (lastMs && lastMs >= (j.slow_threshold_ms || 900)) {
      pill.textContent = 'SLOW';
      pill.classList.add('bad');
    } else {
      pill.textContent = (pulse > 0.10) ? 'ACTIVE' : 'IDLE';
      pill.classList.remove('bad');
    }

    if(j.counters.err > lastErr){
      errBlink = 1;
      audio.beep(420, 0.09);
      setTimeout(()=>audio.beep(320,0.09), 90);
    }
    lastErr = j.counters.err;

    if(j.counters.slow > lastSlow){
      slowBlink = 1;
      audio.beep(740, 0.05);
      setTimeout(()=>audio.beep(660,0.05), 80);
    }
    lastSlow = j.counters.slow;

    if (j.counters.ok > lastOk) {
      if (snd.checked) {
        audio.beep(1300, 0.02);
        setTimeout(()=>audio.beep(1500, 0.02), 70);
      }
      lastOk = j.counters.ok;
    }

    drawSeries(j.series || new Array(60).fill(0));
    fillUpstreams(j.upstreams || []);
  }catch{}
}

setInterval(poll, 1200);
poll();

async function echCheck(){
  try{
    echRes.textContent = 'checking...';
    echRes.classList.remove('bad','warn');
    const r = await fetch('/api/echrr?name=' + encodeURIComponent('cloudflare-ech.com'), { cache:'no-store' });
    const j = await r.json();
    if(!j.ok){
      echRes.textContent = 'FAILED';
      echRes.classList.add('bad');
      return;
    }
    echRes.textContent = (j.has_https_rr ? 'HTTPS RR: OK' : 'HTTPS RR: NOT FOUND') + ' • ans:' + j.answer_count;
    if(!j.has_https_rr) echRes.classList.add('bad');
  }catch{
    echRes.textContent = 'FAILED';
    echRes.classList.add('bad');
  }
}
$('ech1').onclick = (e)=>{ e.preventDefault(); echCheck(); };

$('qt').onclick = async (e)=>{
  e.preventDefault();
  qres.textContent = 'testing...';
  qres.classList.remove('bad','warn');

  const endpoint = $('doh').value;
  const bin = Uint8Array.from(atob("AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE="), c=>c.charCodeAt(0));

  try{
    const t0 = performance.now();
    const r = await fetch(endpoint, {
      method:'POST',
      headers:{ 'content-type':'application/dns-message', 'accept':'application/dns-message' },
      body: bin
    });
    const ms = Math.round(performance.now() - t0);

    const up = r.headers.get('x-upstream') || 'n/a';
    const srv = r.headers.get('x-ms') || 'n/a';
    const mode = r.headers.get('x-mode') || 'AUTO';
    const slow = r.headers.get('x-slow') === '1';

    qres.textContent = \`HTTP \${r.status} • \${ms}ms • \${mode} • \${up} • srv:\${srv}ms\`;
    if(!r.ok) qres.classList.add('bad');
    else if(slow) qres.classList.add('warn');

    poll();
  }catch{
    qres.textContent = 'FAILED';
    qres.classList.add('bad');
  }
};
`;
}

function escapeHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}