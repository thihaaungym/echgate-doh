# echgate-doh
Secure DNS-over-HTTPS gateway with Cloudflare Pages — Web UI, GET toggle, Health JSON/HTML &amp; DPI detection
# ECHGate — Cloudflare DoH DNS Console

Secure DNS-over-HTTPS gateway with:
- GET / POST toggle (KV-backed)
- Health JSON + Human-readable HTML
- DPI heuristic indicator
- Web UI console (username/password)
- Cloudflare / Google upstream auto-fallback

---

## ✨ Features

- Public DoH endpoints (`/dns-query`)
- Web console with login
- GET enable/disable (saved in KV)
- `/health` single endpoint
  - Browser → HTML
  - curl/app → JSON
  - Admin mode → `/health?admin=1`
- Works with **your own Cloudflare account & domain**

---

## 🚀 Quick Deploy (Cloudflare Pages)

### 1️⃣ Fork or Download this repo
