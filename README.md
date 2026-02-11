# echgate-doh
Secure DNS-over-HTTPS gateway with Cloudflare Pages — Web UI, GET toggle, Health JSON/HTML &amp; DPI detection
# ECHGate — DNS-over-HTTPS on Cloudflare Pages

Secure, deploy-your-own **DNS-over-HTTPS (DoH)** gateway running on **Cloudflare Pages** with:

- 🌐 Public DoH endpoints
- 🔐 Login-protected Web Console
- 🔁 GET / POST toggle (KV-backed)
- 🩺 Health endpoint (JSON + HTML)
- 🚨 DPI detection indicator (heuristic)
- 🧠 Multi-tenant friendly (each user deploys on their own account & domain)

---

## ✨ Features

- **DoH Endpoints**
  - `/dns-query` (AUTO fallback)
  - `/dns-query/cf`
  - `/dns-query/cf-sec`
  - `/dns-query/gg`

- **Web UI**
  - Login with username/password
  - Copy-ready DoH URLs
  - GET mode toggle (Remote DNS compatible)
  - Live counters, latency, upstream health

- **Health API**
  - `/health` → public JSON / browser HTML
  - `/health?admin=1` → full admin JSON (login or admin key)

- **Security**
  - CSP, no-store cache
  - HttpOnly auth cookie
  - Optional admin header key
  - POST origin check

---

## 🚀 One-Click Deploy (Cloudflare Pages)

> Each user deploys **on their own Cloudflare account & domain**

[![Deploy to Cloudflare Pages](https://deploy.workers.cloudflare.com/button)](https://dash.cloudflare.com/?to=pages)

---

## ⚙️ Required Environment Variables

Set these in **Cloudflare Pages → Settings → Variables & Secrets**

| Name | Type | Description |
|----|----|----|
| `UI_USER` | Secret | Console login username |
| `UI_PASS` | Secret | Console login password |
| `ADMIN_KEY` | Secret (optional) | Admin JSON access key |

---

## 🗄️ KV Binding (Optional but Recommended)

Create a KV namespace and bind it as:
## Attribution

This project was originally created by **Thiha Aung (Yone Man)**.
If you fork or redistribute, please keep this attribution.
