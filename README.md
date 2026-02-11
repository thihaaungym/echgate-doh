# echgate-doh
Secure DNS-over-HTTPS gateway with Cloudflare Pages — Web UI, GET toggle, Health JSON/HTML & DPI detection

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

### DoH Endpoints
- `/dns-query` (AUTO fallback)
- `/dns-query/cf`
- `/dns-query/cf-sec`
- `/dns-query/gg`

### Web UI
- Login with username/password
- Copy-ready DoH URLs
- GET mode toggle (Remote DNS compatible)
- Live counters, latency, upstream health

### Health API
- `/health` → public JSON / browser HTML
- `/health?admin=1` → full admin JSON (login or admin key)

### Security
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

| Name | Type | Required | Description | Example |
|----|----|----|----|----|
| `UI_USER` | Secret | ✅ | Console login username | `admin` |
| `UI_PASS` | Secret | ✅ | Console login password | `strong-password-123` |
| `ADMIN_KEY` | Secret | ❌ Optional | Admin JSON access key | `echgate-admin-key-change-me` |

> ℹ️ `ADMIN_KEY` ကို ထည့်ထားရင်  
> `/health?admin=1` ကို **login မလုပ်ဘဲ**  
> `x-ech-admin-key` header နဲ့ access လုပ်နိုင်ပါတယ်။

---

## 🗄️ KV Binding (Optional but Recommended)

ECHGate uses **Cloudflare KV** to persist runtime configuration.

### 1️⃣ Create KV Namespace

Cloudflare Dashboard →
---

### 2️⃣ Bind KV to Pages Project

**Pages → Settings → Functions → KV bindings**

| Binding name | Namespace |
|-------------|-----------|
| `KV` | `ECHGATE_KV` |

⚠️ Binding name **must be exactly `KV`**

---

### 3️⃣ KV Keys Used

| Key | Type | Description |
|----|----|----|
| `allow_get` | boolean (`"1"` / `"0"`) | Enable GET mode (Remote DNS compatibility) |
| `last_mode` | string | Last selected DoH endpoint |
| `ui_version` | string | UI schema version |

If KV is **not configured**, ECHGate will fall back to safe defaults.

---

## 🧠 Design Philosophy

- Deploy-your-own (no shared backend)
- Each user owns their Cloudflare account & domain
- No central logging or tracking
- Safe for censorship-resistant DNS setups
- Multi-tenant by design (per deployment isolation)

---

## Attribution

This project was originally created by **Thiha Aung (Yone Man)**.  
If you fork or redistribute, please keep this attribution.
## Attribution

This project was originally created by **Thiha Aung (Yone Man)**.
If you fork or redistribute, please keep this attribution.
