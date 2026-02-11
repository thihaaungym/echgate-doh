# echgate-doh

Secure DNS-over-HTTPS (DoH) gateway on **Cloudflare Pages**  
with Web UI, GET toggle, Health JSON/HTML & DPI detection.

---

## 🌐 ECHGate — DNS-over-HTTPS on Cloudflare Pages

**ECHGate** is a deploy-your-own **DNS-over-HTTPS (DoH)** gateway  
designed for censorship-resistant, privacy-focused DNS usage.

Each user deploys it on **their own Cloudflare account & domain**.  
No shared backend. No tracking. No vendor lock-in.

---

## ✨ Features

### 🚀 DoH Endpoints
- `/dns-query` (AUTO fallback)
- `/dns-query/cf` (Cloudflare)
- `/dns-query/cf-sec` (Cloudflare Secure)
- `/dns-query/gg` (Google)

### 🖥️ Web Console
- Username / password login
- Copy-ready DoH URLs
- GET / POST toggle (Remote DNS compatible)
- Live counters, latency & upstream health

### 🩺 Health API
- `/health` → public JSON or browser HTML
- `/health?admin=1` → full admin JSON  
  (via login **or** admin key)

### 🔐 Security
- CSP + `no-store` cache
- HttpOnly auth cookie
- Optional admin header key
- POST origin check
- HEAD probe support

### 🧠 Architecture
- Multi-tenant friendly
- Per-deployment isolation
- No central logging
- KV-backed runtime config (optional)

---

## 🚀 One-Click Deploy (Cloudflare Pages)

Each user deploys **on their own Cloudflare account & domain**:

👉 https://dash.cloudflare.com/?to=pages

---

## ⚙️ Required Environment Variables

Set in **Cloudflare Pages → Settings → Variables & Secrets**

| Name | Type | Required | Description |
|----|----|----|----|
| `UI_USER` | Secret | ✅ | Web console username |
| `UI_PASS` | Secret | ✅ | Web console password |
| `ADMIN_KEY` | Secret | ❌ Optional | Admin JSON access key |

> ℹ️ If `ADMIN_KEY` is set, `/health?admin=1` can be accessed  
> **without login** using header: `x-ech-admin-key`.

---

## 🗄️ KV Binding (Optional but Recommended)

ECHGate uses **Cloudflare KV** to persist runtime state.

### KV Namespace
Create a KV namespace (any name).

### Bind to Pages
**Pages → Settings → Functions → KV bindings**

| Binding name | Namespace |
|-------------|-----------|
| `KV` | Your KV namespace |

⚠️ Binding name **must be exactly `KV`**

### KV Keys Used

| Key | Type | Purpose |
|----|----|----|
| `allow_get` | `"1"` / `"0"` | Enable GET mode |
| `last_mode` | string | Last selected endpoint |
| `ui_version` | string | UI schema version |

If KV is **not configured**, safe defaults are used.

---

## 🧠 Design Philosophy

- Deploy-your-own, no SaaS
- Each user owns their account & domain
- No telemetry, no tracking
- Safe for censorship-resistant DNS setups
- Simple, auditable, hackable

---

## 📜 License

See `LICENSE` file.

---

## 🙏 Attribution

Created by **Thiha Aung (Yone Man)**  
If you fork or redistribute, please keep this attribution.
