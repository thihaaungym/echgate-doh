<p align="center">
  <img src="./echgate-logo.png" alt="ECHGate Logo" width="120">
</p>

<h1 align="center">ECHGate — DNS-over-HTTPS on Cloudflare Pages</h1>

<p align="center">
  Secure, deploy-your-own DNS-over-HTTPS (DoH) gateway with Web UI, Health API & DPI detection
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Cloudflare-Pages-orange">
  <img src="https://img.shields.io/badge/DoH-DNS--over--HTTPS-blue">
  <img src="https://img.shields.io/badge/Multi--Tenant-Friendly-green">
  <img src="https://img.shields.io/badge/Security-Hardened-critical">
</p>

---

## 🔐 What is ECHGate?

**ECHGate** သည်  
Cloudflare Pages + Workers ပေါ်မှာ run လုပ်တဲ့  
**deploy-your-own DNS-over-HTTPS (DoH) gateway** တစ်ခုဖြစ်ပါတယ်။

✔️ ကိုယ့် Cloudflare account  
✔️ ကိုယ့် domain  
✔️ ကိုယ့် control  

အပြည့်အဝ သုံးနိုင်အောင် design လုပ်ထားပါတယ်။

---

## ✨ Features

### 🌐 DoH Endpoints
- `/dns-query` → AUTO fallback
- `/dns-query/cf` → Cloudflare
- `/dns-query/cf-sec` → Cloudflare (secure profile)
- `/dns-query/gg` → Google

### 🖥️ Web Console
- Username / Password login
- Copy-ready DoH URLs
- GET / POST mode toggle (Remote DNS compatible)
- Live counters & latency view
- Upstream health status

### 🩺 Health API
- `/health`
  - Public JSON (API)
  - Human-readable HTML (browser)
- `/health?admin=1`
  - Full admin JSON
  - Access via login session **or** admin key

### 🚨 DPI Detection (Heuristic)
- Request latency & error pattern analysis
- DPI throttling / anomaly indicator
- WARN / OK badge logic (non-invasive)

### 🔒 Security
- Strict CSP (Content Security Policy)
- `no-store` cache policy
- HttpOnly auth cookie
- Optional admin header key
- POST origin validation

---

## 🚀 One-Click Deploy (Cloudflare Pages)

Each user deploys **on their own Cloudflare account & domain**.

👉 https://dash.cloudflare.com/?to=pages

No shared backend.  
No central logging.  
No vendor lock-in.

---

## ⚙️ Required Environment Variables

Set these in  
**Cloudflare Pages → Settings → Variables & Secrets**

| Name | Type | Required | Description |
|----|----|----|----|
| `UI_USER` | Secret | ✅ | Web console login username |
| `UI_PASS` | Secret | ✅ | Web console login password |
| `ADMIN_KEY` | Secret | ❌ Optional | Admin JSON access key |

> ℹ️ `ADMIN_KEY` ထည့်ထားရင်  
> `/health?admin=1` ကို **login မလုပ်ဘဲ**  
> `x-ech-admin-key` header နဲ့ access လုပ်နိုင်ပါတယ်။

---

## 🗄️ KV Binding (Optional but Recommended)

ECHGate သည် runtime config တွေကို  
**Cloudflare KV** ထဲမှာ သိမ်းပါတယ်။

### 1️⃣ Create KV Namespace
Cloudflare Dashboard → Workers & KV → KV → Create namespace

ဥပမာ:
