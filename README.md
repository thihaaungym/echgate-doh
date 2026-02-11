<p align="center">
  <img src="assets/echgate-logo.png" alt="ECHGate Logo" width="120">
</p>

<h1 align="center">ECHGate — DNS-over-HTTPS on Cloudflare Pages</h1>

<p align="center">
  Secure, deploy-your-own <b>DNS-over-HTTPS (DoH)</b> gateway with Web UI, Health API & DPI detection
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Cloudflare-Pages-orange?logo=cloudflare&logoColor=white">
  <img src="https://img.shields.io/badge/DoH-DNS--over--HTTPS-blue">
  <img src="https://img.shields.io/badge/Multi--Tenant-Friendly-success">
</p>

---

## 🔐 What is ECHGate?

**ECHGate** သည်  
Cloudflare Pages + Workers ပေါ်တွင် chạy နေတဲ့  
**deploy-your-own DNS-over-HTTPS gateway** ဖြစ်ပြီး

- Web UI ပါတယ်  
- Health JSON / HTML ပါတယ်  
- GET / POST toggle ပါတယ်  
- DPI throttling / anomaly ကို heuristic နည်းလမ်းနဲ့ detect လုပ်ပေးတယ်  

👉 **User တစ်ယောက်ချင်းစီက ကိုယ်ပိုင် Cloudflare account + domain နဲ့ deploy လုပ်သုံးနိုင်အောင် design လုပ်ထားတာ** ဖြစ်ပါတယ်။

---

## ✨ Features

### 🌐 DoH Endpoints
- `/dns-query` → AUTO fallback
- `/dns-query/cf` → Cloudflare
- `/dns-query/cf-sec` → Cloudflare (secure profile)
- `/dns-query/gg` → Google

### 🖥️ Web UI
- Username / Password login
- Copy-ready DoH URLs
- GET mode toggle (Remote DNS compatible)
- Live counters, latency & upstream health
- DPI indicator badge (OK / WARN)

### 🩺 Health API
- `/health`  
  → Public JSON (API)  
  → Human-readable HTML (browser)

- `/health?admin=1`  
  → Full admin JSON  
  → Access via **login session** OR **admin key**

### 🔒 Security
- Strict CSP
- `Cache-Control: no-store`
- HttpOnly auth cookie
- Optional `x-ech-admin-key` header
- POST origin validation

### 🧠 Architecture
- No shared backend
- No central logging
- Each deployment isolated (multi-tenant by design)
- Safe for censorship-resistant DNS setups

---

## 📸 Web Console Preview

<p align="center">
  <img src="assets/ui.png" alt="ECHGate Web UI" width="360">
</p>

---

## 🚀 One-Click Deploy (Cloudflare Pages)

> Each user deploys on **their own Cloudflare account & domain**

[![Deploy to Cloudflare Pages](https://deploy.workers.cloudflare.com/button)](https://dash.cloudflare.com/?to=pages)

---

## ⚙️ Required Environment Variables

Configure in  
**Cloudflare Pages → Settings → Variables & Secrets**

| Name | Type | Required | Description | Example |
|----|----|----|----|----|
| `UI_USER` | Secret | ✅ | Web console username | `admin` |
| `UI_PASS` | Secret | ✅ | Web console password | `strong-password-123` |
| `ADMIN_KEY` | Secret | ❌ Optional | Admin JSON access key | `echgate-admin-key-change-me` |

> ℹ️ `ADMIN_KEY` ထည့်ထားရင်  
> `/health?admin=1` ကို  
> **login မလုပ်ဘဲ**  
> `x-ech-admin-key` header နဲ့ access လုပ်နိုင်ပါတယ်။

---

## 🗄️ KV Binding (Optional but Recommended)

ECHGate သည် runtime state ကို **Cloudflare KV** မှာသိမ်းပါတယ်။

### 1️⃣ Create KV Namespace

Cloudflare Dashboard →  
**Workers & Pages → KV → Create namespace**

ဥပမာ
