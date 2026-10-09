# 🔐 CyberShield — Password Security Tool

A privacy-first, fully client-side password analyzer and generator. It evaluates password strength using real-world attack models (zxcvbn), checks for breaches using the Have I Been Pwned k-anonymity API, and generates passwords with a cryptographically secure random number generator.

**Your password never leaves your device.** Only the first 5 characters of its SHA-1 hash are sent for the breach check, and you can switch that off.

---

## 🚀 Features

* 🔎 **Realistic strength analysis**: [zxcvbn](https://github.com/dropbox/zxcvbn) detects dictionary words, l33t substitutions, keyboard walks, sequences, repeats and dates
* 📊 **Effective vs. brute-force entropy**: shows both the realistic estimate and the theoretical maximum
* ⏱️ **Crack-time estimates** for a throttled online attack (10 guesses/s) and an offline GPU attack (10¹⁰ guesses/s)
* 🌐 **Breach detection** via Have I Been Pwned (k-anonymity, padded responses, opt-out toggle)
* 🔐 **Secure password generator**: `crypto.getRandomValues()` with rejection sampling, configurable length (12–64), character sets, and look-alike exclusion
* 📋 **Copy with auto-clearing clipboard** (30 s)
* 👁️ **Show/hide with auto-hide** (20 s) to protect against shoulder surfing
* ♿ Accessible: labelled controls, live regions, keyboard focus styles, reduced-motion support

---

## 🛡️ Security Design

| Area | Protection |
|---|---|
| Randomness | `crypto.getRandomValues()` with rejection sampling (no modulo bias), plus a Fisher–Yates shuffle |
| Breach check | SHA-1 prefix only (k-anonymity), `Add-Padding` header, no cookies, no referrer, `no-store` cache, abortable, race-safe |
| Data handling | Nothing is stored, logged or persisted. No password history, no keystroke timing, no `localStorage` |
| XSS | No `innerHTML`; all output goes through `textContent`. No inline scripts or event handlers |
| CSP | `default-src 'none'`, scripts/styles from `'self'` only, network limited to `api.pwnedpasswords.com` |
| Supply chain | zxcvbn is vendored locally and pinned with an SRI `sha512` hash (verified against cdnjs). No third-party fonts, icons or CDNs |
| Lifecycle | The input is wiped on `pagehide`, so the back/forward cache can't restore a typed password |
| Password managers | The input is marked so password managers don't offer to save it |
| HTTP headers | `_headers` sets CSP with `frame-ancestors 'none'`, HSTS, `nosniff`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP and `no-store` |

### Known limits

* JavaScript strings are immutable, so a password can't be reliably wiped from memory. The app keeps no references to it after each analysis.
* The clipboard auto-clear overwrites whatever is on the clipboard after 30 s, and runs once the tab regains focus if it was in the background.
* zxcvbn analyses the first 100 characters only. Characters beyond that get no extra credit (a conservative choice).

---

## 📂 Project Structure

```
project/
├── index.html        # Markup, CSP meta, inline SVG icon sprite
├── style.css         # Styles (system fonts, no external assets)
├── script.js         # App logic (strict-mode IIFE, no globals)
├── vendor/
│   └── zxcvbn.js     # zxcvbn 4.4.2, integrity-pinned
└── _headers          # Security headers for Netlify / Cloudflare Pages
```

---

## ▶️ How to Run

Serve the folder over HTTP. Opening `index.html` directly (`file://`) blocks the clipboard and integrity-checked scripts in some browsers.

```bash
python -m http.server 8000
# then open http://localhost:8000
```

### Deploying

* **Netlify / Cloudflare Pages**: deploy the folder as is; `_headers` is applied automatically.
* **GitHub Pages**: custom headers aren't supported, so the `<meta>` CSP in `index.html` is the fallback (it can't set `frame-ancestors` or HSTS).
* **Other hosts (nginx, Apache, Vercel)**: copy the headers from `_headers` into the server config.

### Updating zxcvbn

If you replace `vendor/zxcvbn.js`, regenerate the SRI hash and update the `integrity` attribute in `index.html`:

```bash
echo "sha512-$(openssl dgst -sha512 -binary vendor/zxcvbn.js | openssl base64 -A)"
```

---

## 🛠️ Technologies

HTML5 · CSS3 · Vanilla JavaScript · Web Crypto API · zxcvbn · Have I Been Pwned API

---

## 👨‍💻 Author

**Chekuri Satyanarayana Raja Varma**

---

## 📌 Project Goal

To show how password strength is evaluated in real-world systems, and to teach users how to create secure passwords, using a tool that is itself built to modern web-security standards.
