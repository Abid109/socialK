# socialK — CipherPost

Private end-to-end encrypted microblog. Posts are signed (Ed25519 + Schnorr), circle posts and DMs are
encrypted (X25519 + XChaCha20-Poly1305), and sync happens over Nostr relays, cross-tab BroadcastChannel,
and WebRTC P2P.

One codebase ships as:

| Target | How |
| --- | --- |
| **Website / PWA** (PC, iPad, phone) | Cloudflare Pages (`.github/workflows/cloudflare-pages.yml`) |
| **Android APK** | Capacitor + GitHub Actions (`.github/workflows/android-apk.yml`) → GitHub Releases |

All libraries and fonts are bundled, so the APK and the installed PWA work offline (relays/P2P need internet).

## Install

- **PC (Chrome/Edge):** open the site → install icon in the address bar (or Settings → Install App).
- **iPad / iPhone (Safari):** open the site → Share → **Add to Home Screen**.
- **Android:** download `CipherPost.apk` from the [Releases](../../releases/latest) page and install it
  (allow "install unknown apps" for your browser/files app).

## One-time setup in GitHub

Repo → **Settings → Secrets and variables → Actions**

### Website (Cloudflare Pages)
Secrets: `CLOUDFLARE_API_TOKEN` (template "Edit Cloudflare Workers", plus **Cloudflare Pages: Edit**), `CLOUDFLARE_ACCOUNT_ID`
Variables: `CLOUDFLARE_PROJECT_NAME` (default `cipherpost` → `https://cipherpost.pages.dev`)

*Alternative without secrets:* Cloudflare dashboard → Workers & Pages → Create → Pages → connect this repo →
build command `npm run build`, output directory `dist`.

### APK
Variable: `PUBLIC_URL` = your website address (e.g. `https://cipherpost.pages.dev`) so profile links shared from the app open the site.

Optional, for a properly signed release APK (keeps updates installable over each other). Without these the APK
is signed with a debug key, which still installs fine:
```bash
keytool -genkeypair -v -keystore release.keystore -alias cipherpost -keyalg RSA -keysize 2048 -validity 10000
base64 -w0 release.keystore   # paste as ANDROID_KEYSTORE_BASE64
```
Secrets: `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`.
**Back up that keystore** — losing it means users must uninstall to update.

Every push to `main` builds a new APK and publishes it to Releases; pushing a tag like `v1.0.1` publishes a versioned release.

## Develop

```bash
npm install
npm run dev      # local dev server
npm run build    # production build into dist/
```

Replace the icon by editing the images in `assets/` and `public/icons/`.
