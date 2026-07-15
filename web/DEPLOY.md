# 🚀 Deploying Vault100-web

The web edition is a **static, zero-knowledge site**: HTML/JS/WASM only.
There is no backend, no database, nothing to hack on the server side —
visitors' files and passwords never leave their browsers.

- **Option A — Railway** *(below: fastest path, auto-TLS, zero maintenance)*
- **Option B — your own VPS** *(further down: Caddy/Nginx + manual domain)*

---

# Option A — Railway

The repo ships everything Railway needs:

| File | Purpose |
|---|---|
| `Dockerfile` | `node:20-alpine`, non-root, built-in healthcheck |
| `railway.toml` | pins the Dockerfile builder + `/health` healthcheck |
| `web/server.mjs` | zero-dependency static server (preloads assets, `application/wasm`, hardened CSP/HSTS headers, gzip, ETag/304, honors Railway's injected `$PORT`) |
| `package.json` | lets Nixpacks run it too (`npm start`), no dependencies at all |

## Steps

1. **Push the repo to GitHub** (already done — `blazenxt/vault100`).
2. [railway.com](https://railway.com) → **New Project** → **Deploy from GitHub repo** → select **`blazenxt/vault100`**.
3. Railway detects the `Dockerfile` automatically and deploys. Wait for the
   healthcheck to go green (it pings `/health`).
4. **Domain:** Settings → **Networking** →
   - *Generate Domain* for a quick `*.up.railway.app` URL, and/or
   - **Custom Domain** → enter `vault100.blazenxt.in` → Railway shows a
     **CNAME target** (e.g. `abcd123.up.railway.app`).
5. **DNS at your registrar:** create
   `vault100.blazenxt.in  CNAME  <target Railway shows>`.
6. Railway provisions **TLS automatically** — done. ✅

Verify: open the site; the badge at the top must say **green** —
"cryptographically verified — engine decrypts desktop vaults byte-exactly".

## Local dry-run (exactly what Railway runs)

```bash
cd web && PORT=8080 node server.mjs     # then open http://localhost:8080
# or with Docker:
docker build -t vault100-web . && docker run -p 8080:8080 vault100-web
```

---

# Option B — VPS (Caddy/Nginx, manual TLS)

The web/ folder can also be hosted on a plain VPS at `vault100.blazenxt.in`.

Create an **A record** (or AAAA) in the BlazeNXT DNS panel:

```
vault100.blazenxt.in   A   <your server IPv4>
```

## 2. Copy the site

The document root is exactly the `web/` folder:

```
web/
├─ index.html          app shell + CSP + styles
├─ app.js              UI controller (main thread)
├─ worker.js           crypto worker (runs off-thread)
├─ vault-format.js     the .v100 format engine (bit-compatible with CLI)
└─ vendor/
   ├─ libsodium-sumo.js        libsodium WASM build
   ├─ libsodium-wrappers.js    libsodium JS API
   ├─ argon2.js               Argon2 browser bundle (WASM loader)
   └─ argon2.wasm             Argon2 binary
```

Everything is **vendored — zero third-party/CDN requests**. That's a
feature: visitors never trust an external script source.

```bash
rsync -avz web/ user@your-vps:/var/www/vault100/
```

## 3. Serve with Caddy (recommended — automatic HTTPS)

`/etc/caddy/Caddyfile`:

```caddy
vault100.blazenxt.in {
    root * /var/www/vault100
    file_server
    encode zstd gzip

    header {
        # the meta-CSP in index.html covers browsers; this covers everything else
        Content-Security-Policy "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; font-src 'none'; form-action 'none'; base-uri 'none'"
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        Cross-Origin-Opener-Policy "same-origin"
        Referrer-Policy "no-referrer"
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
        -Server
    }

    # Argon2 + libsodium must load as application/wasm
    @wasm path *.wasm
    header @wasm Content-Type application/wasm
    header @wasm Cache-Control "public, max-age=604800"
}
```

```bash
sudo systemctl reload caddy    # Caddy fetches & renews the Let's Encrypt cert
```

## 3b. …or Nginx + Certbot

```nginx
server {
    listen 443 ssl http2;
    server_name vault100.blazenxt.in;
    root /var/www/vault100;
    index index.html;

    ssl_certificate     /etc/letsencrypt/live/vault100.blazenxt.in/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vault100.blazenxt.in/privkey.pem;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;
    add_header Cross-Origin-Opener-Policy same-origin always;
    add_header Content-Security-Policy "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; font-src 'none'; form-action 'none'; base-uri 'none'" always;

    location ~ \.wasm$ { types { application/wasm wasm; } }
    location / { try_files $uri =404; }
}
```

```bash
sudo certbot --nginx -d vault100.blazenxt.in
```

## 4. Smoke-test locally first

```bash
cd web && python3 -m http.server 8080
# open http://localhost:8080 — the top badge must turn GREEN:
# "cryptographically verified — engine decrypts desktop vaults byte-exactly"
```

That badge is a **live cryptographic self-test**: on every page load, the
engine decrypts a real vault produced by the Python CLI. If a deploy, CDN
rewrite, or bad edit ever corrupts the crypto, the badge goes red and users
are warned *before* trusting the build.

## ⚠️ Operational security rules

1. **Never wrap this in an API that receives files/passwords.** The moment
   plaintext touches the server, the "zero-knowledge" guarantee dies.
2. **HTTPS is mandatory** — TLS protects the *code* from being swapped in
   transit. Caddy handles it automatically.
3. **Log minimally.** Access logs only record static-file GETs — nothing
   sensitive can be logged because nothing sensitive is sent. Keep it that way.
4. **Serve from infrastructure you control**, no CDN injection, no tag
   managers, no analytics scripts. `connect-src 'none'` in the CSP already
   neuters exfiltration attempts by XSS-injected scripts.
5. Backups: the site is rebuildable from this repo; vaults belong to users.

## Interop cheat-sheet

| Path | Works |
|---|---|
| CLI `.v100` (password) → web decrypt | ✅ |
| web `.v100` (password) → CLI decrypt | ✅ |
| cascade vaults both directions | ✅ |
| keyfile vaults both directions | ✅ |
| v1 (first-gen) vaults | CLI/desktop only — re-encrypt to upgrade |
