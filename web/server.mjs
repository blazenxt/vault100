/* Vault100-web — zero-dependency static server for Railway / any PaaS.
 *
 * Node >= 20, no npm packages. Preloads web/ into memory at boot:
 *   • correct application/wasm MIME (required for WebAssembly streaming)
 *   • hardened headers on every response (CSP locks the app to self-only)
 *   • gzip responses (pre-compressed at boot), ETag + 304 support
 *   • /health endpoint for Railway health checks
 *   • honors $PORT (Railway injects it), defaults to 8080
 */
import { createServer } from "node:http";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, extname, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)));
const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || "0.0.0.0";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".wasm": "application/wasm",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".webmanifest": "application/manifest+json",
};
const COMPRESSIBLE = new Set([".html", ".js", ".mjs", ".css", ".json",
                              ".map", ".svg", ".txt", ".xml", ".webmanifest"]);

const SEC_HEADERS = {
  "Content-Security-Policy":
    "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; " +
    "worker-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
    "connect-src 'self'; font-src 'none'; form-action 'none'; " +
    "base-uri 'none'; manifest-src 'self'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
};

/* ---- preload the whole site into memory (traversal-proof by design) ---- */
const files = new Map();   // urlpath -> { buf, gz, mime, etag, cacheable }
(function walk(dir) {
  for (const entry of readdirSync(dir)) {
    if (entry.startsWith(".")) continue;
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) { walk(full); continue; }
    if (entry === "server.mjs" || !st.isFile()) continue;
    const url = "/" + full.slice(ROOT.length + 1).split("\\").join("/");
    const buf = readFileSync(full);
    const ext = extname(entry).toLowerCase();
    const etag = '"' + createHash("sha256")
      .update(buf).digest("hex").slice(0, 16) + '"';
    const gz = COMPRESSIBLE.has(ext) && buf.length > 1024
      ? gzipSync(buf, { level: 9 }) : null;
    const inVendor = url.startsWith("/vendor/");
    files.set(url, {
      buf, gz, etag,
      mime: MIME[ext] || "application/octet-stream",
      cacheable: inVendor,      // hashed-by-release assets: cache a week
    });
  }
})(ROOT);
console.log(`vault100-web: preloaded ${files.size} assets from ${ROOT}`);

const server = createServer((req, res) => {
  try {
    if (req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(405, { Allow: "GET, HEAD" });
      return res.end();
    }
    if (req.url === "/health") {
      res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
      return res.end("ok");
    }

    // normalize: strip query, resolve / → /index.html, never escape ROOT
    let path = req.url.split("?")[0].split("#")[0];
    try { path = decodeURIComponent(path); } catch { path = "/"; }
    if (path.includes("\0") || path.includes("..")) {
      res.writeHead(400); return res.end("bad request");
    }
    if (path === "/") path = "/index.html";
    if (path.endsWith("/")) path += "index.html";

    const f = files.get(path);
    if (!f) {
      res.writeHead(404, { ...SEC_HEADERS,
        "Content-Type": "text/plain; charset=utf-8" });
      return res.end("404 — not found");
    }

    if (req.headers["if-none-match"] === f.etag) {
      res.writeHead(304, { ETag: f.etag }); return res.end();
    }

    const wantsGzip = f.gz &&
      String(req.headers["accept-encoding"] || "").includes("gzip");
    const headers = {
      ...SEC_HEADERS,
      "Content-Type": f.mime,
      ETag: f.etag,
      Vary: "Accept-Encoding",
      "Cache-Control": f.cacheable
        ? "public, max-age=604800, immutable"
        : "no-cache",
    };
    let body = f.buf;
    if (wantsGzip) {
      body = f.gz;
      headers["Content-Encoding"] = "gzip";
    }
    headers["Content-Length"] = body.length;
    res.writeHead(200, headers);
    if (req.method === "HEAD") return res.end();
    res.end(body);
  } catch (e) {
    res.writeHead(500); res.end("error");
    console.error(e);
  }
});

server.listen(PORT, HOST, () =>
  console.log(`vault100-web listening on http://${HOST}:${PORT} ` +
              `(health: /health)`));
