/* Vault100 service worker — the counter works with the cable severed.
 *
 * Precaches this exact build (version-stamped URLs) after the first visit:
 *  - same-origin versioned assets: cache-first (immutable per release)
 *  - navigations: network-first, so every visit pulls the freshest form
 *    when the network is present and falls back to the cached form offline
 * Old version caches are destroyed on activation.
 */
"use strict";

const VERSION = "223";
const CACHE = "vault100-" + VERSION;
const Q = "?v=" + VERSION;
const ASSETS = [
  "/",
  "/index.html",
  "/seal.html",
  "/open.html",
  "/annex.html",
  "/rewrap.html",
  "/armor.html",
  "/about.html",
  "/features.html",
  "/faq.html",
  "/get.html",
  "/privacy.html",
  "/terms.html",
  "/bureau.css" + Q,
  "/common.js" + Q,
  "/seal.js" + Q,
  "/open.js" + Q,
  "/annex.js" + Q,
  "/rewrap.js" + Q,
  "/armor.js" + Q,
  "/worker.js" + Q,
  "/vault-format.js" + Q,
  "/vendor/libsodium-sumo.js" + Q,
  "/vendor/libsodium-wrappers.js" + Q,
  "/vendor/argon2.js" + Q,
  "/vendor/argon2.wasm" + Q,
  "/vendor/qrcode.js" + Q,
  "/manifest.json",
  "/icon.svg",
  "/icon-maskable.svg",
  "/icons/icon-16.png",
  "/icons/icon-32.png",
  "/icons/icon-180.png",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
  "/icons/icon-maskable-192.png",
  "/icons/icon-maskable-512.png",
];

self.addEventListener("install", (e) => {
  e.waitUntil(
    caches.open(CACHE)
      .then((c) => c.addAll(ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin) return;   // nothing external anyway (CSP)

  if (e.request.mode === "navigate") {
    e.respondWith(
      fetch(e.request).then((r) => {
        const copy = r.clone();
        const key = url.pathname === "/" ? "/index.html" : url.pathname;
        caches.open(CACHE).then((c) => c.put(key, copy));
        return r;
      }).catch(() =>
        caches.match(e.request).then((m) => m ||
          caches.match(url.pathname).then((m2) => m2 || caches.match("/index.html"))))
    );
    return;
  }

  e.respondWith(
    caches.match(e.request, { ignoreSearch: false })
      .then((hit) => hit || fetch(e.request).then((r) => {
        if (r.ok) {
          const copy = r.clone();
          caches.open(CACHE).then((c) => c.put(e.request, copy));
        }
        return r;
      }))
  );
});
