/* Vault100 service worker — the counter works with the cable severed.
 *
 * Precaches this exact build (version-stamped URLs) after the first visit:
 *  - same-origin versioned assets: cache-first (immutable per release)
 *  - navigations: network-first, so every visit pulls the freshest form
 *    when the network is present and falls back to the cached form offline
 * Old version caches are destroyed on activation.
 */
"use strict";

const VERSION = "208";
const CACHE = "vault100-" + VERSION;
const Q = "?v=" + VERSION;
const ASSETS = [
  "/",
  "/index.html",
  "/app.js" + Q,
  "/worker.js" + Q,
  "/vault-format.js" + Q,
  "/vendor/libsodium-sumo.js" + Q,
  "/vendor/libsodium-wrappers.js" + Q,
  "/vendor/argon2.js" + Q,
  "/vendor/argon2.wasm" + Q,
  "/manifest.json",
  "/icon.svg",
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
        caches.open(CACHE).then((c) => c.put("/index.html", copy));
        return r;
      }).catch(() =>
        caches.match("/index.html").then((m) => m || caches.match("/")))
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
