/* Vault100 web worker — runs all cryptography off the main thread.
 * Loads vendored libsodium + argon2 (WASM, local only — no network).
 */
"use strict";

const V = "?v=210";
importScripts("vendor/libsodium-sumo.js" + V);
importScripts("vendor/libsodium-wrappers.js" + V);
importScripts("vendor/argon2.js" + V);
importScripts("vault-format.js" + V);

let ready = false;
let cancelJob = null;

// argon2-browser: serve the WASM binary ourselves (relative to worker scope)
self.loadArgon2WasmBinary = () =>
  fetch("vendor/argon2.wasm?v=210").then((r) => {
    if (!r.ok) throw new Error("argon2.wasm failed to load (HTTP " + r.status + ")");
    return r.arrayBuffer();
  });

async function init() {
  await sodium.ready;
  VaultFormat.setEnv({
    sodium,
    subtle: self.crypto.subtle,
    randbytes: (n) => {
      const b = new Uint8Array(n);
      self.crypto.getRandomValues(b);
      return b;
    },
    argon2Hash: async (o) => {
      const r = await argon2.hash({
        pass: o.pass, salt: o.salt, time: o.time, mem: o.mem,
        parallelism: o.parallelism, hashLen: o.hashLen,
        type: argon2.ArgonType.Argon2id,  // bundle hardcodes version 0x13
      });
      return r.hash;
    },
  });
  ready = true;
  postMessage({ type: "ready" });
}

function postProgress(id, done, total) {
  postMessage({ type: "progress", id, done, total });
}

async function runJob(msg) {
  const { id, op } = msg;
  const progress = (done, total) => postProgress(id, done, total);
  const shouldCancel = () => cancelJob === id;
  try {
    if (op === "selftest") {
      const ok = await VaultFormat.runSelfTest();
      postMessage({ type: "selftest", ok });
      return;
    }
    if (op === "calibrate") {
      const params = await VaultFormat.calibrateKdf(2.0);
      postMessage({ type: "calibrated", id, params });
      return;
    }
    if (op === "info") {
      const head = new Uint8Array(
        await msg.file.slice(0, 4096).arrayBuffer());
      const info = VaultFormat.info(head);
      info.name = msg.file.name;
      postMessage({ type: "info", id, info });
      return;
    }
    // keyfile bytes arrive raw — digest them exactly like the CLI does
    const keyDigest = msg.keyData
      ? VaultFormat.keyfileDigest(new Uint8Array(msg.keyData)) : null;
    if (op === "encrypt") {
      const res = await VaultFormat.encryptVault(msg.file, {
        password: msg.password, profile: msg.profile,
        params: msg.params || null, keyData: keyDigest,
        cascade: !!msg.cascade, metaBaseName: msg.file.name,
        onProgress: progress, shouldCancel,
        onKdfFold: (mem) => postMessage({ type: "kdf-fold", id, mem }),
      });
      const buffers = res.parts.map((p) => p.buffer.slice(0));
      postMessage({ type: "done", id, op, name: msg.file.name + ".v100",
                    parts: buffers, length: res.length }, buffers);
      return;
    }
    if (op === "decrypt") {
      const res = await VaultFormat.decryptVault(msg.file, {
        password: msg.password, keyData: keyDigest,
        onProgress: progress, shouldCancel,
      });
      const sane = String(res.meta.name || "decrypted.bin")
        .replace(/[\\/:*?"<>|]/g, "_").replace(/^\.+/, "").slice(0, 255)
        || "decrypted.bin";
      const buffers = res.parts.map((p) => p.buffer.slice(0));
      postMessage({ type: "done", id, op, name: sane, meta: res.meta,
                    parts: buffers, length: res.length }, buffers);
      return;
    }
    throw new Error("unknown op " + op);
  } catch (e) {
    postMessage({ type: "error", id, op,
                  kind: (e && e.constructor && e.constructor.name) || "Error",
                  message: (e && e.message) || String(e) });
  } finally {
    if (msg.password && msg.password.fill) msg.password.fill(0); // best effort
    if (msg.keyData && msg.keyData.fill) msg.keyData.fill(0);
    if (cancelJob === id) cancelJob = null;
  }
}

const queue = [];
let busy = false;
async function pump() {
  if (busy) return;
  busy = true;
  while (queue.length) {
    const job = queue.shift();
    if (cancelJob === job.id) { cancelJob = null; continue; }
    await runJob(job);
  }
  busy = false;
}

self.onmessage = async (e) => {
  const msg = e.data;
  if (msg.type === "cancel") { cancelJob = msg.id; return; }
  if (!ready) { await init(); }
  queue.push(msg);
  pump();
};

init();
