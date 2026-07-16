/* Vault100 — shared format logic (environment-agnostic ES module-free file).
 *
 * Implements the exact Vault100 v2 container so web vaults and the
 * Python CLI/desktop app are 100% interoperable. All crypto runs locally —
 * in a browser Worker (zero-knowledge hosting) or in Node for testing.
 *
 * Layout:  see crypto_core.py. Little-endian everywhere.
 *
 *  0   8   magic "V100ENC2"
 *  8   1   version | 9   1 kdf | 10 4 mem-KiB | 14 4 time | 18 1 par
 * 19   1   flags (bit0 cascade, bit1 keyfile)
 * 20  32   salt   | 52 24 wrap-nonce | wrapped FEK (len+16, 48/80)
 * then 24-byte secretstream header, then [u32 len][ciphertext] chunks.
 */
(function (root) {
  "use strict";

  const MAGIC_V1 = "V100ENC1", MAGIC_V2 = "V100ENC2";
  const CHUNK_SIZE = 1024 * 1024;
  const META_MAX = 4096;
  const ABYTES = 17, GCM_TAG = 16;
  const TAG_MESSAGE = 0, TAG_FINAL = 3;
  const FLAG_CASCADE = 1, FLAG_KEYFILE = 2;
  const MAX_MEM_KIB = 4 * 1024 * 1024, MAX_TIME = 64, MAX_PAR = 16;

  const KDF_PROFILES = {
    standard: { memoryKib: 128 * 1024, timeCost: 3, parallelism: 4 },
    paranoid: { memoryKib: 512 * 1024, timeCost: 4, parallelism: 4 },
  };

  /* Environment is injected by the loader (worker / node):
     { sodium, argon2Hash(params)->Uint8Array, subtle, randbytes } */
  let ENV = null;
  function setEnv(env) { ENV = env; }
  function needEnv() {
    if (!ENV) throw new Error("VaultFormat.setEnv() not called");
    return ENV;
  }

  // -- tiny byte helpers ----------------------------------------------------
  const te = new TextEncoder(), td = new TextDecoder();
  const u8 = (s) => te.encode(s);
  function concat(...arrs) {
    const n = arrs.reduce((a, b) => a + b.length, 0);
    const out = new Uint8Array(n);
    let o = 0;
    for (const a of arrs) { out.set(a, o); o += a.length; }
    return out;
  }
  function le32(n) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n, true);
    return b;
  }
  function rd32(buf, off) { return new DataView(buf.buffer, buf.byteOffset + off).getUint32(0, true); }
  function b64d(s) {
    const bin = root.atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  class VaultError extends Error {}
  class VaultAuthError extends VaultError {}
  class VaultFormatError extends VaultError {}
  class VaultCancelled extends VaultError {}

  // -- KDF ------------------------------------------------------------------
  async function argon2id(passwordBytes, salt, p) {
    const { argon2Hash } = needEnv();
    return new Uint8Array(await argon2Hash({
      pass: passwordBytes, salt, time: p.timeCost,
      mem: p.memoryKib, parallelism: p.parallelism,
      hashLen: 32, version: 19,
    }));
  }

  async function hkdfSha256(ikm, salt, info, length = 32) {
    const { subtle } = needEnv();
    const importKey = (kb, usage) =>
      subtle.importKey("raw", kb, { name: "HMAC", hash: "SHA-256" }, false, [usage]);
    const prkKey = await importKey(salt, "sign");
    const prk = new Uint8Array(await subtle.sign("HMAC", prkKey, ikm));
    let out = new Uint8Array(0), block = new Uint8Array(0), i = 1;
    while (out.length < length) {
      const key = await importKey(prk, "sign");
      block = new Uint8Array(await subtle.sign(
        "HMAC", key, concat(block, info, new Uint8Array([i++]))));
      out = concat(out, block);
    }
    return out.slice(0, length);
  }

  async function deriveKek(passwordBytes, salt, params, keyData) {
    const raw = new Uint8Array(await argon2id(passwordBytes, salt, params));
    if (!keyData) return raw;
    return hkdfSha256(concat(raw, keyData), salt, u8("V100-KEK-v2"), 32);
  }

  /** Keyfile digest — MUST match keyfile.load_keyfile (keyed BLAKE2b). */
  function keyfileDigest(bytes) {
    const { sodium } = needEnv();
    const magic = u8("V100KEY1");
    let data = bytes;
    if (data.length > magic.length &&
        magic.every((b, i) => data[i] === b)) data = data.subarray(magic.length);
    return sodium.crypto_generichash(32, data, u8("Vault100-KF-v2"));
  }

  function generateKeyfileBytes(rand) {
    const { randbytes } = needEnv();
    return concat(u8("V100KEY1"), (rand || randbytes)(32));
  }

  // -- AES-GCM cascade layer -------------------------------------------------
  async function aesImport(keyBytes) {
    const { subtle } = needEnv();
    return subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false,
                            ["encrypt", "decrypt"]);
  }
  function ctrNonce(i) {
    const n = new Uint8Array(12);
    new DataView(n.buffer).setUint32(0, i >>> 0, true);
    new DataView(n.buffer).setUint32(4, Math.floor(i / 2 ** 32), true);
    return n;
  }
  async function aesEnc(key, i, data, aad) {
    const { subtle } = needEnv();
    return new Uint8Array(await subtle.encrypt(
      { name: "AES-GCM", iv: ctrNonce(i), additionalData: aad }, key, data));
  }
  async function aesDec(key, i, data, aad) {
    const { subtle } = needEnv();
    try {
      return new Uint8Array(await subtle.decrypt(
        { name: "AES-GCM", iv: ctrNonce(i), additionalData: aad }, key, data));
    } catch (e) {
      throw new VaultAuthError("cascade layer: authentication failed");
    }
  }

  function validateKdf(mem, t, par) {
    if (!(mem >= 8 && mem <= MAX_MEM_KIB)) throw new VaultFormatError("header KDF memory out of range");
    if (!(t >= 1 && t <= MAX_TIME)) throw new VaultFormatError("header KDF time out of range");
    if (!(par >= 1 && par <= MAX_PAR)) throw new VaultFormatError("header KDF parallelism out of range");
  }

  // -- header parse (v2 fixed part) -----------------------------------------
  function parsePrefix(buf) {
    if (buf.length < 52) throw new VaultFormatError("file too short");
    const magic = td.decode(buf.subarray(0, 8));
    if (magic === MAGIC_V1) throw new VaultFormatError(
      "v1 vault — use the desktop/CLI Vault100 to open this file");
    if (magic !== MAGIC_V2) throw new VaultFormatError("not a Vault100 vault");
    const mem = rd32(buf, 10), t = rd32(buf, 14);
    const par = buf[18], flags = buf[19];
    if (buf[8] !== 2) throw new VaultFormatError("unsupported version");
    if (buf[9] !== 1) throw new VaultFormatError("unknown KDF");
    if (flags & ~(FLAG_CASCADE | FLAG_KEYFILE)) throw new VaultFormatError("unknown flags");
    validateKdf(mem, t, par);
    return { mem, t, par, flags, salt: buf.subarray(20, 52) };
  }

  /** Non-secret header facts (CLI `vault100 info` parity). */
  function info(bytes) {
    const h = parsePrefix(bytes.subarray(0, 52));
    return {
      format: 2,
      cascade: !!(h.flags & FLAG_CASCADE),
      keyfile: !!(h.flags & FLAG_KEYFILE),
      kdf: { memoryKib: h.mem, timeCost: h.t, parallelism: h.par },
      size: bytes.length,
    };
  }

  // -- encryption ------------------------------------------------------------
  /**
   * Encrypt a Blob/File into Vault100 v2 bytes.
   * opts: { password, profile|params, keyData?, cascade?, metaBaseName,
   *         onProgress(done,total), shouldCancel() }
   * Returns Uint8Array chunks array + total length {parts, length, meta}.
   */
  async function encryptVault(file, opts) {
    const { sodium, randbytes } = needEnv();
    const p = opts.params || KDF_PROFILES[opts.profile || "standard"];
    if (!p || !Number.isFinite(p.memoryKib) ||
        !Number.isFinite(p.timeCost) || !Number.isFinite(p.parallelism))
      throw new VaultFormatError("invalid KDF parameters");
    validateKdf(p.memoryKib, p.timeCost, p.parallelism);
    const cascade = !!opts.cascade;
    const total = file.size;

    const salt = randbytes(32);
    const fek = randbytes(cascade ? 64 : 32);
    const kek = await deriveKek(opts.password, salt, p, opts.keyData || null);
    const wnonce = randbytes(24);
    const wrapped = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      fek, null, null, wnonce, kek);
    kek.fill(0);

    const flags = (cascade ? FLAG_CASCADE : 0) | (opts.keyData ? FLAG_KEYFILE : 0);
    const fixed = new Uint8Array(52);
    fixed.set(concat(u8(MAGIC_V2), new Uint8Array([2, 1]),
                     le32(p.memoryKib), le32(p.timeCost),
                     new Uint8Array([p.parallelism, flags]), salt));

    const { state, header: streamHdr } =
      sodium.crypto_secretstream_xchacha20poly1305_init_push(fek.subarray(0, 32));
    const aesKey = cascade ? await aesImport(fek.subarray(32, 64)) : null;
    fek.fill(0);

    const streamCtx = concat(u8("V100-CTX"), streamHdr);
    const parts = [fixed, wnonce, wrapped, streamHdr];
    let length = 52 + 24 + wrapped.length + 24;
    let idx = 0;

    async function seal(msg) {
      let out = msg;
      if (aesKey) out = await aesEnc(aesKey, idx, out, streamCtx);
      idx++;
      return out;
    }
    function push(state, msg, aad, tag) {
      const ct = sodium.crypto_secretstream_xchacha20poly1305_push(
        state, msg, aad, tag);
      parts.push(le32(ct.length), ct);
      length += 4 + ct.length;
    }

    const meta = Object.assign({ name: opts.metaBaseName || "file", v: 2 },
                               opts.metadata || {});
    let metaBlob = u8(JSON.stringify(meta));
    if (metaBlob.length > META_MAX) throw new VaultError("metadata too large");
    push(state, await seal(metaBlob), streamCtx, TAG_MESSAGE);

    let done = 0, offset = 0;
    while (true) {
      if (opts.shouldCancel && opts.shouldCancel()) throw new VaultCancelled();
      const end = Math.min(offset + CHUNK_SIZE, total);
      const chunk = new Uint8Array(await file.slice(offset, end).arrayBuffer());
      const isFinal = end >= total;
      push(state, await seal(chunk), null, isFinal ? TAG_FINAL : TAG_MESSAGE);
      done += chunk.length;
      offset = end;
      if (opts.onProgress) await opts.onProgress(done, total);
      if (isFinal) break;
    }
    return { parts, length, meta };
  }

  // -- decryption ------------------------------------------------------------
  /**
   * Decrypt Vault100 bytes → { parts:[Uint8Array], length, meta }.
   * opts: { password, keyData?, onProgress(done,total), shouldCancel() }
   */
  async function decryptVault(blob, opts) {
    const { sodium } = needEnv();
    const prefix = new Uint8Array(await blob.slice(0, 52).arrayBuffer());
    const h = parsePrefix(prefix);
    if ((h.flags & FLAG_KEYFILE) && !opts.keyData) {
      throw new VaultError("this vault requires its keyfile");
    }
    const cascade = !!(h.flags & FLAG_CASCADE);
    const fekLen = cascade ? 64 : 32;
    const hdrRest = new Uint8Array(
      await blob.slice(52, 76 + fekLen + 16 + 24).arrayBuffer());
    if (hdrRest.length < 24 + fekLen + 16 + 24) {
      throw new VaultFormatError("truncated header");
    }
    const wnonce = hdrRest.subarray(0, 24);
    const wrapped = hdrRest.subarray(24, 24 + fekLen + 16);
    const streamHdr = hdrRest.subarray(24 + fekLen + 16,
                                       24 + fekLen + 16 + 24);
    const streamCtx = concat(u8("V100-CTX"), streamHdr);

    const kek = await deriveKek(opts.password, h.salt,
      { memoryKib: h.mem, timeCost: h.t, parallelism: h.par },
      opts.keyData || null);
    let fek;
    try {
      fek = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, wrapped, null, wnonce, kek);
    } catch (e) {
      throw new VaultAuthError("wrong password/keyfile or corrupted vault");
    } finally {
      kek.fill(0);
    }
    const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(
      streamHdr, fek.subarray(0, 32));
    const aesKey = cascade && fek.length >= 64
      ? await aesImport(fek.subarray(32, 64)) : null;
    fek.fill(0);

    const parts = [];
    let length = 0, idx = 0, meta = null, sawFinal = false;
    let off = 52 + 24 + fekLen + 16 + 24;
    const total = blob.size;

    while (true) {
      if (opts.shouldCancel && opts.shouldCancel()) throw new VaultCancelled();
      const lenBuf = new Uint8Array(await blob.slice(off, off + 4).arrayBuffer());
      if (lenBuf.length === 0)
        throw new VaultFormatError("truncated: no end-of-stream marker");
      if (lenBuf.length < 4) throw new VaultFormatError("truncated chunk");
      const ctLen = new DataView(lenBuf.buffer).getUint32(0, true);
      const maxCt = CHUNK_SIZE + GCM_TAG + ABYTES;
      if (ctLen < ABYTES || ctLen > maxCt)
        throw new VaultFormatError("invalid chunk length");
      const ct = new Uint8Array(
        await blob.slice(off + 4, off + 4 + ctLen).arrayBuffer());
      if (ct.length !== ctLen) throw new VaultFormatError("truncated chunk");
      off += 4 + ctLen;

      let res;
      try {
        res = sodium.crypto_secretstream_xchacha20poly1305_pull(
          state, ct, meta === null ? streamCtx : null);
      } catch (e) {
        throw new VaultAuthError("wrong password/keyfile or corrupted vault");
      }
      if (!res) throw new VaultAuthError("authentication failed");
      let payload = res.message;
      if (aesKey) payload = await aesDec(aesKey, idx, payload, streamCtx);
      idx++;

      if (meta === null) {
        if (res.tag !== TAG_MESSAGE || payload.length > META_MAX)
          throw new VaultFormatError("invalid metadata chunk");
        try { meta = JSON.parse(td.decode(payload)); }
        catch (e) { throw new VaultFormatError("corrupt metadata"); }
        if (typeof meta !== "object" || meta === null)
          throw new VaultFormatError("corrupt metadata");
        continue;
      }
      parts.push(payload);
      length += payload.length;
      if (opts.onProgress) await opts.onProgress(Math.min(off, total), total);
      if (res.tag === TAG_FINAL) { sawFinal = true; break; }
    }
    if (!sawFinal) throw new VaultFormatError("missing final chunk");
    if (off < total) throw new VaultFormatError("trailing data after stream");
    return { parts, length, meta };
  }

  // -- KDF calibration ("max") -----------------------------------------------
  /* Browsers vary wildly in how much WASM memory Argon2 may grab. Sample at
     64 MiB first; if the device refuses, step down until one works. Then
     extrapolate — and PROVE the final size really runs on this device,
     halving until it does. Params travel in the vault header, so any
     Vault100 app can still open the result. */
  async function calibrateKdf(targetSeconds = 2.0, maxKib = 512 * 1024) {
    const cache = new Map();   // memKiB -> {dt} | null (refused)
    let lastErr = null;
    async function probe(memKiB) {
      if (cache.has(memKiB)) return cache.get(memKiB);
      let r = null;
      try {
        const t0 = root.performance.now();
        await argon2id(u8("vault100-calibration"), rand16(), {
          memoryKib: memKiB, timeCost: 1, parallelism: 4 });
        r = { dt: Math.max((root.performance.now() - t0) / 1000, 0.01) };
      } catch (e) { lastErr = e; }
      cache.set(memKiB, r);
      return r;
    }

    let sample = 0, dt = 0;
    for (const s of [64 * 1024, 16 * 1024, 8 * 1024]) {
      const r = await probe(s);
      if (r) { sample = s; dt = r.dt; break; }
    }
    if (!sample) throw new VaultError(
      "Argon2id could not run on this device/browser (" +
      ((lastErr && lastErr.message) || lastErr || "unknown") + ")");

    let mem = Math.min(maxKib, Math.max(sample,
      Math.floor(sample * targetSeconds / dt)));
    while (mem > sample && !(await probe(mem)))
      mem = Math.max(sample, Math.floor(mem / 2));

    const est = dt * (mem / sample);
    const timeCost = Math.min(MAX_TIME, Math.max(1, Math.floor(targetSeconds / est)));
    return { memoryKib: mem, timeCost, parallelism: 4 };
  }
  function rand16() { return needEnv().randbytes(16); }

  // -- embedded CLI↔web self-test vector -------------------------------------
  const SELFTEST = {
    b64: "VjEwMEVOQzICAQAgAAABAAAABAD55doq/Zy6Hd19Cg0kJemVp3HkYQk6oqDycxYRxbwmfiqcZ5i" +
         "zxBO5KLfqhLvMTr5bJMZHjovmc7jQL+GQAN8VCU9ibBSqEGByT/xVhEKjd16YzudXfGxbMlUe0" +
         "TBOKYirOGNYw67Hcx+ixYCpMjMC2OdzHD59nB3E90DXq8HWPi4AAADRqYXdfMPpBNLXgVI9jh7" +
         "CcWdovL9CXnJq1p3uN7GtKDGkHYXks6DkGj9B/8grRQAAAJetezgoEjxaOFLJXmAfbjbnHEe0l" +
         "sAEbQFe8VbTT3vs2ksvK/Lbnja7/ikLaC8K23UT/dHnrU+sj4lrtOxM1jBZG68JtQ==",
    password: "vault100-selftest",
    expect: "Vault100 web self-test OK: zero-knowledge verified.\n",
    name: "selftest.txt",
  };

  /** Returns true when this runtime decrypts a CLI-produced vault byte-exactly. */
  async function runSelfTest() {
    const blob = new Blob([b64d(SELFTEST.b64)]);
    const res = await decryptVault(blob,
      { password: u8(SELFTEST.password) });
    const text = td.decode(concat(...res.parts));
    return text === SELFTEST.expect && res.meta.name === SELFTEST.name;
  }

  root.VaultFormat = {
    MAGIC_V2, CHUNK_SIZE, KDF_PROFILES,
    VaultError, VaultAuthError, VaultFormatError, VaultCancelled,
    setEnv, keyfileDigest, generateKeyfileBytes, encryptVault, decryptVault,
    info, calibrateKdf, runSelfTest, SELFTEST,
    _internals: { hkdfSha256, deriveKek, argon2id, parsePrefix, concat, u8 },
  };
})(typeof self !== "undefined" ? self : globalThis);
