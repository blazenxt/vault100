/* Vault100 web — shared bureau plumbing for every page.
 * Creates the crypto worker, routes its messages, and exposes the tools
 * each counter's page script needs, on window.VB. All crypto in worker.js. */
"use strict";

(() => {
  const VB = (window.VB = {});
  const $ = (VB.$ = (s) => document.querySelector(s));
  VB.$$ = (s) => Array.from(document.querySelectorAll(s));
  VB.VERSION = "2.0.20";

  // ---------------- the desk lamp & ink well (themes) ----------------
  // Applied synchronously before first paint, so no theme flash. The
  // choice follows the clerk across pages and visits (localStorage).
  const rootEl = document.documentElement;
  const INKS = ["carbon", "oxford", "sepia", "ledger", "crimson"];
  function applyDesk(ink, shift) {
    if (!INKS.includes(ink)) ink = "carbon";
    if (shift !== "day") shift = "night";
    rootEl.setAttribute("data-theme", ink);
    rootEl.setAttribute("data-shift", shift);
    try {
      localStorage.setItem("v100.ink", ink);
      localStorage.setItem("v100.shift", shift);
    } catch (e) { /* private booth — keep the default stock */ }
  }
  let deskInk = "carbon", deskShift = null;
  try {
    deskInk = localStorage.getItem("v100.ink") || deskInk;
    deskShift = localStorage.getItem("v100.shift");
  } catch (e) {}
  if (!deskShift) {
    deskShift = (rootEl.matchMedia || window.matchMedia)
      .call(window, "(prefers-color-scheme: light)").matches ? "day" : "night";
  }
  applyDesk(deskInk, deskShift);
  VB.applyDesk = applyDesk;

  function paintShiftBtn() {
    const b = $("#shift");
    if (b) b.innerHTML = rootEl.getAttribute("data-shift") === "day"
      ? "&#9788; day desk" : "&#9789; night desk";
  }
  const inkSel = $("#ink"), shiftBtn = $("#shift");
  if (inkSel) {
    inkSel.value = rootEl.getAttribute("data-theme") || "carbon";
    inkSel.addEventListener("change", () => {
      applyDesk(inkSel.value, rootEl.getAttribute("data-shift"));
      log(`ink changed — the counter now writes in ${inkSel.value}.`);
    });
  }
  if (shiftBtn) {
    paintShiftBtn();
    shiftBtn.addEventListener("click", () => {
      const next = rootEl.getAttribute("data-shift") === "day" ? "night" : "day";
      applyDesk(rootEl.getAttribute("data-theme"), next);
      paintShiftBtn();
      log(next === "day"
        ? "office hours — the day desk is lit."
        : "after hours — the night lamp is on.");
    });
  }

  // the clerk stamps today's date on the form
  const todayEl = document.getElementById("today");
  if (todayEl) {
    const d = new Date();
    const M = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG",
               "SEP", "OCT", "NOV", "DEC"];
    todayEl.textContent = `${String(d.getDate()).padStart(2, "0")} ` +
                          `${M[d.getMonth()]} ${d.getFullYear()}`;
  }

  // ---------------- worker plumbing ----------------
  const worker = new Worker("worker.js?v=" + VB.VERSION.replace(/\./g, ""));
  let nextId = 1;
  const pending = new Map();       // id -> {progressEl, resolve}
  let calibratedParams = null;

  worker.onmessage = (e) => {
    const m = e.data;
    if (m.type === "ready") {
      setBadge("INSPECTING ENGINE…", "warn");
      worker.postMessage({ type: "job", op: "selftest", id: nextId++ });
      return;
    }
    if (m.type === "selftest") {
      setBadge(m.ok ? "ENGINE VERIFIED · v2" : "INSPECTION FAILED",
               m.ok ? "ok" : "bad");
      if (m.ok) log(`engine ready — Vault100 web v${VB.VERSION} · zero-knowledge verified`);
      $("#selftest-badge").title = m.ok
        ? "This page just decrypted a reference vault produced by the desktop app — the served code is genuine and compatible."
        : "Self-test failed — do not use this deployment.";
      return;
    }
    if (m.type === "progress") {
      const p = pending.get(m.id);
      if (p && p.progressEl) {
        const frac = m.total ? Math.min(m.done / m.total, 1) : 1;
        p.progressEl.value = frac * 100;
        p.progressEl.nextElementSibling.textContent =
          `${(frac * 100).toFixed(1)}%`;
      }
      return;
    }
    if (m.type === "calibrated") {
      if (m.params && Number.isFinite(m.params.memoryKib))
        calibratedParams = m.params;
      const p = pending.get(m.id);
      if (p) { p.resolve(m.params); pending.delete(m.id); }
      log(`KDF auto-tuned: ${Math.round(m.params.memoryKib / 1024)} MiB × ${m.params.timeCost} pass(es)`);
      return;
    }
    if (m.type === "kdf-fold") {
      log(`RAM ledger short — key folded to ${Math.round(m.mem / 1024)} MiB ` +
          `(turns & lanes unchanged; stamped in the header)`, "note");
      return;
    }
    if (m.type === "bench") {
      const p = pending.get(m.id);
      if (p) { p.resolve(m.res); pending.delete(m.id); }
      return;
    }
    if (m.type === "info" || m.type === "done" || m.type === "error") {
      const p = pending.get(m.id);
      if (p) { p.resolve(m.type === "info" ? m.info : m); pending.delete(m.id); }
      return;
    }
  };

  function setBadge(text, cls) {
    const b = $("#selftest-badge");
    if (b) { b.textContent = text; b.className = "badge " + cls; }
  }

  let lastJobId = null;
  let batchCancel = false;
  VB.sendJob = function (job, progressEl) {
    const id = nextId++;
    job.id = id;
    job.type = "job";
    lastJobId = id;
    // transfer (not copy) every secret byte array offered with the job
    const SECRETS = ["password", "oldPassword", "newPassword",
                     "keyData", "oldKeyData", "newKeyData", "secret"];
    const transfers = [];
    for (const k of SECRETS) {
      if (job[k] instanceof Uint8Array) {
        const buf = job[k].buffer.slice(0);
        job[k] = new Uint8Array(buf);
        transfers.push(buf);
      }
    }
    worker.postMessage(job, transfers);
    return new Promise((resolve) => pending.set(id, { progressEl, resolve }));
  };
  const cancelJob = (id) => worker.postMessage({ type: "cancel", id });

  // "stay the stamp" — cancelling a batch mid-flight
  VB.armCancel = function (btnSel) {
    const b = $(btnSel);
    if (!b) return;
    batchCancel = false;
    b.hidden = false;
    b.onclick = () => {
      batchCancel = true;
      if (lastJobId) cancelJob(lastJobId);
      log("stay requested — releasing the current document…");
    };
  };
  VB.disarmCancel = (btnSel) => { const b = $(btnSel); if (b) b.hidden = true; };
  VB.cancelRequested = () => batchCancel;
  VB.isCancelErr = (res) => res && res.kind === "VaultCancelled";

  // ---------------- security ops: the sweep, the panic drill, the furnace ----
  /* Counter policy (per booth, localStorage "v100.sweep" seconds, 0 = never;
     default five minutes). Any activity resets the clock; when it rings, the
     clerk sweeps the counter: every passphrase field emptied, every filing
     removed, keyfiles un-pocketed, the record book burned and re-opened. */
  const SWEEP_KEY = "v100.sweep";
  let sweepSecs = 300;
  try {
    const v = parseInt(localStorage.getItem(SWEEP_KEY) || "", 10);
    if (Number.isFinite(v)) sweepSecs = v;
  } catch (e) {}

  VB.sweep = function (reason) {
    if (lastJobId) cancelJob(lastJobId);
    batchCancel = true;
    // every secret-bearing field — empty the wells
    for (const i of VB.$$("input[type=password], input[type=text]")) {
      if (i.type === "password" || i.type === "text") i.value = "";
    }
    for (const t of VB.$$("textarea")) t.value = "";   // notes & armor wells
    const qps = $("#qp-slips");                          // quorum slips — burned
    if (qps) qps.innerHTML = "";
    const qpn = $("#qp-joined-note"); if (qpn) qpn.textContent = " ";
    for (const [inp, chk] of [["#enc-pw1", "#show-pw"], ["#enc-pw2", "#show-pw"],
                              ["#dec-pw", null], ["#rw-old", "#rw-show"],
                              ["#rw-new1", "#rw-show"], ["#rw-new2", "#rw-show"]]) {
      const el = $(inp); if (el) el.type = "password";
      const c = chk && $(chk); if (c) c.checked = false;
    }
    // keyfiles un-pocketed
    for (const b of VB.$$("[id$='-keyfile-btn']")) b._file = null;
    for (const l of VB.$$("[id$='-keyfile-name']")) {
      l.textContent = ""; l.classList.remove("kfset");
    }
    // filings off the counter
    for (const u of VB.$$("ul.files")) u.innerHTML = "";
    // the examining tray is emptied
    const ppart = $("#preview-part"), pbox = $("#preview");
    if (ppart && pbox) {
      ppart.hidden = true;
      if (previewURL) { URL.revokeObjectURL(previewURL); previewURL = null; }
      pbox.innerHTML = "";
    }
    for (const u of VB.$$("#results")) if (u) u.innerHTML = "";
    const facts = $("#rw-facts"); if (facts) facts.hidden = true;
    for (const p of VB.$$("progress")) { p.value = 0;
      const sib = p.nextElementSibling;
      if (sib && /%$/.test(sib.textContent)) sib.textContent = ""; }
    // strength labels
    for (const s of VB.$$("#enc-strength-label, #rw-strength-label")) {
      s.textContent = "—"; s.className = ""; }
    // the record book is burned and re-opened
    const el = $("#log");
    if (el) el.innerHTML = "";
    log(reason === "panic"
      ? "panic drill — the counter is swept clean; nothing remains."
      : reason === "idle"
        ? "the clerk swept the counter — office policy after idle."
        : "the counter is swept clean.");
  };

  let sweepTimer = null;
  function armSweepClock() {
    if (sweepTimer) clearTimeout(sweepTimer);
    if (!sweepSecs) return;
    sweepTimer = setTimeout(() => VB.sweep("idle"), sweepSecs * 1000);
  }
  VB.setSweep = function (secs) {
    sweepSecs = Math.max(0, secs | 0);
    try { localStorage.setItem(SWEEP_KEY, String(sweepSecs)); } catch (e) {}
    armSweepClock();
  };
  VB.getSweep = () => sweepSecs;
  for (const ev of ["pointerdown", "keydown", "input", "dragover", "drop"]) {
    document.addEventListener(ev, armSweepClock, { passive: true });
  }
  armSweepClock();

  // panic drill — Esc, Esc (within 0.8 s): sweep, then clear the window to
  // the front desk
  let lastEsc = 0;
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    const now = Date.now();
    if (now - lastEsc < 800) {
      lastEsc = 0;
      VB.sweep("panic");
      location.replace("index.html");
    } else {
      lastEsc = now;
    }
  });

  // the furnace — secrets copied to the clipboard are burned after 60 s
  VB.copySecret = async function (text, what) {
    if (!text) { log("nothing on the desk to copy.", "err"); return false; }
    try {
      await navigator.clipboard.writeText(text);
    } catch (e) {
      log("the clipboard refused the scrap — copy by hand.", "err");
      return false;
    }
    log(`${what || "scrap"} copied — the furnace burns it from the clipboard in 60 s.`);
    setTimeout(async () => {
      try { await navigator.clipboard.writeText(""); } catch (e) {}
    }, 60 * 1000);
    return true;
  };

  // ---------------- clerk's record ----------------
  function log(text, cls = "") {
    const el = $("#log");
    if (!el) return;
    const line = document.createElement("div");
    line.className = "logline " + cls;
    line.textContent = text;
    el.prepend(line);
  }
  VB.log = log;

  VB.download = function (name, parts, length) {
    const blob = new Blob(parts, { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { a.remove(); URL.revokeObjectURL(url); }, 4000);
    return { name, size: blob.size };
  };

  VB.addResult = function (name, size) {
    const list = $("#results");
    if (!list) return;
    const empty = $("#results-empty");
    if (empty) empty.remove();
    const li = document.createElement("li");
    li.textContent = `№ ${name} — ${size.toLocaleString()} B`;
    list.prepend(li);
  };

  VB.kb = (n) => new TextEncoder().encode(n);

  // ---------------- filings: folder → tar bundling ----------------
  /* Walks a directory picker FileList and staples it into one .tar under
     the user's nose (POSIX ustar — `tar -xf` and Python's tarfile read it
     as-is). Long names ride the ustar prefix field. */
  VB.bundleFolder = async function (files, bundleName) {
    const list = Array.from(files || []);
    if (!list.length) return null;
    const enc = new TextEncoder();
    const parts = [];
    const push = (u8) => parts.push(u8);
    const zeros = (n) => new Uint8Array(n);

    function ustar(path, size, mtime) {
      function splitName(p) {
        if (enc.encode(p).length <= 100) return [p, ""];
        const seg = p.split("/");
        // slide the split until name ≤100 and prefix ≤155
        for (let k = 1; k < seg.length; k++) {
          const name = seg.slice(k).join("/");
          const prefix = seg.slice(0, k).join("/");
          if (enc.encode(name).length <= 100 &&
              enc.encode(prefix).length <= 155) return [name, prefix];
        }
        return [seg[seg.length - 1].slice(-100), ""];   // last resort
      }
      const [name, prefix] = splitName(path);
      const h = new Uint8Array(512);
      const put = (str, off, len) => {
        const b = enc.encode(String(str));
        h.set(b.subarray(0, len), off);
      };
      const oct = (n, off, len) => {
        put(n.toString(8).padStart(len - 1, "0"), off, len - 1);
        h[off + len - 1] = 0;
      };
      put(name, 0, 100);
      oct(0o644, 100, 8); oct(0, 108, 8); oct(0, 116, 8);
      const sz = h.subarray(124, 136);            // size: 11 octal + space
      const so = size.toString(8).padStart(11, "0");
      for (let i = 0; i < 11; i++) sz[i] = so.charCodeAt(i);
      sz[11] = 32;
      put(Math.floor(mtime / 1000).toString(8).padStart(11, "0"), 136, 147);
      h[147] = 32;
      h.fill(32, 148, 156);                       // checksum field: blanks
      h[156] = 48;                                // typeflag '0'
      put("ustar", 257, 6); h[257 + 5] = 0;
      put("00", 263, 265);
      put("vault100", 265, 273);
      put(prefix, 345, 500);
      let sum = 0;
      for (let i = 0; i < 512; i++) sum += h[i];
      const cs = sum.toString(8).padStart(6, "0");
      for (let i = 0; i < 6; i++) h[148 + i] = cs.charCodeAt(i);
      h[154] = 0; h[155] = 32;
      return h;
    }

    let entries = 0, bytes = 0;
    for (const f of list) {
      const rel = f.webkitRelativePath || f.name;
      const norm = rel.replace(/^\/+/, "").replace(/\.\.(\/|$)/g, "_$1");
      if (!norm || norm.endsWith("/") || norm.includes("\0")) continue;
      const data = new Uint8Array(await f.arrayBuffer());
      push(ustar(norm, data.length, f.lastModified || Date.now()));
      push(data);
      const rem = data.length % 512;
      if (rem) push(zeros(512 - rem));
      entries++; bytes += data.length;
    }
    if (!entries) return null;
    push(zeros(1024));                            // two end-of-archive blocks
    let root = bundleName;
    if (!root) {
      const first = list[0].webkitRelativePath || "bundle";
      root = first.split("/")[0] || "bundle";
    }
    const file = new File(parts, root.replace(/[^\w.-]+/g, "_") + ".tar",
                          { type: "application/x-tar" });
    return { file, entries, bytes };
  };

  // ---------------- the examining tray (preview after opening) -------------
  let previewURL = null;
  VB.maybePreview = async function (name, parts, length) {
    const part = $("#preview-part"), box = $("#preview");
    if (!part || !box) return;
    if (previewURL) { URL.revokeObjectURL(previewURL); previewURL = null; }
    box.innerHTML = "";
    part.hidden = true;
    const CAP = 25 * 1024 * 1024;
    if (!length || length > CAP) return;
    const ext = (name.includes(".") ? name.split(".").pop() : "").toLowerCase();
    const TEXT = new Set(["txt", "md", "markdown", "json", "log", "csv",
      "py", "js", "ts", "html", "css", "xml", "yml", "yaml", "ini", "conf",
      "cfg", "sh", "bat", "toml", "env", "sql", "r", "java", "c", "h",
      "cpp", "go", "rs", "rb", "pl", "tex", "nfo", "srt"]);
    const IMG = new Set(["png", "jpg", "jpeg", "gif", "webp", "bmp", "avif"]);
    const head = document.createElement("div");
    head.className = "pvhead";
    const blob = new Blob(parts);
    let node = null, kind = null;

    if (TEXT.has(ext)) {
      let text = await blob.text();
      if (text.includes("\0")) return;              // not really text
      const full = text.length;
      if (text.length > 200000) text = text.slice(0, 200000);
      node = document.createElement("pre");
      node.className = "pvtext";
      node.textContent = text +
        (full > 200000 ? `\n… (${(full - 200000).toLocaleString()} more chars — download for the whole document)` : "");
      kind = "text";
    } else if (IMG.has(ext)) {
      node = document.createElement("img");
      node.className = "pvimg";
      node.alt = name;
      if (length <= 6 * 1024 * 1024) {
        // data: URL — works even where blob: subresources are restricted
        const rd = new FileReader();
        const ready = new Promise((res) => { rd.onload = res; });
        rd.readAsDataURL(blob);
        await ready;
        node.src = String(rd.result);
      } else {
        previewURL = URL.createObjectURL(blob);
        node.src = previewURL;
      }
      kind = "image";
    } else if (ext === "pdf") {
      node = document.createElement("iframe");
      node.className = "pvpdf";
      node.title = name;
      if (length <= 8 * 1024 * 1024) {
        const rd = new FileReader();
        const ready = new Promise((res) => { rd.onload = res; });
        rd.readAsDataURL(blob);
        await ready;
        node.src = String(rd.result);
      } else {
        previewURL = URL.createObjectURL(blob);
        node.src = previewURL;
      }
      kind = "document";
    } else {
      return;                                        // nothing for the tray
    }

    head.textContent = `${name} — ${length.toLocaleString()} B · ${kind} · ` +
      "laid on the tray unsealed; the sweep empties it";
    box.appendChild(head);
    box.appendChild(node);
    part.hidden = false;
  };

  // keyfile raw bytes are sent to the worker, which digests them
  // (BLAKE2b keyed — same scheme as the desktop app) inside the sandbox.

  // ---------------- strength meter (port of strength.py) ----------------
  const COMMON = ["password", "123456", "12345678", "qwerty", "abc123",
    "password1", "111111", "letmein", "iloveyou", "admin", "welcome",
    "monkey", "dragon", "football", "sunshine", "master", "passw0rd"];
  const LABELS = ["Very weak", "Weak", "Fair", "Strong", "Excellent"];
  function estimateStrength(pw) {
    if (!pw) return { score: 0, label: "—" };
    if (COMMON.includes(pw.toLowerCase()))
      return { score: 0, label: LABELS[0] };
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
    let bits = pw.length * Math.log2(pool || 1);
    if (/(.)\1{2,}/.test(pw)) bits *= 0.6;
    if (/(?:0123|1234|2345|3456|4567|5678|6789|abcd|qwer)/i.test(pw)) bits -= 8;
    if (pw.length < 8) bits *= 0.5;
    const score = bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
    return { score, label: LABELS[score] };
  }
  VB.estimateStrength = estimateStrength;
  VB.bindStrength = function (inputSel, barSel, lblSel) {
    const inp = $(inputSel), bar = $(barSel), lbl = $(lblSel);
    if (!inp) return;
    inp.addEventListener("input", () => {
      const r = estimateStrength(inp.value);
      bar.value = r.score;
      lbl.textContent = r.label;
      lbl.className = "s" + r.score;
    });
  };

  // ---------------- file pickers / drop zones ----------------
  VB.bindDrop = function (zoneSel, listSel) {
    const zone = $(zoneSel), listEl = $(listSel);
    if (!zone || !listEl) return;
    // CSP blocks inline onclick attributes, so "click to browse" is wired here
    zone.addEventListener("click", () => {
      const inp = zone.querySelector('input[type="file"]');
      if (inp) inp.click();
    });
    zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("over"); });
    zone.addEventListener("dragleave", () => zone.classList.remove("over"));
    zone.addEventListener("drop", (e) => {
      e.preventDefault(); zone.classList.remove("over");
      for (const f of e.dataTransfer.files) VB.addFileRow(listSel, f);
    });
  };
  VB.addFileRow = function (listSel, file) {
    const listEl = typeof listSel === "string" ? $(listSel) : listSel;
    if (!listEl) return;
    const li = document.createElement("li");
    li.className = "filerow";
    li.dataset.name = file.name;
    li._file = file;
    const prog = document.createElement("progress");
    prog.max = 100; prog.value = 0;
    const pct = document.createElement("span");
    pct.className = "pct"; pct.textContent = "";
    const rm = document.createElement("button");
    rm.textContent = "✖"; rm.className = "rm";
    rm.onclick = () => li.remove();
    li.append(
      Object.assign(document.createElement("span"),
        { textContent: `${file.name} (${file.size.toLocaleString()} B)`, className: "fname" }),
      prog, pct, rm);
    listEl.appendChild(li);
  };
  VB.rowsOf = (listSel) => {
    const el = typeof listSel === "string" ? $(listSel) : listSel;
    return Array.from(el ? el.children : [])
      .map((li) => ({ file: li._file, prog: li.querySelector("progress") }));
  };

  // ---------------- keyfile wiring (present / pocket again) ----------------
  VB.wireKeyfile = function (btnSel, inpSel, lblSel) {
    const btn = $(btnSel), inp = $(inpSel), lbl = $(lblSel);
    if (!btn || !inp || !lbl) return;
    btn.onclick = () => inp.click();
    inp.onchange = (e) => {
      btn._file = e.target.files[0] || null;
      if (btn._file) {
        lbl.textContent = "🔑 " + btn._file.name + "  ✖";
        lbl.classList.add("kfset");
        lbl.title = "keyfile attached — click to remove it";
      } else {
        lbl.textContent = "";
        lbl.classList.remove("kfset");
      }
    };
    lbl.onclick = () => {
      btn._file = null;
      inp.value = "";
      lbl.textContent = "";
      lbl.classList.remove("kfset");
      log("keyfile pocketed again.");
    };
  };

  // ---------------- the receipt punch ---------------------------------
  /* Bureau-style batch serial. Pure ceremony — the bureau keeps no ledger
     of these; the serial exists only in this page's record book. */
  VB.makeSerial = function (kind) {
    const d = new Date();
    const ymd = String(d.getFullYear()).slice(-2) +
      String(d.getMonth() + 1).padStart(2, "0") +
      String(d.getDate()).padStart(2, "0");
    const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";   // no I/O/0/1 — unambiguous
    const buf = new Uint8Array(4);
    crypto.getRandomValues(buf);
    let r = "";
    for (const b of buf) r += A[b % A.length];
    return `№ V100·${ymd}·${kind}·${r}`;
  };

  // ---------------- the fine ladder: 108 key-turning notches ----------------
  /* memory tiers (MiB) × turning counts, graded weakest → heaviest.
     Values ride as raw params: p:<memKiB>:<turns>:<lanes>. They are stamped
     into the vault header, so every notch opens in the CLI & desktop app. */
  VB.buildLadder = function (sel) {
    const selx = typeof sel === "string" ? $(sel) : (sel || $("#enc-security"));
    if (!selx) return;
    const MEM = [16, 24, 32, 48, 64, 96, 128, 160, 192, 256, 320, 384,
                 448, 512, 640, 768, 896, 1024];
    const TURNS = [1, 2, 3, 4, 5, 6];
    const combos = [];
    for (const m of MEM) for (const t of TURNS) combos.push([m, t]);
    combos.sort((a, b) => (a[0] * a[1]) - (b[0] * b[1]) || a[0] - b[0]);
    const grp = document.createElement("optgroup");
    grp.label = `the fine ladder — ${combos.length} notches, weak → heavy`;
    combos.forEach(([m, t], i) => {
      const o = document.createElement("option");
      o.value = `p:${m * 1024}:${t}:4`;
      o.textContent = `№ ${String(i + 1).padStart(3, "0")} · ${m} MiB × ${t} turn${t > 1 ? "s" : ""}`;
      grp.appendChild(o);
    });
    selx.appendChild(grp);
  };

  VB.resolveProfile = async function (sel) {
    if (sel.startsWith("p:")) {
      const [mem, t, par] = sel.slice(2).split(":").map(Number);
      return { params: { memoryKib: mem, timeCost: t, parallelism: par } };
    }
    if (sel !== "max") return { profile: sel };
    if (calibratedParams) return { params: calibratedParams };
    log("Calibrating Argon2id to this device (~2 s target)…");
    const res = await VB.sendJob({ op: "calibrate" });
    if (!res || res.type === "error" || !Number.isFinite(res.memoryKib)) {
      log("✗ calibration failed: " + ((res && res.message) || "no result") +
          " — falling back to standard (128 MiB × 3).", "err");
      return { profile: "standard" };
    }
    if (res.memoryKib < 128 * 1024) log(
      "⚠ this browser limits Argon2 memory — vault tuned to what the device " +
      "allows. The desktop app can go higher.");
    return { params: res };
  };

  // ---------------- offline service worker ----------------
  /* The bureau's claim is that every instrument keeps working with the
     network cable severed — the service worker makes that literally true:
     it deposits this exact build in a versioned cache after first load. */
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker
      .register("sw.js?v=" + VB.VERSION.replace(/\./g, ""))
      .then((reg) => {
        if (reg.installing || reg.waiting) {
          log("caching the bureau for offline duty…");
        } else {
          log("offline cache ready — the cable may be severed at will");
        }
      })
      .catch(() => { /* private windows may refuse; the counter still works */ });
  }
})();
