/* Vault100 web — shared bureau plumbing for every page.
 * Creates the crypto worker, routes its messages, and exposes the tools
 * each counter's page script needs, on window.VB. All crypto in worker.js. */
"use strict";

(() => {
  const VB = (window.VB = {});
  const $ = (VB.$ = (s) => document.querySelector(s));
  VB.$$ = (s) => Array.from(document.querySelectorAll(s));
  VB.VERSION = "2.0.11";

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
    if (job.password) {                     // transfer (not copy) secret bytes
      const buf = job.password.buffer.slice(0);
      job.password = new Uint8Array(buf);
      worker.postMessage(job, [buf]);
    } else if (job.keyData) {
      const buf = job.keyData.buffer.slice(0);
      job.keyData = new Uint8Array(buf);
      worker.postMessage(job, [buf]);
    } else {
      worker.postMessage(job);
    }
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

  // ---------------- the fine ladder: 108 key-turning notches ----------------
  /* memory tiers (MiB) × turning counts, graded weakest → heaviest.
     Values ride as raw params: p:<memKiB>:<turns>:<lanes>. They are stamped
     into the vault header, so every notch opens in the CLI & desktop app. */
  VB.buildLadder = function () {
    const selx = $("#enc-security");
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
