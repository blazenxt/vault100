/* Vault100 web — main-thread UI controller. All crypto in worker.js. */
"use strict";

(() => {
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));

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
  const worker = new Worker("worker.js");
  let nextId = 1;
  const pending = new Map();       // id -> {progressEl, resolve, reject, kind}
  let engineReady = false;
  let calibratedParams = null;

  worker.onmessage = (e) => {
    const m = e.data;
    if (m.type === "ready") {
      engineReady = true;
      setBadge("INSPECTING ENGINE…", "warn");
      worker.postMessage({ type: "job", op: "selftest", id: nextId++ });
      return;
    }
    if (m.type === "selftest") {
      setBadge(m.ok ? "ENGINE VERIFIED · v2" : "INSPECTION FAILED",
               m.ok ? "ok" : "bad");
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
      calibratedParams = m.params;
      const p = pending.get(m.id);
      if (p) { p.resolve(m.params); pending.delete(m.id); }
      log(`KDF auto-tuned: ${Math.round(m.params.memoryKib / 1024)} MiB × ${m.params.timeCost} pass(es)`);
      return;
    }
    if (m.type === "info") {
      const p = pending.get(m.id);
      if (p) { p.resolve(m.info); pending.delete(m.id); }
      return;
    }
    if (m.type === "done") {
      const p = pending.get(m.id);
      if (p) { p.resolve(m); pending.delete(m.id); }
      return;
    }
    if (m.type === "error") {
      const p = pending.get(m.id);
      if (p) { p.resolve(m); pending.delete(m.id); }
      return;
    }
  };

  function setBadge(text, cls) {
    const b = $("#selftest-badge");
    b.textContent = text;
    b.className = "badge " + cls;
  }  function sendJob(job, progressEl) {
    const id = nextId++;
    job.id = id;
    job.type = "job";
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
  }
  const cancelJob = (id) => worker.postMessage({ type: "cancel", id });

  // ---------------- helpers ----------------
  function log(text, cls = "") {
    const el = $("#log");
    const line = document.createElement("div");
    line.className = "logline " + cls;
    line.textContent = text;
    el.prepend(line);
  }

  function download(name, parts, length) {
    const blob = new Blob(parts, { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { a.remove(); URL.revokeObjectURL(url); }, 4000);
    return { name, size: blob.size };
  }

  function addResult(name, size) {
    const empty = $("#results-empty");
    if (empty) empty.remove();
    const li = document.createElement("li");
    li.textContent = `№ ${name} — ${size.toLocaleString()} B`;
    $("#results").prepend(li);
  }

  const kb = (n) => new TextEncoder().encode(n);
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
  function bindStrength(inputSel, barSel, lblSel) {
    const inp = $(inputSel), bar = $(barSel), lbl = $(lblSel);
    if (!inp) return;
    inp.addEventListener("input", () => {
      const r = estimateStrength(inp.value);
      bar.value = r.score;
      lbl.textContent = r.label;
      lbl.className = "s" + r.score;
    });
  }

  // ---------------- tabs ----------------
  $$(".tabbtn").forEach((b) => b.addEventListener("click", () => {
    $$(".tabbtn").forEach((x) => x.classList.remove("active"));
    $$(".tab").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    $("#" + b.dataset.tab).classList.add("active");
  }));

  // ---------------- file pickers / drop zones ----------------
  function bindDrop(zoneSel, listEl) {
    const zone = $(zoneSel);
    // CSP blocks inline onclick attributes, so "click to browse" is wired here
    zone.addEventListener("click", () => {
      const inp = zone.querySelector('input[type="file"]');
      if (inp) inp.click();
    });
    zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("over"); });
    zone.addEventListener("dragleave", () => zone.classList.remove("over"));
    zone.addEventListener("drop", (e) => {
      e.preventDefault(); zone.classList.remove("over");
      for (const f of e.dataTransfer.files) addFileRow(listEl, f);
    });
  }
  function addFileRow(listEl, file) {
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
  }
  const rowsOf = (listEl) => Array.from(listEl.children)
    .map((li) => ({ file: li._file, prog: li.querySelector("progress") }));

  bindDrop("#enc-drop", $("#enc-list"));
  bindDrop("#dec-drop", $("#dec-list"));
  $("#enc-pick").onchange = (e) => { for (const f of e.target.files) addFileRow($("#enc-list"), f); e.target.value = ""; };
  $("#dec-pick").onchange = (e) => { for (const f of e.target.files) addFileRow($("#dec-list"), f); e.target.value = ""; };

  for (const [btnSel, inpSel, lblSel] of [
    ["#enc-keyfile-btn", "#enc-keyfile", "#enc-keyfile-name"],
    ["#dec-keyfile-btn", "#dec-keyfile", "#dec-keyfile-name"],
  ]) {
    const btn = $(btnSel);
    if (!btn) continue;
    btn.onclick = () => $(inpSel).click();
    $(inpSel).onchange = (e) => {
      $(lblSel).textContent = e.target.files[0]
        ? "🔑 " + e.target.files[0].name : "";
      btn._file = e.target.files[0] || null;
    };
  }
  bindStrength("#enc-pw1", "#enc-strength", "#enc-strength-label");

  $("#show-pw").onchange = (e) => {
    for (const s of ["#enc-pw1", "#enc-pw2", "#dec-pw"]) {
      const i = $(s); if (i) i.type = e.target.checked ? "text" : "password";
    }
  };

  async function resolveProfile(sel) {
    if (sel !== "max") return { profile: sel };
    if (!calibratedParams) {
      log("Calibrating Argon2id to this device (~2 s target)…");
      const params = await sendJob({ op: "calibrate" });
      return { params };
    }
    return { params: calibratedParams };
  }

  // ---------------- encrypt batch ----------------
  $("#enc-go").onclick = async () => {
    const rows = rowsOf($("#enc-list"));
    if (!rows.length) return log("Add at least one file.", "err");
    const pw1 = $("#enc-pw1").value, pw2 = $("#enc-pw2").value;
    if (!pw1) return log("Enter a password.", "err");
    if (pw1 !== pw2) return log("Passwords do not match.", "err");
    const rep = estimateStrength(pw1);
    if (rep.score < 3 && !confirm(
      `Password strength: ${rep.label}.\nUse it anyway? (A 4-5 word passphrase is stronger.)`)) return;

    const sel = $("#enc-security").value;
    const { profile, params } = await resolveProfile(sel);
    const cascade = $("#enc-cascade").checked;
    const keyBtn = $("#enc-keyfile-btn");
    const keyData = keyBtn._file
      ? new Uint8Array(await keyBtn._file.arrayBuffer()) : null;

    $("#enc-go").disabled = true;
    for (const { file, prog } of rows) {
      log(`encrypt ${file.name}${cascade ? " [cascade]" : ""}`);
      const res = await sendJob({
        op: "encrypt", file, password: kb(pw1), profile, params,
        keyData, cascade,
      }, prog);
      if (res.type === "error") {
        log(`✗ ${file.name}: ${res.message}`, "err");
        continue;
      }
      const saved = download(res.name, res.parts, res.length);
      addResult(saved.name, saved.size);
      log(`✓ ${res.name} sealed (${saved.size.toLocaleString()} B)`);
    }
    $("#enc-pw1").value = $("#enc-pw2").value = "";
    $("#enc-go").disabled = false;
    log("Batch finished.");
  };

  // ---------------- decrypt batch ----------------
  $("#dec-go").onclick = async () => {
    const rows = rowsOf($("#dec-list"));
    if (!rows.length) return log("Add at least one .v100 file.", "err");
    const pw = $("#dec-pw").value;
    if (!pw) return log("Enter the password.", "err");
    const keyBtn = $("#dec-keyfile-btn");
    const keyData = keyBtn._file
      ? new Uint8Array(await keyBtn._file.arrayBuffer()) : null;

    $("#dec-go").disabled = true;
    for (const { file, prog } of rows) {
      log(`decrypt ${file.name}`);
      const res = await sendJob({
        op: "decrypt", file, password: kb(pw), keyData,
      }, prog);
      if (res.type === "error") {
        const hint = res.kind === "VaultAuthError"
          ? "wrong password/keyfile or corrupted vault" : res.message;
        log(`✗ ${file.name}: ${hint}`, "err");
        continue;
      }
      const saved = download(res.name, res.parts, res.length);
      addResult(saved.name, saved.size);
      log(`✓ ${res.name} restored (${saved.size.toLocaleString()} B)`);
    }
    $("#dec-pw").value = "";
    $("#dec-go").disabled = false;
    log("Batch finished.");
  };

  // ---------------- tools ----------------
  $("#keygen-go").onclick = () => {
    const bytes = new Uint8Array(8 + 32);
    bytes.set(new TextEncoder().encode("V100KEY1"), 0);
    crypto.getRandomValues(bytes.subarray(8));
    const saved = download("vault100-" +
      Date.now().toString(36) + ".v100key", [bytes], bytes.length);
    addResult(saved.name, saved.size);
    log("Keyfile created — store it like a house key, and back it up.");
  };

  $("#info-pick-btn").onclick = () => $("#info-pick").click();
  $("#info-pick").onchange = async (e) => {
    const f = e.target.files[0];
    e.target.value = "";
    if (!f) return;
    const info = await sendJob({ op: "info", file: f });
    if (!info || !info.format) return log("Could not parse vault header.", "err");
    log(`🔍 ${info.name}: v${info.format} · ` +
      `cipher ${info.cascade ? "AES-256-GCM⟶XChaCha20" : "XChaCha20-Poly1305"} · ` +
      `keyfile ${info.keyfile ? "required" : "no"} · ` +
      `Argon2id ${Math.round(info.kdf.memoryKib / 1024)} MiB×${info.kdf.timeCost}`);
  };

  const WORDS = ("amber anvil apple arrow aspen atlas aurora bacon badge bamboo banjo " +
    "barn basin bazaar beacon beaver berry birch biscuit blaze blender blossom bonsai " +
    "border boulder breeze brick bridge bronze brook bubble bucket butter button cactus " +
    "camel canoe canyon caramel castle cedar cellar cello chalk charcoal cherry chest " +
    "chimney cider cinder circuit citrus clover cobalt cocoa comet compass copper coral " +
    "crater cricket crystal cypress dagger daisy dawn delta denim desert dew diamond " +
    "dolphin dome donkey dragon drift drum dune eagle echo ember emerald engine falcon " +
    "feather fern fiddle flint forge fossil fountain fox frost galaxy garden garnet gate " +
    "gecko glacier gondola granite gravel grove guitar harbor harvest hazel hedge heron " +
    "honey horizon hotel hunter iceberg igloo indigo iron island ivory jade jaguar jasmine " +
    "jester jet jewel jungle juniper kayak kestrel kettle kingdom kite kitten ladder " +
    "lagoon lantern lark lava lemon leopard lily linen lion lizard lobster lodge lotus " +
    "lunar magnet mahogany mango maple marble marlin meadow mesa meteor midnight mill " +
    "mirror mist molten monsoon moss moth mountain mulberry mustard nectar needle nickel " +
    "north oasis obsidian ocean olive onyx opal orbit orchid otter owl oyster panda " +
    "panther paper parrot pearl pebble pelican pepper petal phoenix piano pilgrim pine " +
    "pioneer planet plum polar poppy prairie prism python quartz quill rabbit rain raven " +
    "reef rhino river robin rocket root rose ruby saddle safari sage salmon sand sapphire " +
    "satin savanna scarlet seashell sequoia shadow shale shard silver skylark slate smoke " +
    "snow solar sparrow sphinx spider spirit spring spruce stable star stone storm summit " +
    "sunrise sunset swallow tango temple thunder tidal tiger timber titan topaz torch " +
    "tornado trader trident tropic tulip tundra tunnel turquoise turtle twilight umber " +
    "unicorn valley vapor velvet vine violet viper vortex voyage walnut wanderer wasp " +
    "wave weasel west whale wheat whisper willow winter wolf wren yellow zenith zephyr " +
    "zinc zodiac").split(" ");
  function randInt(max) {
    const b = new Uint32Array(1);
    crypto.getRandomValues(b);
    return b[0] % max;
  }
  $("#genpass-go").onclick = () => {
    const phrase = $("#genpass-words").checked;
    let pw;
    if (phrase) {
      const parts = [];
      for (let i = 0; i < 8; i++) parts.push(WORDS[randInt(WORDS.length)]);
      pw = parts.join("-");
    } else {
      const A = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>?/~";
      pw = Array.from({ length: 20 }, () => A[randInt(A.length)]).join("");
    }
    $("#genpass-out").value = pw;
    const r = estimateStrength(pw);
    $("#genpass-strength").textContent = r.label;
  };
  $("#genpass-copy").onclick = async () => {
    await navigator.clipboard.writeText($("#genpass-out").value);
    log("Password copied to clipboard.");
  };
})();
