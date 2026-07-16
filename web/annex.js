/* Vault100 web — Annex D instruments script. */
"use strict";

(() => {
  const { $, log, sendJob, download, addResult, estimateStrength,
          copySecret, sweep, setSweep, getSweep } = window.VB;

  // (e) the office policy — sweep clock lives in common.js for every page
  const sweepSel = $("#policy-sweep");
  if (sweepSel) {
    sweepSel.value = String(getSweep());
    sweepSel.onchange = () => {
      setSweep(parseInt(sweepSel.value, 10));
      log(sweepSel.value === "0"
        ? "office policy amended — the clerk will never sweep. Your own risk."
        : `office policy amended — counter sweeps after ${sweepSel.value} idle seconds.`);
    };
  }
  const sweepNow = $("#policy-now");
  if (sweepNow) sweepNow.onclick = () => window.VB.sweep("manual");

  // (a) the keyfile press
  $("#keygen-go").onclick = () => {
    const bytes = new Uint8Array(8 + 32);
    bytes.set(new TextEncoder().encode("V100KEY1"), 0);
    crypto.getRandomValues(bytes.subarray(8));
    const saved = download("vault100-" +
      Date.now().toString(36) + ".v100key", [bytes], bytes.length);
    addResult(saved.name, saved.size);
    log("Keyfile created — store it like a house key, and back it up.");
  };

  // (b) the examining glass
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

  // (c) the passphrase press
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
  $("#genpass-copy").onclick = () =>
    copySecret($("#genpass-out").value, "combination");

  // (f) the timekeeper — device speed trials, all inside the worker
  const benchBtn = $("#bench-go"), benchOut = $("#bench-out");
  const setReport = (lines) => {
    benchOut.innerHTML = "";
    for (const ln of lines) {
      const div = document.createElement("div");
      div.textContent = ln;
      benchOut.appendChild(div);
    }
  };
  if (benchBtn) benchBtn.onclick = async () => {
    benchBtn.disabled = true;
    benchOut.textContent = "the clerk winds the stopwatch…";
    log("timekeeper engaged — clocking this device's ciphers & key turns…");
    const r = await sendJob({ op: "bench" });
    benchBtn.disabled = false;
    if (!r || r.type === "error" || !r.xchacha) {
      setReport(["the stopwatch jammed — " +
                 ((r && r.message) || "an unknown fault")]);
      return log("✗ timekeeper: " + ((r && r.message) || "unknown fault"), "err");
    }
    const lines = [];
    lines.push(`xchacha20-poly1305 — ${r.xchacha.mbps.toFixed(0)} MiB/s ` +
               `(${r.xchacha.mib} MiB in ${r.xchacha.dt.toFixed(2)} s)`);
    lines.push(r.aes
      ? `aes-256-gcm (hardware path) — ${r.aes.mbps.toFixed(0)} MiB/s ` +
        `(${r.aes.mib} MiB in ${r.aes.dt.toFixed(2)} s)`
      : "aes-256-gcm — not offered by this browser's WebCrypto");
    for (const n of r.argon2) {
      lines.push(n.dt == null
        ? `argon2id ${Math.round(n.memKib / 1024)} MiB × 1 turn × 4 lanes — ` +
          `refused (this booth's RAM ledger is short)`
        : `argon2id ${Math.round(n.memKib / 1024)} MiB × 1 turn × 4 lanes — ` +
          `${n.dt.toFixed(2)} s`);
    }
    lines.push(r.standard != null
      ? `standard profile (128 MiB × 3 turns) on this desk ≈ ` +
        `${r.standard.toFixed(1)} s per seal / unseal`
      : "standard profile — could not be estimated here");
    lines.push("advice — pick a notch whose cost stays ≈ 1–4 s on this desk;");
    lines.push("turns multiply cost, memory multiplies the attacker's bill.");
    setReport(lines);
    log("timekeeper's report filed at instrument (f) —");
    for (const ln of lines) log("  " + ln);
  };

  // (g) the quorum press — Shamir M-of-N, in the worker, zero-knowledge
  const qpN = $("#qp-n"), qpM = $("#qp-m");
  if (qpN && qpM) {
    for (let i = 2; i <= 12; i++)
      qpN.innerHTML += `<option value="${i}"${i === 5 ? " selected" : ""}>${i}</option>`;
    const refillM = () => {
      const n = parseInt(qpN.value, 10);
      const was = parseInt(qpM.value || "3", 10);
      qpM.innerHTML = "";
      for (let i = 2; i <= n; i++)
        qpM.innerHTML += `<option value="${i}">${i}</option>`;
      qpM.value = String(Math.min(Math.max(was, 2), n));
    };
    refillM();
    qpN.onchange = refillM;
  }

  const qpSecret = $("#qp-secret"), qpSlips = $("#qp-slips");
  $("#qp-genkey").onclick = () => {
    const b = new Uint8Array(32);
    crypto.getRandomValues(b);
    let s = "";
    for (const x of b) s += String.fromCharCode(x);
    qpSecret.value = btoa(s);
    log("a fresh 256-bit secret pressed into the well — strike it into slips, " +
        "then lodge the slips apart.");
  };

  $("#qp-mint").onclick = async () => {
    const text = qpSecret.value;
    const secret = new TextEncoder().encode(text);
    qpSlips.innerHTML = "";
    if (!text) return log("the press needs a secret in the well first.", "err");
    if (secret.length > 4096)
      return log("the press takes at most 4 KiB here — " +
                 "seal documents as .v100 vaults; split a passphrase.", "err");
    const n = parseInt(qpN.value, 10), m = parseInt(qpM.value, 10);
    log(`the quorum press engages — ${n} slips, any ${m} reprint…`);
    const r = await sendJob({ op: "share-split", secret, n, m });
    if (!r || !r.slips)
      return log("✗ the press jammed — " + ((r && r.message) || "fault"), "err");
    const serial = window.VB.makeSerial("Q");
    r.slips.forEach((slip, i) => {
      const box = document.createElement("div");
      box.className = "qpslip";
      const head = document.createElement("div");
      head.className = "sliphead";
      const t = document.createElement("span");
      t.textContent = `slip ${i + 1} of ${n}`;
      const pid = document.createElement("span");
      pid.className = "pid";
      pid.textContent = `press №${r.press} · quorum ${m} · ${serial}`;
      head.appendChild(t); head.appendChild(pid);
      const ta = document.createElement("textarea");
      ta.className = "ro"; ta.readOnly = true; ta.value = slip;
      const row = document.createElement("div");
      row.className = "rowline";
      const cp = document.createElement("button");
      cp.className = "ghost"; cp.type = "button"; cp.textContent = "Copy";
      cp.onclick = () => copySecret(slip, `slip ${i + 1}`);
      const dl = document.createElement("button");
      dl.className = "ghost"; dl.type = "button"; dl.textContent = "Download";
      dl.onclick = () => download(
        `vault100.slip-${i + 1}-of-${n}.v100s`, [slip], slip.length);
      row.appendChild(cp); row.appendChild(dl);
      box.appendChild(head); box.appendChild(ta); box.appendChild(row);
      qpSlips.appendChild(box);
    });
    const all = document.createElement("div");
    all.className = "rowline";
    all.style.marginTop = "12px";
    const alldl = document.createElement("button");
    alldl.className = "ghost"; alldl.type = "button";
    alldl.textContent = "⭳ Download all slips (one folder of paper)";
    const heap = r.slips.join("\n");
    alldl.onclick = () =>
      download(`vault100.slips-${r.press}-any-${m}-of-${n}.txt`,
               [heap], heap.length);
    all.appendChild(alldl);
    qpSlips.appendChild(all);
    log(`press №${r.press}: ${n} slips struck — lodge them apart; ` +
        `any ${m} reprint the secret. ${serial}`);
  };

  $("#qp-join").onclick = async () => {
    const text = $("#qp-join-in").value;
    $("#qp-joined").value = "";
    $("#qp-joined-note").textContent = " ";
    if (!text.trim())
      return log("paste the quorum's slips into the well first.", "err");
    const r = await sendJob({ op: "share-join", text });
    if (!r || (r.secret === undefined))
      return log("✗ the quorum was not satisfied — " +
                 ((r && r.message) || "fault"), "err");
    if (r.text !== null && r.text !== undefined) {
      $("#qp-joined").value = r.text;
      $("#qp-joined-note").textContent =
        "reprinted as readable text — copy it where it belongs, then sweep.";
    } else {
      const b = new Uint8Array(r.secret);
      $("#qp-joined").value =
        Array.from(b.slice(0, 32), (x) => x.toString(16).padStart(2, "0"))
          .join("") + (b.length > 32 ? "…" : "");
      $("#qp-joined-note").textContent =
        `a binary secret (${b.length} bytes) — “Download bytes” saves it raw.`;
    }
    $("#qp-joined").dataset.raw = "";
    log("quorum satisfied — the secret stands reprinted on the counter.");
  };

  $("#qp-joined-copy").onclick = () => {
    const v = $("#qp-joined").value;
    if (v) copySecret(v, "reprinted secret");
  };
  $("#qp-joined-save").onclick = async () => {
    const text = $("#qp-join-in").value;
    if (!text.trim()) return;
    const r = await sendJob({ op: "share-join", text });
    if (r && r.secret) {
      const b = new Uint8Array(r.secret);
      download("vault100-reprinted-secret.bin", [b], b.length);
      log("raw reprinted bytes downloaded — guard the file like the secret.");
    }
  };
})();
