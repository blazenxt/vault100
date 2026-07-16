/* Vault100 web — FORM 100-C counter script (open vaults). */
"use strict";

(() => {
  const { $, log, sendJob, bindDrop, addFileRow, rowsOf, wireKeyfile,
          armCancel, disarmCancel, cancelRequested, isCancelErr,
          download, addResult, kb } = window.VB;

  bindDrop("#dec-drop", "#dec-list");
  wireKeyfile("#dec-keyfile-btn", "#dec-keyfile", "#dec-keyfile-name");

  $("#dec-pick").onchange = (e) => {
    for (const f of e.target.files) addFileRow("#dec-list", f);
    e.target.value = "";
  };

  // deliveries land anywhere on this counter, not just the intake tray
  window.VB.onFilesDropped = (files) => {
    for (const f of files) addFileRow("#dec-list", f);
    log(`${files.length} vault(s) delivered to the counter floor — heads read.`);
  };

  // ---------------- the peek — the clerk reads the head aloud ----------------
  // Every vault placed on the counter gets its public head read BEFORE any
  // passphrase is asked: key-turning notch, double-lock, keyfile binding.
  const peeked = new WeakSet();
  let keyfileHinted = false;
  async function peek(li) {
    if (!li || peeked.has(li) || !li._file) return;
    peeked.add(li);
    const fname = li.querySelector(".fname");
    if (!fname) return;
    const res = await sendJob({ op: "info", file: li._file });
    const facts = document.createElement("span");
    facts.className = "facts";
    if (!res || res.kdf === undefined) {
      facts.innerHTML = "unreadable — not a Vault100 v2 vault";
      fname.appendChild(facts);
      return;
    }
    const bits = [`${Math.round(res.kdf.memoryKib / 1024)} MiB × ` +
                  `${res.kdf.timeCost} turn${res.kdf.timeCost > 1 ? "s" : ""}`];
    if (res.cascade) bits.push("double-lock");
    if (res.keyfile) bits.push("<b class='kf'>keyfile needed</b>");
    facts.innerHTML = "the head reads: " + bits.join(" · ");
    fname.appendChild(facts);
    if (res.keyfile && !keyfileHinted) {
      keyfileHinted = true;
      log("a vault on the counter is bound to a keyfile — present it in Part III.");
    }
  }
  new MutationObserver((muts) => {
    for (const m of muts)
      for (const n of m.addedNodes)
        if (n.nodeType === 1 && n.tagName === "LI") peek(n);
  }).observe($("#dec-list"), { childList: true });

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
    armCancel("#dec-cancel");
    for (const { file, prog } of rows) {
      if (cancelRequested()) { log("batch stayed — remaining documents untouched."); break; }
      log(`decrypt ${file.name}`);
      const res = await sendJob({
        op: "decrypt", file, password: kb(pw), keyData,
      }, prog);
      if (res.type === "error") {
        if (isCancelErr(res)) { log(`✗ ${file.name}: stayed by request`, "err"); break; }
        const hint = res.kind === "VaultAuthError"
          ? "wrong password/keyfile or corrupted vault" : res.message;
        log(`✗ ${file.name}: ${hint}`, "err");
        continue;
      }
      const saved = download(res.name, res.parts, res.length);
      addResult(saved.name, saved.size);
      log(`✓ ${res.name} restored (${saved.size.toLocaleString()} B)`);
      window.VB.maybePreview(res.name, res.parts, res.length);
    }
    $("#dec-pw").value = "";
    $("#dec-go").disabled = false;
    disarmCancel("#dec-cancel");
    log("Batch finished.");
  };
})();
