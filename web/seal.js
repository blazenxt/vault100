/* Vault100 web — FORM 100-B counter script (seal documents). */
"use strict";

(() => {
  const { $, log, sendJob, resolveProfile, buildLadder, bindStrength,
          bindDrop, addFileRow, rowsOf, wireKeyfile, armCancel, disarmCancel,
          cancelRequested, isCancelErr, estimateStrength, download, addResult,
          kb } = window.VB;

  buildLadder();
  bindDrop("#enc-drop", "#enc-list");
  bindStrength("#enc-pw1", "#enc-strength", "#enc-strength-label");
  wireKeyfile("#enc-keyfile-btn", "#enc-keyfile", "#enc-keyfile-name");

  $("#enc-pick").onchange = (e) => {
    for (const f of e.target.files) addFileRow("#enc-list", f);
    e.target.value = "";
  };

  $("#show-pw").onchange = (e) => {
    for (const s of ["#enc-pw1", "#enc-pw2"]) {
      const i = $(s); if (i) i.type = e.target.checked ? "text" : "password";
    }
  };

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
    armCancel("#enc-cancel");
    for (const { file, prog } of rows) {
      if (cancelRequested()) { log("batch stayed — remaining documents untouched."); break; }
      log(`encrypt ${file.name}${cascade ? " [cascade]" : ""}`);
      const res = await sendJob({
        op: "encrypt", file, password: kb(pw1), profile, params,
        keyData, cascade,
      }, prog);
      if (res.type === "error") {
        if (isCancelErr(res)) { log(`✗ ${file.name}: stayed by request`, "err"); break; }
        log(`✗ ${file.name}: ${res.message}`, "err");
        continue;
      }
      const saved = download(res.name, res.parts, res.length);
      addResult(saved.name, saved.size);
      log(`✓ ${res.name} sealed (${saved.size.toLocaleString()} B)`);
    }
    $("#enc-pw1").value = $("#enc-pw2").value = "";
    $("#enc-go").disabled = false;
    disarmCancel("#enc-cancel");
    log("Batch finished.");
  };
})();
