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
    }
    $("#dec-pw").value = "";
    $("#dec-go").disabled = false;
    disarmCancel("#dec-cancel");
    log("Batch finished.");
  };
})();
