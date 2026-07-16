/* Vault100 web — FORM 100-R counter script (change of combination).
 * The body's chunks are never touched — the clerk melts the old wrap
 * off the head and presses a new one on. */
"use strict";

(() => {
  const { $, log, sendJob, resolveProfile, buildLadder, bindStrength,
          bindDrop, rowsOf, wireKeyfile, armCancel, disarmCancel,
          cancelRequested, isCancelErr, estimateStrength, download,
          addResult, kb } = window.VB;

  buildLadder("#rw-security");
  bindDrop("#rw-drop", "#rw-list");
  bindStrength("#rw-new1", "#rw-strength", "#rw-strength-label");
  wireKeyfile("#rw-oldkey-btn", "#rw-oldkey", "#rw-oldkey-name");
  wireKeyfile("#rw-newkey-btn", "#rw-newkey", "#rw-newkey-name");

  // single document at this counter — picking again replaces the last
  $("#rw-pick").onchange = async (e) => {
    const f = e.target.files && e.target.files[0];
    e.target.value = "";
    if (!f) return;
    $("#rw-list").innerHTML = "";
    window.VB.addFileRow("#rw-list", f);
    inspect(f);
  };
  // bindDrop appends rows; keep facts in step with whatever is there
  new MutationObserver(() => {
    const rows = rowsOf($("#rw-list"));
    if (rows.length) {
      const keep = rows[rows.length - 1].file;
      if (rows.length > 1) {
        $("#rw-list").innerHTML = "";
        window.VB.addFileRow("#rw-list", keep);
        log("this counter re-issues one document at a time — kept the last.");
      }
      inspect(keep);
    } else {
      $("#rw-facts").hidden = true;
    }
  }).observe($("#rw-list"), { childList: true });

  async function inspect(file) {
    const facts = $("#rw-facts");
    facts.hidden = true;
    $("#rw-oldkey-row").hidden = true;
    const res = await sendJob({ op: "info", file });
    if (!res || res.kdf === undefined) {
      log(`✗ ${file.name}: ${(res && res.message) || "not a Vault100 vault"}`, "err");
      return;
    }
    const bits = [];
    bits.push(`${Math.round(res.kdf.memoryKib / 1024)} MiB × ${res.kdf.timeCost} turn(s), lanes ${res.kdf.parallelism}`);
    if (res.cascade) bits.push("double-lock (cascade)");
    if (res.keyfile) bits.push("bound to a keyfile");
    bits.push(`${res.size.toLocaleString()} B`);
    facts.textContent = `the clerk reads the head: ${bits.join(" · ")}`;
    facts.hidden = false;
    if (res.keyfile) {
      $("#rw-oldkey-row").hidden = false;
      log("this vault is bound to a keyfile — present it under Part II.");
    }
  }

  $("#rw-show").onchange = (e) => {
    for (const s of ["#rw-old", "#rw-new1", "#rw-new2"]) {
      const i = $(s); if (i) i.type = e.target.checked ? "text" : "password";
    }
  };

  $("#rw-go").onclick = async () => {
    const rows = rowsOf($("#rw-list"));
    if (!rows.length) return log("Present one sealed document.", "err");
    const oldPw = $("#rw-old").value;
    const pw1 = $("#rw-new1").value, pw2 = $("#rw-new2").value;
    if (!oldPw) return log("Enter the current passphrase.", "err");
    if (!pw1) return log("Enter the new passphrase.", "err");
    if (pw1 !== pw2) return log("New passphrases do not match.", "err");
    if (pw1 === oldPw) log("note — the new words read like the old ones; the salt still changes everything.");
    const rep = estimateStrength(pw1);
    if (rep.score < 3 && !confirm(
      `New passphrase strength: ${rep.label}.\nUse it anyway? (A 4-5 word passphrase is stronger.)`)) return;

    const { profile, params } = await resolveProfile($("#rw-security").value);
    const oldKeyBtn = $("#rw-oldkey-btn");
    const oldKeyData = oldKeyBtn._file
      ? new Uint8Array(await oldKeyBtn._file.arrayBuffer()) : null;
    const newKeyBtn = $("#rw-newkey-btn");
    const newKeyData = newKeyBtn._file
      ? new Uint8Array(await newKeyBtn._file.arrayBuffer()) : null;

    $("#rw-go").disabled = true;
    armCancel("#rw-cancel");
    for (const { file } of rows) {
      if (cancelRequested()) { log("recombination stayed by request."); break; }
      log(`recombinate ${file.name} — melting the old wrap…`);
      const res = await sendJob({
        op: "recombine", file,
        oldPassword: kb(oldPw), newPassword: kb(pw1),
        oldKeyData, newKeyData, profile, params,
      });
      if (res.type === "error") {
        if (isCancelErr(res)) { log(`✗ ${file.name}: stayed by request`, "err"); break; }
        log(`✗ ${file.name}: ${res.message}`, "err");
        continue;
      }
      const saved = download(res.name, res.parts, res.length);
      addResult(saved.name, saved.size);
      log(`✓ ${res.name} re-issued — head re-wrapped, body carried over (${saved.size.toLocaleString()} B)`);
    }
    $("#rw-old").value = $("#rw-new1").value = $("#rw-new2").value = "";
    $("#rw-go").disabled = false;
    disarmCancel("#rw-cancel");
    log("Batch finished.");
  };
})();
