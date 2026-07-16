/* Vault100 web — FORM 100-M counter script (the armorer: text ⇆ armor). */
"use strict";

(() => {
  const { $, log, sendJob, resolveProfile, buildLadder, bindStrength,
          estimateStrength, download, kb, copySecret, armCancel, disarmCancel,
          cancelRequested, isCancelErr } = window.VB;

  const MAX_LETTER = 512 * 1024;  // a letter, not a ledger
  const te = new TextEncoder();

  buildLadder("#ar-security");
  bindStrength("#st-pw1", "#st-strength", "#st-strength-label");

  $("#st-show").onchange = (e) => {
    for (const s of ["#st-pw1", "#st-pw2"]) {
      const i = $(s); if (i) i.type = e.target.checked ? "text" : "password";
    }
  };

  // ---------------- counter one: the stamper ----------------
  $("#st-go").onclick = async () => {
    const text = $("#st-text").value;
    if (!text) return log("The well is empty — whisper a message first.", "err");
    if (te.encode(text).length > MAX_LETTER)
      return log("The letter exceeds 512 KiB — take a knife to it first.", "err");
    const pw1 = $("#st-pw1").value, pw2 = $("#st-pw2").value;
    if (!pw1) return log("Choose a combination.", "err");
    if (pw1 !== pw2) return log("Combinations do not match.", "err");
    const rep = estimateStrength(pw1);
    if (rep.score < 3 && !confirm(
      `Combination strength: ${rep.label}.\nSeal anyway?`)) return;

    const sel = $("#ar-security").value;
    const { profile, params } = await resolveProfile(sel);
    const cascade = $("#ar-cascade").checked;

    $("#st-go").disabled = true;
    armCancel("#st-cancel");
    log(`mint armor — ${te.encode(text).length.toLocaleString()} B letter`
        + (cascade ? " [double-lock]" : ""));
    const res = await sendJob({
      op: "armor-enc", text, password: kb(pw1), profile, params, cascade,
    });
    $("#st-go").disabled = false;
    disarmCancel("#st-cancel");
    if (cancelRequested() || isCancelErr(res)) {
      log("the press was stayed — no armor minted.");
      return;
    }
    if (res.type === "error") return log("✗ minting failed: " + res.message, "err");
    $("#st-out").value = res.armor;
    $("#st-pw1").value = $("#st-pw2").value = "";
    log(`✓ armor minted — ${res.armor.length.toLocaleString()} characters ` +
        `(body ${res.armor.length.toLocaleString()} B), ready to travel`);
  };

  $("#st-copy").onclick = () => {
    const a = $("#st-out").value;
    if (!a) return log("Nothing to copy — mint first.", "err");
    copySecret(a, "armor");
  };

  $("#st-dl").onclick = () => {
    const a = $("#st-out").value;
    if (!a) return log("Nothing to file — mint first.", "err");
    const bytes = te.encode(a);
    const saved = download("message.v100asc", [bytes], bytes.length);
    log(`armor filed as ${saved.name}`);
  };

  // courier hand-off — short armor scraps fly to the phone by camera, not wire
  $("#st-qr").onclick = () => {
    const a = $("#st-out").value;
    if (!a) return log("Nothing to stamp — mint first.", "err");
    const r = window.VB.makeQR(a);
    if (r.error)
      return log("✗ the courier refused: " + r.error +
        ". Long letters travel as .v100asc files; the stamp is for short scraps.", "err");
    let box = $("#st-qrbox");
    if (!box) {
      box = document.createElement("div");
      box.id = "st-qrbox";
      box.className = "qrbox";
      box.hidden = true;
      const frame = document.createElement("div");
      frame.className = "qrframe";
      frame.setAttribute("role", "img");
      frame.setAttribute("aria-label", "courier QR stamp");
      const meta = document.createElement("div");
      meta.className = "qrmeta";
      box.appendChild(frame); box.appendChild(meta);
      const out = $("#st-out");
      out.parentElement.insertBefore(box, out.nextSibling);
    }
    box.hidden = false;
    box.querySelector(".qrframe").innerHTML = r.svg;
    box.querySelector(".qrmeta").innerHTML = "";
    const d = document.createElement("div");
    d.textContent = `${r.chars.toLocaleString()} ch pressed into a ` +
      `${r.size}×${r.size} stamp · scan with any phone camera — ` +
      "no cable, no cloud, no record";
    box.querySelector(".qrmeta").appendChild(d);
    log(`courier stamp pressed — ${r.chars.toLocaleString()} ch; ` +
        `the phone reads ${r.size}×${r.size} ink`);
  };

  // ---------------- counter two: the opener ----------------
  $("#op-go").onclick = async () => {
    const armor = $("#op-in").value.trim();
    if (!armor) return log("Paste an armor block first.", "err");
    if (!armor.includes("BEGIN V100 ARMOR"))
      return log("No BEGIN V100 ARMOR fence in sight — is that armor?", "err");
    const pw = $("#op-pw").value;
    if (!pw) return log("Enter the combination.", "err");

    $("#op-go").disabled = true;
    armCancel("#op-cancel");
    const res = await sendJob({ op: "armor-dec", armor, password: kb(pw) });
    $("#op-go").disabled = false;
    disarmCancel("#op-cancel");
    if (isCancelErr(res)) return log("the opening was stayed.");
    if (res.type === "error") return log("✗ " + res.message, "err");
    $("#op-out").value = res.text;
    $("#op-pw").value = "";
    log(`✓ letter opened — ${te.encode(res.text).length.toLocaleString()} B ` +
        `of readable message; the furnace will take your copy in 60 s if used`);
  };

  $("#op-copy").onclick = () => {
    const t = $("#op-out").value;
    if (!t) return log("Nothing to copy — open a letter first.", "err");
    copySecret(t, "message");
  };
})();
