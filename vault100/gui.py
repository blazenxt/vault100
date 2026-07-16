"""Vault100 desktop GUI v2 (Tkinter — no extra dependencies).

Run:  python -m vault100.gui
"""

from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .crypto_core import (DEFAULT_PROFILE, KDF_PROFILES, VaultAuthError,
                          VaultCancelled, VaultError, calibrate_profile,
                          change_password, decrypt_file, encrypt_file,
                          sanitize_filename, unique_path, vault_info)
from .keyfile import KeyfileError, generate_keyfile, identify, load_keyfile
from .shredder import ShredError, shred_file
from .strength import estimate

SECURITY_CHOICES = sorted(KDF_PROFILES) + ["max (auto-tune)"]


class Vault100App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Vault100 v2 — Maximum-Security File Encryption")
        self.geometry("820x700")
        self.minsize(700, 600)

        self._tasks: queue.Queue = queue.Queue()
        self._cancel = threading.Event()
        self._worker: threading.Thread | None = None

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.enc_tab = _CryptoTab(nb, self, mode="encrypt")
        self.dec_tab = _CryptoTab(nb, self, mode="decrypt")
        self.shred_tab = _ShredTab(nb, self)
        self.tools_tab = _ToolsTab(nb, self)
        nb.add(self.enc_tab, text="  Encrypt  ")
        nb.add(self.dec_tab, text="  Decrypt  ")
        nb.add(self.shred_tab, text="  Shred  ")
        nb.add(self.tools_tab, text="  Tools  ")
        nb.add(_AboutTab(nb), text="  About  ")

        self._tabs = (self.enc_tab, self.dec_tab, self.shred_tab,
                      self.tools_tab)
        self.after(80, self._pump)

    # -- worker plumbing ----------------------------------------------------
    def start_task(self, label: str, fn) -> bool:
        if self._worker and self._worker.is_alive():
            messagebox.showwarning("Vault100", "An operation is already "
                                               "running.")
            return False
        self._cancel.clear()
        self.log(f"▶ {label}")
        for t in self._tabs:
            t.set_progress(0.0, "")
        self._worker = threading.Thread(target=self._run, args=(fn,),
                                        daemon=True)
        self._worker.start()
        return True

    def _run(self, fn):
        try:
            fn()
            self._tasks.put(("done", True, "Operation completed."))
        except VaultCancelled:
            self._tasks.put(("done", False, "Cancelled."))
        except VaultAuthError:
            self._tasks.put(("done", False,
                             "Wrong password/keyfile or corrupted vault."))
        except (VaultError, KeyfileError, ShredError, OSError) as e:
            self._tasks.put(("done", False, str(e)))
        except Exception as e:  # never leave the UI hanging
            self._tasks.put(("done", False, f"Unexpected error: {e}"))

    def _pump(self):
        try:
            while True:
                kind, *payload = self._tasks.get_nowait()
                if kind == "log":
                    for t in self._tabs:
                        t.log(payload[0])
                elif kind == "progress":
                    frac = payload[0]
                    for t in self._tabs:
                        t.set_progress(frac, "")
                elif kind == "done":
                    success, msg = payload
                    for t in self._tabs:
                        t.set_progress(0.0, "")
                        t.log(("✓ " if success else "✗ ") + msg)
                    if msg != "Operation completed." and msg != "Cancelled.":
                        (messagebox.showinfo if success
                         else messagebox.showerror)("Vault100", msg)
        except queue.Empty:
            pass
        self.after(80, self._pump)

    def log(self, text):
        self._tasks.put(("log", text))

    def progress(self, frac, text=""):
        self._tasks.put(("progress", frac, text))


class _BaseTab(ttk.Frame):
    def __init__(self, parent, app: Vault100App):
        super().__init__(parent)
        self.app = app

    def log(self, text):
        pass

    def set_progress(self, frac, text):
        pass

    def _progress_cb(self, label):
        def cb(done, total):
            if self.app._cancel.is_set():
                raise VaultCancelled()
            self.app.progress(done / total if total else 0.0, label)
        return cb

    def _log_area(self, parent_frame):
        box = tk.Text(parent_frame, height=6, state="disabled", wrap="word")
        return box

    def _write_log(self, box, text):
        box.configure(state="normal")
        box.insert("end", text + "\n")
        box.see("end")
        box.configure(state="disabled")


class _CryptoTab(_BaseTab):
    def __init__(self, parent, app, *, mode: str):
        super().__init__(parent, app)
        self.mode = mode
        pad = {"padx": 6, "pady": 4}
        verb = "Encrypt" if mode == "encrypt" else "Decrypt"

        ttk.Label(self,
                  text="Files / folders to encrypt" if mode == "encrypt"
                  else "Vault100 files (.v100) to decrypt",
                  font=("TkDefaultFont", 10, "bold")).pack(anchor="w", **pad)

        lb_frame = ttk.Frame(self)
        lb_frame.pack(fill="both", expand=True, **pad)
        self.listbox = tk.Listbox(lb_frame, height=6, selectmode="extended")
        sb = ttk.Scrollbar(lb_frame, command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=sb.set)
        self.listbox.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        btns = ttk.Frame(self)
        btns.pack(fill="x", **pad)
        ttk.Button(btns, text="Add files…", command=self._add_files
                   ).pack(side="left")
        if mode == "encrypt":
            ttk.Button(btns, text="Add folder…", command=self._add_folder
                       ).pack(side="left", padx=4)
        ttk.Button(btns, text="Remove selected", command=self._remove
                   ).pack(side="left", padx=4)
        ttk.Button(btns, text="Clear",
                   command=lambda: self.listbox.delete(0, "end")
                   ).pack(side="left")

        opts = ttk.LabelFrame(self, text="Options")
        opts.pack(fill="x", **pad)
        ttk.Label(opts, text="Output folder:").grid(row=0, column=0,
                                                    sticky="w", **pad)
        self.outdir = tk.StringVar()
        ttk.Entry(opts, textvariable=self.outdir, width=40
                  ).grid(row=0, column=1, **pad)
        ttk.Button(opts, text="Browse…", command=self._browse_out
                   ).grid(row=0, column=2, **pad)

        # second factor
        ttk.Label(opts, text="Keyfile:").grid(row=1, column=0,
                                              sticky="w", **pad)
        self.keyfile = tk.StringVar()
        ttk.Entry(opts, textvariable=self.keyfile, width=40
                  ).grid(row=1, column=1, **pad)
        ttk.Button(opts, text="Browse…", command=self._browse_key
                   ).grid(row=1, column=2, **pad)
        hint = ("optional second factor — vault then needs BOTH"
                if mode == "encrypt" else "required if vault was made with one")
        ttk.Label(opts, text=hint, foreground="#666"
                  ).grid(row=1, column=3, sticky="w", **pad)

        self.shred = tk.BooleanVar(value=False)
        self.cascade = tk.BooleanVar(value=False)
        if mode == "encrypt":
            ttk.Label(opts, text="Security level:").grid(row=2, column=0,
                                                         sticky="w", **pad)
            self.security = tk.StringVar(value=DEFAULT_PROFILE)
            ttk.Combobox(opts, textvariable=self.security, width=16,
                         state="readonly",
                         values=SECURITY_CHOICES).grid(row=2, column=1,
                                                       sticky="w", **pad)
            ttk.Checkbutton(
                opts, variable=self.cascade,
                text="Cascade mode (AES-256-GCM + XChaCha20, dual cipher)"
                ).grid(row=3, column=0, columnspan=3, sticky="w", **pad)
            ttk.Checkbutton(
                opts, variable=self.shred,
                text="Shred originals after encryption").grid(
                row=4, column=0, columnspan=3, sticky="w", **pad)
        else:
            self.restore = tk.BooleanVar(value=True)
            ttk.Checkbutton(opts, variable=self.restore,
                            text="Restore original filenames"
                            ).grid(row=2, column=0, columnspan=3,
                                   sticky="w", **pad)
            ttk.Checkbutton(opts, variable=self.shred,
                            text="Delete encrypted copies after decryption"
                            ).grid(row=3, column=0, columnspan=3,
                                   sticky="w", **pad)

        pwbox = ttk.LabelFrame(self, text="Password")
        pwbox.pack(fill="x", **pad)
        show = tk.BooleanVar(value=False)
        self.pw1 = ttk.Entry(pwbox, show="•", width=36)
        self.pw1.grid(row=0, column=0, **pad)
        widgets = [self.pw1]
        if mode == "encrypt":
            self.pw2 = ttk.Entry(pwbox, show="•", width=36)
            self.pw2.grid(row=0, column=1, **pad)
            widgets.append(self.pw2)
            self.strength_lbl = ttk.Label(pwbox, text="strength: —")
            self.strength_lbl.grid(row=1, column=0, columnspan=2,
                                   sticky="w", **pad)
            self.pw1.bind("<KeyRelease>", self._strength)
        ttk.Checkbutton(
            pwbox, text="Show", variable=show,
            command=lambda: [w.configure(show="" if show.get() else "•")
                             for w in widgets]).grid(row=0, column=3, **pad)

        act = ttk.Frame(self)
        act.pack(fill="x", **pad)
        ttk.Button(act, text=f"▶  {verb}", command=self._go).pack(side="left")
        ttk.Button(act, text="✖  Cancel", command=self.app._cancel.set
                   ).pack(side="left", padx=8)
        self.bar = ttk.Progressbar(act, mode="determinate")
        self.bar.pack(side="left", fill="x", expand=True, padx=8)

        self.logbox = self._log_area(self)
        self.logbox.pack(fill="both", expand=False, **pad)

    # -- helpers ------------------------------------------------------------
    def _add_files(self):
        for p in filedialog.askopenfilenames():
            self.listbox.insert("end", p)

    def _add_folder(self):
        p = filedialog.askdirectory()
        if p:
            self.listbox.insert("end", p)

    def _remove(self):
        for i in reversed(self.listbox.curselection()):
            self.listbox.delete(i)

    def _browse_out(self):
        p = filedialog.askdirectory()
        if p:
            self.outdir.set(p)

    def _browse_key(self):
        p = filedialog.askopenfilename()
        if p:
            self.keyfile.set(p)

    def _strength(self, _evt):
        rep = estimate(self.pw1.get())
        colors = ["#c0392b", "#e67e22", "#f1c40f", "#27ae60", "#1e8449"]
        self.strength_lbl.configure(
            text=f"strength: {rep['label']} (offline-attack resistance: "
                 f"{rep['crack_time']})",
            foreground=colors[rep["score"]])

    def log(self, text):
        self._write_log(self.logbox, text)

    def set_progress(self, frac, text):
        self.bar["value"] = frac * 100

    def _key_data(self):
        kf = self.keyfile.get().strip()
        return load_keyfile(kf) if kf else None

    def _go(self):
        paths, pw = [self.listbox.get(i) for i in
                     range(self.listbox.size())], self.pw1.get()
        if not paths:
            messagebox.showwarning("Vault100", "Add at least one file/folder.")
            return
        if not pw:
            messagebox.showwarning("Vault100", "Enter a password.")
            return
        if self.mode == "encrypt":
            if self.pw2.get() != pw:
                messagebox.showerror("Vault100", "Passwords do not match.")
                return
            rep = estimate(pw)
            if rep["score"] < 3 and not messagebox.askyesno(
                    "Vault100", f"Password strength: {rep['label']}.\n"
                    + "\n".join(rep["tips"]) + "\n\nUse it anyway?"):
                return
            self.app.start_task(f"Encrypting {len(paths)} item(s)…",
                                lambda: self._encrypt_all(paths, pw))
        else:
            self.app.start_task(f"Decrypting {len(paths)} file(s)…",
                                lambda: self._decrypt_all(paths, pw))

    # -- workers ------------------------------------------------------------
    def _expand(self, paths):
        for p in paths:
            if os.path.isdir(p):
                base = os.path.basename(p.rstrip(os.sep))
                for root, _d, files in os.walk(p):
                    for fn in sorted(files):
                        full = os.path.join(root, fn)
                        yield full, os.path.join(
                            base, os.path.relpath(full, p))
            elif os.path.isfile(p):
                yield p, os.path.basename(p)

    def _encrypt_all(self, paths, pw):
        outdir = self.outdir.get().strip() or None
        key_data = self._key_data()
        if key_data is not None:
            self.app.log(f"  keyfile: {identify(self.keyfile.get().strip())}")
        sec = self.security.get()
        if sec.startswith("max"):
            self.app.log("  calibrating Argon2id to this machine…")
            params = calibrate_profile(target_seconds=2.0)
            profile = DEFAULT_PROFILE
            self.app.log(f"  → {params['memory_kib'] // 1024} MiB × "
                         f"{params['time_cost']} pass(es)")
        else:
            params = None
            profile = sec
        for src, arc in self._expand(paths):
            if self.app._cancel.is_set():
                raise VaultCancelled()
            if outdir:
                dst = os.path.join(outdir, arc + ".v100")
                os.makedirs(os.path.dirname(os.path.abspath(dst)),
                            exist_ok=True)
            else:
                dst = src + ".v100"
            self.app.log(f"  encrypt {arc}"
                         + (" [cascade]" if self.cascade.get() else ""))
            encrypt_file(src, dst, pw.encode(), profile=profile,
                         params=params, key_data=key_data,
                         cascade=self.cascade.get(),
                         progress=self._progress_cb(arc))
            if self.shred.get():
                shred_file(src)
                self.app.log(f"    shredded {arc}")

    def _decrypt_all(self, paths, pw):
        outdir = self.outdir.get().strip() or None
        key_data = self._key_data()
        for src in paths:
            if self.app._cancel.is_set():
                raise VaultCancelled()
            self.app.log(f"  decrypt {os.path.basename(src)}")
            tmp = unique_path(src + ".out")
            try:
                meta = decrypt_file(src, tmp, pw.encode(),
                                    key_data=key_data,
                                    progress=self._progress_cb(
                                        os.path.basename(src)))
            except BaseException:
                if os.path.exists(tmp):
                    os.unlink(tmp)
                raise
            if self.restore.get() and meta.get("name"):
                final = sanitize_filename(str(meta["name"]))
            else:
                base = os.path.basename(src)
                final = base[:-5] if base.endswith(".v100") else base + ".out"
            d = outdir or os.path.dirname(src)
            dst = unique_path(os.path.join(d, final))
            os.replace(tmp, dst)
            self.app.log(f"    → {dst}")
            if self.shred.get():
                shred_file(src)


class _ShredTab(_BaseTab):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        pad = {"padx": 6, "pady": 4}
        ttk.Label(self, text="Permanently destroy files (unrecoverable)",
                  font=("TkDefaultFont", 10, "bold")).pack(anchor="w", **pad)
        self.listbox = tk.Listbox(self, height=8, selectmode="extended")
        self.listbox.pack(fill="both", expand=True, **pad)
        row = ttk.Frame(self)
        row.pack(fill="x", **pad)
        ttk.Button(row, text="Add files…",
                   command=lambda: [self.listbox.insert("end", p) for p in
                                    filedialog.askopenfilenames()]
                   ).pack(side="left")
        ttk.Button(row, text="Clear",
                   command=lambda: self.listbox.delete(0, "end")
                   ).pack(side="left", padx=6)
        ttk.Label(row, text="Passes:").pack(side="left", padx=(20, 4))
        self.passes = tk.IntVar(value=3)
        ttk.Spinbox(row, from_=1, to=35, width=5,
                    textvariable=self.passes).pack(side="left")
        self.bar = ttk.Progressbar(self, mode="determinate")
        self.bar.pack(fill="x", **pad)
        ttk.Button(self, text="🔥  SHRED NOW", command=self._go
                   ).pack(anchor="w", **pad)
        self.logbox = self._log_area(self)
        self.logbox.pack(fill="both", expand=False, **pad)

    def log(self, text):
        self._write_log(self.logbox, text)

    def set_progress(self, frac, text):
        self.bar["value"] = frac * 100

    def _go(self):
        paths = [self.listbox.get(i) for i in range(self.listbox.size())]
        if not paths:
            messagebox.showwarning("Vault100", "Add files first.")
            return
        if not messagebox.askyesno(
                "Vault100", f"PERMANENTLY destroy {len(paths)} file(s)?\n"
                "This cannot be undone."):
            return
        n = self.passes.get()

        def work():
            for pth in paths:
                if self.app._cancel.is_set():
                    raise VaultCancelled()
                self.app.log(f"  shredding {pth}")
                shred_file(pth, passes=n,
                           progress=lambda d, t: self.app.progress(
                               d / max(t, 1), pth))
                self.app.log("    gone.")
            self.listbox.delete(0, "end")

        self.app.start_task(f"Shredding {len(paths)} file(s)…", work)


class _ToolsTab(_BaseTab):
    """keygen / change password / vault info."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        pad = {"padx": 6, "pady": 4}

        kg = ttk.LabelFrame(self, text="Generate keyfile (second factor)")
        kg.pack(fill="x", **pad)
        self.kg_path = tk.StringVar()
        ttk.Entry(kg, textvariable=self.kg_path, width=52
                  ).pack(side="left", **pad)
        ttk.Button(kg, text="Save as…", command=self._kg_browse
                   ).pack(side="left")
        ttk.Button(kg, text="Generate", command=self._kg_go
                   ).pack(side="left", padx=6)

        pc = ttk.LabelFrame(self, text="Change vault password "
                                       "(instant — no data re-encryption)")
        pc.pack(fill="x", **pad)
        self.pc_file = tk.StringVar()
        ttk.Label(pc, text="Vault:").grid(row=0, column=0, sticky="w", **pad)
        ttk.Entry(pc, textvariable=self.pc_file, width=44
                  ).grid(row=0, column=1, **pad)
        ttk.Button(pc, text="Browse…", command=lambda: self._pick(
            self.pc_file)).grid(row=0, column=2, **pad)
        ttk.Label(pc, text="Current password:").grid(row=1, column=0,
                                                     sticky="w", **pad)
        self.pc_old = ttk.Entry(pc, show="•", width=30)
        self.pc_old.grid(row=1, column=1, sticky="w", **pad)
        ttk.Label(pc, text="New password:").grid(row=2, column=0,
                                                 sticky="w", **pad)
        self.pc_new = ttk.Entry(pc, show="•", width=30)
        self.pc_new.grid(row=2, column=1, sticky="w", **pad)
        ttk.Label(pc, text="Current keyfile (if any):").grid(
            row=3, column=0, sticky="w", **pad)
        self.pc_key = tk.StringVar()
        ttk.Entry(pc, textvariable=self.pc_key, width=44
                  ).grid(row=3, column=1, **pad)
        ttk.Button(pc, text="Browse…", command=lambda: self._pick(
            self.pc_key)).grid(row=3, column=2, **pad)
        ttk.Button(pc, text="Change password", command=self._pc_go
                   ).grid(row=4, column=1, sticky="w", **pad)

        iv = ttk.LabelFrame(self, text="Vault info (no secrets)")
        iv.pack(fill="x", **pad)
        ttk.Button(iv, text="Inspect a .v100 file…", command=self._info_go
                   ).pack(side="left", **pad)

        self.logbox = self._log_area(self)
        self.logbox.pack(fill="both", expand=True, **pad)

    def log(self, text):
        self._write_log(self.logbox, text)

    def _pick(self, var):
        p = filedialog.askopenfilename()
        if p:
            var.set(p)

    def _kg_browse(self):
        p = filedialog.asksaveasfilename(defaultextension=".v100key")
        if p:
            self.kg_path.set(p)

    def _kg_go(self):
        path = self.kg_path.get().strip()
        if not path:
            messagebox.showwarning("Vault100", "Choose a save location.")
            return

        def work():
            self.app.log(f"  generating {path}")
            generate_keyfile(path, overwrite=False)
            self.app.log("  guard it like a house key — and back it up.")

        self.app.start_task("Generating keyfile…", work)

    def _pc_go(self):
        vault = self.pc_file.get().strip()
        if not vault or not self.pc_old.get() or not self.pc_new.get():
            messagebox.showwarning("Vault100", "Fill in vault + both "
                                               "passwords.")
            return

        def work():
            kf = self.pc_key.get().strip()
            change_password(
                vault, self.pc_old.get().encode(),
                self.pc_new.get().encode(),
                old_key_data=load_keyfile(kf) if kf else None,
                new_key_data=load_keyfile(kf) if kf else None)
            self.app.log("  password re-sealed; the old one is now useless "
                         "for this vault")

        self.app.start_task("Changing password…", work)

    def _info_go(self):
        p = filedialog.askopenfilename(filetypes=[("Vault100", "*.v100"),
                                                  ("All files", "*")])
        if not p:
            return
        try:
            info = vault_info(p)
        except (VaultError, OSError) as e:
            messagebox.showerror("Vault100", str(e))
            return
        k = info["kdf"]
        self.log(f"  {os.path.basename(p)}")
        self.log(f"    format v{info['format']} · cipher {info['cipher']}")
        self.log(f"    cascade {'yes' if info['cascade'] else 'no'} · "
                 f"keyfile {'required' if info['keyfile'] else 'no'}")
        self.log(f"    Argon2id {k['memory_kib'] // 1024} MiB × "
                 f"{k['time_cost']} · {info['size']:,} bytes")


class _AboutTab(ttk.Frame):
    TEXT = """\
Vault100 v2 — security design

  Vault key   Random per-file key (FEK), wrapped by your password key
              ⇒ password changes are instant; data is never re-encrypted

  Factors     password  (+ optional keyfile = physical 2nd factor)
              KEK = HKDF( Argon2id(password) ‖ BLAKE2b(keyfile) )

  Cipher      XChaCha20-Poly1305 (libsodium secretstream)
              optional CASCADE: AES-256-GCM sealed inside XChaCha20 —
              if either algorithm is ever broken, the other still holds

  Key deriv.  Argon2id, random 32-byte salt per vault
              standard 128 MiB×3 · paranoid 512 MiB×4 · max: auto-tuned
              to your machine (~2 s per unlock, forever for attackers)

  Integrity   AEAD per chunk + header bound as AAD at both layers —
              tampering, reordering, truncation all fail loudly

  Privacy     Original filename + metadata encrypted inside the vault

No backdoors, no telemetry, no key escrow. Lose both your password and
keyfile and the data is gone forever — keep backups of what matters.
"""

    def __init__(self, parent):
        super().__init__(parent)
        t = tk.Text(self, wrap="word", relief="flat", state="normal")
        t.insert("1.0", self.TEXT)
        t.configure(state="disabled")
        t.pack(fill="both", expand=True, padx=10, pady=10)


def main() -> None:
    app = Vault100App()
    app.mainloop()


if __name__ == "__main__":
    main()
