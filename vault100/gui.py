"""Vault100 desktop GUI v2 (Tkinter — no extra dependencies).

Run:  python -m vault100.gui

v2.0.22 — night-ledger bureau theme, live strength bar, the timekeeper
(bench), recently-handled forms, and a vault-verify desk.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .crypto_core import (DEFAULT_PROFILE, KDF_PROFILES, VaultAuthError,
                          VaultCancelled, VaultError, calibrate_profile,
                          change_password, decrypt_file, encrypt_file,
                          sanitize_filename, unique_path, vault_info,
                          verify_file)
from .keyfile import KeyfileError, generate_keyfile, identify, load_keyfile
from .shredder import ShredError, shred_file
from .strength import estimate
from . import __version__

SECURITY_CHOICES = sorted(KDF_PROFILES) + ["max (auto-tune)"]

# -- night-ledger palette (matches the web counter) ---------------------------
SHEET = "#121317"     # desk felt
PAPER = "#1c1e24"     # form paper
PAPER2 = "#23262e"    # raised paper
LINE = "#3a3d46"      # ruling lines
INK = "#ddd6c4"       # carbon ink
INK2 = "#8b8574"      # faded ink
RED = "#e15555"       # official stamp red
RED_D = "#a83838"     # stamp shadow
GREEN = "#58b368"
AMBER = "#e0a055"

STRENGTH_COLORS = ["#c0392b", "#e67e22", "#f1c40f", "#27ae60", "#1e8449"]


def _apply_theme(root: tk.Tk) -> ttk.Style:
    """Dress the whole box in the bureau's night ledger."""
    style = ttk.Style(root)
    style.theme_use("clam")
    root.configure(bg=SHEET)
    style.configure(".", background=SHEET, foreground=INK,
                    fieldbackground=PAPER, bordercolor=LINE,
                    darkcolor=SHEET, lightcolor=SHEET, troughcolor=SHEET,
                    selectbackground=RED_D, selectforeground="#ffffff")
    style.configure("TFrame", background=SHEET)
    style.configure("TLabel", background=SHEET, foreground=INK)
    style.configure("Hint.TLabel", background=SHEET, foreground=INK2)
    style.configure("Title.TLabel", background=SHEET, foreground=INK,
                    font=("TkDefaultFont", 10, "bold"))
    style.configure("TLabelframe", background=SHEET, foreground=INK,
                    bordercolor=LINE)
    style.configure("TLabelframe.Label", background=SHEET, foreground=RED,
                    font=("TkDefaultFont", 9, "bold"))
    style.configure("TButton", background=PAPER, foreground=INK,
                    bordercolor=LINE, padding=(10, 5))
    style.map("TButton",
              background=[("active", PAPER2), ("pressed", RED_D),
                          ("disabled", SHEET)],
              foreground=[("disabled", INK2), ("pressed", "#ffffff")])
    style.configure("Go.TButton", background=RED_D, foreground="#ffffff",
                    bordercolor=RED)
    style.map("Go.TButton",
              background=[("active", RED), ("pressed", RED_D)])
    style.configure("TCheckbutton", background=SHEET, foreground=INK)
    style.map("TCheckbutton", background=[("active", SHEET)])
    style.configure("TEntry", fieldbackground=PAPER, foreground=INK,
                    insertcolor=INK, bordercolor=LINE)
    style.configure("TCombobox", fieldbackground=PAPER, foreground=INK,
                    arrowcolor=INK, bordercolor=LINE, insertcolor=INK)
    style.map("TCombobox",
              fieldbackground=[("readonly", PAPER)],
              foreground=[("readonly", INK)],
              selectbackground=[("readonly", PAPER)],
              selectforeground=[("readonly", INK)])
    style.configure("TSpinbox", fieldbackground=PAPER, foreground=INK,
                    arrowcolor=INK, bordercolor=LINE, insertcolor=INK)
    style.configure("TNotebook", background=SHEET, bordercolor=LINE,
                    tabmargins=(2, 4, 2, 0))
    style.configure("TNotebook.Tab", background=PAPER, foreground=INK2,
                    padding=(16, 7), bordercolor=LINE)
    style.map("TNotebook.Tab",
              background=[("selected", PAPER2)],
              foreground=[("selected", RED)])
    style.configure("Horizontal.TProgressbar", background=RED,
                    troughcolor=PAPER, bordercolor=LINE)
    style.configure("TScrollbar", background=PAPER2, troughcolor=SHEET,
                    arrowcolor=INK, bordercolor=SHEET)
    style.map("TScrollbar", background=[("active", LINE)])
    root.option_add("*TCombobox*Listbox.background", PAPER)
    root.option_add("*TCombobox*Listbox.foreground", INK)
    root.option_add("*TCombobox*Listbox.selectBackground", RED_D)
    return style


def _plain(widget_parent, kind, **kw):
    """A palette-dressed tk.Listbox / tk.Text (the non-ttk widgets)."""
    base = dict(bg=PAPER, fg=INK, highlightthickness=1,
                highlightbackground=LINE, highlightcolor=RED,
                selectbackground=RED_D, selectforeground="#ffffff",
                relief="flat", bd=0)
    if kind is not tk.Listbox:               # listbox has no insertion cursor
        base["insertbackground"] = INK
    base.update(kw)
    return kind(widget_parent, **base)


# -- recently handled forms (kept on the user's own desk) ---------------------
def _recents_path() -> str:
    cfg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config")
    d = os.path.join(cfg, "vault100")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "recent.json")


def recents_load() -> list[str]:
    try:
        with open(_recents_path(), "r", encoding="utf-8") as f:
            items = json.load(f)
        return [p for p in items if isinstance(p, str)][:8]
    except (OSError, ValueError):
        return []


def recents_add(path: str) -> None:
    path = os.path.abspath(path)
    items = [p for p in recents_load() if p != path]
    items.insert(0, path)
    try:
        with open(_recents_path(), "w", encoding="utf-8") as f:
            json.dump(items[:8], f)
    except OSError:
        pass


class Vault100App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"Vault100 v{__version__} — the seal bureau's desk box")
        self.geometry("860x720")
        self.minsize(720, 620)
        self._style = _apply_theme(self)

        self._tasks: queue.Queue = queue.Queue()
        self._cancel = threading.Event()
        self._worker: threading.Thread | None = None

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.enc_tab = _CryptoTab(nb, self, mode="encrypt")
        self.dec_tab = _CryptoTab(nb, self, mode="decrypt")
        self.shred_tab = _ShredTab(nb, self)
        self.tools_tab = _ToolsTab(nb, self)
        nb.add(self.enc_tab, text="  Seal  ")
        nb.add(self.dec_tab, text="  Open  ")
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
        raise NotImplementedError

    def set_progress(self, frac, text):
        pass

    def _progress_cb(self, label):
        def cb(done, total):
            if self.app._cancel.is_set():
                raise VaultCancelled()
            if total:
                self.app.progress(min(1.0, done / total), label)
        return cb

    def _log_area(self, parent_frame):
        box = _plain(parent_frame, tk.Text, height=6, state="disabled",
                     wrap="word")
        return box

    def _write_log(self, box, text):
        box.configure(state="normal")
        stamp = time.strftime("%H:%M:%S")
        box.insert("end", f"[{stamp}] {text}\n")
        box.configure(state="disabled")
        box.see("end")


class _CryptoTab(_BaseTab):
    def __init__(self, parent, app, *, mode: str):
        super().__init__(parent, app)
        self.mode = mode
        pad = {"padx": 6, "pady": 4}
        verb = "Seal" if mode == "encrypt" else "Open"

        ttk.Label(self,
                  text="Files / folders to seal" if mode == "encrypt"
                  else "Vault100 files (.v100) to open",
                  style="Title.TLabel").pack(anchor="w", **pad)

        lb_frame = ttk.Frame(self)
        lb_frame.pack(fill="both", expand=True, **pad)
        self.listbox = _plain(lb_frame, tk.Listbox, height=6,
                              selectmode="extended")
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
        self.recent = tk.StringVar(value="recently handled…")
        self.recents_box = ttk.Combobox(
            btns, textvariable=self.recent, width=28, state="readonly",
            postcommand=self._recents_refresh)
        self.recents_box.pack(side="right")
        self.recents_box.bind("<<ComboboxSelected>>", self._recents_pick)

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
        ttk.Label(opts, text=hint, style="Hint.TLabel"
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
            self.compress = tk.BooleanVar(value=False)
            ttk.Checkbutton(
                opts, variable=self.cascade,
                text="Cascade mode (AES-256-GCM + XChaCha20, dual cipher)"
                ).grid(row=3, column=0, columnspan=3, sticky="w", **pad)
            ttk.Checkbutton(
                opts, variable=self.compress,
                text="Compress first (gzip inside the vault)") \
                .grid(row=4, column=0, columnspan=3, sticky="w", **pad)
            ttk.Checkbutton(
                opts, variable=self.shred,
                text="Shred originals after encryption").grid(
                row=5, column=0, columnspan=3, sticky="w", **pad)
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
            self.strength_bar = ttk.Progressbar(
                pwbox, mode="determinate", maximum=4, length=110)
            self.strength_bar.grid(row=1, column=1, sticky="e", **pad)
            self.strength_lbl = ttk.Label(pwbox, text="strength: —",
                                          style="Hint.TLabel")
            self.strength_lbl.grid(row=1, column=0, sticky="w", **pad)
            self.pw1.bind("<KeyRelease>", self._strength)
        ttk.Checkbutton(
            pwbox, text="Show", variable=show,
            command=lambda: [w.configure(show="" if show.get() else "•")
                             for w in widgets]).grid(row=0, column=3, **pad)

        act = ttk.Frame(self)
        act.pack(fill="x", **pad)
        ttk.Button(act, text=f"▶  {verb}", style="Go.TButton",
                   command=self._go).pack(side="left")
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

    def _recents_refresh(self):
        want = "" if self.mode == "encrypt" else ".v100"
        items = [p for p in recents_load()
                 if (p.endswith(".v100") if want else not p.endswith(".v100"))
                 and os.path.exists(p)]
        self.recents_box["values"] = items or ["(nothing handled recently)"]

    def _recents_pick(self, _evt):
        p = self.recent.get()
        if p and os.path.exists(p) and p not in self.listbox.get(0, "end"):
            self.listbox.insert("end", p)
        self.recent.set("recently handled…")

    def _strength(self, _evt):
        rep = estimate(self.pw1.get())
        self.strength_bar["value"] = rep["score"]
        self.strength_bar.configure(
            style=f"S{rep['score']}.Horizontal.TProgressbar")
        self.strength_lbl.configure(
            text=f"strength: {rep['label']} (offline-attack resistance: "
                 f"{rep['crack_time']})",
            foreground=STRENGTH_COLORS[rep["score"]])

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
            self.app.start_task(f"Sealing {len(paths)} item(s)…",
                                lambda: self._encrypt_all(paths, pw))
        else:
            self.app.start_task(f"Opening {len(paths)} file(s)…",
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
            self.app.log(f"  seal {arc}"
                         + (" [cascade]" if self.cascade.get() else "")
                         + (" [gzip]" if self.compress.get() else ""))
            encrypt_file(src, dst, pw.encode(), profile=profile,
                         params=params, key_data=key_data,
                         cascade=self.cascade.get(),
                         compress=self.compress.get(),
                         progress=self._progress_cb(arc))
            recents_add(dst)
            if self.shred.get():
                shred_file(src)
                self.app.log(f"    shredded {arc}")

    def _decrypt_all(self, paths, pw):
        outdir = self.outdir.get().strip() or None
        key_data = self._key_data()
        for src in paths:
            if self.app._cancel.is_set():
                raise VaultCancelled()
            self.app.log(f"  open {os.path.basename(src)}")
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
            recents_add(dst)
            recents_add(src)
            self.app.log(f"    → {dst}")
            if self.shred.get():
                shred_file(src)


class _ShredTab(_BaseTab):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        pad = {"padx": 6, "pady": 4}
        ttk.Label(self, text="Permanently destroy files (unrecoverable)",
                  style="Title.TLabel").pack(anchor="w", **pad)
        self.listbox = _plain(self, tk.Listbox, height=8,
                              selectmode="extended")
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
        ttk.Button(self, text="🔥  SHRED NOW", style="Go.TButton",
                   command=self._go).pack(anchor="w", **pad)
        self.logbox = self._log_area(self)
        self.logbox.pack(fill="both", expand=False, **pad)

    def log(self, text):
        self._write_log(self.logbox, text)

    def set_progress(self, frac, text):
        self.bar["value"] = frac * 100

    def _go(self):
        paths = [self.listbox.get(i) for i in range(self.listbox.size())]
        if not paths:
            messagebox.showwarning("Vault100", "Add at least one file.")
            return
        if not messagebox.askyesno(
                "Vault100",
                f"PERMANENTLY destroy {len(paths)} file(s)?"):
            return

        def work():
            for p in paths:
                if self.app._cancel.is_set():
                    raise VaultCancelled()
                self.app.log(f"  shred {p}")
                shred_file(p, passes=self.passes.get(),
                           progress=lambda d, t: self.app.progress(
                               min(1.0, d / t) if t else 0.0))

        self.app.start_task("Shredding…", work)


class _ToolsTab(_BaseTab):
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
        self.pc_vault = ttk.Combobox(pc, textvariable=self.pc_file, width=41,
                                     postcommand=self._pc_recents)
        self.pc_vault.grid(row=0, column=1, **pad)
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

        iv = ttk.LabelFrame(self, text="Vault desks — inspect & prove")
        iv.pack(fill="x", **pad)
        ttk.Button(iv, text="Inspect a .v100 file…", command=self._info_go
                   ).pack(side="left", **pad)
        ttk.Button(iv, text="Verify integrity (no files written)…",
                   command=self._verify_go).pack(side="left", **pad)
        ttk.Button(iv, text="⏱ Engage the stopwatch (bench)",
                   command=self._bench_go).pack(side="left", **pad)

        self.logbox = self._log_area(self)
        self.logbox.pack(fill="both", expand=True, **pad)

    def log(self, text):
        self._write_log(self.logbox, text)

    def _pick(self, var):
        p = filedialog.askopenfilename()
        if p:
            var.set(p)

    def _pc_recents(self):
        items = [p for p in recents_load()
                 if p.endswith(".v100") and os.path.exists(p)]
        self.pc_vault["values"] = items

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
            recents_add(path)
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
            recents_add(vault)
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
        recents_add(p)

    def _verify_go(self):
        paths = filedialog.askopenfilenames(
            filetypes=[("Vault100", "*.v100*"), ("All files", "*")])
        if not paths:
            return
        pw = self.pc_old.get()
        if not pw:
            messagebox.showwarning(
                "Vault100",
                "Enter the vault's password in “Current password” above — "
                "integrity is proven WITH the combination, never without.")
            return
        kf = self.pc_key.get().strip()

        def work():
            key_data = load_keyfile(kf) if kf else None
            for p in paths:
                if self.app._cancel.is_set():
                    raise VaultCancelled()
                t0 = time.time()
                self.app.log(f"  custody check {os.path.basename(p)}…")
                try:
                    meta = verify_file(p, pw.encode(), key_data=key_data,
                                       progress=self._progress_cb(
                                           os.path.basename(p)))
                except VaultAuthError:
                    self.app.log(f"    ✗ REFUSED — wrong combination/keyfile"
                                 f" or tampered vault: {p}")
                    continue
                name = meta.get("name") or "?"
                self.app.log(
                    f"    ✓ integrity proven — “{name}” opens clean "
                    f"({time.time() - t0:.1f}s; nothing written to disk)")
                recents_add(p)

        self.app.start_task(f"Verifying {len(paths)} vault(s)…", work)

    def _bench_go(self):
        def work():
            from .crypto_core import benchmark
            rep = benchmark(stream_mib=16, kdf_mibs=(8, 32, 64))
            x = rep["xchacha"]
            self.app.log(f"  xchacha20-poly1305 : {x['mib_s']:.1f} MiB/s")
            a = rep["aes"]
            self.app.log(f"  aes-256-gcm        : "
                         + (f"{a['mib_s']:.1f} MiB/s" if a else "unavailable"))
            for n in rep["argon2"]:
                if n["seconds"] is None:
                    self.app.log(f"  argon2id {n['memory_kib'] // 1024} MiB"
                                 f" ×1t : refused (out of memory)")
                else:
                    self.app.log(f"  argon2id {n['memory_kib'] // 1024} MiB"
                                 f" ×1t : {n['seconds']:.2f} s (4 lanes)")
            s = rep["standard_seconds"]
            if s is not None:
                self.app.log(f"  → standard profile (128 MiB × 3) ≈ {s:.1f} s"
                             f" per unlock on this desk")
            self.app.log("  advice: pick a notch whose cost stays ≈ 1–4 s "
                         "on this device")

        self.app.start_task("The timekeeper clocks this device…", work)


class _AboutTab(ttk.Frame):
    TEXT = f"""\
Vault100 v{__version__} — the seal bureau's desk box · security design

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
              tampering, reordering, truncation all fail loudly;
              Tools → “Verify integrity” proves a vault opens clean
              without writing a single byte to disk

  Shield      Armor (V100A1) folds vaults into paste-anywhere text;
              the quorum press (vault100 share) splits a secret into
              N slips, any M of which reprint it

  Privacy     Original filename + metadata encrypted inside the vault

No backdoors, no telemetry, no key escrow. Lose both your password and
keyfile and the data is gone forever — keep backups of what matters,
and lodge quorum slips apart for what you fear forgetting.
"""

    def __init__(self, parent):
        super().__init__(parent)
        t = _plain(self, tk.Text, wrap="word", state="normal")
        t.insert("1.0", self.TEXT)
        t.configure(state="disabled")
        t.pack(fill="both", expand=True, padx=10, pady=10)


def main() -> None:
    app = Vault100App()
    # per-score strength bar styles need the live style object
    st = app._style
    for i, col in enumerate(STRENGTH_COLORS):
        st.configure(f"S{i}.Horizontal.TProgressbar", background=col,
                     troughcolor=PAPER, bordercolor=LINE)
    app.mainloop()


if __name__ == "__main__":
    main()
