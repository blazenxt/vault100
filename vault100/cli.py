"""Vault100 command-line interface (v2).

Examples
--------
    python -m vault100 encrypt secret.pdf photos/ --shred
    python -m vault100 encrypt big.iso --security paranoid --cascade
    python -m vault100 keygen usb/key.v100key
    python -m vault100 encrypt wallet.dat --keyfile usb/key.v100key
    python -m vault100 passwd wallet.dat.v100
    python -m vault100 info wallet.dat.v100
    python -m vault100 genpass --passphrase
    python -m vault100 bench
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time

from .crypto_core import (DEFAULT_PROFILE, KDF_PROFILES, VaultAuthError,
                          VaultCancelled, VaultError, calibrate_profile,
                          change_password, decrypt_file, encrypt_file,
                          sanitize_filename, unique_path, vault_info)
from .genpass import gen_passphrase, gen_password
from .keyfile import KeyfileError, generate_keyfile, identify, load_keyfile
from .shredder import ShredError, shred_file
from .strength import estimate

EXT = ".v100"
SECURITY_CHOICES = sorted(KDF_PROFILES) + ["max"]


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def _read_password(args, *, confirm: bool, prompt: str = "Password: ") -> bytes:
    if getattr(args, "password_file", None):
        with open(args.password_file, "rb") as f:
            return f.read().rstrip(b"\r\n")
    env = os.environ.get("VAULT100_PASSWORD")
    if env is not None:
        return env.encode("utf-8")
    pw = getpass.getpass(prompt)
    if confirm:
        if pw != getpass.getpass("Confirm password: "):
            raise VaultError("passwords do not match")
        rep = estimate(pw)
        print(f"Password strength: {rep['label']} "
              f"(offline-attack resistance: {rep['crack_time']})",
              file=sys.stderr)
        if rep["score"] < 3 and not getattr(args, "force", False):
            for tip in rep["tips"]:
                print(f"  tip: {tip}", file=sys.stderr)
            if sys.stdin.isatty():
                if input("Use this weak password anyway? [y/N] "
                         ).strip().lower() != "y":
                    raise VaultError("aborted — choose a stronger password")
            else:
                raise VaultError("weak password refused (--force overrides)")
    if not pw:
        raise VaultError("empty password is not allowed")
    return pw.encode("utf-8")


def _load_key(path: str | None) -> bytes | None:
    if not path:
        return None
    return load_keyfile(path)


def _kdf_params(args) -> dict | None:
    """Resolve --security to explicit params (None → named default)."""
    if getattr(args, "security", None) == "max":
        print("  calibrating Argon2id to this machine…", file=sys.stderr)
        p = calibrate_profile(target_seconds=2.0)
        print(f"  → {p['memory_kib'] // 1024} MiB × {p['time_cost']} pass(es)",
              file=sys.stderr)
        return p
    return None  # core applies the named profile


def _iter_targets(paths, recursive):
    for p in paths:
        ap = os.path.abspath(p)
        if os.path.isdir(ap):
            if not recursive:
                print(f"  ! skipping directory (use -r): {p}", file=sys.stderr)
                continue
            base = os.path.basename(ap.rstrip(os.sep)) or "root"
            for root, _dirs, files in os.walk(ap):
                for fn in sorted(files):
                    full = os.path.join(root, fn)
                    yield full, os.path.join(base, os.path.relpath(full, ap))
        elif os.path.isfile(ap):
            yield ap, os.path.basename(ap)
        else:
            print(f"  ! not found, skipped: {p}", file=sys.stderr)


class _Progress:
    def __init__(self, label: str, total: int, quiet: bool):
        self.label, self.total, self.quiet = label, max(total, 1), quiet
        self.t0 = time.monotonic()

    def __call__(self, done, total):
        if self.quiet:
            return
        t = total or self.total
        frac = min(done / t, 1.0) if t else 1.0
        bars = int(frac * 28)
        print(f"\r    [{'#' * bars:<28}] {frac * 100:5.1f}%",
              end="", flush=True)

    def finish(self, note=""):
        if self.quiet:
            return
        dt = max(time.monotonic() - self.t0, 1e-6)
        rate = (self.total / dt) / (1024 * 1024)
        print(f"\r    done in {dt:.1f}s ({rate:.1f} MiB/s){note}          ")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_encrypt(args) -> int:
    targets = list(_iter_targets(args.paths, args.recursive))
    if not targets:
        print("nothing to encrypt", file=sys.stderr)
        return 1
    pw = _read_password(args, confirm=True)
    key_data = _load_key(args.keyfile)
    if args.keyfile:
        print(f"  keyfile: {identify(args.keyfile)}")
    params = _kdf_params(args)

    ok = True
    out_ext = ".v100asc" if args.armor else EXT
    for src, arc in targets:
        if src.endswith(EXT) or src.endswith(".v100asc"):
            print(f"  ! already looks encrypted, skipped: {arc}")
            continue
        if args.output:
            dst = os.path.join(args.output, arc + out_ext)
            os.makedirs(os.path.dirname(os.path.abspath(dst)), exist_ok=True)
        else:
            dst = src + out_ext
        print(f"  encrypt {arc}" + (" [armor]" if args.armor else ""))
        prog = _Progress(arc, os.path.getsize(src), args.quiet)
        try:
            encrypt_file(src, dst, pw, profile=args.security
                         if args.security != "max" else DEFAULT_PROFILE,
                         params=params, key_data=key_data,
                         cascade=args.cascade, compress=args.compress,
                         armor=args.armor, progress=prog)
            prog.finish((" [armor]" if args.armor else "")
                        + (" [cascade]" if args.cascade else ""))
            if args.shred:
                shred_file(src, passes=args.passes)
                if not args.quiet:
                    print("    original shredded")
        except (VaultError, OSError, ShredError, KeyfileError) as e:
            prog.finish(" FAILED")
            print(f"  ✗ {arc}: {e}", file=sys.stderr)
            ok = False
    return 0 if ok else 1


def cmd_decrypt(args) -> int:
    targets = [(os.path.abspath(p), os.path.basename(p))
               for p in args.paths if os.path.isfile(p)]
    if not targets:
        print("nothing to decrypt (no such files)", file=sys.stderr)
        return 1
    pw = _read_password(args, confirm=False)
    key_data = _load_key(args.keyfile)

    ok = True
    exit_code = 0
    for src, arc in targets:
        print(f"  decrypt {arc}")
        prog = _Progress(arc, os.path.getsize(src), args.quiet)
        outdir = args.output or os.path.dirname(src) or os.getcwd()
        if args.output:
            os.makedirs(args.output, exist_ok=True)
        tmp_out = unique_path(os.path.join(outdir, ".v100-out"))
        try:
            meta = decrypt_file(src, tmp_out, pw, key_data=key_data,
                                progress=prog)
            if args.restore_names and meta.get("name"):
                final = sanitize_filename(str(meta["name"]))
            else:
                final = arc[:-len(EXT)] if arc.endswith(EXT) else arc + ".out"
            dst = unique_path(os.path.join(outdir, final))
            os.replace(tmp_out, dst)
            prog.finish()
            print(f"    → {dst}")
            if args.shred:
                shred_file(src, passes=args.passes)
                if not args.quiet:
                    print("    encrypted copy shredded")
        except VaultAuthError:
            prog.finish(" FAILED")
            print(f"  ✗ {arc}: wrong password/keyfile or corrupted vault",
                  file=sys.stderr)
            if os.path.exists(tmp_out):
                os.unlink(tmp_out)
            ok, exit_code = False, 2
        except (VaultError, OSError, ShredError) as e:
            prog.finish(" FAILED")
            print(f"  ✗ {arc}: {e}", file=sys.stderr)
            if os.path.exists(tmp_out):
                os.unlink(tmp_out)
            ok = False
            exit_code = exit_code or 1
    return 0 if ok else exit_code


def cmd_passwd(args) -> int:
    if not os.path.isfile(args.file):
        print("no such vault", file=sys.stderr)
        return 1
    old_pw = _read_password(args, confirm=False, prompt="Current password: ")
    new_pw = _read_password(args, confirm=True, prompt="New password: ") \
        if not getattr(args, "new_password_file", None) else \
        open(args.new_password_file, "rb").read().rstrip(b"\r\n")
    old_key = _load_key(args.keyfile)
    new_key = _load_key(args.new_keyfile) if args.new_keyfile else old_key
    params = _kdf_params(args)
    try:
        t0 = time.monotonic()
        change_password(args.file, old_pw, new_pw, old_key_data=old_key,
                        new_key_data=new_key,
                        new_params=params or args.security)
        dt = time.monotonic() - t0
        print(f"  ✓ password changed in {dt:.2f}s (data untouched — "
              "only the key wrap was re-sealed)")
        return 0
    except VaultAuthError:
        print("  ✗ wrong current password or keyfile", file=sys.stderr)
        return 2
    except (VaultError, OSError) as e:
        print(f"  ✗ {e}", file=sys.stderr)
        return 1


def cmd_keygen(args) -> int:
    try:
        generate_keyfile(args.path, overwrite=args.force)
    except KeyfileError as e:
        print(f"  ✗ {e}", file=sys.stderr)
        return 1
    print(f"  ✓ keyfile written: {args.path}")
    print("    guard it like a house key — and make a backup copy.")
    return 0


def cmd_info(args) -> int:
    ok = True
    for p in args.paths:
        try:
            info = vault_info(p)
        except (VaultError, OSError) as e:
            print(f"  ✗ {p}: {e}", file=sys.stderr)
            ok = False
            continue
        k = info["kdf"]
        print(f"  {os.path.basename(p)}")
        print(f"    format   : v{info['format']}")
        print(f"    cipher   : {info['cipher']}")
        print(f"    cascade  : {'yes (dual-cipher)' if info['cascade'] else 'no'}")
        print(f"    keyfile  : {'required' if info['keyfile'] else 'no'}")
        print(f"    kdf      : Argon2id {k['memory_kib'] // 1024} MiB "
              f"× {k['time_cost']} pass(es), p={k['parallelism']}")
        print(f"    size     : {info['size']:,} bytes")
    return 0 if ok else 1


def cmd_genpass(args) -> int:
    for _ in range(args.count):
        if args.passphrase:
            pw = gen_passphrase(words=args.words)
        else:
            pw = gen_password(length=args.length, symbols=not args.no_symbols)
        rep = estimate(pw)
        print(f"{pw}   [{rep['label']}, ~{rep['entropy_bits']} bits]")
    return 0


def cmd_bench(args) -> int:
    from .crypto_core import benchmark
    from . import __version__
    print(f"vault100 {__version__} — the timekeeper (trials on this device)")
    mib = 8 if args.quick else 32
    kdf = (8,) if args.quick else (4, 16, 64)
    rep = benchmark(stream_mib=mib, kdf_mibs=kdf)
    x = rep["xchacha"]
    print(f"  xchacha20-poly1305 : {x['mib_s']:8.1f} MiB/s"
          f"  ({x['mib']:.0f} MiB in {x['seconds']:.2f} s)")
    a = rep["aes"]
    if a:
        print(f"  aes-256-gcm        : {a['mib_s']:8.1f} MiB/s"
              f"  ({a['mib']:.0f} MiB in {a['seconds']:.2f} s)")
    else:
        print("  aes-256-gcm        : unavailable (cryptography not installed)")
    for n in rep["argon2"]:
        mib_n = n["memory_kib"] / 1024
        if n["seconds"] is None:
            print(f"  argon2id {mib_n:4.0f} MiB x1t : refused (out of memory)")
        else:
            print(f"  argon2id {mib_n:4.0f} MiB x1t : {n['seconds']:6.2f} s"
                  f"   (4 lanes)")
    s = rep["standard_seconds"]
    if s is not None:
        print(f"  → standard profile (128 MiB × 3) ≈ {s:.1f} s per unlock here")
    print("  advice: pick a notch whose cost stays ≈ 1–4 s on this device")
    return 0


def cmd_shred(args) -> int:
    files = [os.path.abspath(p) for p in args.paths if os.path.isfile(p)]
    if not files:
        print("nothing to shred", file=sys.stderr)
        return 1
    if not args.yes:
        if not sys.stdin.isatty():
            print("refusing without confirmation (use --yes)", file=sys.stderr)
            return 1
        print(f"About to PERMANENTLY destroy {len(files)} file(s):")
        for f in files:
            print(f"   {f}")
        if input("Type YES to continue: ").strip() != "YES":
            print("aborted")
            return 1
    ok = True
    for f in files:
        try:
            size = os.path.getsize(f)
            prog = _Progress(os.path.basename(f), size * args.passes,
                             args.quiet)
            print(f"  shred {f}")
            shred_file(f, passes=args.passes, progress=prog)
            prog.finish()
        except (ShredError, OSError) as e:
            print(f"  ✗ {f}: {e}", file=sys.stderr)
            ok = False
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vault100",
        description="Vault100 — envelope-encrypted, keyfile-capable, "
                    "dual-cipher file vaults")
    p.add_argument("--version", action="store_true")
    sub = p.add_subparsers(dest="command")

    def common(sp):
        sp.add_argument("-q", "--quiet", action="store_true")
        sp.add_argument("--password-file", help="read password from file")

    e = sub.add_parser("encrypt", help="encrypt files/folders (v2 format)")
    e.add_argument("paths", nargs="+")
    e.add_argument("-o", "--output", help="output directory")
    e.add_argument("-r", "--recursive", action="store_true", default=True)
    e.add_argument("--security", choices=SECURITY_CHOICES,
                   default=DEFAULT_PROFILE,
                   help="'max' auto-tunes Argon2id to this machine (~2 s)")
    e.add_argument("--cascade", action="store_true",
                   help="AES-256-GCM inside XChaCha20-Poly1305 (dual cipher)")
    e.add_argument("--armor", action="store_true",
                   help="wrap the vault in paste-anywhere ASCII armor (.v100asc)")
    e.add_argument("--compress", action="store_true",
                   help="gzip the payload first (auto-decompressed on open)")
    e.add_argument("--keyfile", help="require this keyfile as second factor")
    e.add_argument("--shred", action="store_true",
                   help="securely delete originals after encrypting")
    e.add_argument("--passes", type=int, default=3, help="shred passes")
    e.add_argument("--force", action="store_true",
                   help="accept a weak password without asking")
    common(e)
    e.set_defaults(func=cmd_encrypt)

    d = sub.add_parser("decrypt", help="decrypt .v100 files")
    d.add_argument("paths", nargs="+")
    d.add_argument("-o", "--output", help="output directory")
    d.add_argument("--keyfile", help="keyfile for keyfile-protected vaults")
    d.add_argument("--no-restore-names", dest="restore_names",
                   action="store_false", default=True)
    d.add_argument("--shred", action="store_true",
                   help="delete encrypted files after decrypting")
    d.add_argument("--passes", type=int, default=3)
    common(d)
    d.set_defaults(func=cmd_decrypt)

    pw = sub.add_parser("passwd", help="change a vault's password instantly "
                                       "(re-wraps the key, no data rewrite)")
    pw.add_argument("file")
    pw.add_argument("--keyfile", help="current keyfile (if vault needs one)")
    pw.add_argument("--new-keyfile", help="switch to this keyfile")
    pw.add_argument("--new-password-file")
    pw.add_argument("--security", choices=SECURITY_CHOICES,
                    default=DEFAULT_PROFILE,
                    help="KDF hardness for the new password")
    pw.add_argument("--force", action="store_true")
    common(pw)
    pw.set_defaults(func=cmd_passwd)

    kg = sub.add_parser("keygen", help="create a random 256-bit keyfile")
    kg.add_argument("path")
    kg.add_argument("--force", action="store_true", help="overwrite existing")
    kg.set_defaults(func=cmd_keygen)

    i = sub.add_parser("info", help="show non-secret vault header facts")
    i.add_argument("paths", nargs="+")
    i.set_defaults(func=cmd_info)

    g = sub.add_parser("genpass", help="generate strong passwords")
    g.add_argument("--passphrase", action="store_true",
                   help="word passphrase instead of random characters")
    g.add_argument("--words", type=int, default=8)
    g.add_argument("--length", type=int, default=20)
    g.add_argument("--no-symbols", action="store_true")
    g.add_argument("--count", type=int, default=1)
    g.set_defaults(func=cmd_genpass)

    s = sub.add_parser("shred", help="securely delete files")
    s.add_argument("paths", nargs="+")
    s.add_argument("--passes", type=int, default=3)
    s.add_argument("-y", "--yes", action="store_true")
    s.add_argument("-q", "--quiet", action="store_true")
    s.set_defaults(func=cmd_shred)

    b = sub.add_parser("bench", help="the timekeeper — device speed trials")
    b.add_argument("--quick", action="store_true",
                   help="short trials (8 MiB), for slow machines or CI")
    b.set_defaults(func=cmd_bench)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "version", False):
        from . import __version__
        print(f"vault100 {__version__}")
        return 0
    if not hasattr(args, "func"):
        build_parser().print_help()
        return 1
    try:
        return args.func(args)
    except VaultCancelled:
        print("\ncancelled", file=sys.stderr)
        return 130
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except (VaultError, KeyfileError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
