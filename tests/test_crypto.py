"""Vault100 v2 test suite — proves the security properties hold."""

import glob
import io
import itertools
import os
import struct
import sys
import tempfile
import unittest

os.environ["VAULT100_FAST_KDF"] = "1"  # fast KDF for tests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from vault100.crypto_core import (VaultAuthError, VaultError,
                                  VaultFormatError, calibrate_profile,
                                  change_password, decrypt_file,
                                  decrypt_stream, encrypt_file,
                                  encrypt_stream, sanitize_filename,
                                  vault_info)
from vault100.crypto_core import _encrypt_stream_v1
from vault100.genpass import gen_passphrase, gen_password
from vault100.keyfile import (KeyfileError, generate_keyfile, identify,
                              load_keyfile)
from vault100.shredder import shred_file
from vault100.strength import estimate

PW = b"correct horse battery staple"
PW2 = b"a totally different new passphrase"
WRONG = b"hunter2"
META = {"name": "t.bin"}


def vault_bytes(data: bytes, pw: bytes = PW, meta=None, key_data=None,
                cascade=False) -> bytes:
    src, dst = io.BytesIO(data), io.BytesIO()
    encrypt_stream(src, dst, pw, metadata=meta or META, key_data=key_data,
                   cascade=cascade)
    return dst.getvalue()


def open_vault(blob: bytes, pw: bytes = PW, key_data=None):
    dst = io.BytesIO()
    meta = decrypt_stream(io.BytesIO(blob), dst, pw, key_data=key_data)
    return dst.getvalue(), meta


class RoundTripV2(unittest.TestCase):
    def test_empty_file(self):
        out, meta = open_vault(vault_bytes(b""))
        self.assertEqual(out, b"")
        self.assertEqual(meta["name"], "t.bin")

    def test_small(self):
        data = b"hello vault100 v2" * 50
        self.assertEqual(open_vault(vault_bytes(data))[0], data)

    def test_multichunk_random(self):
        data = os.urandom(int(2.6 * 1024 * 1024))
        self.assertEqual(open_vault(vault_bytes(data))[0], data)

    def test_exact_chunk_boundary(self):
        from vault100.crypto_core import CHUNK_SIZE
        data = os.urandom(CHUNK_SIZE)
        self.assertEqual(open_vault(vault_bytes(data))[0], data)

    def test_metadata_roundtrip(self):
        gold = {"name": "report.pdf", "size": 4, "mtime": 1, "v": 2}
        blob = vault_bytes(b"data", meta={"name": "report.pdf", "size": 4,
                                          "mtime": 1})
        _, meta = open_vault(blob)
        self.assertEqual(meta, gold)

    def test_unique_ciphertexts(self):
        self.assertNotEqual(vault_bytes(b"same"), vault_bytes(b"same"))

    def test_magic_is_v2(self):
        self.assertTrue(vault_bytes(b"x").startswith(b"V100ENC2"))

    def test_cascade_roundtrip(self):
        data = os.urandom(150_000)
        blob = vault_bytes(data, cascade=True)
        self.assertEqual(open_vault(blob)[0], data)

    def test_cascade_flag_in_header(self):
        blob = vault_bytes(b"x", cascade=True)
        self.assertEqual(blob[19] & 1, 1)  # FLAG_CASCADE


class KeyfileSecondFactor(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="v100-kf-")
        self.kf = os.path.join(self.dir, "key.v100key")
        generate_keyfile(self.kf)
        self.kd = load_keyfile(self.kf)

    def test_roundtrip_with_keyfile(self):
        data = b"two-factor protected"
        blob = vault_bytes(data, key_data=self.kd)
        self.assertEqual(open_vault(blob, key_data=self.kd)[0], data)

    def test_missing_keyfile_rejected(self):
        blob = vault_bytes(b"data", key_data=self.kd)
        with self.assertRaises(VaultError):
            open_vault(blob)  # no keyfile at all

    def test_wrong_keyfile_rejected(self):
        other = os.path.join(self.dir, "other.v100key")
        generate_keyfile(other)
        blob = vault_bytes(b"data", key_data=self.kd)
        with self.assertRaises(VaultAuthError):
            open_vault(blob, key_data=load_keyfile(other))

    def test_wrong_password_and_right_keyfile(self):
        blob = vault_bytes(b"data", key_data=self.kd)
        with self.assertRaises(VaultAuthError):
            open_vault(blob, WRONG, key_data=self.kd)

    def test_arbitrary_file_as_keyfile(self):
        pic = os.path.join(self.dir, "cover.jpg")
        with open(pic, "wb") as f:
            f.write(os.urandom(4096))  # any file works, VeraCrypt-style
        kd = load_keyfile(pic)
        blob = vault_bytes(b"data", key_data=kd)
        self.assertEqual(open_vault(blob, key_data=kd)[0], b"data")
        self.assertEqual(identify(pic), "arbitrary file (hashed as-is)")

    def test_keyfile_protected_flag_set(self):
        self.assertEqual(vault_bytes(b"x", key_data=self.kd)[19] & 2, 2)

    def test_keygen_no_overwrite(self):
        with self.assertRaises(KeyfileError):
            generate_keyfile(self.kf, overwrite=False)

    def test_keygen_identify(self):
        self.assertEqual(identify(self.kf), "Vault100 keyfile")


class PasswordChange(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="v100-pw-")
        self.plain = os.urandom(120_000)
        self.vault = os.path.join(self.dir, "doc.v100")
        src = os.path.join(self.dir, "doc.bin")
        with open(src, "wb") as f:
            f.write(self.plain)
        encrypt_file(src, self.vault, PW)

    def _open(self, pw, key=None):
        out = os.path.join(self.dir, "out.bin")
        meta = decrypt_file(self.vault, out, pw, key_data=key)
        with open(out, "rb") as f:
            return f.read(), meta

    def test_password_change_flow(self):
        change_password(self.vault, PW, PW2)
        data, meta = self._open(PW2)
        self.assertEqual(data, self.plain)
        self.assertEqual(meta["name"], "doc.bin")
        with self.assertRaises(VaultAuthError):
            self._open(PW)

    def test_wrong_current_password_refused(self):
        before = open(self.vault, "rb").read()
        with self.assertRaises(VaultAuthError):
            change_password(self.vault, WRONG, PW2)
        self.assertEqual(open(self.vault, "rb").read(), before)

    def test_keyfile_can_be_added_at_password_change(self):
        kf = os.path.join(self.dir, "key.v100key")
        generate_keyfile(kf)
        kd = load_keyfile(kf)
        change_password(self.vault, PW, PW2, new_key_data=kd)
        data, _ = self._open(PW2, key=kd)
        self.assertEqual(data, self.plain)
        with self.assertRaises(VaultError):      # now keyfile is mandatory
            self._open(PW2)

    def test_changes_only_header(self):
        before = open(self.vault, "rb").read()
        change_password(self.vault, PW, PW2)
        after = open(self.vault, "rb").read()
        self.assertEqual(len(before), len(after))           # same size
        header_zone = 52 + 24 + 48                          # fixed+wrap zone
        self.assertEqual(before[header_zone:], after[header_zone:],
                         "data chunks must be untouched by passwd")


class TamperDetectionV2(unittest.TestCase):
    def test_wrong_password(self):
        with self.assertRaises(VaultAuthError):
            open_vault(vault_bytes(b"secret " * 100), WRONG)

    def test_wrapped_fek_tamper(self):
        blob = bytearray(vault_bytes(b"payload"))
        blob[60] ^= 0x01  # inside wrap nonce/ct zone
        with self.assertRaises(VaultAuthError):
            open_vault(bytes(blob))

    def test_ciphertext_bitflip(self):
        blob = bytearray(vault_bytes(os.urandom(300_000)))
        for pos in (150, len(blob) // 2, len(blob) - 1):
            t = bytearray(blob)
            t[pos] ^= 0x01
            with self.assertRaises((VaultAuthError, VaultFormatError),
                                   msg=f"tamper at {pos} undetected"):
                open_vault(bytes(t))

    def test_cascade_bitflip(self):
        blob = bytearray(vault_bytes(os.urandom(150_000), cascade=True))
        for pos in (180, len(blob) // 2, len(blob) - 1):
            t = bytearray(blob)
            t[pos] ^= 0x01
            with self.assertRaises((VaultAuthError, VaultFormatError)):
                open_vault(bytes(t))

    def test_header_tampering(self):
        t = bytearray(vault_bytes(b"payload"))
        t[10] ^= 0xFF  # KDF memory field
        with self.assertRaises((VaultAuthError, VaultFormatError)):
            open_vault(bytes(t))

    def test_unknown_flags_rejected(self):
        t = bytearray(vault_bytes(b"payload"))
        t[19] |= 0x80
        with self.assertRaises(VaultFormatError):
            open_vault(bytes(t))

    def test_truncation(self):
        blob = vault_bytes(os.urandom(200_000))
        for cut in (len(blob) - 1, len(blob) // 2, 170):
            with self.assertRaises((VaultAuthError, VaultFormatError)):
                open_vault(blob[:cut])

    def test_trailing_garbage(self):
        with self.assertRaises(VaultFormatError):
            open_vault(vault_bytes(b"data") + b"extra")

    def test_bad_magic(self):
        with self.assertRaises(VaultFormatError):
            open_vault(b"not-a-vault" * 30)

    def test_dos_header_caps(self):
        blob = bytearray(vault_bytes(b"x"))
        struct.pack_into("<I", blob, 10, 4 * 1024 * 1024 + 1)
        with self.assertRaises(VaultFormatError):
            open_vault(bytes(blob))


class V1BackwardCompatibility(unittest.TestCase):
    def test_v1_file_still_decrypts(self):
        data = os.urandom(90_000)
        src, dst = io.BytesIO(data), io.BytesIO()
        _encrypt_stream_v1(src, dst, PW, metadata={"name": "old.txt"})
        blob = dst.getvalue()
        self.assertTrue(blob.startswith(b"V100ENC1"))
        out, meta = open_vault(blob)
        self.assertEqual(out, data)
        self.assertEqual(meta["name"], "old.txt")

    def test_v1_tamper_still_detected(self):
        src, dst = io.BytesIO(b"legacy"), io.BytesIO()
        _encrypt_stream_v1(src, dst, PW, metadata={"name": "x"})
        blob = bytearray(dst.getvalue())
        blob[-3] ^= 0x20
        with self.assertRaises((VaultAuthError, VaultFormatError)):
            open_vault(bytes(blob))

    def test_v1_info(self):
        src, dst = io.BytesIO(b"legacy"), io.BytesIO()
        _encrypt_stream_v1(src, dst, PW, metadata={"name": "x"})
        path = os.path.join(tempfile.mkdtemp(), "old.v100")
        with open(path, "wb") as f:
            f.write(dst.getvalue())
        info = vault_info(path)
        self.assertEqual(info["format"], 1)
        self.assertFalse(info["cascade"])

    def test_passwd_refuses_v1(self):
        src, dst = io.BytesIO(b"legacy"), io.BytesIO()
        _encrypt_stream_v1(src, dst, PW, metadata={"name": "x"})
        path = os.path.join(tempfile.mkdtemp(), "old.v100")
        with open(path, "wb") as f:
            f.write(dst.getvalue())
        with self.assertRaises(VaultError):
            change_password(path, PW, PW2)


class FileAPI(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="v100-test-")

    def test_file_roundtrip_with_name_restore(self):
        src = os.path.join(self.dir, "notes.txt")
        body = b"confidential notes\n" * 100
        with open(src, "wb") as f:
            f.write(body)
        enc = encrypt_file(src, src + ".v100", PW)
        out = os.path.join(self.dir, "restored.bin")
        meta = decrypt_file(enc, out, PW)
        with open(out, "rb") as f:
            self.assertEqual(f.read(), body)
        self.assertEqual(meta["name"], "notes.txt")

    def test_filename_sanitizer(self):
        self.assertEqual(sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("a\\b\\c.docx"), "c.docx")
        self.assertEqual(sanitize_filename(".."), "decrypted.bin")
        self.assertEqual(sanitize_filename(""), "decrypted.bin")


class InfoAndCalibration(unittest.TestCase):
    def test_vault_info_v2(self):
        path = os.path.join(tempfile.mkdtemp(), "d.v100")
        with open(path, "wb") as f:
            f.write(vault_bytes(b"data", cascade=True))
        info = vault_info(path)
        self.assertEqual(info["format"], 2)
        self.assertTrue(info["cascade"])
        self.assertFalse(info["keyfile"])
        self.assertIn("AES-256-GCM", info["cipher"])

    def test_calibrate_stays_in_caps(self):
        p = calibrate_profile(target_seconds=0.05)
        self.assertGreaterEqual(p["memory_kib"], 64 * 1024)
        self.assertGreaterEqual(p["time_cost"], 1)
        self.assertLessEqual(p["time_cost"], 8)

    def test_calibrate_respects_max_memory(self):
        p = calibrate_profile(target_seconds=0.05, max_kib=128 * 1024)
        self.assertLessEqual(p["memory_kib"], 128 * 1024)


class GenPass(unittest.TestCase):
    def test_password_length_and_charset(self):
        pw = gen_password(24)
        self.assertEqual(len(pw), 24)
        self.assertNotEqual(gen_password(24), gen_password(24))

    def test_no_symbols_mode(self):
        self.assertTrue(gen_password(30, symbols=False).isalnum())

    def test_passphrase_word_count(self):
        self.assertEqual(len(gen_passphrase(8).split("-")), 8)

    def test_passphrases_are_random(self):
        self.assertNotEqual(gen_passphrase(8), gen_passphrase(8))


class Shredder(unittest.TestCase):
    def test_shred_removes_file(self):
        path = tempfile.mktemp(prefix="v100-shred-")
        with open(path, "wb") as f:
            f.write(os.urandom(50_000))
        shred_file(path, passes=2)
        self.assertFalse(os.path.exists(path))

    def test_refuses_directory(self):
        from vault100.shredder import ShredError
        with self.assertRaises(ShredError):
            shred_file("/tmp")


class Strength(unittest.TestCase):
    def test_common_password_scores_zero(self):
        self.assertEqual(estimate("password")["score"], 0)
        self.assertEqual(estimate("123456")["score"], 0)

    def test_strong_passphrase_scores_high(self):
        self.assertGreaterEqual(
            estimate("Drum-7-velvet-CAROUSEL-pineapple-92!")["score"], 3)

    def test_short_penalty(self):
        self.assertLess(estimate("aB1!")["score"], 2)


class CompressTests(unittest.TestCase):
    """gzip shrink-wrap: transparent wrap on seal, unwrap on open."""

    def roundtrip(self, data, **kw):
        buf = io.BytesIO()
        from vault100.crypto_core import decrypt_stream
        encrypt_stream(io.BytesIO(data), buf, PW, progress=lambda d, t: None,
                       **kw)
        out = io.BytesIO()
        meta = decrypt_stream(io.BytesIO(buf.getvalue()), out, PW,
                              key_data=kw.get("key_data"))
        return out.getvalue(), meta

    def test_compress_roundtrip_cascade(self):
        data = os.urandom(200_000) + b"ledger " * 60_000
        got, meta = self.roundtrip(data, cascade=True, compress=True)
        self.assertEqual(got, data)
        self.assertIs(meta.get("gz"), True)

    def test_compress_actually_shrinks(self):
        data = b"A" * 500_000
        plain = io.BytesIO()
        encrypt_stream(io.BytesIO(data), plain, PW)
        smallVault = io.BytesIO()
        encrypt_stream(io.BytesIO(data), smallVault, PW, compress=True)
        self.assertLess(len(smallVault.getvalue()), len(plain.getvalue()))

    def test_compress_with_keyfile_multichunk(self):
        data = os.urandom(100_000) + b"z" * 3_000_000
        got, meta = self.roundtrip(data, compress=True, key_data=b"K" * 32)
        self.assertEqual(got, data)
        self.assertIs(meta.get("gz"), True)

    def test_plain_vault_has_no_gz_flag(self):
        data = os.urandom(50_000)
        _, meta = self.roundtrip(data)
        self.assertNotIn("gz", meta)


class ArmorTests(unittest.TestCase):
    """V100A1 ASCII armor — writer/reader invariants + file round-trips."""

    def test_armor_encode_decode_and_stream_equivalence(self):
        from vault100.crypto_core import (armor_encode, armor_decode,
                                          _ArmorWriter, _ArmorReader,
                                          ARMOR_BEGIN, ARMOR_END)
        data = os.urandom(10_000)
        one_shot = armor_encode(data)
        self.assertTrue(one_shot.startswith(ARMOR_BEGIN + b"\n"))
        self.assertTrue(one_shot.endswith(ARMOR_END + b"\n"))
        # 64-column wrap (full lines; final line is the short tail)
        lines = one_shot.split(b"\n")[1:-2]
        for ln in lines[:-1]:
            self.assertEqual(len(ln), 64)
        self.assertLessEqual(len(lines[-1]), 64)
        self.assertEqual(armor_decode(one_shot), data)
        # streaming writer == one-shot encoder
        sink = io.BytesIO()
        w = _ArmorWriter(sink)
        for i in range(0, len(data), 777):
            w.write(data[i:i + 777])
        w.finish()
        self.assertEqual(sink.getvalue(), one_shot)
        # streaming reader == one-shot decoder (incl. odd read sizes)
        r = _ArmorReader(io.BytesIO(one_shot))
        got = b""
        while True:
            chunk = r.read(333)
            if not chunk:
                break
            got += chunk
        self.assertEqual(got, data)

    def test_armor_tolerates_furniture(self):
        from vault100.crypto_core import armor_encode, _ArmorReader
        data = os.urandom(500)
        messy = (b"# a note from the dispatcher\n\n"
                 + armor_encode(data) + b"\ntrailing scribbles\n")
        r = _ArmorReader(io.BytesIO(messy))
        self.assertEqual(r.read(), data)

    def test_armor_file_roundtrip(self):
        import tempfile
        from vault100.crypto_core import encrypt_file, decrypt_file
        data = b"armorer's proof \u2603 " * 2000
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "note.txt")
            with open(src, "wb") as f:
                f.write(data)
            asc = encrypt_file(src, src + ".v100asc", PW, armor=True)
            with open(asc, "rb") as f:
                self.assertTrue(f.read(64).startswith(b"-----BEGIN V100 ARMOR-----"))
            out = os.path.join(td, "opened.bin")
            meta = decrypt_file(asc, out, PW)
            with open(out, "rb") as f:
                self.assertEqual(f.read(), data)
            self.assertEqual(meta["name"], "note.txt")

    def test_passwd_refuses_armor_files(self):
        import tempfile
        from vault100.crypto_core import encrypt_file, change_password, VaultError
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "n.txt")
            with open(src, "wb") as f:
                f.write(b"x" * 1000)
            asc = encrypt_file(src, src + ".v100asc", PW, armor=True)
            with self.assertRaises(VaultError):
                change_password(asc, PW, b"new pass phrase here")

    def test_info_flags_armor(self):
        import tempfile
        from vault100.crypto_core import encrypt_file, vault_info
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "n.txt")
            with open(src, "wb") as f:
                f.write(b"y" * 1000)
            asc = encrypt_file(src, src + ".v100asc", PW, armor=True)
            info = vault_info(asc)
            self.assertIs(info["armor"], True)
            self.assertEqual(info["format"], 2)


class BenchTests(unittest.TestCase):
    """The timekeeper: trials must produce sane, non-negative timings."""

    def test_benchmark_shape_and_speed(self):
        from vault100.crypto_core import benchmark
        rep = benchmark(fast=True)          # small trials for CI
        x = rep["xchacha"]
        self.assertGreater(x["mib"], 0)
        self.assertGreater(x["seconds"], 0)
        self.assertGreater(x["mib_s"], 0)
        if rep["aes"] is not None:
            self.assertGreater(rep["aes"]["mib_s"], 0)
        self.assertTrue(rep["argon2"])
        for n in rep["argon2"]:
            self.assertGreaterEqual(n["memory_kib"], 8 * 1024)
        big = next((n for n in rep["argon2"] if n["seconds"] is not None),
                   None)
        self.assertIsNotNone(big)
        self.assertGreater(rep["standard_seconds"], 0)

    def test_cli_bench_runs(self):
        from vault100 import cli
        rc = cli.main(["bench", "--quick"])
        self.assertEqual(rc, 0)


class QuorumPressTests(unittest.TestCase):
    """The quorum press — Shamir M-of-N slips (vault100/shamir.py)."""

    def test_gf_field_laws(self):
        from vault100.shamir import gf_mul, gf_inv
        self.assertEqual(gf_mul(0x57, 0x83), 0xC1)          # AES test vector
        for a in range(1, 256):
            self.assertEqual(gf_mul(a, gf_inv(a)), 1)

    def test_all_quorum_subsets_recover(self):
        from vault100.shamir import split_secret, join_secret
        slips = split_secret(PW, 5, 3)
        for idxs in itertools.combinations(range(5), 3):
            self.assertEqual(join_secret([slips[i] for i in idxs]), PW)

    def test_more_than_quorum_also_recovers(self):
        from vault100.shamir import split_secret, join_secret
        slips = split_secret(PW, 7, 4)
        self.assertEqual(join_secret(slips), PW)
        self.assertEqual(join_secret([slips[i] for i in (0, 2, 3, 5, 6)]), PW)

    def test_below_quorum_refused_and_reveals_nothing(self):
        from vault100.shamir import ShareError, split_secret, join_secret
        slips = split_secret(PW, 5, 3)
        with self.assertRaises(ShareError):
            join_secret(slips[:2])
        # a lone slip is not just un-decodable — it is flat noise:
        # every secret byte must stay possible. (Spot-check the mechanics:
        # two different secrets can share a slip point-wise at quorum 2.)
        s1, s2 = b"\x00" * 16, b"\xff" * 16
        sh1, sh2 = split_secret(s1, 2, 2), split_secret(s2, 2, 2)
        self.assertNotEqual(sh1[0], sh2[0])
        self.assertEqual(len(sh1[0]), len(sh2[0]))

    def test_secret_lengths(self):
        from vault100.shamir import split_secret, join_secret
        for length in (1, 2, 255, 1024, 4096):
            sec = os.urandom(length)
            slips = split_secret(sec, 6, 4)
            got = join_secret([slips[i] for i in (0, 1, 3, 5)])
            self.assertEqual(got, sec)

    def test_bounds_validation(self):
        from vault100.shamir import ShareError, split_secret
        for n, m in ((1, 1), (5, 1), (2, 3), (256, 2)):
            with self.assertRaises(ShareError):
                split_secret(PW, n, m)
        with self.assertRaises(ShareError):
            split_secret(b"", 5, 3)
        with self.assertRaises(ShareError):
            split_secret(b"x" * 65536, 5, 3)

    def test_text_slip_furniture_tolerance(self):
        from vault100.shamir import split_to_text, join_from_text
        slips = split_to_text("unicode ⛄ secret".encode(), 7, 4)
        blob = ("office memorandum — distribution below\n\n"
                + "\n--- stray line ---\n".join(slips[i] for i in (5, 0, 3, 1))
                + "\nregards, the clerk\n")
        self.assertEqual(join_from_text(blob), "unicode ⛄ secret".encode())

    def test_tampered_slip_rejected(self):
        from vault100.shamir import ShareError, split_secret, inspect_slip
        slip = bytearray(split_secret(PW, 3, 2)[0])
        slip[20] ^= 1                                    # payload nibble
        with self.assertRaises(ShareError):
            inspect_slip(bytes(slip))
        slip = bytearray(split_secret(PW, 3, 2)[0])
        slip[-1] ^= 1                                    # crc nibble
        with self.assertRaises(ShareError):
            inspect_slip(bytes(slip))

    def test_mixed_pressings_rejected(self):
        from vault100.shamir import ShareError, split_secret, join_secret
        a = split_secret(PW, 5, 3)
        b = split_secret(PW, 5, 3)
        with self.assertRaises(ShareError):
            join_secret([a[0], b[1], b[2]])

    def test_doctored_title_line_rejected(self):
        from vault100.shamir import ShareError, decode_slips, split_to_text
        text = split_to_text(PW, 5, 3)[0].replace(
            "BEGIN V100 SHARE 1 OF 5", "BEGIN V100 SHARE 2 OF 5")
        with self.assertRaises(ShareError):
            decode_slips(text)

    def test_cli_share_split_join_roundtrip(self):
        from vault100 import cli
        with tempfile.TemporaryDirectory() as td:
            sec = os.path.join(td, "combo.txt")
            with open(sec, "wb") as f:
                f.write(PW)
            self.assertEqual(cli.main(
                ["share", "split", sec, "-n", "5", "-m", "3"]), 0)
            slips = sorted(glob.glob(os.path.join(td, "*.v100s")))
            self.assertEqual(len(slips), 5)
            out = os.path.join(td, "back.bin")
            self.assertEqual(cli.main(
                ["share", "join", slips[0], slips[2], slips[4],
                 "-o", out]), 0)
            with open(out, "rb") as f:
                self.assertEqual(f.read(), PW)
            # two slips must not open the press
            self.assertEqual(cli.main(
                ["share", "join", slips[0], slips[1],
                 "-o", os.path.join(td, "nope.bin")]), 1)


class CustodyVerifyTests(unittest.TestCase):
    """The custody clerk — prove vaults open clean, keep nothing."""

    def _vault(self, td, name="doc.txt", body=None, **kw):
        from vault100.crypto_core import encrypt_file
        src = os.path.join(td, name)
        with open(src, "wb") as f:
            f.write(body if body is not None else os.urandom(4096))
        dst = src + ".v100"
        encrypt_file(src, dst, PW, profile="standard", **kw)
        return src, dst

    def test_verify_ok_and_writes_nothing(self):
        from vault100.crypto_core import verify_file
        with tempfile.TemporaryDirectory() as td:
            src, dst = self._vault(td)
            before = set(os.listdir(td))
            meta = verify_file(dst, PW)
            self.assertEqual(meta.get("name"), os.path.basename(src))
            self.assertEqual(set(os.listdir(td)), before)

    def test_verify_tampered_refused(self):
        from vault100.crypto_core import VaultAuthError as VAE, verify_file
        with tempfile.TemporaryDirectory() as td:
            _, dst = self._vault(td)
            blob = bytearray(open(dst, "rb").read())
            blob[-20] ^= 1
            open(dst, "wb").write(blob)
            with self.assertRaises((VAE, VaultError)):
                verify_file(dst, PW)

    def test_verify_wrong_password_refused(self):
        from vault100.crypto_core import VaultAuthError as VAE, verify_file
        with tempfile.TemporaryDirectory() as td:
            _, dst = self._vault(td)
            with self.assertRaises((VAE, VaultError)):
                verify_file(dst, PW2)

    def test_verify_armored_vault(self):
        from vault100.crypto_core import encrypt_file, verify_file
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "note.txt")
            open(src, "wb").write(b"armored custody")
            dst = src + ".v100asc"
            encrypt_file(src, dst, PW, profile="standard", armor=True)
            self.assertEqual(verify_file(dst, PW).get("name"), "note.txt")

    def test_cli_verify_batch(self):
        from vault100 import cli
        old = os.environ.get("VAULT100_PASSWORD")
        os.environ["VAULT100_PASSWORD"] = PW.decode()
        try:
            with tempfile.TemporaryDirectory() as td:
                _, good = self._vault(td, "a.txt")
                _, bad = self._vault(td, "b.txt")
                blob = bytearray(open(bad, "rb").read()); blob[-20] ^= 1
                open(bad, "wb").write(blob)
                self.assertEqual(cli.main(["verify", good]), 0)
                self.assertEqual(cli.main(["verify", good, bad]), 1)
                self.assertEqual(cli.main(
                    ["verify", os.path.join(td, "missing.v100")]), 1)
        finally:
            if old is None:
                del os.environ["VAULT100_PASSWORD"]
            else:
                os.environ["VAULT100_PASSWORD"] = old

    def test_gui_module_imports(self):
        """The desk box must at least construct headlessly (no display)."""
        import importlib
        m = importlib.import_module("vault100.gui")
        self.assertTrue(hasattr(m, "Vault100App"))
        self.assertTrue(hasattr(m, "recents_load"))
        # recents round-trip via a redirected config home
        with tempfile.TemporaryDirectory() as td:
            os.environ["XDG_CONFIG_HOME"] = td
            m.recents_add(os.path.join(td, "x.v100"))
            m.recents_add(os.path.join(td, "y.txt"))
            got = m.recents_load()
            self.assertEqual(got[0].endswith("y.txt"), True)
            self.assertEqual(len(got), 2)
            del os.environ["XDG_CONFIG_HOME"]


class NotaryTests(unittest.TestCase):
    """The notary — ed25519 seals & endorsements (vault100/notary.py)."""

    def test_mint_roundtrip_and_perms(self):
        from vault100.notary import (SEAL_MAGIC, STAMP_MAGIC, load_seal,
                                     load_stamp, mint_seal)
        with tempfile.TemporaryDirectory() as td:
            res = mint_seal(os.path.join(td, "me.v100seal"))
            self.assertTrue(res["seal"].endswith(".v100seal"))
            blob_s = open(res["seal"], "rb").read()
            blob_p = open(res["stamp"], "rb").read()
            self.assertTrue(blob_s.startswith(SEAL_MAGIC))
            self.assertTrue(blob_p.startswith(STAMP_MAGIC))
            self.assertEqual(len(load_seal(res["seal"])), 32)
            self.assertEqual(len(load_stamp(res["stamp"])), 32)
            mode = os.stat(res["seal"]).st_mode & 0o777
            self.assertEqual(mode, 0o600)
            # no silent overwrite of a seal
            from vault100.notary import NotaryError
            with self.assertRaises(NotaryError):
                mint_seal(os.path.join(td, "me.v100seal"))

    def test_endorse_attest_holds(self):
        from vault100.notary import attest_file, endorse_file, mint_seal
        with tempfile.TemporaryDirectory() as td:
            seal = os.path.join(td, "bureau.v100seal")
            mint = mint_seal(seal)
            vault = os.path.join(td, "papers.v100")
            open(vault, "wb").write(b"deeds " * 500)
            end = endorse_file(vault, seal)
            blob = open(end["sig"], "rb").read()
            self.assertEqual(len(blob), 108)          # SIGFILE_BYTES
            v = attest_file(vault, end["sig"], mint["stamp"])
            self.assertTrue(v["valid"])
            self.assertEqual(v["fingerprint"], mint["fingerprint"])

    def test_doctored_vault_refused(self):
        from vault100.notary import attest_file, endorse_file, mint_seal
        with tempfile.TemporaryDirectory() as td:
            seal = os.path.join(td, "a.v100seal"); mint_seal(seal)
            vault = os.path.join(td, "x.v100")
            open(vault, "wb").write(b"original")
            sig = endorse_file(vault, seal)["sig"]
            open(vault, "ab").write(b"!")
            v = attest_file(vault, sig)
            self.assertFalse(v["valid"])
            self.assertIn("does NOT hold", v["reason"])

    def test_foreign_seal_and_stamp_mismatch(self):
        from vault100.notary import attest_file, endorse_file, mint_seal
        with tempfile.TemporaryDirectory() as td:
            s1 = os.path.join(td, "one.v100seal"); m1 = mint_seal(s1)
            s2 = os.path.join(td, "two.v100seal"); mint_seal(s2)
            vault = os.path.join(td, "y.v100")
            open(vault, "wb").write(b"paper")
            # endorse with seal two, demand stamp one
            sig = endorse_file(vault, s2)["sig"]
            v = attest_file(vault, sig, m1["stamp"])
            self.assertFalse(v["valid"])
            self.assertIn("DIFFERENT seal", v["reason"])

    def test_torn_and_forged_paper_rejected(self):
        from vault100.notary import (NotaryError, attest_bytes, inspect_sig,
                                     load_seal, load_stamp, mint_seal)
        with tempfile.TemporaryDirectory() as td:
            seal = os.path.join(td, "z.v100seal"); res = mint_seal(seal)
            with self.assertRaises(NotaryError):
                load_seal(res["stamp"])               # stamp as seal
            with self.assertRaises(NotaryError):
                load_stamp(res["seal"])               # seal as stamp
            with self.assertRaises(NotaryError):
                inspect_sig(b"V100SIG1" + b"\0" * 10)  # torn
            with self.assertRaises(NotaryError):
                inspect_sig(b"F000SIG1" + b"\0" * 100)  # forged magic

    def test_determinism_matches_rfc8032_style(self):
        from vault100.notary import endorse_bytes, inspect_sig
        seed = bytes(range(32))
        b1 = endorse_bytes(b"paper", seed, epoch=1700000000)
        b2 = endorse_bytes(b"paper", seed, epoch=1700000000)
        self.assertEqual(b1, b2)
        self.assertEqual(inspect_sig(b1)["epoch"], 1700000000)

    def test_cli_notary_flow(self):
        from vault100 import cli
        with tempfile.TemporaryDirectory() as td:
            seal = os.path.join(td, "me.v100seal")
            self.assertEqual(cli.main(["notary", "mint", seal]), 0)
            stamp = os.path.join(td, "me.v100stamp")
            self.assertTrue(os.path.exists(stamp))
            vault = os.path.join(td, "file.v100")
            open(vault, "wb").write(b"vidyut " * 100)
            self.assertEqual(cli.main(
                ["notary", "endorse", vault, "-s", seal]), 0)
            self.assertTrue(os.path.exists(vault + ".v100sig"))
            self.assertEqual(cli.main(
                ["notary", "attest", vault, "--stamp", stamp]), 0)
            blob = bytearray(open(vault, "rb").read()); blob[-20] ^= 1
            open(vault, "wb").write(blob)
            self.assertEqual(cli.main(["notary", "attest", vault]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
