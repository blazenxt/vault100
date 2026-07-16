"""Vault100 v2 test suite — proves the security properties hold."""

import io
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
