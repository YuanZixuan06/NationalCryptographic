import os
import tempfile
import unittest
from pathlib import Path

from crypto_app import (
    InputValidationError,
    BundleFormatError,
    decrypt_file_bundle,
    decrypt_file_sm4_raw,
    encrypt_file_sm2_sm4_bundle,
    encrypt_file_sm4_bundle,
    encrypt_file_sm4_raw,
    generate_sm2_keypair,
    parse_size_list,
    save_benchmark_charts,
    sm2_decrypt_text,
    sm2_encrypt_text,
    sm3_digest_bytes,
    sm4_decrypt_text,
    sm4_encrypt_text,
    summarize_benchmark_payload,
    sha256_file,
    benchmark_files,
)


class CryptoAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sm2_keys = generate_sm2_keypair(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
        self.sm4_key = "0123456789abcdeffedcba9876543210"
        self.sm4_iv = "000102030405060708090a0b0c0d0e0f"
        self.sample_text = "测试 gmssl 国密算法"

    def test_sm2_text_roundtrip(self) -> None:
        ciphertext = sm2_encrypt_text(self.sample_text, self.sm2_keys["public_key"])
        plaintext = sm2_decrypt_text(ciphertext, self.sm2_keys["private_key"])
        self.assertEqual(plaintext, self.sample_text)

    def test_sm4_text_roundtrip(self) -> None:
        ciphertext = sm4_encrypt_text(
            self.sample_text,
            key_hex=self.sm4_key,
            mode_name="cbc",
            iv_hex=self.sm4_iv,
        )["ciphertext"]
        plaintext = sm4_decrypt_text(
            ciphertext,
            key_hex=self.sm4_key,
            mode_name="cbc",
            iv_hex=self.sm4_iv,
        )
        self.assertEqual(plaintext, self.sample_text)

    def test_sm3_digest_has_expected_length(self) -> None:
        digest = sm3_digest_bytes(self.sample_text.encode("utf-8"))
        self.assertEqual(len(digest), 64)

    def test_sm4_bundle_file_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            source_path = temp_root / "bundle_source.bin"
            encrypted_path = temp_root / "bundle_source.gms"
            decrypted_path = temp_root / "bundle_source.dec"
            source_path.write_bytes(b"HEADER-1234567890" + os.urandom(8192) + b"TAIL")

            encrypt_result = encrypt_file_sm4_bundle(
                input_path=source_path,
                output_path=encrypted_path,
                mode_name="cbc",
                chunk_size=4096,
                monitor_interval=0.01,
                keep_header_bytes=16,
                key_hex=self.sm4_key,
                iv_hex=self.sm4_iv,
            )
            decrypt_file_bundle(
                input_path=encrypted_path,
                output_path=decrypted_path,
                chunk_size=4096,
                monitor_interval=0.01,
                sm4_key_hex=encrypt_result["key_hex"],
            )
            self.assertEqual(sha256_file(source_path), sha256_file(decrypted_path))

    def test_sm4_raw_file_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            source_path = temp_root / "raw_source.bmp"
            encrypted_path = temp_root / "raw_source.enc.bmp"
            decrypted_path = temp_root / "raw_source.dec.bmp"
            source_path.write_bytes(b"BMPHEADER" * 8 + os.urandom(4096))

            encrypt_file_sm4_raw(
                input_path=source_path,
                output_path=encrypted_path,
                mode_name="cbc",
                chunk_size=2048,
                monitor_interval=0.01,
                keep_header_bytes=32,
                key_hex=self.sm4_key,
                iv_hex=self.sm4_iv,
            )
            decrypt_file_sm4_raw(
                input_path=encrypted_path,
                output_path=decrypted_path,
                key_hex=self.sm4_key,
                mode_name="cbc",
                chunk_size=2048,
                monitor_interval=0.01,
                keep_header_bytes=32,
                iv_hex=self.sm4_iv,
            )
            self.assertEqual(sha256_file(source_path), sha256_file(decrypted_path))

    def test_sm2_sm4_bundle_file_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            source_path = temp_root / "hybrid_source.bin"
            encrypted_path = temp_root / "hybrid_source.gms"
            decrypted_path = temp_root / "hybrid_source.dec"
            source_path.write_bytes(os.urandom(6000))

            encrypt_file_sm2_sm4_bundle(
                input_path=source_path,
                output_path=encrypted_path,
                public_key_hex=self.sm2_keys["public_key"],
                sm2_mode_name="c1c3c2",
                sm4_mode_name="cbc",
                chunk_size=2048,
                monitor_interval=0.01,
                keep_header_bytes=0,
                session_key_hex=self.sm4_key,
                iv_hex=self.sm4_iv,
            )
            decrypt_file_bundle(
                input_path=encrypted_path,
                output_path=decrypted_path,
                chunk_size=2048,
                monitor_interval=0.01,
                private_key_hex=self.sm2_keys["private_key"],
            )
            self.assertEqual(sha256_file(source_path), sha256_file(decrypted_path))

    def test_invalid_sm4_key_raises_validation_error(self) -> None:
        with self.assertRaises(InputValidationError):
            sm4_encrypt_text("hello", key_hex="1234", mode_name="cbc", iv_hex=self.sm4_iv)

    def test_invalid_size_list_raises_validation_error(self) -> None:
        with self.assertRaises(InputValidationError):
            parse_size_list("")

    def test_invalid_bundle_raises_bundle_format_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            fake_bundle = temp_root / "fake.gms"
            output_path = temp_root / "fake.out"
            fake_bundle.write_bytes(b"not-a-bundle")
            with self.assertRaises(BundleFormatError):
                decrypt_file_bundle(
                    input_path=fake_bundle,
                    output_path=output_path,
                    chunk_size=4096,
                    monitor_interval=0.01,
                    sm4_key_hex=self.sm4_key,
                )

    def test_benchmark_summary_and_charts(self) -> None:
        payload = benchmark_files(
            algorithm="sm4",
            sizes=[4096, 8192],
            chunk_size=4096,
            sm4_mode_name="cbc",
            monitor_interval=0.01,
            layout="bundle",
            keep_header_bytes=0,
            auto_image_header=False,
            sm4_key_hex=self.sm4_key,
            iv_hex=self.sm4_iv,
        )
        summary = summarize_benchmark_payload(payload)
        self.assertTrue(summary["all_verified"])
        with tempfile.TemporaryDirectory() as temp_dir:
            chart_paths = save_benchmark_charts([payload], Path(temp_dir))
            self.assertTrue(Path(chart_paths["time_chart"]).exists())
            self.assertTrue(Path(chart_paths["throughput_chart"]).exists())


if __name__ == "__main__":
    unittest.main()
