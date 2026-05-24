import tempfile
import unittest
from pathlib import Path

from crypto_app import (
    decrypt_file_bundle,
    decrypt_file_sm4_raw,
    encrypt_file_sm2_sm4_bundle,
    encrypt_file_sm4_bundle,
    encrypt_file_sm4_raw,
    generate_sm2_keypair,
    sha256_file,
    sm2_decrypt_text,
    sm2_encrypt_text,
    sm3_digest_bytes,
    sm4_decrypt_text,
    sm4_encrypt_text,
)


ASSET_DIR = Path(__file__).resolve().parent / "test_assets"


def load_text_asset() -> str:
    data = (ASSET_DIR / "text.txt").read_bytes()
    for encoding in ("utf-8", "utf-8-sig", "gb18030", "gbk"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise AssertionError("Unable to decode test_assets/text.txt with expected encodings")


@unittest.skipUnless(ASSET_DIR.exists(), "test_assets directory is required for integration tests")
class AssetIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sm2_keys = generate_sm2_keypair(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
        cls.sm4_key = "0123456789abcdeffedcba9876543210"
        cls.sm4_iv = "000102030405060708090a0b0c0d0e0f"
        cls.text_asset = load_text_asset()
        cls.asset_paths = {
            "txt": ASSET_DIR / "text.txt",
            "jpg": ASSET_DIR / "photo.jpg",
            "pdf": ASSET_DIR / "pdf.pdf",
            "docx": ASSET_DIR / "word.docx",
        }

    def test_text_asset_roundtrip_and_hash(self) -> None:
        excerpt = self.text_asset[:512]
        sm2_ciphertext = sm2_encrypt_text(excerpt, self.sm2_keys["public_key"])
        self.assertEqual(sm2_decrypt_text(sm2_ciphertext, self.sm2_keys["private_key"]), excerpt)

        sm4_ciphertext = sm4_encrypt_text(
            self.text_asset,
            key_hex=self.sm4_key,
            mode_name="cbc",
            iv_hex=self.sm4_iv,
        )["ciphertext"]
        self.assertEqual(
            sm4_decrypt_text(
                sm4_ciphertext,
                key_hex=self.sm4_key,
                mode_name="cbc",
                iv_hex=self.sm4_iv,
            ),
            self.text_asset,
        )

        digest = sm3_digest_bytes(self.text_asset.encode("utf-8"))
        self.assertEqual(len(digest), 64)

    def test_sm4_bundle_roundtrip_for_all_asset_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            for name, source_path in self.asset_paths.items():
                encrypted_path = temp_root / f"{name}.gms"
                decrypted_path = temp_root / f"{name}.dec"

                encrypt_result = encrypt_file_sm4_bundle(
                    input_path=source_path,
                    output_path=encrypted_path,
                    mode_name="cbc",
                    chunk_size=64 * 1024,
                    monitor_interval=0.01,
                    keep_header_bytes=0,
                    key_hex=self.sm4_key,
                    iv_hex=self.sm4_iv,
                )
                decrypt_file_bundle(
                    input_path=encrypted_path,
                    output_path=decrypted_path,
                    chunk_size=64 * 1024,
                    monitor_interval=0.01,
                    sm4_key_hex=encrypt_result["key_hex"],
                )

                self.assertEqual(sha256_file(source_path), sha256_file(decrypted_path), source_path.name)

    def test_sm2_sm4_bundle_roundtrip_for_pdf_and_docx(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            for name in ("pdf", "docx"):
                source_path = self.asset_paths[name]
                encrypted_path = temp_root / f"{name}.hybrid.gms"
                decrypted_path = temp_root / f"{name}.hybrid.dec"

                encrypt_file_sm2_sm4_bundle(
                    input_path=source_path,
                    output_path=encrypted_path,
                    public_key_hex=self.sm2_keys["public_key"],
                    sm2_mode_name="c1c3c2",
                    sm4_mode_name="cbc",
                    chunk_size=64 * 1024,
                    monitor_interval=0.01,
                    keep_header_bytes=0,
                    session_key_hex=self.sm4_key,
                    iv_hex=self.sm4_iv,
                )
                decrypt_file_bundle(
                    input_path=encrypted_path,
                    output_path=decrypted_path,
                    chunk_size=64 * 1024,
                    monitor_interval=0.01,
                    private_key_hex=self.sm2_keys["private_key"],
                )

                self.assertEqual(sha256_file(source_path), sha256_file(decrypted_path), source_path.name)

    def test_jpg_raw_mode_preserves_header_and_restores_file(self) -> None:
        source_path = self.asset_paths["jpg"]
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            encrypted_path = temp_root / "photo.enc.jpg"
            decrypted_path = temp_root / "photo.dec.jpg"
            header_size = 2048

            encrypt_file_sm4_raw(
                input_path=source_path,
                output_path=encrypted_path,
                mode_name="cbc",
                chunk_size=32 * 1024,
                monitor_interval=0.01,
                keep_header_bytes=header_size,
                key_hex=self.sm4_key,
                iv_hex=self.sm4_iv,
            )
            original_bytes = source_path.read_bytes()
            encrypted_bytes = encrypted_path.read_bytes()

            self.assertEqual(encrypted_bytes[:header_size], original_bytes[:header_size])
            self.assertNotEqual(encrypted_bytes, original_bytes)

            decrypt_file_sm4_raw(
                input_path=encrypted_path,
                output_path=decrypted_path,
                key_hex=self.sm4_key,
                mode_name="cbc",
                chunk_size=32 * 1024,
                monitor_interval=0.01,
                keep_header_bytes=header_size,
                iv_hex=self.sm4_iv,
            )
            self.assertEqual(sha256_file(source_path), sha256_file(decrypted_path))


if __name__ == "__main__":
    unittest.main()
