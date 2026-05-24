from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import struct
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional

import psutil
from gmssl import sm2, sm3, sm4


SM4_BLOCK_SIZE = 16
BUNDLE_MAGIC = b"GMSB1"
BUNDLE_VERSION = 1
DEFAULT_CHUNK_SIZE = 1024 * 1024
DEFAULT_BENCHMARK_SIZES = "64KB,1MB,5MB"
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
IMAGE_HEADER_PRESETS = {
    ".bmp": 54,
    ".gif": 13,
    ".png": 33,
    ".webp": 30,
    ".jpg": 2048,
    ".jpeg": 2048,
}


class CryptoAppError(Exception):
    pass


class InputValidationError(CryptoAppError):
    pass


class CryptoOperationError(CryptoAppError):
    pass


class BundleFormatError(CryptoAppError):
    pass


@dataclass
class OperationMetrics:
    algorithm: str
    operation: str
    logical_bytes: int
    seconds: float
    throughput_mb_s: float
    cpu_avg_percent: float
    cpu_peak_percent: float
    memory_avg_mb: float
    memory_peak_mb: float
    sample_count: int
    chunk_size: int
    source_path: Optional[str] = None
    target_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "operation": self.operation,
            "logical_bytes": self.logical_bytes,
            "seconds": round(self.seconds, 6),
            "throughput_mb_s": round(self.throughput_mb_s, 6),
            "cpu_avg_percent": round(self.cpu_avg_percent, 4),
            "cpu_peak_percent": round(self.cpu_peak_percent, 4),
            "memory_avg_mb": round(self.memory_avg_mb, 4),
            "memory_peak_mb": round(self.memory_peak_mb, 4),
            "sample_count": self.sample_count,
            "chunk_size": self.chunk_size,
            "source_path": self.source_path,
            "target_path": self.target_path,
        }


class ResourceMonitor:
    def __init__(self, interval: float = 0.1) -> None:
        if interval <= 0:
            raise ValueError("monitor interval must be greater than 0")
        self.interval = interval
        self.process = psutil.Process(os.getpid())
        self.samples: List[Dict[str, float]] = []
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.samples = []
        self.stop_event.clear()
        self.process.cpu_percent(None)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _sample(self) -> None:
        self.samples.append(
            {
                "cpu_percent": self.process.cpu_percent(None),
                "rss_bytes": float(self.process.memory_info().rss),
            }
        )

    def _run(self) -> None:
        while not self.stop_event.wait(self.interval):
            self._sample()

    def stop(self) -> Dict[str, float]:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=max(1.0, self.interval * 2))
        self._sample()

        if not self.samples:
            return {
                "cpu_avg_percent": 0.0,
                "cpu_peak_percent": 0.0,
                "memory_avg_mb": 0.0,
                "memory_peak_mb": 0.0,
                "sample_count": 0,
            }

        cpu_values = [sample["cpu_percent"] for sample in self.samples]
        memory_values = [sample["rss_bytes"] / (1024 * 1024) for sample in self.samples]
        return {
            "cpu_avg_percent": sum(cpu_values) / len(cpu_values),
            "cpu_peak_percent": max(cpu_values),
            "memory_avg_mb": sum(memory_values) / len(memory_values),
            "memory_peak_mb": max(memory_values),
            "sample_count": len(self.samples),
        }


def print_json(data: Dict[str, Any]) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2))


def normalize_hex(value: str, expected_bytes: int, field_name: str) -> str:
    cleaned = value.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != expected_bytes * 2 or not HEX_RE.fullmatch(cleaned):
        raise InputValidationError(f"{field_name} must be {expected_bytes * 2} hex characters")
    return cleaned


def normalize_public_key(value: str) -> str:
    cleaned = value.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if cleaned.startswith("04") and len(cleaned) == 130:
        cleaned = cleaned[2:]
    if len(cleaned) != 128 or not HEX_RE.fullmatch(cleaned):
        raise InputValidationError("SM2 public key must be 128 hex characters, optionally prefixed with 04")
    return cleaned


def encode_binary(data: bytes, output_encoding: str) -> str:
    if output_encoding == "hex":
        return data.hex()
    if output_encoding == "base64":
        return base64.b64encode(data).decode("ascii")
    raise InputValidationError("unsupported output encoding")


def decode_binary(data: str, input_encoding: str) -> bytes:
    try:
        if input_encoding == "hex":
            return bytes.fromhex(data.strip())
        if input_encoding == "base64":
            return base64.b64decode(data.strip(), validate=True)
    except Exception as exc:
        raise InputValidationError(f"invalid {input_encoding} ciphertext") from exc
    raise InputValidationError("unsupported input encoding")


def parse_size(value: Any) -> int:
    if isinstance(value, int):
        if value < 0:
            raise InputValidationError("size must be non-negative")
        return value

    text = str(value).strip()
    if text.isdigit():
        return int(text)

    match = re.fullmatch(r"(?i)\s*(\d+(?:\.\d+)?)\s*([kmgt]?b)\s*", text)
    if not match:
        raise InputValidationError(
            "invalid size, use plain bytes or forms like 64KB, 1MB, 0.5GB"
        )

    number = float(match.group(1))
    unit = match.group(2).lower()
    scale = {
        "b": 1,
        "kb": 1024,
        "mb": 1024 ** 2,
        "gb": 1024 ** 3,
        "tb": 1024 ** 4,
    }[unit]
    return int(number * scale)


def parse_size_list(spec: str) -> List[int]:
    sizes = [parse_size(item) for item in spec.split(",") if item.strip()]
    if not sizes:
        raise InputValidationError("benchmark sizes cannot be empty")
    return sizes


def parse_monitor_interval(value: Any) -> float:
    try:
        interval = float(value)
    except (TypeError, ValueError) as exc:
        raise InputValidationError("monitor interval must be a number") from exc
    if interval <= 0:
        raise InputValidationError("monitor interval must be greater than 0")
    return interval


def ensure_positive_chunk_size(chunk_size: int) -> int:
    if chunk_size <= 0:
        raise InputValidationError("chunk size must be greater than 0")
    if chunk_size < SM4_BLOCK_SIZE:
        raise InputValidationError("chunk size must be at least 16 bytes")
    return chunk_size


def ensure_input_file_exists(path: Path) -> None:
    if not path.exists():
        raise InputValidationError(f"input file does not exist: {path}")
    if not path.is_file():
        raise InputValidationError(f"input path is not a file: {path}")


def pkcs7_pad(data: bytes) -> bytes:
    pad_len = SM4_BLOCK_SIZE - (len(data) % SM4_BLOCK_SIZE)
    if pad_len == 0:
        pad_len = SM4_BLOCK_SIZE
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % SM4_BLOCK_SIZE != 0:
        raise CryptoOperationError("invalid PKCS#7 padded data length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > SM4_BLOCK_SIZE:
        raise CryptoOperationError("invalid PKCS#7 padding value")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise CryptoOperationError("invalid PKCS#7 padding bytes")
    return data[:-pad_len]


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def sm3_digest_bytes(data: bytes) -> str:
    return sm3.sm3_hash(list(data))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(DEFAULT_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def write_random_file(path: Path, size: int, chunk_size: int = DEFAULT_CHUNK_SIZE) -> None:
    remaining = size
    with path.open("wb") as handle:
        while remaining > 0:
            chunk_len = min(chunk_size, remaining)
            handle.write(os.urandom(chunk_len))
            remaining -= chunk_len


def detect_header_bytes(path: Path, auto_image_header: bool, keep_header_bytes: int) -> int:
    if keep_header_bytes > 0:
        return keep_header_bytes
    if auto_image_header:
        return IMAGE_HEADER_PRESETS.get(path.suffix.lower(), 0)
    return 0


def default_encrypt_output_path(path: Path, layout: str) -> Path:
    if layout == "bundle":
        return path.with_suffix(path.suffix + ".gms")
    return path.with_name(path.stem + ".enc" + path.suffix)


def default_decrypt_output_path(path: Path, layout: str) -> Path:
    if layout == "bundle" and path.suffix == ".gms":
        return path.with_suffix("")
    return path.with_name(path.stem + ".dec" + path.suffix)


def sm2_mode_to_int(mode_name: str) -> int:
    return 1 if mode_name == "c1c3c2" else 0


def generate_sm2_keypair(private_key_hex: Optional[str] = None) -> Dict[str, str]:
    curve_n = int(sm2.default_ecc_table["n"], 16)
    if private_key_hex:
        private_key = normalize_hex(private_key_hex, 32, "SM2 private key")
        private_value = int(private_key, 16)
        if not 1 <= private_value < curve_n:
            raise InputValidationError("SM2 private key must be in the valid curve range")
    else:
        private_value = secrets.randbelow(curve_n - 1) + 1
        private_key = "{:064x}".format(private_value)

    helper = sm2.CryptSM2(private_key=private_key, public_key="", mode=sm2_mode_to_int("c1c3c2"))
    public_key = helper._kg(private_value, sm2.default_ecc_table["g"])
    return {
        "private_key": private_key,
        "public_key": public_key,
    }


def generate_sm4_material(mode_name: str, key_hex: Optional[str] = None, iv_hex: Optional[str] = None) -> Dict[str, Optional[str]]:
    if mode_name not in ("ecb", "cbc"):
        raise InputValidationError("SM4 mode must be ecb or cbc")
    material_key = normalize_hex(key_hex, 16, "SM4 key") if key_hex else secrets.token_hex(16)
    material_iv = None
    if mode_name == "cbc":
        material_iv = normalize_hex(iv_hex, 16, "SM4 IV") if iv_hex else secrets.token_hex(16)
    return {"key_hex": material_key, "iv_hex": material_iv}


def build_sm2_encryptor(public_key_hex: str, mode_name: str) -> sm2.CryptSM2:
    return sm2.CryptSM2(
        private_key="",
        public_key=normalize_public_key(public_key_hex),
        mode=sm2_mode_to_int(mode_name),
    )


def build_sm2_decryptor(private_key_hex: str, mode_name: str) -> sm2.CryptSM2:
    return sm2.CryptSM2(
        private_key=normalize_hex(private_key_hex, 32, "SM2 private key"),
        public_key="",
        mode=sm2_mode_to_int(mode_name),
    )


def sm2_encrypt_text(
    text: str,
    public_key_hex: str,
    mode_name: str = "c1c3c2",
    text_encoding: str = "utf-8",
    output_encoding: str = "base64",
) -> str:
    encryptor = build_sm2_encryptor(public_key_hex, mode_name)
    encrypted = encryptor.encrypt(text.encode(text_encoding))
    if encrypted is None:
        raise CryptoOperationError("SM2 encryption failed")
    return encode_binary(encrypted, output_encoding)


def sm2_decrypt_text(
    ciphertext: str,
    private_key_hex: str,
    mode_name: str = "c1c3c2",
    input_encoding: str = "base64",
    text_encoding: str = "utf-8",
) -> str:
    decryptor = build_sm2_decryptor(private_key_hex, mode_name)
    plaintext = decryptor.decrypt(decode_binary(ciphertext, input_encoding))
    if plaintext is None:
        raise CryptoOperationError("SM2 decryption failed")
    try:
        return plaintext.decode(text_encoding)
    except UnicodeDecodeError as exc:
        raise CryptoOperationError("SM2 decrypted bytes could not be decoded with the selected text encoding") from exc


class StreamingSM4Cipher:
    def __init__(self, key_bytes: bytes, mode_name: str = "cbc", iv_bytes: Optional[bytes] = None) -> None:
        if len(key_bytes) != SM4_BLOCK_SIZE:
            raise InputValidationError("SM4 key must be 16 bytes")
        if mode_name not in ("ecb", "cbc"):
            raise InputValidationError("SM4 mode must be ecb or cbc")
        if mode_name == "cbc" and (iv_bytes is None or len(iv_bytes) != SM4_BLOCK_SIZE):
            raise InputValidationError("SM4 CBC mode requires a 16-byte IV")

        self.mode_name = mode_name
        self.iv_bytes = iv_bytes
        self.encryptor = sm4.CryptSM4()
        self.encryptor.set_key(key_bytes, sm4.SM4_ENCRYPT)
        self.decryptor = sm4.CryptSM4()
        self.decryptor.set_key(key_bytes, sm4.SM4_DECRYPT)

    @staticmethod
    def _run_block(worker: sm4.CryptSM4, block: bytes) -> bytes:
        return bytes(worker.one_round(worker.sk, list(block)))

    def _encrypt_block(self, block: bytes, state: Optional[bytes]) -> (bytes, Optional[bytes]):
        working = block
        if self.mode_name == "cbc":
            working = xor_bytes(block, state or b"\x00" * SM4_BLOCK_SIZE)
        ciphertext = self._run_block(self.encryptor, working)
        next_state = ciphertext if self.mode_name == "cbc" else state
        return ciphertext, next_state

    def _decrypt_block(self, block: bytes, state: Optional[bytes]) -> (bytes, Optional[bytes]):
        plaintext = self._run_block(self.decryptor, block)
        if self.mode_name == "cbc":
            plaintext = xor_bytes(plaintext, state or b"\x00" * SM4_BLOCK_SIZE)
            next_state = block
        else:
            next_state = state
        return plaintext, next_state

    def encrypt_bytes(self, data: bytes) -> bytes:
        state = self.iv_bytes
        output = bytearray()
        padded = pkcs7_pad(data)
        for offset in range(0, len(padded), SM4_BLOCK_SIZE):
            block = padded[offset : offset + SM4_BLOCK_SIZE]
            ciphertext, state = self._encrypt_block(block, state)
            output.extend(ciphertext)
        return bytes(output)

    def decrypt_bytes(self, data: bytes) -> bytes:
        if not data:
            return b""
        if len(data) % SM4_BLOCK_SIZE != 0:
            raise CryptoOperationError("SM4 ciphertext length must be a multiple of 16 bytes")
        state = self.iv_bytes
        output = bytearray()
        for offset in range(0, len(data), SM4_BLOCK_SIZE):
            block = data[offset : offset + SM4_BLOCK_SIZE]
            plaintext, state = self._decrypt_block(block, state)
            output.extend(plaintext)
        return pkcs7_unpad(bytes(output))

    def encrypt_stream(self, reader: BinaryIO, writer: BinaryIO, chunk_size: int) -> int:
        total_plain_bytes = 0
        state = self.iv_bytes
        buffer = b""

        while True:
            chunk = reader.read(chunk_size)
            if not chunk:
                break
            total_plain_bytes += len(chunk)
            buffer += chunk

            while len(buffer) >= SM4_BLOCK_SIZE:
                block = buffer[:SM4_BLOCK_SIZE]
                buffer = buffer[SM4_BLOCK_SIZE:]
                ciphertext, state = self._encrypt_block(block, state)
                writer.write(ciphertext)

        if total_plain_bytes == 0:
            return 0

        final_block = pkcs7_pad(buffer)
        for offset in range(0, len(final_block), SM4_BLOCK_SIZE):
            ciphertext, state = self._encrypt_block(final_block[offset : offset + SM4_BLOCK_SIZE], state)
            writer.write(ciphertext)
        return total_plain_bytes

    def decrypt_stream(self, reader: BinaryIO, writer: BinaryIO, chunk_size: int) -> int:
        total_cipher_bytes = 0
        state = self.iv_bytes
        buffer = b""

        while True:
            chunk = reader.read(chunk_size)
            if not chunk:
                break
            total_cipher_bytes += len(chunk)
            buffer += chunk

            while len(buffer) > SM4_BLOCK_SIZE:
                block = buffer[:SM4_BLOCK_SIZE]
                buffer = buffer[SM4_BLOCK_SIZE:]
                plaintext, state = self._decrypt_block(block, state)
                writer.write(plaintext)

        if total_cipher_bytes == 0:
            return 0
        if total_cipher_bytes % SM4_BLOCK_SIZE != 0 or len(buffer) != SM4_BLOCK_SIZE:
            raise CryptoOperationError("SM4 ciphertext file is not aligned to 16-byte blocks")

        plaintext, state = self._decrypt_block(buffer, state)
        writer.write(pkcs7_unpad(plaintext))
        return total_cipher_bytes


def sm4_encrypt_text(
    text: str,
    key_hex: str,
    mode_name: str = "cbc",
    iv_hex: Optional[str] = None,
    text_encoding: str = "utf-8",
    output_encoding: str = "base64",
) -> Dict[str, Optional[str]]:
    if not text:
        raise InputValidationError("plaintext cannot be empty")
    material = generate_sm4_material(mode_name, key_hex=key_hex, iv_hex=iv_hex)
    cipher = StreamingSM4Cipher(
        key_bytes=bytes.fromhex(material["key_hex"] or ""),
        mode_name=mode_name,
        iv_bytes=bytes.fromhex(material["iv_hex"]) if material["iv_hex"] else None,
    )
    encrypted = cipher.encrypt_bytes(text.encode(text_encoding))
    return {
        "ciphertext": encode_binary(encrypted, output_encoding),
        "key_hex": material["key_hex"],
        "iv_hex": material["iv_hex"],
        "mode": mode_name,
    }


def sm4_decrypt_text(
    ciphertext: str,
    key_hex: str,
    mode_name: str = "cbc",
    iv_hex: Optional[str] = None,
    input_encoding: str = "base64",
    text_encoding: str = "utf-8",
) -> str:
    normalized_key = normalize_hex(key_hex, 16, "SM4 key")
    normalized_iv = None
    if mode_name == "cbc":
        if not iv_hex:
            raise InputValidationError("SM4 CBC decryption requires --iv-hex")
        normalized_iv = normalize_hex(iv_hex, 16, "SM4 IV")

    cipher = StreamingSM4Cipher(
        key_bytes=bytes.fromhex(normalized_key),
        mode_name=mode_name,
        iv_bytes=bytes.fromhex(normalized_iv) if normalized_iv else None,
    )
    plaintext = cipher.decrypt_bytes(decode_binary(ciphertext, input_encoding))
    try:
        return plaintext.decode(text_encoding)
    except UnicodeDecodeError as exc:
        raise CryptoOperationError("SM4 decrypted bytes could not be decoded with the selected text encoding") from exc


def read_bundle_metadata(handle: BinaryIO) -> Dict[str, Any]:
    magic = handle.read(len(BUNDLE_MAGIC))
    if magic != BUNDLE_MAGIC:
        raise BundleFormatError("file is not a supported bundle container")
    length_bytes = handle.read(4)
    if len(length_bytes) != 4:
        raise BundleFormatError("bundle metadata length is missing")
    metadata_length = struct.unpack(">I", length_bytes)[0]
    metadata_bytes = handle.read(metadata_length)
    if len(metadata_bytes) != metadata_length:
        raise BundleFormatError("bundle metadata is incomplete")
    try:
        metadata = json.loads(metadata_bytes.decode("utf-8"))
    except Exception as exc:
        raise BundleFormatError("bundle metadata is not valid JSON") from exc
    if metadata.get("bundle_version") != BUNDLE_VERSION:
        raise BundleFormatError("unsupported bundle version")
    return metadata


def write_bundle_metadata(handle: BinaryIO, metadata: Dict[str, Any]) -> None:
    metadata_bytes = json.dumps(metadata, ensure_ascii=False, sort_keys=True).encode("utf-8")
    handle.write(BUNDLE_MAGIC)
    handle.write(struct.pack(">I", len(metadata_bytes)))
    handle.write(metadata_bytes)


def is_bundle_file(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(len(BUNDLE_MAGIC)) == BUNDLE_MAGIC
    except OSError:
        return False


def build_metrics(
    algorithm: str,
    operation: str,
    logical_bytes: int,
    seconds: float,
    resource_summary: Dict[str, float],
    chunk_size: int,
    source_path: Optional[Path],
    target_path: Optional[Path],
) -> OperationMetrics:
    throughput = 0.0 if seconds <= 0 else logical_bytes / seconds / (1024 * 1024)
    return OperationMetrics(
        algorithm=algorithm,
        operation=operation,
        logical_bytes=logical_bytes,
        seconds=seconds,
        throughput_mb_s=throughput,
        cpu_avg_percent=resource_summary["cpu_avg_percent"],
        cpu_peak_percent=resource_summary["cpu_peak_percent"],
        memory_avg_mb=resource_summary["memory_avg_mb"],
        memory_peak_mb=resource_summary["memory_peak_mb"],
        sample_count=int(resource_summary["sample_count"]),
        chunk_size=chunk_size,
        source_path=str(source_path) if source_path else None,
        target_path=str(target_path) if target_path else None,
    )


def encrypt_file_sm4_bundle(
    input_path: Path,
    output_path: Path,
    mode_name: str,
    chunk_size: int,
    monitor_interval: float,
    keep_header_bytes: int = 0,
    key_hex: Optional[str] = None,
    iv_hex: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_input_file_exists(input_path)
    chunk_size = ensure_positive_chunk_size(chunk_size)
    monitor_interval = parse_monitor_interval(monitor_interval)
    source_size = input_path.stat().st_size
    material = generate_sm4_material(mode_name, key_hex=key_hex, iv_hex=iv_hex)
    cipher = StreamingSM4Cipher(
        key_bytes=bytes.fromhex(material["key_hex"] or ""),
        mode_name=mode_name,
        iv_bytes=bytes.fromhex(material["iv_hex"]) if material["iv_hex"] else None,
    )
    actual_header_bytes = min(source_size, keep_header_bytes)
    operation_state: Dict[str, Any] = {}
    monitor = ResourceMonitor(monitor_interval)
    start = time.perf_counter()
    monitor.start()
    try:
        with input_path.open("rb") as reader, output_path.open("wb") as writer:
            plaintext_header = reader.read(actual_header_bytes)
            metadata = {
                "bundle_version": BUNDLE_VERSION,
                "algorithm": "sm4",
                "sm4_mode": mode_name,
                "iv_hex": material["iv_hex"],
                "keep_header_bytes": len(plaintext_header),
                "original_size": source_size,
                "payload_plain_size": source_size - len(plaintext_header),
                "created_from": input_path.name,
            }
            write_bundle_metadata(writer, metadata)
            writer.write(plaintext_header)
            cipher.encrypt_stream(reader, writer, chunk_size)
            operation_state["metadata"] = metadata
    finally:
        elapsed = time.perf_counter() - start
        resource_summary = monitor.stop()

    metrics = build_metrics(
        algorithm="sm4",
        operation="encrypt_file",
        logical_bytes=source_size,
        seconds=elapsed,
        resource_summary=resource_summary,
        chunk_size=chunk_size,
        source_path=input_path,
        target_path=output_path,
    )
    return {
        "algorithm": "sm4",
        "layout": "bundle",
        "output_path": str(output_path),
        "key_hex": material["key_hex"],
        "iv_hex": material["iv_hex"],
        "keep_header_bytes": actual_header_bytes,
        "metrics": metrics.to_dict(),
        "metadata": operation_state["metadata"],
    }


def encrypt_file_sm2_sm4_bundle(
    input_path: Path,
    output_path: Path,
    public_key_hex: str,
    sm2_mode_name: str,
    sm4_mode_name: str,
    chunk_size: int,
    monitor_interval: float,
    keep_header_bytes: int = 0,
    session_key_hex: Optional[str] = None,
    iv_hex: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_input_file_exists(input_path)
    chunk_size = ensure_positive_chunk_size(chunk_size)
    monitor_interval = parse_monitor_interval(monitor_interval)
    source_size = input_path.stat().st_size
    material = generate_sm4_material(sm4_mode_name, key_hex=session_key_hex, iv_hex=iv_hex)
    encryptor = build_sm2_encryptor(public_key_hex, sm2_mode_name)
    wrapped_key = encryptor.encrypt(bytes.fromhex(material["key_hex"] or ""))
    if wrapped_key is None:
        raise CryptoOperationError("SM2 failed to wrap the SM4 session key")

    cipher = StreamingSM4Cipher(
        key_bytes=bytes.fromhex(material["key_hex"] or ""),
        mode_name=sm4_mode_name,
        iv_bytes=bytes.fromhex(material["iv_hex"]) if material["iv_hex"] else None,
    )
    actual_header_bytes = min(source_size, keep_header_bytes)
    operation_state: Dict[str, Any] = {}
    monitor = ResourceMonitor(monitor_interval)
    start = time.perf_counter()
    monitor.start()
    try:
        with input_path.open("rb") as reader, output_path.open("wb") as writer:
            plaintext_header = reader.read(actual_header_bytes)
            metadata = {
                "bundle_version": BUNDLE_VERSION,
                "algorithm": "sm2-sm4",
                "sm2_mode": sm2_mode_name,
                "sm4_mode": sm4_mode_name,
                "iv_hex": material["iv_hex"],
                "wrapped_sm4_key": encode_binary(wrapped_key, "base64"),
                "keep_header_bytes": len(plaintext_header),
                "original_size": source_size,
                "payload_plain_size": source_size - len(plaintext_header),
                "created_from": input_path.name,
            }
            write_bundle_metadata(writer, metadata)
            writer.write(plaintext_header)
            cipher.encrypt_stream(reader, writer, chunk_size)
            operation_state["metadata"] = metadata
    finally:
        elapsed = time.perf_counter() - start
        resource_summary = monitor.stop()

    metrics = build_metrics(
        algorithm="sm2-sm4",
        operation="encrypt_file",
        logical_bytes=source_size,
        seconds=elapsed,
        resource_summary=resource_summary,
        chunk_size=chunk_size,
        source_path=input_path,
        target_path=output_path,
    )
    return {
        "algorithm": "sm2-sm4",
        "layout": "bundle",
        "output_path": str(output_path),
        "wrapped_sm4_key": operation_state["metadata"]["wrapped_sm4_key"],
        "iv_hex": material["iv_hex"],
        "keep_header_bytes": actual_header_bytes,
        "metrics": metrics.to_dict(),
        "metadata": operation_state["metadata"],
    }


def decrypt_file_bundle(
    input_path: Path,
    output_path: Path,
    chunk_size: int,
    monitor_interval: float,
    sm4_key_hex: Optional[str] = None,
    private_key_hex: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_input_file_exists(input_path)
    chunk_size = ensure_positive_chunk_size(chunk_size)
    monitor_interval = parse_monitor_interval(monitor_interval)
    with input_path.open("rb") as reader:
        metadata = read_bundle_metadata(reader)
        keep_header_bytes = int(metadata.get("keep_header_bytes", 0))
        plaintext_header = reader.read(keep_header_bytes)
        if len(plaintext_header) != keep_header_bytes:
            raise BundleFormatError("bundle plaintext header is incomplete")

        algorithm = metadata["algorithm"]
        sm4_mode_name = metadata["sm4_mode"]
        iv_hex = metadata.get("iv_hex")

        if algorithm == "sm4":
            if not sm4_key_hex:
                raise InputValidationError("bundle decryption requires --key-hex for SM4")
            key_hex = normalize_hex(sm4_key_hex, 16, "SM4 key")
        elif algorithm == "sm2-sm4":
            if not private_key_hex:
                raise InputValidationError("bundle decryption requires --private-key-hex for SM2-SM4")
            decryptor = build_sm2_decryptor(private_key_hex, metadata.get("sm2_mode", "c1c3c2"))
            unwrapped_key = decryptor.decrypt(decode_binary(metadata["wrapped_sm4_key"], "base64"))
            if unwrapped_key is None or len(unwrapped_key) != SM4_BLOCK_SIZE:
                raise CryptoOperationError("failed to unwrap the SM4 session key")
            key_hex = unwrapped_key.hex()
        else:
            raise BundleFormatError("unsupported bundle algorithm")

        cipher = StreamingSM4Cipher(
            key_bytes=bytes.fromhex(key_hex),
            mode_name=sm4_mode_name,
            iv_bytes=bytes.fromhex(iv_hex) if iv_hex else None,
        )
        logical_bytes = int(metadata.get("original_size", 0))
        monitor = ResourceMonitor(monitor_interval)
        start = time.perf_counter()
        monitor.start()
        try:
            with output_path.open("wb") as writer:
                writer.write(plaintext_header)
                cipher.decrypt_stream(reader, writer, chunk_size)
        finally:
            elapsed = time.perf_counter() - start
            resource_summary = monitor.stop()

    metrics = build_metrics(
        algorithm=algorithm,
        operation="decrypt_file",
        logical_bytes=logical_bytes,
        seconds=elapsed,
        resource_summary=resource_summary,
        chunk_size=chunk_size,
        source_path=input_path,
        target_path=output_path,
    )
    return {
        "algorithm": algorithm,
        "layout": "bundle",
        "output_path": str(output_path),
        "keep_header_bytes": keep_header_bytes,
        "metrics": metrics.to_dict(),
        "metadata": metadata,
    }


def encrypt_file_sm4_raw(
    input_path: Path,
    output_path: Path,
    mode_name: str,
    chunk_size: int,
    monitor_interval: float,
    keep_header_bytes: int = 0,
    key_hex: Optional[str] = None,
    iv_hex: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_input_file_exists(input_path)
    chunk_size = ensure_positive_chunk_size(chunk_size)
    monitor_interval = parse_monitor_interval(monitor_interval)
    source_size = input_path.stat().st_size
    actual_header_bytes = min(source_size, keep_header_bytes)
    material = generate_sm4_material(mode_name, key_hex=key_hex, iv_hex=iv_hex)
    cipher = StreamingSM4Cipher(
        key_bytes=bytes.fromhex(material["key_hex"] or ""),
        mode_name=mode_name,
        iv_bytes=bytes.fromhex(material["iv_hex"]) if material["iv_hex"] else None,
    )

    monitor = ResourceMonitor(monitor_interval)
    start = time.perf_counter()
    monitor.start()
    try:
        with input_path.open("rb") as reader, output_path.open("wb") as writer:
            header = reader.read(actual_header_bytes)
            writer.write(header)
            cipher.encrypt_stream(reader, writer, chunk_size)
    finally:
        elapsed = time.perf_counter() - start
        resource_summary = monitor.stop()

    metrics = build_metrics(
        algorithm="sm4",
        operation="encrypt_file",
        logical_bytes=source_size,
        seconds=elapsed,
        resource_summary=resource_summary,
        chunk_size=chunk_size,
        source_path=input_path,
        target_path=output_path,
    )
    return {
        "algorithm": "sm4",
        "layout": "raw",
        "output_path": str(output_path),
        "key_hex": material["key_hex"],
        "iv_hex": material["iv_hex"],
        "keep_header_bytes": actual_header_bytes,
        "metrics": metrics.to_dict(),
    }


def decrypt_file_sm4_raw(
    input_path: Path,
    output_path: Path,
    key_hex: str,
    mode_name: str,
    chunk_size: int,
    monitor_interval: float,
    keep_header_bytes: int = 0,
    iv_hex: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_input_file_exists(input_path)
    chunk_size = ensure_positive_chunk_size(chunk_size)
    monitor_interval = parse_monitor_interval(monitor_interval)
    source_size = input_path.stat().st_size
    actual_header_bytes = min(source_size, keep_header_bytes)
    normalized_key = normalize_hex(key_hex, 16, "SM4 key")
    normalized_iv = None
    if mode_name == "cbc":
        if not iv_hex:
            raise InputValidationError("raw CBC decryption requires --iv-hex")
        normalized_iv = normalize_hex(iv_hex, 16, "SM4 IV")

    cipher = StreamingSM4Cipher(
        key_bytes=bytes.fromhex(normalized_key),
        mode_name=mode_name,
        iv_bytes=bytes.fromhex(normalized_iv) if normalized_iv else None,
    )
    monitor = ResourceMonitor(monitor_interval)
    start = time.perf_counter()
    monitor.start()
    try:
        with input_path.open("rb") as reader, output_path.open("wb") as writer:
            header = reader.read(actual_header_bytes)
            writer.write(header)
            cipher.decrypt_stream(reader, writer, chunk_size)
    finally:
        elapsed = time.perf_counter() - start
        resource_summary = monitor.stop()

    metrics = build_metrics(
        algorithm="sm4",
        operation="decrypt_file",
        logical_bytes=source_size,
        seconds=elapsed,
        resource_summary=resource_summary,
        chunk_size=chunk_size,
        source_path=input_path,
        target_path=output_path,
    )
    return {
        "algorithm": "sm4",
        "layout": "raw",
        "output_path": str(output_path),
        "keep_header_bytes": actual_header_bytes,
        "metrics": metrics.to_dict(),
    }


def save_json_if_requested(data: Dict[str, Any], output_path: Optional[str]) -> None:
    if not output_path:
        return
    Path(output_path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def benchmark_files(
    algorithm: str,
    sizes: List[int],
    chunk_size: int,
    sm4_mode_name: str,
    monitor_interval: float,
    layout: str,
    keep_header_bytes: int,
    auto_image_header: bool,
    sm4_key_hex: Optional[str] = None,
    iv_hex: Optional[str] = None,
    sm2_public_key_hex: Optional[str] = None,
    sm2_private_key_hex: Optional[str] = None,
    sm2_mode_name: str = "c1c3c2",
) -> Dict[str, Any]:
    if layout != "bundle" and algorithm != "sm4":
        raise InputValidationError("SM2-SM4 benchmark only supports bundle layout")
    if algorithm not in ("sm4", "sm2-sm4"):
        raise InputValidationError("unsupported benchmark algorithm")
    chunk_size = ensure_positive_chunk_size(chunk_size)
    monitor_interval = parse_monitor_interval(monitor_interval)
    if not sizes:
        raise InputValidationError("benchmark sizes cannot be empty")
    sizes = sorted(sizes)

    results: List[Dict[str, Any]] = []
    benchmark_keypair = None
    if algorithm == "sm2-sm4" and (not sm2_public_key_hex or not sm2_private_key_hex):
        benchmark_keypair = generate_sm2_keypair()
        sm2_public_key_hex = benchmark_keypair["public_key"]
        sm2_private_key_hex = benchmark_keypair["private_key"]

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir)
        for size in sizes:
            source_path = temp_root / ("sample_%d.bin" % size)
            encrypted_path = temp_root / ("sample_%d.enc" % size)
            decrypted_path = temp_root / ("sample_%d.dec" % size)
            write_random_file(source_path, size)

            effective_header = detect_header_bytes(source_path, auto_image_header, keep_header_bytes)
            if algorithm == "sm4":
                if layout == "bundle":
                    encrypt_result = encrypt_file_sm4_bundle(
                        input_path=source_path,
                        output_path=encrypted_path,
                        mode_name=sm4_mode_name,
                        chunk_size=chunk_size,
                        monitor_interval=monitor_interval,
                        keep_header_bytes=effective_header,
                        key_hex=sm4_key_hex,
                        iv_hex=iv_hex,
                    )
                    decrypt_result = decrypt_file_bundle(
                        input_path=encrypted_path,
                        output_path=decrypted_path,
                        chunk_size=chunk_size,
                        monitor_interval=monitor_interval,
                        sm4_key_hex=encrypt_result["key_hex"],
                    )
                else:
                    encrypt_result = encrypt_file_sm4_raw(
                        input_path=source_path,
                        output_path=encrypted_path,
                        mode_name=sm4_mode_name,
                        chunk_size=chunk_size,
                        monitor_interval=monitor_interval,
                        keep_header_bytes=effective_header,
                        key_hex=sm4_key_hex,
                        iv_hex=iv_hex,
                    )
                    decrypt_result = decrypt_file_sm4_raw(
                        input_path=encrypted_path,
                        output_path=decrypted_path,
                        key_hex=encrypt_result["key_hex"],
                        mode_name=sm4_mode_name,
                        chunk_size=chunk_size,
                        monitor_interval=monitor_interval,
                        keep_header_bytes=effective_header,
                        iv_hex=encrypt_result["iv_hex"],
                    )
            else:
                encrypt_result = encrypt_file_sm2_sm4_bundle(
                    input_path=source_path,
                    output_path=encrypted_path,
                    public_key_hex=sm2_public_key_hex or "",
                    sm2_mode_name=sm2_mode_name,
                    sm4_mode_name=sm4_mode_name,
                    chunk_size=chunk_size,
                    monitor_interval=monitor_interval,
                    keep_header_bytes=effective_header,
                    session_key_hex=sm4_key_hex,
                    iv_hex=iv_hex,
                )
                decrypt_result = decrypt_file_bundle(
                    input_path=encrypted_path,
                    output_path=decrypted_path,
                    chunk_size=chunk_size,
                    monitor_interval=monitor_interval,
                    private_key_hex=sm2_private_key_hex,
                )

            verified = sha256_file(source_path) == sha256_file(decrypted_path)
            results.append(
                {
                    "size_bytes": size,
                    "verified": verified,
                    "encrypt": encrypt_result["metrics"],
                    "decrypt": decrypt_result["metrics"],
                }
            )

    payload: Dict[str, Any] = {
        "algorithm": algorithm,
        "layout": layout,
        "sizes": sizes,
        "results": results,
    }
    if benchmark_keypair:
        payload["generated_sm2_keypair"] = benchmark_keypair
    return payload


def summarize_benchmark_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    results = payload.get("results", [])
    if not results:
        raise InputValidationError("benchmark payload contains no results")

    average_encrypt_time = sum(item["encrypt"]["seconds"] for item in results) / len(results)
    average_decrypt_time = sum(item["decrypt"]["seconds"] for item in results) / len(results)
    average_encrypt_throughput = sum(item["encrypt"]["throughput_mb_s"] for item in results) / len(results)
    average_decrypt_throughput = sum(item["decrypt"]["throughput_mb_s"] for item in results) / len(results)

    return {
        "algorithm": payload["algorithm"],
        "layout": payload["layout"],
        "cases": len(results),
        "all_verified": all(item["verified"] for item in results),
        "average_encrypt_seconds": round(average_encrypt_time, 6),
        "average_decrypt_seconds": round(average_decrypt_time, 6),
        "average_encrypt_throughput_mb_s": round(average_encrypt_throughput, 6),
        "average_decrypt_throughput_mb_s": round(average_decrypt_throughput, 6),
    }


def save_benchmark_charts(payloads: List[Dict[str, Any]], output_dir: Path) -> Dict[str, str]:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as exc:
        raise CryptoOperationError("matplotlib is required to generate benchmark charts") from exc

    if not payloads:
        raise InputValidationError("no benchmark data available for plotting")

    output_dir.mkdir(parents=True, exist_ok=True)
    time_chart = output_dir / "encryption_time_comparison.png"
    throughput_chart = output_dir / "throughput_comparison.png"

    plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "Arial Unicode MS", "DejaVu Sans"]
    plt.rcParams["axes.unicode_minus"] = False

    figure_time, axis_time = plt.subplots(figsize=(9, 5.5))
    for payload in payloads:
        x_values = [item["size_bytes"] / 1024 for item in payload["results"]]
        y_values = [item["encrypt"]["seconds"] for item in payload["results"]]
        axis_time.plot(x_values, y_values, marker="o", linewidth=2, label=payload["algorithm"])
    axis_time.set_title("Encryption Time Comparison")
    axis_time.set_xlabel("Data Size (KB)")
    axis_time.set_ylabel("Encryption Time (s)")
    axis_time.grid(True, linestyle="--", alpha=0.4)
    axis_time.legend()
    figure_time.tight_layout()
    figure_time.savefig(time_chart, dpi=150)
    plt.close(figure_time)

    figure_throughput, axis_throughput = plt.subplots(figsize=(9, 5.5))
    for payload in payloads:
        x_values = [item["size_bytes"] / 1024 for item in payload["results"]]
        y_values = [item["encrypt"]["throughput_mb_s"] for item in payload["results"]]
        axis_throughput.plot(x_values, y_values, marker="o", linewidth=2, label=payload["algorithm"])
    axis_throughput.set_title("Throughput Comparison")
    axis_throughput.set_xlabel("Data Size (KB)")
    axis_throughput.set_ylabel("Throughput (MB/s)")
    axis_throughput.grid(True, linestyle="--", alpha=0.4)
    axis_throughput.legend()
    figure_throughput.tight_layout()
    figure_throughput.savefig(throughput_chart, dpi=150)
    plt.close(figure_throughput)

    return {
        "time_chart": str(time_chart),
        "throughput_chart": str(throughput_chart),
    }


def run_self_test() -> Dict[str, Any]:
    sample_text = "国密算法测试 SM2/SM4"
    sm2_keys = generate_sm2_keypair("0000000000000000000000000000000000000000000000000000000000000001")
    sm2_ciphertext = sm2_encrypt_text(sample_text, sm2_keys["public_key"])
    sm2_plaintext = sm2_decrypt_text(sm2_ciphertext, sm2_keys["private_key"])

    sm4_result = sm4_encrypt_text(
        sample_text,
        key_hex="0123456789abcdeffedcba9876543210",
        mode_name="cbc",
        iv_hex="000102030405060708090a0b0c0d0e0f",
    )
    sm4_plaintext = sm4_decrypt_text(
        sm4_result["ciphertext"],
        key_hex=sm4_result["key_hex"] or "",
        mode_name="cbc",
        iv_hex=sm4_result["iv_hex"],
    )

    file_verified = False
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_root = Path(temp_dir)
        source_path = temp_root / "self_test.bin"
        encrypted_path = temp_root / "self_test.gms"
        decrypted_path = temp_root / "self_test.dec"
        source_path.write_bytes(os.urandom(4096) + b"SM4-BLOCK-TEST")
        encrypt_result = encrypt_file_sm4_bundle(
            input_path=source_path,
            output_path=encrypted_path,
            mode_name="cbc",
            chunk_size=4096,
            monitor_interval=0.05,
            keep_header_bytes=32,
            key_hex="0123456789abcdeffedcba9876543210",
            iv_hex="000102030405060708090a0b0c0d0e0f",
        )
        decrypt_file_bundle(
            input_path=encrypted_path,
            output_path=decrypted_path,
            chunk_size=4096,
            monitor_interval=0.05,
            sm4_key_hex=encrypt_result["key_hex"],
        )
        file_verified = sha256_file(source_path) == sha256_file(decrypted_path)

    return {
        "sm2_roundtrip": sm2_plaintext == sample_text,
        "sm4_roundtrip": sm4_plaintext == sample_text,
        "sm3_digest": sm3_digest_bytes(sample_text.encode("utf-8")),
        "file_roundtrip": file_verified,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="gmssl-based SM2/SM3/SM4 crypto application")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = True

    generate_key_parser = subparsers.add_parser("generate-key", help="generate or normalize SM2/SM4 keys")
    generate_key_parser.add_argument("--algorithm", required=True, choices=["sm2", "sm4"])
    generate_key_parser.add_argument("--private-key-hex", help="fixed SM2 private key used to derive the public key")
    generate_key_parser.add_argument("--key-hex", help="fixed SM4 key in hex")
    generate_key_parser.add_argument("--iv-hex", help="fixed SM4 IV in hex")
    generate_key_parser.add_argument("--mode", default="cbc", choices=["ecb", "cbc"], help="SM4 mode")

    encrypt_text_parser = subparsers.add_parser("encrypt-text", help="encrypt text with SM2 or SM4")
    encrypt_text_parser.add_argument("--algorithm", required=True, choices=["sm2", "sm4"])
    encrypt_text_parser.add_argument("--text", required=True, help="plaintext string")
    encrypt_text_parser.add_argument("--text-encoding", default="utf-8")
    encrypt_text_parser.add_argument("--output-encoding", default="base64", choices=["base64", "hex"])
    encrypt_text_parser.add_argument("--public-key-hex", help="SM2 public key")
    encrypt_text_parser.add_argument("--sm2-mode", default="c1c3c2", choices=["c1c2c3", "c1c3c2"])
    encrypt_text_parser.add_argument("--key-hex", help="SM4 key")
    encrypt_text_parser.add_argument("--mode", default="cbc", choices=["ecb", "cbc"], help="SM4 mode")
    encrypt_text_parser.add_argument("--iv-hex", help="SM4 IV, autogenerated when omitted in CBC mode")

    decrypt_text_parser = subparsers.add_parser("decrypt-text", help="decrypt text with SM2 or SM4")
    decrypt_text_parser.add_argument("--algorithm", required=True, choices=["sm2", "sm4"])
    decrypt_text_parser.add_argument("--ciphertext", required=True)
    decrypt_text_parser.add_argument("--input-encoding", default="base64", choices=["base64", "hex"])
    decrypt_text_parser.add_argument("--text-encoding", default="utf-8")
    decrypt_text_parser.add_argument("--private-key-hex", help="SM2 private key")
    decrypt_text_parser.add_argument("--sm2-mode", default="c1c3c2", choices=["c1c2c3", "c1c3c2"])
    decrypt_text_parser.add_argument("--key-hex", help="SM4 key")
    decrypt_text_parser.add_argument("--mode", default="cbc", choices=["ecb", "cbc"], help="SM4 mode")
    decrypt_text_parser.add_argument("--iv-hex", help="SM4 IV for CBC mode")

    hash_text_parser = subparsers.add_parser("hash-text", help="hash text with SM3")
    hash_text_parser.add_argument("--text", required=True)
    hash_text_parser.add_argument("--text-encoding", default="utf-8")

    hash_file_parser = subparsers.add_parser("hash-file", help="hash a file with SM3")
    hash_file_parser.add_argument("--input", required=True)

    encrypt_file_parser = subparsers.add_parser("encrypt-file", help="encrypt a file with SM4 or SM2-SM4 hybrid mode")
    encrypt_file_parser.add_argument("--algorithm", required=True, choices=["sm4", "sm2-sm4"])
    encrypt_file_parser.add_argument("--input", required=True)
    encrypt_file_parser.add_argument("--output")
    encrypt_file_parser.add_argument("--layout", default="bundle", choices=["bundle", "raw"])
    encrypt_file_parser.add_argument("--mode", default="cbc", choices=["ecb", "cbc"], help="SM4 mode")
    encrypt_file_parser.add_argument("--chunk-size", type=parse_size, default=DEFAULT_CHUNK_SIZE)
    encrypt_file_parser.add_argument("--monitor-interval", type=float, default=0.1)
    encrypt_file_parser.add_argument("--keep-header-bytes", type=parse_size, default=0)
    encrypt_file_parser.add_argument("--auto-image-header", action="store_true")
    encrypt_file_parser.add_argument("--key-hex", help="SM4 key or SM2-SM4 session key")
    encrypt_file_parser.add_argument("--iv-hex", help="SM4 IV")
    encrypt_file_parser.add_argument("--public-key-hex", help="SM2 public key for hybrid file encryption")
    encrypt_file_parser.add_argument("--sm2-mode", default="c1c3c2", choices=["c1c2c3", "c1c3c2"])
    encrypt_file_parser.add_argument("--metrics-out", help="write JSON result to a file")

    decrypt_file_parser = subparsers.add_parser("decrypt-file", help="decrypt a file")
    decrypt_file_parser.add_argument("--input", required=True)
    decrypt_file_parser.add_argument("--output")
    decrypt_file_parser.add_argument("--layout", default="auto", choices=["auto", "bundle", "raw"])
    decrypt_file_parser.add_argument("--mode", default="cbc", choices=["ecb", "cbc"], help="raw SM4 mode")
    decrypt_file_parser.add_argument("--chunk-size", type=parse_size, default=DEFAULT_CHUNK_SIZE)
    decrypt_file_parser.add_argument("--monitor-interval", type=float, default=0.1)
    decrypt_file_parser.add_argument("--keep-header-bytes", type=parse_size, default=0)
    decrypt_file_parser.add_argument("--key-hex", help="SM4 key for plain SM4 decryption")
    decrypt_file_parser.add_argument("--iv-hex", help="SM4 IV for raw CBC mode")
    decrypt_file_parser.add_argument("--private-key-hex", help="SM2 private key for hybrid bundle decryption")
    decrypt_file_parser.add_argument("--metrics-out", help="write JSON result to a file")

    benchmark_parser = subparsers.add_parser("benchmark", help="benchmark file encryption and decryption")
    benchmark_parser.add_argument("--algorithm", default="sm4", choices=["sm4", "sm2-sm4"])
    benchmark_parser.add_argument("--sizes", default=DEFAULT_BENCHMARK_SIZES)
    benchmark_parser.add_argument("--layout", default="bundle", choices=["bundle", "raw"])
    benchmark_parser.add_argument("--mode", default="cbc", choices=["ecb", "cbc"])
    benchmark_parser.add_argument("--chunk-size", type=parse_size, default=DEFAULT_CHUNK_SIZE)
    benchmark_parser.add_argument("--monitor-interval", type=float, default=0.1)
    benchmark_parser.add_argument("--keep-header-bytes", type=parse_size, default=0)
    benchmark_parser.add_argument("--auto-image-header", action="store_true")
    benchmark_parser.add_argument("--key-hex", help="SM4 key or session key")
    benchmark_parser.add_argument("--iv-hex", help="SM4 IV")
    benchmark_parser.add_argument("--public-key-hex", help="SM2 public key for hybrid benchmark")
    benchmark_parser.add_argument("--private-key-hex", help="SM2 private key for hybrid benchmark")
    benchmark_parser.add_argument("--sm2-mode", default="c1c3c2", choices=["c1c2c3", "c1c3c2"])
    benchmark_parser.add_argument("--metrics-out", help="write JSON benchmark result to a file")

    self_test_parser = subparsers.add_parser("self-test", help="run a quick built-in smoke test")
    self_test_parser.add_argument("--metrics-out", help="write JSON result to a file")
    return parser


def handle_generate_key(args: argparse.Namespace) -> Dict[str, Any]:
    if args.algorithm == "sm2":
        keys = generate_sm2_keypair(args.private_key_hex)
        return {
            "algorithm": "sm2",
            "key_source": "fixed" if args.private_key_hex else "random",
            "private_key": keys["private_key"],
            "public_key": keys["public_key"],
        }

    material = generate_sm4_material(args.mode, key_hex=args.key_hex, iv_hex=args.iv_hex)
    return {
        "algorithm": "sm4",
        "key_source": "fixed" if args.key_hex else "random",
        "key_hex": material["key_hex"],
        "mode": args.mode,
        "iv_hex": material["iv_hex"],
    }


def handle_encrypt_text(args: argparse.Namespace) -> Dict[str, Any]:
    if args.algorithm == "sm2":
        if not args.public_key_hex:
            raise ValueError("SM2 text encryption requires --public-key-hex")
        ciphertext = sm2_encrypt_text(
            text=args.text,
            public_key_hex=args.public_key_hex,
            mode_name=args.sm2_mode,
            text_encoding=args.text_encoding,
            output_encoding=args.output_encoding,
        )
        return {
            "algorithm": "sm2",
            "sm2_mode": args.sm2_mode,
            "ciphertext": ciphertext,
            "output_encoding": args.output_encoding,
        }

    if not args.key_hex:
        raise ValueError("SM4 text encryption requires --key-hex")
    result = sm4_encrypt_text(
        text=args.text,
        key_hex=args.key_hex,
        mode_name=args.mode,
        iv_hex=args.iv_hex,
        text_encoding=args.text_encoding,
        output_encoding=args.output_encoding,
    )
    result["algorithm"] = "sm4"
    result["output_encoding"] = args.output_encoding
    return result


def handle_decrypt_text(args: argparse.Namespace) -> Dict[str, Any]:
    if args.algorithm == "sm2":
        if not args.private_key_hex:
            raise ValueError("SM2 text decryption requires --private-key-hex")
        plaintext = sm2_decrypt_text(
            ciphertext=args.ciphertext,
            private_key_hex=args.private_key_hex,
            mode_name=args.sm2_mode,
            input_encoding=args.input_encoding,
            text_encoding=args.text_encoding,
        )
        return {
            "algorithm": "sm2",
            "sm2_mode": args.sm2_mode,
            "plaintext": plaintext,
        }

    if not args.key_hex:
        raise ValueError("SM4 text decryption requires --key-hex")
    plaintext = sm4_decrypt_text(
        ciphertext=args.ciphertext,
        key_hex=args.key_hex,
        mode_name=args.mode,
        iv_hex=args.iv_hex,
        input_encoding=args.input_encoding,
        text_encoding=args.text_encoding,
    )
    return {
        "algorithm": "sm4",
        "mode": args.mode,
        "plaintext": plaintext,
    }


def handle_hash_text(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "algorithm": "sm3",
        "digest": sm3_digest_bytes(args.text.encode(args.text_encoding)),
        "note": "SM3 is a one-way hash algorithm and does not support decryption",
    }


def handle_hash_file(args: argparse.Namespace) -> Dict[str, Any]:
    input_path = Path(args.input)
    return {
        "algorithm": "sm3",
        "input": str(input_path),
        "digest": sm3_digest_bytes(input_path.read_bytes()),
        "note": "SM3 is a one-way hash algorithm and does not support decryption",
    }


def handle_encrypt_file(args: argparse.Namespace) -> Dict[str, Any]:
    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else default_encrypt_output_path(input_path, args.layout)
    keep_header_bytes = detect_header_bytes(input_path, args.auto_image_header, args.keep_header_bytes)

    if args.algorithm == "sm2-sm4" and args.layout != "bundle":
        raise ValueError("SM2-SM4 file encryption only supports bundle layout")

    if args.algorithm == "sm4":
        if args.layout == "bundle":
            result = encrypt_file_sm4_bundle(
                input_path=input_path,
                output_path=output_path,
                mode_name=args.mode,
                chunk_size=args.chunk_size,
                monitor_interval=args.monitor_interval,
                keep_header_bytes=keep_header_bytes,
                key_hex=args.key_hex,
                iv_hex=args.iv_hex,
            )
        else:
            result = encrypt_file_sm4_raw(
                input_path=input_path,
                output_path=output_path,
                mode_name=args.mode,
                chunk_size=args.chunk_size,
                monitor_interval=args.monitor_interval,
                keep_header_bytes=keep_header_bytes,
                key_hex=args.key_hex,
                iv_hex=args.iv_hex,
            )
    else:
        if not args.public_key_hex:
            raise ValueError("SM2-SM4 file encryption requires --public-key-hex")
        result = encrypt_file_sm2_sm4_bundle(
            input_path=input_path,
            output_path=output_path,
            public_key_hex=args.public_key_hex,
            sm2_mode_name=args.sm2_mode,
            sm4_mode_name=args.mode,
            chunk_size=args.chunk_size,
            monitor_interval=args.monitor_interval,
            keep_header_bytes=keep_header_bytes,
            session_key_hex=args.key_hex,
            iv_hex=args.iv_hex,
        )

    if keep_header_bytes:
        result["header_note"] = (
            "Header bytes were preserved in plaintext. This is useful for image files, "
            "but compressed formats may still need a larger preserved header to remain viewable."
        )
    save_json_if_requested(result, args.metrics_out)
    return result


def handle_decrypt_file(args: argparse.Namespace) -> Dict[str, Any]:
    input_path = Path(args.input)
    layout = args.layout
    if layout == "auto":
        layout = "bundle" if is_bundle_file(input_path) else "raw"
    output_path = Path(args.output) if args.output else default_decrypt_output_path(input_path, layout)

    if layout == "bundle":
        result = decrypt_file_bundle(
            input_path=input_path,
            output_path=output_path,
            chunk_size=args.chunk_size,
            monitor_interval=args.monitor_interval,
            sm4_key_hex=args.key_hex,
            private_key_hex=args.private_key_hex,
        )
    else:
        if not args.key_hex:
            raise ValueError("raw SM4 file decryption requires --key-hex")
        result = decrypt_file_sm4_raw(
            input_path=input_path,
            output_path=output_path,
            key_hex=args.key_hex,
            mode_name=args.mode,
            chunk_size=args.chunk_size,
            monitor_interval=args.monitor_interval,
            keep_header_bytes=args.keep_header_bytes,
            iv_hex=args.iv_hex,
        )

    save_json_if_requested(result, args.metrics_out)
    return result


def handle_benchmark(args: argparse.Namespace) -> Dict[str, Any]:
    result = benchmark_files(
        algorithm=args.algorithm,
        sizes=parse_size_list(args.sizes),
        chunk_size=args.chunk_size,
        sm4_mode_name=args.mode,
        monitor_interval=args.monitor_interval,
        layout=args.layout,
        keep_header_bytes=args.keep_header_bytes,
        auto_image_header=args.auto_image_header,
        sm4_key_hex=args.key_hex,
        iv_hex=args.iv_hex,
        sm2_public_key_hex=args.public_key_hex,
        sm2_private_key_hex=args.private_key_hex,
        sm2_mode_name=args.sm2_mode,
    )
    save_json_if_requested(result, args.metrics_out)
    return result


def handle_self_test(args: argparse.Namespace) -> Dict[str, Any]:
    result = run_self_test()
    save_json_if_requested(result, args.metrics_out)
    return result


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "generate-key":
            result = handle_generate_key(args)
        elif args.command == "encrypt-text":
            result = handle_encrypt_text(args)
        elif args.command == "decrypt-text":
            result = handle_decrypt_text(args)
        elif args.command == "hash-text":
            result = handle_hash_text(args)
        elif args.command == "hash-file":
            result = handle_hash_file(args)
        elif args.command == "encrypt-file":
            result = handle_encrypt_file(args)
        elif args.command == "decrypt-file":
            result = handle_decrypt_file(args)
        elif args.command == "benchmark":
            result = handle_benchmark(args)
        elif args.command == "self-test":
            result = handle_self_test(args)
        else:
            raise ValueError("unknown command")
    except Exception as exc:
        print_json({"ok": False, "error": str(exc)})
        return 1

    if isinstance(result, dict):
        result.setdefault("ok", True)
    print_json(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
