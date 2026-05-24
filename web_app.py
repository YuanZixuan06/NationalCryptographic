from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

from flask import Flask, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.utils import secure_filename

from crypto_app import (
    InputValidationError,
    benchmark_files,
    default_decrypt_output_path,
    default_encrypt_output_path,
    decrypt_file_bundle,
    decrypt_file_sm4_raw,
    detect_header_bytes,
    encrypt_file_sm2_sm4_bundle,
    encrypt_file_sm4_bundle,
    encrypt_file_sm4_raw,
    generate_sm2_keypair,
    generate_sm4_material,
    parse_monitor_interval,
    parse_size,
    parse_size_list,
    save_benchmark_charts,
    sm2_decrypt_text,
    sm2_encrypt_text,
    sm3_digest_bytes,
    sm4_decrypt_text,
    sm4_encrypt_text,
    summarize_benchmark_payload,
)


BASE_DIR = Path(__file__).resolve().parent
RUNTIME_DIR = BASE_DIR / "/tmp/web_runtime"
UPLOAD_DIR = RUNTIME_DIR / "uploads"
OUTPUT_DIR = RUNTIME_DIR / "outputs"
CHART_DIR = RUNTIME_DIR / "charts"

for folder in (UPLOAD_DIR, OUTPUT_DIR, CHART_DIR):
    folder.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "crypto-local-web-secret"
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024

KEY_FIELDS = ("sm2_public_key", "sm2_private_key", "sm4_key", "sm4_iv")
DEFAULT_FORM_STATE: Dict[str, Any] = {
    "text_algorithm": "sm4",
    "text_sm4_mode": "cbc",
    "text_sm2_mode": "c1c3c2",
    "text_encoding": "base64",
    "text_input": "",
    "file_algorithm": "sm4",
    "file_layout": "bundle",
    "file_sm4_mode": "cbc",
    "file_sm2_mode": "c1c3c2",
    "file_chunk_size": "1MB",
    "file_monitor_interval": "0.1",
    "file_keep_header": "0",
    "file_auto_header": False,
    "bench_layout": "bundle",
    "bench_sm4_mode": "cbc",
    "bench_sm2_mode": "c1c3c2",
    "bench_sizes": "64KB,256KB,1MB",
    "bench_chunk_size": "256KB",
    "bench_monitor_interval": "0.1",
    "bench_keep_header": "0",
    "bench_auto_header": False,
    "bench_algorithms": ["sm4"],
    "sm2_public_key": "",
    "sm2_private_key": "",
    "sm4_key": "",
    "sm4_iv": "",
}


def pretty_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def current_form_state(overrides: Dict[str, Any] | None = None) -> Dict[str, Any]:
    state = dict(DEFAULT_FORM_STATE)
    for field in KEY_FIELDS:
        if session.get(field):
            state[field] = session[field]
    if overrides:
        state.update(overrides)
    return state


def persist_key_state(form_state: Dict[str, Any]) -> None:
    for field in KEY_FIELDS:
        value = str(form_state.get(field, "")).strip()
        if value:
            session[field] = value


def extract_form_state() -> Dict[str, Any]:
    state = current_form_state()
    scalar_fields = (
        "text_algorithm",
        "text_sm4_mode",
        "text_sm2_mode",
        "text_encoding",
        "text_input",
        "file_algorithm",
        "file_layout",
        "file_sm4_mode",
        "file_sm2_mode",
        "file_chunk_size",
        "file_monitor_interval",
        "file_keep_header",
        "bench_layout",
        "bench_sm4_mode",
        "bench_sm2_mode",
        "bench_sizes",
        "bench_chunk_size",
        "bench_monitor_interval",
        "bench_keep_header",
        "sm2_public_key",
        "sm2_private_key",
        "sm4_key",
        "sm4_iv",
    )
    for key in scalar_fields:
        value = request.form.get(key, state.get(key, ""))
        state[key] = value.strip() if isinstance(value, str) else value
    state["file_auto_header"] = request.form.get("file_auto_header") == "on"
    state["bench_auto_header"] = request.form.get("bench_auto_header") == "on"
    selected_algorithms = request.form.getlist("bench_algorithms")
    state["bench_algorithms"] = selected_algorithms if selected_algorithms else list(state["bench_algorithms"])
    return state


def render_home(**kwargs: Any) -> str:
    context = {
        "form": current_form_state(kwargs.pop("form_state", None)),
        "text_result": None,
        "file_result": None,
        "benchmark_result": None,
    }
    context.update(kwargs)
    return render_template("index.html", **context)


def make_output_name(original_name: str, layout: str, action: str) -> Path:
    base_path = Path(original_name)
    generated = (
        default_encrypt_output_path(base_path, layout).name
        if action == "encrypt"
        else default_decrypt_output_path(base_path, layout).name
    )
    return OUTPUT_DIR / generated


def save_uploaded_file(field_name: str) -> Tuple[Path, str]:
    file_storage = request.files.get(field_name)
    if not file_storage or not file_storage.filename:
        raise InputValidationError("请上传要处理的文件")

    original_name = Path(file_storage.filename).name
    suffix = Path(original_name).suffix or ".bin"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, prefix="upload_", dir=UPLOAD_DIR) as temp_file:
        file_storage.save(temp_file.name)
        return Path(temp_file.name), original_name


def execute_text_action(form_state: Dict[str, Any], action: str, text_input: str) -> Dict[str, Any]:
    if not text_input.strip():
        raise InputValidationError("请输入文本或密文内容")

    algorithm = form_state["text_algorithm"]
    encoding = form_state["text_encoding"]
    sm2_mode = form_state["text_sm2_mode"]
    sm4_mode = form_state["text_sm4_mode"]

    if action == "encrypt":
        if algorithm == "sm3":
            return {
                "title": "SM3 摘要结果",
                "left_label": "摘要值",
                "left_value": sm3_digest_bytes(text_input.encode("utf-8")),
                "right_label": "说明",
                "right_value": "SM3 是单向摘要算法，只能用于完整性校验，不能解密。",
            }
        if algorithm == "sm2":
            ciphertext = sm2_encrypt_text(
                text=text_input,
                public_key_hex=form_state["sm2_public_key"],
                mode_name=sm2_mode,
                output_encoding=encoding,
            )
            return {
                "title": "SM2 文本加密结果",
                "left_label": "密文",
                "left_value": ciphertext,
                "right_label": "说明",
                "right_value": "SM2 加密带随机数参与计算，因此即使输入完全相同，多次加密得到的密文也会不同。这是正常现象，但解密后明文会一致。",
            }

        payload = sm4_encrypt_text(
            text=text_input,
            key_hex=form_state["sm4_key"],
            mode_name=sm4_mode,
            iv_hex=form_state["sm4_iv"] or None,
            output_encoding=encoding,
        )
        form_state["sm4_key"] = payload["key_hex"] or form_state["sm4_key"]
        form_state["sm4_iv"] = payload["iv_hex"] or form_state["sm4_iv"]
        return {
            "title": "SM4 文本加密结果",
            "left_label": "密文",
            "left_value": payload["ciphertext"],
            "right_label": "参数",
            "right_value": f"SM4 Key: {payload['key_hex']}\nSM4 IV: {payload['iv_hex'] or '无'}\n模式: {payload['mode']}",
        }

    if action == "decrypt":
        if algorithm == "sm3":
            raise InputValidationError("SM3 是单向摘要算法，不能解密")
        if algorithm == "sm2":
            plaintext = sm2_decrypt_text(
                ciphertext=text_input,
                private_key_hex=form_state["sm2_private_key"],
                mode_name=sm2_mode,
                input_encoding=encoding,
            )
        else:
            plaintext = sm4_decrypt_text(
                ciphertext=text_input,
                key_hex=form_state["sm4_key"],
                mode_name=sm4_mode,
                iv_hex=form_state["sm4_iv"] or None,
                input_encoding=encoding,
            )
        return {
            "title": "文本解密结果",
            "left_label": "明文",
            "left_value": plaintext,
            "right_label": "",
            "right_value": "",
        }

    if action == "hash":
        return {
            "title": "SM3 摘要结果",
            "left_label": "摘要值",
            "left_value": sm3_digest_bytes(text_input.encode("utf-8")),
            "right_label": "说明",
            "right_value": "SM3 适用于完整性校验，不支持解密。",
        }

    raise InputValidationError("未知的文本操作")


def execute_file_action(form_state: Dict[str, Any], action: str, input_path: Path, original_name: str) -> Dict[str, Any]:
    algorithm = form_state["file_algorithm"]
    layout = form_state["file_layout"]
    sm4_mode = form_state["file_sm4_mode"]
    sm2_mode = form_state["file_sm2_mode"]
    chunk_size = parse_size(form_state["file_chunk_size"])
    monitor_interval = parse_monitor_interval(form_state["file_monitor_interval"])
    keep_header = parse_size(form_state["file_keep_header"])
    output_path = make_output_name(original_name, layout, action)

    if action == "encrypt":
        actual_header = detect_header_bytes(input_path, bool(form_state["file_auto_header"]), keep_header)
        if algorithm == "sm4":
            if layout == "bundle":
                payload = encrypt_file_sm4_bundle(
                    input_path=input_path,
                    output_path=output_path,
                    mode_name=sm4_mode,
                    chunk_size=chunk_size,
                    monitor_interval=monitor_interval,
                    keep_header_bytes=actual_header,
                    key_hex=form_state["sm4_key"] or None,
                    iv_hex=form_state["sm4_iv"] or None,
                )
            else:
                payload = encrypt_file_sm4_raw(
                    input_path=input_path,
                    output_path=output_path,
                    mode_name=sm4_mode,
                    chunk_size=chunk_size,
                    monitor_interval=monitor_interval,
                    keep_header_bytes=actual_header,
                    key_hex=form_state["sm4_key"] or None,
                    iv_hex=form_state["sm4_iv"] or None,
                )
        else:
            payload = encrypt_file_sm2_sm4_bundle(
                input_path=input_path,
                output_path=output_path,
                public_key_hex=form_state["sm2_public_key"],
                sm2_mode_name=sm2_mode,
                sm4_mode_name=sm4_mode,
                chunk_size=chunk_size,
                monitor_interval=monitor_interval,
                keep_header_bytes=actual_header,
                session_key_hex=form_state["sm4_key"] or None,
                iv_hex=form_state["sm4_iv"] or None,
            )
        return {
            "title": "文件加密完成",
            "download_name": output_path.name,
            "download_url": url_for("download_output", filename=output_path.name),
            "summary": {
                "algorithm": payload["algorithm"],
                "layout": payload["layout"],
                "keep_header_bytes": payload.get("keep_header_bytes", 0),
                "metrics": payload["metrics"],
                "key_hex": payload.get("key_hex"),
                "iv_hex": payload.get("iv_hex"),
                "wrapped_sm4_key": payload.get("wrapped_sm4_key"),
            },
        }

    if action == "decrypt":
        if layout == "raw":
            payload = decrypt_file_sm4_raw(
                input_path=input_path,
                output_path=output_path,
                key_hex=form_state["sm4_key"],
                mode_name=sm4_mode,
                chunk_size=chunk_size,
                monitor_interval=monitor_interval,
                keep_header_bytes=keep_header,
                iv_hex=form_state["sm4_iv"] or None,
            )
        else:
            payload = decrypt_file_bundle(
                input_path=input_path,
                output_path=output_path,
                chunk_size=chunk_size,
                monitor_interval=monitor_interval,
                sm4_key_hex=form_state["sm4_key"] or None,
                private_key_hex=form_state["sm2_private_key"] or None,
            )
        return {
            "title": "文件解密完成",
            "download_name": output_path.name,
            "download_url": url_for("download_output", filename=output_path.name),
            "summary": {
                "algorithm": payload["algorithm"],
                "layout": payload["layout"],
                "keep_header_bytes": payload.get("keep_header_bytes", 0),
                "metrics": payload["metrics"],
            },
        }

    raise InputValidationError("未知的文件操作")


def execute_benchmark_action(form_state: Dict[str, Any]) -> Dict[str, Any]:
    selected_algorithms = list(form_state["bench_algorithms"])
    if not selected_algorithms:
        raise InputValidationError("请至少选择一种算法用于性能测试")

    parsed_sizes = parse_size_list(form_state["bench_sizes"])
    chunk_size = parse_size(form_state["bench_chunk_size"])
    monitor_interval = parse_monitor_interval(form_state["bench_monitor_interval"])
    keep_header = parse_size(form_state["bench_keep_header"])

    payloads: List[Dict[str, Any]] = []
    for algorithm in selected_algorithms:
        payloads.append(
            benchmark_files(
                algorithm=algorithm,
                sizes=parsed_sizes,
                chunk_size=chunk_size,
                sm4_mode_name=form_state["bench_sm4_mode"],
                monitor_interval=monitor_interval,
                layout=form_state["bench_layout"],
                keep_header_bytes=keep_header,
                auto_image_header=bool(form_state["bench_auto_header"]),
                sm4_key_hex=form_state["sm4_key"] or None,
                iv_hex=form_state["sm4_iv"] or None,
                sm2_public_key_hex=form_state["sm2_public_key"] or None,
                sm2_private_key_hex=form_state["sm2_private_key"] or None,
                sm2_mode_name=form_state["bench_sm2_mode"],
            )
        )

    chart_paths = save_benchmark_charts(payloads, CHART_DIR)
    return {
        "source_note": "性能测试使用程序在本地临时生成的随机二进制数据，不依赖上传文件。默认数据量偏小，便于快速预览；你可以手动调大。",
        "summary": [summarize_benchmark_payload(payload) for payload in payloads],
        "cases": [
            {
                "algorithm": payload["algorithm"],
                "rows": [
                    {
                        "size_bytes": item["size_bytes"],
                        "verified": item["verified"],
                        "encrypt_seconds": item["encrypt"]["seconds"],
                        "decrypt_seconds": item["decrypt"]["seconds"],
                        "encrypt_throughput_mb_s": item["encrypt"]["throughput_mb_s"],
                        "decrypt_throughput_mb_s": item["decrypt"]["throughput_mb_s"],
                    }
                    for item in payload["results"]
                ],
            }
            for payload in payloads
        ],
        "charts": {
            "time_chart": url_for("download_chart", filename=Path(chart_paths["time_chart"]).name),
            "throughput_chart": url_for("download_chart", filename=Path(chart_paths["throughput_chart"]).name),
            "time_chart_preview": url_for("view_chart", filename=Path(chart_paths["time_chart"]).name),
            "throughput_chart_preview": url_for("view_chart", filename=Path(chart_paths["throughput_chart"]).name),
        },
    }


def api_error(message: str, status_code: int = 400):
    return jsonify({"ok": False, "error": message}), status_code


def key_state_payload(form_state: Dict[str, Any]) -> Dict[str, str]:
    return {field: str(form_state.get(field, "")).strip() for field in KEY_FIELDS}


@app.route("/", methods=["GET"])
def index() -> str:
    return render_home()


@app.route("/help", methods=["GET"])
def help_page() -> str:
    return render_template("help.html")


@app.route("/api/keys/<string:key_type>", methods=["POST"])
def api_generate_keys(key_type: str):
    try:
        if key_type == "sm2":
            keys = generate_sm2_keypair()
            session["sm2_public_key"] = keys["public_key"]
            session["sm2_private_key"] = keys["private_key"]
            return jsonify({"ok": True, "message": "已生成新的 SM2 公私钥。", "keys": keys})
        if key_type == "sm4":
            payload = request.get_json(silent=True) or {}
            mode_name = str(payload.get("mode", "cbc")).strip() or "cbc"
            material = generate_sm4_material(mode_name)
            session["sm4_key"] = material["key_hex"] or ""
            session["sm4_iv"] = material["iv_hex"] or ""
            return jsonify({"ok": True, "message": "已生成新的 SM4 Key 与 IV。", "keys": material})
        raise InputValidationError("未知的密钥类型")
    except Exception as exc:
        return api_error(str(exc))


@app.route("/api/text", methods=["POST"])
def api_text_tools():
    form_state = extract_form_state()
    try:
        result = execute_text_action(form_state, request.form.get("text_action", ""), request.form.get("text_input", ""))
        persist_key_state(form_state)
        return jsonify({"ok": True, "result": result, "keys": key_state_payload(form_state)})
    except Exception as exc:
        return api_error(str(exc))


@app.route("/api/file", methods=["POST"])
def api_file_tools():
    form_state = extract_form_state()
    try:
        input_path, original_name = save_uploaded_file("file_input")
        result = execute_file_action(form_state, request.form.get("file_action", ""), input_path, original_name)
        persist_key_state(form_state)
        return jsonify({"ok": True, "result": result, "keys": key_state_payload(form_state)})
    except Exception as exc:
        return api_error(str(exc))


@app.route("/api/benchmark", methods=["POST"])
def api_benchmark_tools():
    form_state = extract_form_state()
    try:
        result = execute_benchmark_action(form_state)
        persist_key_state(form_state)
        return jsonify({"ok": True, "result": result, "keys": key_state_payload(form_state)})
    except Exception as exc:
        return api_error(str(exc))


@app.route("/text", methods=["POST"])
def text_tools() -> str:
    form_state = extract_form_state()
    try:
        result = execute_text_action(form_state, request.form.get("text_action", ""), request.form.get("text_input", ""))
        persist_key_state(form_state)
        return render_home(form_state=form_state, text_result=result)
    except Exception:
        return render_home(form_state=form_state)


@app.route("/file", methods=["POST"])
def file_tools() -> str:
    form_state = extract_form_state()
    try:
        input_path, original_name = save_uploaded_file("file_input")
        result = execute_file_action(form_state, request.form.get("file_action", ""), input_path, original_name)
        persist_key_state(form_state)
        return render_home(form_state=form_state, file_result=result)
    except Exception:
        return render_home(form_state=form_state)


@app.route("/benchmark", methods=["POST"])
def benchmark_tools() -> str:
    form_state = extract_form_state()
    try:
        result = execute_benchmark_action(form_state)
        persist_key_state(form_state)
        return render_home(form_state=form_state, benchmark_result=result)
    except Exception:
        return render_home(form_state=form_state)


@app.route("/download/output/<path:filename>", methods=["GET"])
def download_output(filename: str):
    file_path = OUTPUT_DIR / filename
    if not file_path.exists():
        return redirect(url_for("index"))
    return send_file(file_path, as_attachment=True, download_name=file_path.name)


@app.route("/download/chart/<path:filename>", methods=["GET"])
def download_chart(filename: str):
    file_path = CHART_DIR / filename
    if not file_path.exists():
        return redirect(url_for("index"))
    return send_file(file_path, as_attachment=True, download_name=file_path.name)


@app.route("/view/chart/<path:filename>", methods=["GET"])
def view_chart(filename: str):
    file_path = CHART_DIR / filename
    if not file_path.exists():
        return redirect(url_for("index"))
    return send_file(file_path, as_attachment=False, mimetype="image/png")


def main() -> None:
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
