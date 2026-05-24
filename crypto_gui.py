from __future__ import annotations

import json
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Any, Callable, Dict, List, Optional

from crypto_app import (
    BundleFormatError,
    CryptoAppError,
    CryptoOperationError,
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
    is_bundle_file,
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


class ReadOnlyText(ScrolledText):
    def __init__(self, master: tk.Widget, **kwargs: Any) -> None:
        super().__init__(master, **kwargs)
        self.configure(state="disabled")
        self.bind("<Key>", lambda event: "break")
        self.bind("<<Paste>>", lambda event: "break")
        self.bind("<Button-3>", self._show_context_menu)
        self._menu = tk.Menu(self, tearoff=0)
        self._menu.add_command(label="Copy", command=self._copy_selection)
        self._menu.add_command(label="Select All", command=self._select_all)

    def set_text(self, text: str) -> None:
        self.configure(state="normal")
        self.delete("1.0", "end")
        self.insert("1.0", text)
        self.configure(state="disabled")

    def clear(self) -> None:
        self.set_text("")

    def _copy_selection(self) -> None:
        try:
            selected = self.get("sel.first", "sel.last")
        except tk.TclError:
            return
        self.clipboard_clear()
        self.clipboard_append(selected)

    def _select_all(self) -> None:
        self.tag_add("sel", "1.0", "end-1c")
        self.mark_set("insert", "1.0")
        self.see("insert")

    def _show_context_menu(self, event: tk.Event) -> str:
        self._menu.tk_popup(event.x_root, event.y_root)
        return "break"


class CryptoGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("GMSSL Crypto Tool")
        self.root.geometry("1280x900")
        self.root.minsize(1120, 780)

        self.status_var = tk.StringVar(value="Ready")
        self.busy_var = tk.BooleanVar(value=False)

        self.sm2_public_var = tk.StringVar()
        self.sm2_private_var = tk.StringVar()
        self.sm4_key_var = tk.StringVar()
        self.sm4_iv_var = tk.StringVar()

        self.text_algorithm_var = tk.StringVar(value="sm4")
        self.text_sm2_mode_var = tk.StringVar(value="c1c3c2")
        self.text_sm4_mode_var = tk.StringVar(value="cbc")
        self.text_cipher_encoding_var = tk.StringVar(value="base64")

        self.file_algorithm_var = tk.StringVar(value="sm4")
        self.file_layout_var = tk.StringVar(value="bundle")
        self.file_sm2_mode_var = tk.StringVar(value="c1c3c2")
        self.file_sm4_mode_var = tk.StringVar(value="cbc")
        self.file_chunk_size_var = tk.StringVar(value="1MB")
        self.file_monitor_interval_var = tk.StringVar(value="0.1")
        self.file_keep_header_var = tk.StringVar(value="0")
        self.file_auto_image_header_var = tk.BooleanVar(value=False)
        self.file_input_var = tk.StringVar()
        self.file_output_var = tk.StringVar()

        self.bench_algorithms_var = {
            "sm4": tk.BooleanVar(value=True),
            "sm2-sm4": tk.BooleanVar(value=True),
        }
        self.bench_layout_var = tk.StringVar(value="bundle")
        self.bench_sm2_mode_var = tk.StringVar(value="c1c3c2")
        self.bench_sm4_mode_var = tk.StringVar(value="cbc")
        self.bench_sizes_var = tk.StringVar(value="64KB,1MB,5MB")
        self.bench_chunk_size_var = tk.StringVar(value="1MB")
        self.bench_monitor_interval_var = tk.StringVar(value="0.2")
        self.bench_keep_header_var = tk.StringVar(value="0")
        self.bench_auto_image_header_var = tk.BooleanVar(value=False)
        self.bench_chart_dir_var = tk.StringVar(value=str(Path.cwd() / "charts"))
        self.latest_benchmark_payloads: List[Dict[str, Any]] = []

        self.action_buttons: List[ttk.Button] = []

        self._configure_style()
        self._build_layout()

    def _configure_style(self) -> None:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Title.TLabel", font=("Segoe UI", 12, "bold"))
        style.configure("Section.TLabelframe", padding=10)
        style.configure("Section.TLabelframe.Label", font=("Segoe UI", 10, "bold"))
        style.configure("Action.TButton", padding=(12, 6))

    def _build_layout(self) -> None:
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill="both", expand=True)

        ttk.Label(main, text="GMSSL Crypto Desktop App", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            main,
            text="Long-running encryption and benchmark tasks are CPU-bound in pure Python. The window now stays responsive, but benchmark runs will still heavily use the CPU.",
            foreground="#4b5563",
        ).pack(anchor="w", pady=(4, 0))

        self._build_key_frame(main)

        notebook = ttk.Notebook(main)
        notebook.pack(fill="both", expand=True, pady=(12, 0))

        text_tab = ttk.Frame(notebook, padding=10)
        file_tab = ttk.Frame(notebook, padding=10)
        bench_tab = ttk.Frame(notebook, padding=10)
        notebook.add(text_tab, text="Text")
        notebook.add(file_tab, text="File")
        notebook.add(bench_tab, text="Benchmark")

        self._build_text_tab(text_tab)
        self._build_file_tab(file_tab)
        self._build_benchmark_tab(bench_tab)

        status_bar = ttk.Label(main, textvariable=self.status_var, relief="groove", anchor="w")
        status_bar.pack(fill="x", pady=(10, 0))

    def _add_action_button(self, parent: ttk.Frame, text: str, command: Callable[[], None]) -> ttk.Button:
        button = ttk.Button(parent, text=text, style="Action.TButton", command=command)
        self.action_buttons.append(button)
        return button

    def _build_key_frame(self, parent: ttk.Frame) -> None:
        frame = ttk.LabelFrame(parent, text="Shared Keys", style="Section.TLabelframe")
        frame.pack(fill="x", pady=(12, 0))
        frame.columnconfigure(1, weight=1)
        frame.columnconfigure(3, weight=1)

        ttk.Label(frame, text="SM2 Public Key").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(frame, textvariable=self.sm2_public_var).grid(row=0, column=1, columnspan=3, sticky="ew", pady=6)

        ttk.Label(frame, text="SM2 Private Key").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(frame, textvariable=self.sm2_private_var).grid(row=1, column=1, sticky="ew", pady=6)
        self._add_action_button(frame, "Generate SM2", self.generate_sm2_keys).grid(
            row=1, column=2, padx=8, pady=6, sticky="w"
        )

        ttk.Label(frame, text="SM4 Key").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(frame, textvariable=self.sm4_key_var).grid(row=2, column=1, sticky="ew", pady=6)
        ttk.Label(frame, text="SM4 IV").grid(row=2, column=2, sticky="w", padx=(12, 8), pady=6)
        ttk.Entry(frame, textvariable=self.sm4_iv_var).grid(row=2, column=3, sticky="ew", pady=6)
        self._add_action_button(frame, "Generate SM4", self.generate_sm4_materials).grid(
            row=2, column=4, padx=(12, 0), pady=6, sticky="w"
        )

    def _build_text_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(2, weight=1)
        parent.rowconfigure(4, weight=1)

        options = ttk.LabelFrame(parent, text="Options", style="Section.TLabelframe")
        options.grid(row=0, column=0, columnspan=2, sticky="ew")

        ttk.Label(options, text="Algorithm").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Combobox(
            options,
            textvariable=self.text_algorithm_var,
            values=("sm4", "sm2", "sm3"),
            state="readonly",
            width=12,
        ).grid(row=0, column=1, sticky="w", pady=6)

        ttk.Label(options, text="SM4 Mode").grid(row=0, column=2, sticky="w", padx=(18, 8), pady=6)
        ttk.Combobox(
            options,
            textvariable=self.text_sm4_mode_var,
            values=("cbc", "ecb"),
            state="readonly",
            width=10,
        ).grid(row=0, column=3, sticky="w", pady=6)

        ttk.Label(options, text="SM2 Mode").grid(row=0, column=4, sticky="w", padx=(18, 8), pady=6)
        ttk.Combobox(
            options,
            textvariable=self.text_sm2_mode_var,
            values=("c1c3c2", "c1c2c3"),
            state="readonly",
            width=10,
        ).grid(row=0, column=5, sticky="w", pady=6)

        ttk.Label(options, text="Cipher Encoding").grid(row=0, column=6, sticky="w", padx=(18, 8), pady=6)
        ttk.Combobox(
            options,
            textvariable=self.text_cipher_encoding_var,
            values=("base64", "hex"),
            state="readonly",
            width=10,
        ).grid(row=0, column=7, sticky="w", pady=6)

        ttk.Label(parent, text="Input Text / Ciphertext").grid(row=1, column=0, columnspan=2, sticky="w", pady=(10, 4))
        self.text_input = ScrolledText(parent, wrap="word", height=10)
        self.text_input.grid(row=2, column=0, columnspan=2, sticky="nsew")

        button_bar = ttk.Frame(parent)
        button_bar.grid(row=3, column=0, columnspan=2, sticky="ew", pady=10)
        self._add_action_button(button_bar, "Encrypt", self.run_text_encrypt).pack(side="left", padx=(0, 8))
        self._add_action_button(button_bar, "Decrypt", self.run_text_decrypt).pack(side="left", padx=(0, 8))
        self._add_action_button(button_bar, "Hash", self.run_text_hash).pack(side="left", padx=(0, 8))
        ttk.Button(button_bar, text="Clear", command=self.clear_text_tab).pack(side="left")

        output_frame = ttk.Frame(parent)
        output_frame.grid(row=4, column=0, columnspan=2, sticky="nsew")
        output_frame.columnconfigure(0, weight=1)
        output_frame.columnconfigure(1, weight=1)
        output_frame.rowconfigure(1, weight=1)

        ttk.Label(output_frame, text="Ciphertext / Digest").grid(row=0, column=0, sticky="w")
        ttk.Label(output_frame, text="Plaintext / Notes").grid(row=0, column=1, sticky="w")
        self.text_cipher_output = ReadOnlyText(output_frame, wrap="word", height=12)
        self.text_cipher_output.grid(row=1, column=0, sticky="nsew", padx=(0, 6))
        self.text_plain_output = ReadOnlyText(output_frame, wrap="word", height=12)
        self.text_plain_output.grid(row=1, column=1, sticky="nsew", padx=(6, 0))

    def _build_file_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(4, weight=1)

        ttk.Label(parent, text="Input File").grid(row=0, column=0, sticky="w", pady=6)
        ttk.Entry(parent, textvariable=self.file_input_var).grid(row=0, column=1, sticky="ew", pady=6)
        ttk.Button(parent, text="Browse", command=self.browse_file_input).grid(row=0, column=2, padx=(8, 0), pady=6)

        ttk.Label(parent, text="Output File").grid(row=1, column=0, sticky="w", pady=6)
        ttk.Entry(parent, textvariable=self.file_output_var).grid(row=1, column=1, sticky="ew", pady=6)
        ttk.Button(parent, text="Browse", command=self.browse_file_output).grid(row=1, column=2, padx=(8, 0), pady=6)

        options = ttk.LabelFrame(parent, text="Options", style="Section.TLabelframe")
        options.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(10, 0))

        ttk.Label(options, text="Algorithm").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Combobox(
            options,
            textvariable=self.file_algorithm_var,
            values=("sm4", "sm2-sm4"),
            state="readonly",
            width=10,
        ).grid(row=0, column=1, sticky="w", pady=6)

        ttk.Label(options, text="Layout").grid(row=0, column=2, sticky="w", padx=(18, 8), pady=6)
        ttk.Combobox(
            options,
            textvariable=self.file_layout_var,
            values=("bundle", "raw", "auto"),
            state="readonly",
            width=10,
        ).grid(row=0, column=3, sticky="w", pady=6)

        ttk.Label(options, text="SM4 Mode").grid(row=0, column=4, sticky="w", padx=(18, 8), pady=6)
        ttk.Combobox(
            options,
            textvariable=self.file_sm4_mode_var,
            values=("cbc", "ecb"),
            state="readonly",
            width=10,
        ).grid(row=0, column=5, sticky="w", pady=6)

        ttk.Label(options, text="SM2 Mode").grid(row=0, column=6, sticky="w", padx=(18, 8), pady=6)
        ttk.Combobox(
            options,
            textvariable=self.file_sm2_mode_var,
            values=("c1c3c2", "c1c2c3"),
            state="readonly",
            width=10,
        ).grid(row=0, column=7, sticky="w", pady=6)

        ttk.Label(options, text="Chunk Size").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(options, textvariable=self.file_chunk_size_var, width=14).grid(row=1, column=1, sticky="w", pady=6)

        ttk.Label(options, text="Monitor Interval").grid(row=1, column=2, sticky="w", padx=(18, 8), pady=6)
        ttk.Entry(options, textvariable=self.file_monitor_interval_var, width=14).grid(row=1, column=3, sticky="w", pady=6)

        ttk.Label(options, text="Keep Header").grid(row=1, column=4, sticky="w", padx=(18, 8), pady=6)
        ttk.Entry(options, textvariable=self.file_keep_header_var, width=14).grid(row=1, column=5, sticky="w", pady=6)

        ttk.Checkbutton(options, text="Auto Image Header", variable=self.file_auto_image_header_var).grid(
            row=1, column=6, columnspan=2, sticky="w", padx=(18, 0), pady=6
        )

        button_bar = ttk.Frame(parent)
        button_bar.grid(row=3, column=0, columnspan=3, sticky="ew", pady=10)
        self._add_action_button(button_bar, "Encrypt File", self.run_file_encrypt).pack(side="left", padx=(0, 8))
        self._add_action_button(button_bar, "Decrypt File", self.run_file_decrypt).pack(side="left", padx=(0, 8))
        self._add_action_button(button_bar, "Hash File", self.run_file_hash).pack(side="left", padx=(0, 8))
        ttk.Button(button_bar, text="Clear", command=lambda: self.file_output.clear()).pack(side="left")

        self.file_output = ReadOnlyText(parent, wrap="word")
        self.file_output.grid(row=4, column=0, columnspan=3, sticky="nsew")

    def _build_benchmark_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(2, weight=1)

        options = ttk.LabelFrame(parent, text="Benchmark Options", style="Section.TLabelframe")
        options.grid(row=0, column=0, sticky="ew")

        ttk.Label(options, text="Algorithms").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Checkbutton(options, text="SM4", variable=self.bench_algorithms_var["sm4"]).grid(row=0, column=1, sticky="w", pady=6)
        ttk.Checkbutton(options, text="SM2-SM4", variable=self.bench_algorithms_var["sm2-sm4"]).grid(
            row=0, column=2, sticky="w", pady=6
        )

        ttk.Label(options, text="Layout").grid(row=0, column=3, sticky="w", padx=(18, 8), pady=6)
        ttk.Combobox(
            options,
            textvariable=self.bench_layout_var,
            values=("bundle", "raw"),
            state="readonly",
            width=10,
        ).grid(row=0, column=4, sticky="w", pady=6)

        ttk.Label(options, text="SM4 Mode").grid(row=0, column=5, sticky="w", padx=(18, 8), pady=6)
        ttk.Combobox(
            options,
            textvariable=self.bench_sm4_mode_var,
            values=("cbc", "ecb"),
            state="readonly",
            width=10,
        ).grid(row=0, column=6, sticky="w", pady=6)

        ttk.Label(options, text="SM2 Mode").grid(row=0, column=7, sticky="w", padx=(18, 8), pady=6)
        ttk.Combobox(
            options,
            textvariable=self.bench_sm2_mode_var,
            values=("c1c3c2", "c1c2c3"),
            state="readonly",
            width=10,
        ).grid(row=0, column=8, sticky="w", pady=6)

        ttk.Label(options, text="Sizes").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=6)
        ttk.Entry(options, textvariable=self.bench_sizes_var, width=30).grid(row=1, column=1, columnspan=2, sticky="w", pady=6)

        ttk.Label(options, text="Chunk Size").grid(row=1, column=3, sticky="w", padx=(18, 8), pady=6)
        ttk.Entry(options, textvariable=self.bench_chunk_size_var, width=14).grid(row=1, column=4, sticky="w", pady=6)

        ttk.Label(options, text="Monitor Interval").grid(row=1, column=5, sticky="w", padx=(18, 8), pady=6)
        ttk.Entry(options, textvariable=self.bench_monitor_interval_var, width=14).grid(row=1, column=6, sticky="w", pady=6)

        ttk.Label(options, text="Keep Header").grid(row=1, column=7, sticky="w", padx=(18, 8), pady=6)
        ttk.Entry(options, textvariable=self.bench_keep_header_var, width=14).grid(row=1, column=8, sticky="w", pady=6)

        ttk.Checkbutton(options, text="Auto Image Header", variable=self.bench_auto_image_header_var).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=6
        )
        ttk.Label(options, text="Chart Directory").grid(row=2, column=3, sticky="w", padx=(18, 8), pady=6)
        ttk.Entry(options, textvariable=self.bench_chart_dir_var, width=30).grid(row=2, column=4, columnspan=3, sticky="ew", pady=6)
        ttk.Button(options, text="Browse", command=self.browse_chart_dir).grid(row=2, column=7, sticky="w", pady=6)

        button_bar = ttk.Frame(parent)
        button_bar.grid(row=1, column=0, sticky="w", pady=10)
        self._add_action_button(button_bar, "Run Benchmark", self.run_benchmark).pack(side="left", padx=(0, 8))
        self._add_action_button(button_bar, "Generate Charts", self.generate_benchmark_charts).pack(side="left", padx=(0, 8))
        ttk.Button(button_bar, text="Clear", command=lambda: self.bench_output.clear()).pack(side="left")

        self.bench_output = ReadOnlyText(parent, wrap="word")
        self.bench_output.grid(row=2, column=0, sticky="nsew")

    def set_status(self, message: str) -> None:
        self.status_var.set(message)

    def set_busy(self, value: bool, message: str = "") -> None:
        self.busy_var.set(value)
        for button in self.action_buttons:
            button.state(["disabled"] if value else ["!disabled"])
        if message:
            self.set_status(message)

    def show_json(self, widget: ReadOnlyText, payload: object) -> None:
        widget.set_text(json.dumps(payload, ensure_ascii=False, indent=2))

    def run_background(
        self,
        description: str,
        callback: Callable[[], object],
        success_handler: Callable[[object], None],
        error_widget: Optional[ReadOnlyText] = None,
    ) -> None:
        self.set_busy(True, f"{description}...")

        def worker() -> None:
            try:
                result = callback()
            except Exception as exc:
                self.root.after(0, lambda: self._handle_error(description, exc, error_widget))
                return
            self.root.after(0, lambda: self._handle_success(description, result, success_handler))

        threading.Thread(target=worker, daemon=True).start()

    def _handle_success(self, description: str, result: object, success_handler: Callable[[object], None]) -> None:
        try:
            success_handler(result)
            self.set_status(f"{description} finished")
        finally:
            self.set_busy(False)

    def _handle_error(self, description: str, exc: Exception, error_widget: Optional[ReadOnlyText]) -> None:
        payload = {
            "ok": False,
            "error_type": exc.__class__.__name__,
            "error": str(exc),
        }
        if error_widget is not None:
            self.show_json(error_widget, payload)
        self.set_busy(False, f"{description} failed")
        title = "Input Error" if isinstance(exc, InputValidationError) else "Operation Error"
        messagebox.showerror(title, f"{description} failed:\n{exc}")

    def generate_sm2_keys(self) -> None:
        try:
            keys = generate_sm2_keypair()
        except CryptoAppError as exc:
            messagebox.showerror("Key Generation Error", str(exc))
            return
        self.sm2_public_var.set(keys["public_key"])
        self.sm2_private_var.set(keys["private_key"])
        self.set_status("Generated new SM2 keypair")

    def generate_sm4_materials(self) -> None:
        try:
            mode_name = self.text_sm4_mode_var.get() or "cbc"
            material = generate_sm4_material(mode_name)
        except CryptoAppError as exc:
            messagebox.showerror("Key Generation Error", str(exc))
            return
        self.sm4_key_var.set(material["key_hex"] or "")
        self.sm4_iv_var.set(material["iv_hex"] or "")
        self.set_status("Generated new SM4 key material")

    def clear_text_tab(self) -> None:
        self.text_input.delete("1.0", "end")
        self.text_cipher_output.clear()
        self.text_plain_output.clear()
        self.set_status("Cleared text inputs")

    def browse_file_input(self) -> None:
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_input_var.set(file_path)

    def browse_file_output(self) -> None:
        file_path = filedialog.asksaveasfilename()
        if file_path:
            self.file_output_var.set(file_path)

    def browse_chart_dir(self) -> None:
        directory = filedialog.askdirectory()
        if directory:
            self.bench_chart_dir_var.set(directory)

    def _get_non_empty_text(self) -> str:
        text = self.text_input.get("1.0", "end-1c")
        if not text.strip():
            raise InputValidationError("text input cannot be empty")
        return text

    def run_text_encrypt(self) -> None:
        def callback():
            text = self._get_non_empty_text()
            algorithm = self.text_algorithm_var.get()
            if algorithm == "sm3":
                return {
                    "cipher_or_digest": sm3_digest_bytes(text.encode("utf-8")),
                    "plain_or_note": "SM3 is a one-way hash algorithm. It produces a digest and does not support decryption.",
                }
            if algorithm == "sm2":
                ciphertext = sm2_encrypt_text(
                    text=text,
                    public_key_hex=self.sm2_public_var.get(),
                    mode_name=self.text_sm2_mode_var.get(),
                    output_encoding=self.text_cipher_encoding_var.get(),
                )
                return {
                    "cipher_or_digest": ciphertext,
                    "plain_or_note": "SM2 encryption completed.",
                }
            result = sm4_encrypt_text(
                text=text,
                key_hex=self.sm4_key_var.get(),
                mode_name=self.text_sm4_mode_var.get(),
                iv_hex=self.sm4_iv_var.get() or None,
                output_encoding=self.text_cipher_encoding_var.get(),
            )
            return result

        def on_success(result: object) -> None:
            payload = result if isinstance(result, dict) else {}
            if "key_hex" in payload and payload["key_hex"]:
                self.sm4_key_var.set(payload["key_hex"])
            if "iv_hex" in payload and payload["iv_hex"]:
                self.sm4_iv_var.set(payload["iv_hex"])
            self.text_cipher_output.set_text(str(payload.get("cipher_or_digest") or payload.get("ciphertext") or ""))
            note_lines = []
            if payload.get("plain_or_note"):
                note_lines.append(str(payload["plain_or_note"]))
            if payload.get("key_hex"):
                note_lines.append(f"SM4 Key: {payload['key_hex']}")
            if payload.get("iv_hex"):
                note_lines.append(f"SM4 IV: {payload['iv_hex']}")
            if payload.get("mode"):
                note_lines.append(f"Mode: {payload['mode']}")
            self.text_plain_output.set_text("\n".join(note_lines))

        self.run_background("Text encryption", callback, on_success, self.text_plain_output)

    def run_text_decrypt(self) -> None:
        def callback():
            ciphertext = self._get_non_empty_text()
            algorithm = self.text_algorithm_var.get()
            if algorithm == "sm3":
                raise InputValidationError("SM3 is a one-way hash algorithm and cannot decrypt")
            if algorithm == "sm2":
                plaintext = sm2_decrypt_text(
                    ciphertext=ciphertext,
                    private_key_hex=self.sm2_private_var.get(),
                    mode_name=self.text_sm2_mode_var.get(),
                    input_encoding=self.text_cipher_encoding_var.get(),
                )
                return {"plaintext": plaintext}
            plaintext = sm4_decrypt_text(
                ciphertext=ciphertext,
                key_hex=self.sm4_key_var.get(),
                mode_name=self.text_sm4_mode_var.get(),
                iv_hex=self.sm4_iv_var.get() or None,
                input_encoding=self.text_cipher_encoding_var.get(),
            )
            return {"plaintext": plaintext}

        def on_success(result: object) -> None:
            payload = result if isinstance(result, dict) else {}
            self.text_cipher_output.set_text(self.text_input.get("1.0", "end-1c"))
            self.text_plain_output.set_text(str(payload.get("plaintext") or ""))

        self.run_background("Text decryption", callback, on_success, self.text_plain_output)

    def run_text_hash(self) -> None:
        def callback():
            text = self._get_non_empty_text()
            return {
                "digest": sm3_digest_bytes(text.encode("utf-8")),
                "note": "SM3 digest generated. This algorithm does not support decryption.",
            }

        def on_success(result: object) -> None:
            payload = result if isinstance(result, dict) else {}
            self.text_cipher_output.set_text(str(payload.get("digest") or ""))
            self.text_plain_output.set_text(str(payload.get("note") or ""))

        self.run_background("Text hash", callback, on_success, self.text_plain_output)

    def _parse_file_common(self) -> Dict[str, Any]:
        input_path = Path(self.file_input_var.get().strip())
        if not self.file_input_var.get().strip():
            raise InputValidationError("please select an input file")
        chunk_size = parse_size(self.file_chunk_size_var.get())
        monitor_interval = parse_monitor_interval(self.file_monitor_interval_var.get())
        keep_header_bytes = parse_size(self.file_keep_header_var.get())
        return {
            "input_path": input_path,
            "chunk_size": chunk_size,
            "monitor_interval": monitor_interval,
            "keep_header_bytes": keep_header_bytes,
        }

    def run_file_encrypt(self) -> None:
        def callback():
            common = self._parse_file_common()
            input_path: Path = common["input_path"]
            algorithm = self.file_algorithm_var.get()
            layout = self.file_layout_var.get()
            if layout == "auto":
                layout = "bundle"
            if algorithm == "sm2-sm4" and layout != "bundle":
                raise InputValidationError("SM2-SM4 file encryption only supports bundle layout")

            output_path = Path(self.file_output_var.get().strip()) if self.file_output_var.get().strip() else default_encrypt_output_path(input_path, layout)
            actual_header_bytes = detect_header_bytes(
                input_path,
                self.file_auto_image_header_var.get(),
                common["keep_header_bytes"],
            )

            if algorithm == "sm4":
                if layout == "bundle":
                    return encrypt_file_sm4_bundle(
                        input_path=input_path,
                        output_path=output_path,
                        mode_name=self.file_sm4_mode_var.get(),
                        chunk_size=common["chunk_size"],
                        monitor_interval=common["monitor_interval"],
                        keep_header_bytes=actual_header_bytes,
                        key_hex=self.sm4_key_var.get() or None,
                        iv_hex=self.sm4_iv_var.get() or None,
                    )
                return encrypt_file_sm4_raw(
                    input_path=input_path,
                    output_path=output_path,
                    mode_name=self.file_sm4_mode_var.get(),
                    chunk_size=common["chunk_size"],
                    monitor_interval=common["monitor_interval"],
                    keep_header_bytes=actual_header_bytes,
                    key_hex=self.sm4_key_var.get() or None,
                    iv_hex=self.sm4_iv_var.get() or None,
                )

            return encrypt_file_sm2_sm4_bundle(
                input_path=input_path,
                output_path=output_path,
                public_key_hex=self.sm2_public_var.get(),
                sm2_mode_name=self.file_sm2_mode_var.get(),
                sm4_mode_name=self.file_sm4_mode_var.get(),
                chunk_size=common["chunk_size"],
                monitor_interval=common["monitor_interval"],
                keep_header_bytes=actual_header_bytes,
                session_key_hex=self.sm4_key_var.get() or None,
                iv_hex=self.sm4_iv_var.get() or None,
            )

        self.run_background("File encryption", callback, lambda result: self.show_json(self.file_output, result), self.file_output)

    def run_file_decrypt(self) -> None:
        def callback():
            common = self._parse_file_common()
            input_path: Path = common["input_path"]
            layout = self.file_layout_var.get()
            if layout == "auto":
                layout = "bundle" if is_bundle_file(input_path) else "raw"
            output_path = Path(self.file_output_var.get().strip()) if self.file_output_var.get().strip() else default_decrypt_output_path(input_path, layout)

            if layout == "bundle":
                return decrypt_file_bundle(
                    input_path=input_path,
                    output_path=output_path,
                    chunk_size=common["chunk_size"],
                    monitor_interval=common["monitor_interval"],
                    sm4_key_hex=self.sm4_key_var.get() or None,
                    private_key_hex=self.sm2_private_var.get() or None,
                )

            return decrypt_file_sm4_raw(
                input_path=input_path,
                output_path=output_path,
                key_hex=self.sm4_key_var.get(),
                mode_name=self.file_sm4_mode_var.get(),
                chunk_size=common["chunk_size"],
                monitor_interval=common["monitor_interval"],
                keep_header_bytes=common["keep_header_bytes"],
                iv_hex=self.sm4_iv_var.get() or None,
            )

        self.run_background("File decryption", callback, lambda result: self.show_json(self.file_output, result), self.file_output)

    def run_file_hash(self) -> None:
        def callback():
            input_path_text = self.file_input_var.get().strip()
            if not input_path_text:
                raise InputValidationError("please select an input file")
            input_path = Path(input_path_text)
            return {
                "algorithm": "sm3",
                "input": str(input_path),
                "digest": sm3_digest_bytes(input_path.read_bytes()),
                "note": "SM3 is a one-way hash algorithm and does not support decryption",
            }

        self.run_background("File hash", callback, lambda result: self.show_json(self.file_output, result), self.file_output)

    def _selected_benchmark_algorithms(self) -> List[str]:
        algorithms = [name for name, flag in self.bench_algorithms_var.items() if flag.get()]
        if not algorithms:
            raise InputValidationError("select at least one benchmark algorithm")
        return algorithms

    def run_benchmark(self) -> None:
        def callback():
            algorithms = self._selected_benchmark_algorithms()
            sizes = parse_size_list(self.bench_sizes_var.get())
            chunk_size = parse_size(self.bench_chunk_size_var.get())
            monitor_interval = parse_monitor_interval(self.bench_monitor_interval_var.get())
            keep_header = parse_size(self.bench_keep_header_var.get())

            payloads = []
            for algorithm in algorithms:
                payloads.append(
                    benchmark_files(
                        algorithm=algorithm,
                        sizes=sizes,
                        chunk_size=chunk_size,
                        sm4_mode_name=self.bench_sm4_mode_var.get(),
                        monitor_interval=monitor_interval,
                        layout=self.bench_layout_var.get(),
                        keep_header_bytes=keep_header,
                        auto_image_header=self.bench_auto_image_header_var.get(),
                        sm4_key_hex=self.sm4_key_var.get() or None,
                        iv_hex=self.sm4_iv_var.get() or None,
                        sm2_public_key_hex=self.sm2_public_var.get() or None,
                        sm2_private_key_hex=self.sm2_private_var.get() or None,
                        sm2_mode_name=self.bench_sm2_mode_var.get(),
                    )
                )
            return payloads

        def on_success(result: object) -> None:
            payloads = result if isinstance(result, list) else []
            self.latest_benchmark_payloads = payloads
            summary = {
                "summaries": [summarize_benchmark_payload(payload) for payload in payloads],
                "details": payloads,
            }
            self.show_json(self.bench_output, summary)

        self.run_background("Benchmark", callback, on_success, self.bench_output)

    def generate_benchmark_charts(self) -> None:
        def callback():
            if not self.latest_benchmark_payloads:
                raise InputValidationError("run a benchmark before generating charts")
            chart_dir = Path(self.bench_chart_dir_var.get().strip() or "charts")
            return save_benchmark_charts(self.latest_benchmark_payloads, chart_dir)

        def on_success(result: object) -> None:
            payload = result if isinstance(result, dict) else {}
            message = {
                "ok": True,
                "message": "Benchmark charts generated successfully.",
                "files": payload,
            }
            self.show_json(self.bench_output, message)
            messagebox.showinfo(
                "Charts Generated",
                "Charts generated:\n"
                f"- {payload.get('time_chart', '')}\n"
                f"- {payload.get('throughput_chart', '')}",
            )

        self.run_background("Chart generation", callback, on_success, self.bench_output)


def main() -> None:
    root = tk.Tk()
    CryptoGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
