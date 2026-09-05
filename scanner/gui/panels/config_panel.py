"""
scanner.gui.panels.config_panel
==================================

The "Configuration" tab. Owns all the widgets for:

* Picking a backend (Ollama / OpenAI-compatible / Demo) and testing
  connectivity to it.
* Defining the **target system prompt** -- the system prompt the
  scanner tells the model to follow before attacking it. This is what
  makes the "System Prompt Extraction" category meaningful: without a
  real system prompt configured, there's nothing to extract. See the
  module docstring in ``core/models.py`` (``DEFAULT_TEST_SYSTEM_PROMPT``)
  for why the shipped example is designed the way it is.
* Canary tokens -- the exact strings the analyzer treats as
  unambiguous proof of leakage.
* Scan-level settings (temperature, timeout, delay, categories).

This panel mutates ``app.config`` in place and calls back into
``app`` for things that affect shared state (setting the active
adapter after a successful connection test).
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import TYPE_CHECKING

from ...adapters import get_adapter
from ...core.config import resolve_api_key
from ...core.models import DEFAULT_CANARY_TOKENS, DEFAULT_TEST_SYSTEM_PROMPT
from ..theme import COLORS, FONTS

if TYPE_CHECKING:
    from ..app import ScannerApp


class ConfigPanel(ttk.Frame):
    def __init__(self, parent: tk.Widget, app: "ScannerApp"):
        super().__init__(parent, padding=20)
        self.app = app
        self._build()
        self._load_from_config()
        self._on_backend_change()

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)

        self._build_backend_section().grid(row=0, column=0, sticky="ew", pady=(0, 14))
        self._build_system_prompt_section().grid(row=1, column=0, sticky="ew", pady=(0, 14))
        self._build_scan_settings_section().grid(row=2, column=0, sticky="ew", pady=(0, 14))
        self._build_persistence_section().grid(row=3, column=0, sticky="ew")

    def _build_backend_section(self) -> ttk.Labelframe:
        box = ttk.Labelframe(self, text="  TARGET BACKEND  ", padding=16)
        box.columnconfigure(1, weight=1)

        ttk.Label(box, text="Backend:").grid(row=0, column=0, sticky="w", pady=4)
        self.backend_var = tk.StringVar(value="ollama")
        backend_row = ttk.Frame(box)
        backend_row.grid(row=0, column=1, sticky="w", pady=4)
        for i, (label, value) in enumerate([
            ("Ollama (local)", "ollama"),
            ("OpenAI-compatible API", "openai"),
            ("Demo (no LLM required)", "mock"),
        ]):
            ttk.Radiobutton(backend_row, text=label, value=value, variable=self.backend_var,
                             command=self._on_backend_change).grid(row=0, column=i, padx=(0, 16))

        ttk.Label(box, text="Host:").grid(row=1, column=0, sticky="w", pady=4)
        self.host_var = tk.StringVar(value="http://localhost:11434")
        self.host_entry = ttk.Entry(box, textvariable=self.host_var, width=42)
        self.host_entry.grid(row=1, column=1, sticky="w", pady=4)

        ttk.Label(box, text="Model:").grid(row=2, column=0, sticky="w", pady=4)
        model_row = ttk.Frame(box)
        model_row.grid(row=2, column=1, sticky="w", pady=4)
        self.model_var = tk.StringVar(value="llama3.2")
        self.model_combo = ttk.Combobox(model_row, textvariable=self.model_var, width=28,
                                         values=["llama3.2", "llama3.1", "mistral", "gemma3", "qwen2.5"])
        self.model_combo.grid(row=0, column=0, padx=(0, 8))
        ttk.Button(model_row, text="Refresh Models", command=self._refresh_models).grid(row=0, column=1)

        self.api_key_label = ttk.Label(box, text="API Key:")
        self.api_key_label.grid(row=3, column=0, sticky="w", pady=4)
        self.api_key_var = tk.StringVar(value="")
        self.api_key_entry = ttk.Entry(box, textvariable=self.api_key_var, width=42, show="*")
        self.api_key_entry.grid(row=3, column=1, sticky="w", pady=4)

        action_row = ttk.Frame(box)
        action_row.grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 0))
        self.test_btn = ttk.Button(action_row, text="Test Connection", style="Accent.TButton",
                                    command=self._test_connection)
        self.test_btn.grid(row=0, column=0, padx=(0, 12))
        self.status_dot = tk.Canvas(action_row, width=12, height=12, bg=COLORS.BG, highlightthickness=0)
        self.status_dot.grid(row=0, column=1, padx=(0, 6))
        self._draw_status_dot(COLORS.TEXT_FAINT)
        self.status_label = ttk.Label(action_row, text="Not connected yet.", style="Dim.TLabel")
        self.status_label.grid(row=0, column=2, sticky="w")

        self.remote_notice = ttk.Label(
            box,
            text="Note: this backend can send requests to a remote host -- data leaves this machine.",
            style="Dim.TLabel", wraplength=560,
        )
        self.remote_notice.grid(row=5, column=0, columnspan=2, sticky="w", pady=(10, 0))

        return box

    def _build_system_prompt_section(self) -> ttk.Labelframe:
        box = ttk.Labelframe(self, text="  TARGET SYSTEM PROMPT  ", padding=16)
        box.columnconfigure(0, weight=1)

        ttk.Label(
            box,
            text="This is the system prompt the target model will follow. Extraction payloads try to "
                 "make the model reveal it; canary tokens below are checked against the model's responses "
                 "as unambiguous proof of a leak.",
            style="Dim.TLabel", wraplength=680, justify="left",
        ).grid(row=0, column=0, sticky="w", pady=(0, 8))

        self.system_prompt_text = tk.Text(
            box, height=6, wrap="word", bg=COLORS.SURFACE_2, fg=COLORS.TEXT,
            insertbackground=COLORS.TEXT, relief="flat", padx=10, pady=8,
            font=(FONTS.FAMILY_FALLBACK, FONTS.SIZE_BODY),
        )
        self.system_prompt_text.grid(row=1, column=0, sticky="ew")

        btn_row = ttk.Frame(box)
        btn_row.grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Button(btn_row, text="Load Example (SecureBank demo)",
                   command=self._load_example_prompt).grid(row=0, column=0, padx=(0, 8))
        ttk.Button(btn_row, text="Clear", command=lambda: self.system_prompt_text.delete("1.0", "end")
                   ).grid(row=0, column=1, padx=(0, 8))
        ttk.Button(btn_row, text="Load from file...", command=self._load_prompt_from_file
                   ).grid(row=0, column=2)

        ttk.Label(box, text="Canary tokens (comma-separated):").grid(row=3, column=0, sticky="w", pady=(12, 4))
        self.canary_var = tk.StringVar(value=", ".join(DEFAULT_CANARY_TOKENS))
        ttk.Entry(box, textvariable=self.canary_var).grid(row=4, column=0, sticky="ew")

        return box

    def _build_scan_settings_section(self) -> ttk.Labelframe:
        box = ttk.Labelframe(self, text="  SCAN SETTINGS  ", padding=16)
        for c in range(4):
            box.columnconfigure(c, weight=1)

        ttk.Label(box, text="Temperature:").grid(row=0, column=0, sticky="w", pady=4)
        self.temperature_var = tk.DoubleVar(value=0.7)
        self.temp_scale = ttk.Scale(box, from_=0.0, to=1.5, variable=self.temperature_var,
                                     orient="horizontal", command=lambda _v: self._update_temp_label())
        self.temp_scale.grid(row=1, column=0, sticky="ew", padx=(0, 10))
        self.temp_value_label = ttk.Label(box, text="0.70", style="Dim.TLabel")
        self.temp_value_label.grid(row=1, column=1, sticky="w")

        ttk.Label(box, text="Max tokens:").grid(row=0, column=2, sticky="w", pady=4)
        self.max_tokens_var = tk.IntVar(value=512)
        ttk.Spinbox(box, from_=32, to=4096, increment=32, textvariable=self.max_tokens_var, width=10
                    ).grid(row=1, column=2, sticky="w")

        ttk.Label(box, text="Timeout (s):").grid(row=2, column=0, sticky="w", pady=(10, 4))
        self.timeout_var = tk.IntVar(value=60)
        ttk.Spinbox(box, from_=5, to=300, increment=5, textvariable=self.timeout_var, width=10
                    ).grid(row=3, column=0, sticky="w")

        ttk.Label(box, text="Delay between requests (s):").grid(row=2, column=1, columnspan=2, sticky="w", pady=(10, 4))
        self.delay_var = tk.DoubleVar(value=0.4)
        ttk.Spinbox(box, from_=0.0, to=10.0, increment=0.1, textvariable=self.delay_var, width=10
                    ).grid(row=3, column=1, sticky="w")

        ttk.Separator(box).grid(row=4, column=0, columnspan=4, sticky="ew", pady=12)

        ttk.Label(box, text="Attack categories to include:").grid(row=5, column=0, columnspan=4, sticky="w")
        self.cat_extraction_var = tk.BooleanVar(value=True)
        self.cat_injection_var = tk.BooleanVar(value=True)
        self.cat_bypass_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(box, text="System Prompt Extraction (9)", variable=self.cat_extraction_var
                        ).grid(row=6, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Checkbutton(box, text="Indirect Prompt Injection (8)", variable=self.cat_injection_var
                        ).grid(row=7, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(box, text="Guardrail Bypass (8)", variable=self.cat_bypass_var
                        ).grid(row=8, column=0, columnspan=2, sticky="w")
        ttk.Label(box, text="(fine-grained per-payload selection is in the Payload Library tab)",
                  style="Dim.TLabel").grid(row=9, column=0, columnspan=4, sticky="w", pady=(6, 0))

        return box

    def _build_persistence_section(self) -> ttk.Frame:
        row = ttk.Frame(self)
        ttk.Button(row, text="Save Configuration...", command=self._save_config).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(row, text="Load Configuration...", command=self._load_config_from_file).grid(row=0, column=1)
        return row

    # ------------------------------------------------------------------
    # Behavior
    # ------------------------------------------------------------------

    def _draw_status_dot(self, color: str) -> None:
        self.status_dot.delete("all")
        self.status_dot.create_oval(1, 1, 11, 11, fill=color, outline="")

    def _update_temp_label(self) -> None:
        self.temp_value_label.configure(text=f"{self.temperature_var.get():.2f}")

    def _on_backend_change(self) -> None:
        backend = self.backend_var.get()
        if backend == "ollama":
            self.host_var.set("http://localhost:11434")
            self.api_key_entry.configure(state="disabled")
            self.api_key_label.configure(state="disabled")
            self.remote_notice.configure(
                text="Ollama runs on your machine -- requests stay on localhost and are never logged externally."
            )
        elif backend == "openai":
            self.host_var.set("https://api.openai.com")
            self.api_key_entry.configure(state="normal")
            self.api_key_label.configure(state="normal")
            if not self.api_key_var.get():
                self.api_key_var.set(resolve_api_key())
            self.remote_notice.configure(
                text="Warning: this backend sends your prompts to a remote API. Data leaves this machine."
            )
        else:  # mock
            self.host_var.set("n/a")
            self.api_key_entry.configure(state="disabled")
            self.api_key_label.configure(state="disabled")
            self.remote_notice.configure(
                text="Demo mode uses pre-written canned responses -- no network requests are made at all."
            )
        self._draw_status_dot(COLORS.TEXT_FAINT)
        self.status_label.configure(text="Not connected yet.", style="Dim.TLabel")

    def _refresh_models(self) -> None:
        backend = self.backend_var.get()
        try:
            adapter = get_adapter(backend, host=self.host_var.get(), model=self.model_var.get(),
                                   api_key=self.api_key_var.get())
        except ValueError as exc:
            messagebox.showerror("Configuration error", str(exc))
            return
        models = adapter.list_models()
        if models:
            self.model_combo.configure(values=models)
            self.app.set_status(f"Found {len(models)} model(s).")
        else:
            self.app.set_status("No models found (is the backend reachable?).")

    def _test_connection(self) -> None:
        backend = self.backend_var.get()
        self.test_btn.configure(state="disabled")
        self.status_label.configure(text="Connecting...")
        self._draw_status_dot(COLORS.WARNING)
        self.update_idletasks()

        try:
            adapter = get_adapter(backend, host=self.host_var.get(), model=self.model_var.get(),
                                   api_key=self.api_key_var.get())
        except ValueError as exc:
            messagebox.showerror("Configuration error", str(exc))
            self.test_btn.configure(state="normal")
            return

        ok, message = adapter.test_connection()
        self._draw_status_dot(COLORS.SUCCESS if ok else COLORS.CRITICAL)
        self.status_label.configure(text=message)
        self.test_btn.configure(state="normal")
        if ok:
            self.app.set_adapter(adapter)
            self.app.set_status(f"Connected: {adapter.describe_target(self.model_var.get())}")
        else:
            self.app.set_status("Connection failed.")

    def _load_example_prompt(self) -> None:
        self.system_prompt_text.delete("1.0", "end")
        self.system_prompt_text.insert("1.0", DEFAULT_TEST_SYSTEM_PROMPT)
        self.canary_var.set(", ".join(DEFAULT_CANARY_TOKENS))

    def _load_prompt_from_file(self) -> None:
        path = filedialog.askopenfilename(title="Select a system prompt file",
                                           filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                content = fh.read()
        except OSError as exc:
            messagebox.showerror("Could not read file", str(exc))
            return
        self.system_prompt_text.delete("1.0", "end")
        self.system_prompt_text.insert("1.0", content)

    def _save_config(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                             filetypes=[("JSON files", "*.json")])
        if not path:
            return
        self.apply_to_config()
        from ...core.config import save_config
        save_config(self.app.config, path)
        self.app.set_status(f"Configuration saved to {path}")

    def _load_config_from_file(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not path:
            return
        from ...core.config import load_config
        try:
            loaded = load_config(path)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Could not load configuration", str(exc))
            return
        self.app.config = loaded
        self._load_from_config()
        self.app.set_status(f"Configuration loaded from {path}")

    # ------------------------------------------------------------------
    # Sync with app.config
    # ------------------------------------------------------------------

    def _load_from_config(self) -> None:
        cfg = self.app.config
        self.backend_var.set(cfg.backend)
        self.host_var.set(cfg.host)
        self.model_var.set(cfg.model)
        self.system_prompt_text.delete("1.0", "end")
        self.system_prompt_text.insert("1.0", cfg.target_system_prompt)
        self.canary_var.set(", ".join(cfg.canary_tokens))
        self.temperature_var.set(cfg.temperature)
        self._update_temp_label()
        self.max_tokens_var.set(cfg.max_tokens)
        self.timeout_var.set(cfg.request_timeout)
        self.delay_var.set(cfg.delay_between_requests)
        self.cat_extraction_var.set(cfg.categories_enabled.get("prompt_extraction", True))
        self.cat_injection_var.set(cfg.categories_enabled.get("prompt_injection", True))
        self.cat_bypass_var.set(cfg.categories_enabled.get("guardrail_bypass", True))

    def apply_to_config(self) -> None:
        """Write every widget's current value back into ``app.config``.

        Called right before a scan starts (see gui/panels/scan_panel.py)
        so the engine always sees exactly what's on screen, even if the
        person tweaked a field without pressing an explicit "Apply"
        button (there isn't one, by design -- this panel behaves like a
        live-bound settings form).
        """
        cfg = self.app.config
        cfg.backend = self.backend_var.get()
        cfg.host = self.host_var.get()
        cfg.model = self.model_var.get()
        cfg.api_key = self.api_key_var.get()
        cfg.target_system_prompt = self.system_prompt_text.get("1.0", "end").strip()
        cfg.canary_tokens = [t.strip() for t in self.canary_var.get().split(",") if t.strip()]
        cfg.temperature = round(self.temperature_var.get(), 2)
        cfg.max_tokens = self.max_tokens_var.get()
        cfg.request_timeout = self.timeout_var.get()
        cfg.delay_between_requests = self.delay_var.get()
        cfg.categories_enabled = {
            "prompt_extraction": self.cat_extraction_var.get(),
            "prompt_injection": self.cat_injection_var.get(),
            "guardrail_bypass": self.cat_bypass_var.get(),
        }
