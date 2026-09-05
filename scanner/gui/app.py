"""
scanner.gui.app
==================

The main application window. Wires together the five tabs
(Configuration, Payload Library, Live Scan, Results, Analytics), owns
the shared state every panel reads/writes (``config``, ``adapter``,
``scan_controller``), and shows a one-time responsible-use notice on
first launch.

Run via ``python run_gui.py`` at the project root.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional

from ..adapters.base import BaseLLMAdapter
from ..core.config import DEFAULT_CONFIG_PATH, load_config, save_config
from ..core.models import ScanConfig
from .panels.charts_panel import ChartsPanel
from .panels.config_panel import ConfigPanel
from .panels.payload_panel import PayloadPanel
from .panels.results_panel import ResultsPanel
from .panels.scan_panel import ScanPanel
from .scan_controller import ScanController
from .theme import COLORS, FONTS, apply_theme

APP_TITLE = "LLM Security & Prompt Injection Scanner"
APP_VERSION = "1.0.0"

RESPONSIBLE_USE_TEXT = (
    "This tool sends adversarial test prompts (jailbreaks, extraction attempts, "
    "injection payloads) to whatever model backend you configure, and records "
    "the responses for analysis.\n\n"
    "Only point it at models and systems you own or have explicit authorization "
    "to test. Running it against a third-party service without permission may "
    "violate that service's terms of use.\n\n"
    "The default backend (Ollama, localhost) keeps everything on this machine. "
    "Switching to the OpenAI-compatible backend sends data to a remote API -- "
    "the app will remind you again if you do that."
)


class ScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1180x820")
        self.minsize(980, 680)

        self._fonts = apply_theme(self)

        self.config_obj: ScanConfig = load_config()
        self.adapter: Optional[BaseLLMAdapter] = None
        self.active_backend_name: Optional[str] = None
        self.scan_controller = ScanController(self)
        self._is_scanning = False

        self._build_menu()
        self._build_header()
        self._build_notebook()
        self._build_statusbar()

        self.after(150, self._show_first_run_notice)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # Backward/forward-compatible alias -- panels were written against
    # ``app.config`` before ``config`` was reserved by tk.Tk's own
    # ``configure``/``config`` method; exposing it as a plain attribute
    # keeps panel code readable (``self.app.config.model``) without
    # colliding with tkinter's widget-configuration ``config()`` method.
    @property
    def config(self) -> ScanConfig:  # type: ignore[override]
        return self.config_obj

    @config.setter
    def config(self, value: ScanConfig) -> None:
        self.config_obj = value

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save Configuration...", command=lambda: self.config_panel._save_config())
        file_menu.add_command(label="Load Configuration...", command=lambda: self.config_panel._load_config_from_file())
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Responsible Use Notice", command=self._show_first_run_notice)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.configure(menu=menubar)

    def _build_header(self) -> None:
        header = ttk.Frame(self, style="Surface.TFrame", padding=(20, 14))
        header.pack(side="top", fill="x")

        left = ttk.Frame(header, style="Surface.TFrame")
        left.pack(side="left")
        ttk.Label(left, text=APP_TITLE, style="SurfaceHeading.TLabel",
                  font=(self._fonts["body_family"], FONTS.SIZE_TITLE, "bold")).pack(anchor="w")
        ttk.Label(left, text="Automated red-teaming for local & API-based LLMs \u2022 v" + APP_VERSION,
                  style="SurfaceDim.TLabel").pack(anchor="w")

        right = ttk.Frame(header, style="Surface.TFrame")
        right.pack(side="right")
        self.conn_dot = tk.Canvas(right, width=10, height=10, bg=COLORS.SURFACE, highlightthickness=0)
        self.conn_dot.grid(row=0, column=0, padx=(0, 6))
        self.conn_dot.create_oval(1, 1, 9, 9, fill=COLORS.TEXT_FAINT, outline="")
        self.conn_label = ttk.Label(right, text="No backend connected", style="SurfaceDim.TLabel")
        self.conn_label.grid(row=0, column=1)

    def _build_notebook(self) -> None:
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(side="top", fill="both", expand=True, padx=12, pady=(10, 0))

        self.config_panel = ConfigPanel(self.notebook, self)
        self.payload_panel = PayloadPanel(self.notebook, self)
        self.scan_panel = ScanPanel(self.notebook, self)
        self.results_panel = ResultsPanel(self.notebook, self)
        self.charts_panel = ChartsPanel(self.notebook, self)

        self.notebook.add(self.config_panel, text="  Configuration  ")
        self.notebook.add(self.payload_panel, text="  Payload Library  ")
        self.notebook.add(self.scan_panel, text="  Live Scan  ")
        self.notebook.add(self.results_panel, text="  Results  ")
        self.notebook.add(self.charts_panel, text="  Analytics  ")

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self, style="Surface.TFrame", padding=(14, 6))
        bar.pack(side="bottom", fill="x")
        self.status_label = ttk.Label(bar, text="Ready.", style="SurfaceDim.TLabel")
        self.status_label.pack(side="left")
        ttk.Label(bar, text=f"Config: {DEFAULT_CONFIG_PATH}", style="SurfaceDim.TLabel").pack(side="right")

    # ------------------------------------------------------------------
    # Shared state mutators, called by panels
    # ------------------------------------------------------------------

    def set_status(self, message: str) -> None:
        self.status_label.configure(text=message)

    def set_adapter(self, adapter: BaseLLMAdapter) -> None:
        self.adapter = adapter
        self.active_backend_name = self.config_obj.backend
        self.conn_dot.delete("all")
        self.conn_dot.create_oval(1, 1, 9, 9, fill=COLORS.SUCCESS, outline="")
        self.conn_label.configure(text=adapter.describe_target(self.config_obj.model))

    def set_scanning_state(self, is_scanning: bool) -> None:
        self._is_scanning = is_scanning
        # Prevent editing the target mid-scan (payload list / config are
        # snapshotted at start already, but locking the tabs avoids
        # confusing "did my edit apply?" questions).
        for index, panel in enumerate((self.config_panel, self.payload_panel)):
            state = "disabled" if is_scanning else "normal"
            try:
                self.notebook.tab(index, state=state if is_scanning else "normal")
            except tk.TclError:
                pass

    def _on_close(self) -> None:
        if self.scan_controller.is_running:
            if not messagebox.askyesno("Scan in progress",
                                        "A scan is still running. Quit anyway?"):
                return
            self.scan_controller.cancel()
        try:
            self.config_panel.apply_to_config()
            save_config(self.config_obj)
        except Exception:  # noqa: BLE001 - never block shutdown on a save failure
            pass
        self.destroy()

    # ------------------------------------------------------------------
    # Dialogs
    # ------------------------------------------------------------------

    def _show_first_run_notice(self) -> None:
        messagebox.showinfo("Responsible Use", RESPONSIBLE_USE_TEXT, parent=self)

    def _show_about(self) -> None:
        messagebox.showinfo(
            "About",
            f"{APP_TITLE}\nVersion {APP_VERSION}\n\n"
            "A red-teaming automation framework covering system prompt / hidden-context "
            "extraction, indirect prompt injection, and guardrail bypass testing.\n\n"
            "Category mappings reference the OWASP Top 10 for LLM Applications (2026).\n"
            "See README.md for methodology, architecture, and limitations.",
            parent=self,
        )


def main() -> None:
    app = ScannerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
