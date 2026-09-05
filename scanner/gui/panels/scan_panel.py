"""
scanner.gui.panels.scan_panel
================================

The "Live Scan" tab: Start / Pause / Cancel controls, an overall
progress bar, a live per-category breakdown, and a scrolling,
color-coded log -- the real-time view the original project brief
called for ("Real time progress, charts, and detailed analysis tabs
are a must").

This panel does not talk to the network or the engine directly; it
only calls ``app.scan_controller`` (see gui/scan_controller.py) and
renders whatever events that controller hands back. That keeps all
the threading concerns in exactly one place.
"""
from __future__ import annotations

import time
import tkinter as tk
from tkinter import ttk, messagebox
from typing import TYPE_CHECKING

from ...core.engine import EngineEvent
from ...core.models import AttackCategory, ScanConfig, TestResult
from ...payloads.loader import filter_payloads, load_payloads
from ..theme import COLORS, FONTS

if TYPE_CHECKING:
    from ..app import ScannerApp

_LOG_TAG_COLORS = {
    "status": COLORS.TEXT_DIM,
    "vulnerable": COLORS.CRITICAL,
    "safe": COLORS.SUCCESS,
    "error": COLORS.HIGH,
}


class ScanPanel(ttk.Frame):
    def __init__(self, parent: tk.Widget, app: "ScannerApp"):
        super().__init__(parent, padding=20)
        self.app = app
        self._start_time = 0.0
        self._timer_job = None
        self._category_counts = {c: {"total": 0, "done": 0} for c in AttackCategory}
        self._build()

    # ------------------------------------------------------------------

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        # Controls row
        controls = ttk.Frame(self)
        controls.grid(row=0, column=0, sticky="ew", pady=(0, 14))
        self.start_btn = ttk.Button(controls, text="\u25b6  Start Scan", style="Accent.TButton",
                                     command=self._on_start)
        self.start_btn.grid(row=0, column=0, padx=(0, 8))
        self.pause_btn = ttk.Button(controls, text="\u23f8  Pause", command=self._on_pause_resume,
                                     state="disabled")
        self.pause_btn.grid(row=0, column=1, padx=(0, 8))
        self.cancel_btn = ttk.Button(controls, text="\u2716  Cancel", style="Danger.TButton",
                                      command=self._on_cancel, state="disabled")
        self.cancel_btn.grid(row=0, column=2, padx=(0, 20))

        self.elapsed_label = ttk.Label(controls, text="Elapsed: 0.0s", style="Dim.TLabel")
        self.elapsed_label.grid(row=0, column=3, padx=(0, 20))
        self.overall_label = ttk.Label(controls, text="0 / 0 tests", style="Dim.TLabel")
        self.overall_label.grid(row=0, column=4)

        # Overall progress bar
        self.progress = ttk.Progressbar(self, orient="horizontal", mode="determinate", maximum=100)
        self.progress.grid(row=1, column=0, sticky="ew", pady=(0, 14))

        # Per-category mini progress
        cat_row = ttk.Frame(self)
        cat_row.grid(row=2, column=0, sticky="ew", pady=(0, 14))
        self._cat_bars = {}
        self._cat_labels = {}
        for i, cat in enumerate(AttackCategory):
            box = ttk.Frame(cat_row, style="Surface.TFrame", padding=12)
            box.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 10, 0))
            cat_row.columnconfigure(i, weight=1)
            ttk.Label(box, text=cat.value, style="SurfaceDim.TLabel").grid(row=0, column=0, sticky="w")
            lbl = ttk.Label(box, text="0 / 0", style="Surface.TLabel")
            lbl.grid(row=1, column=0, sticky="w", pady=(2, 6))
            bar = ttk.Progressbar(box, orient="horizontal", mode="determinate", maximum=100, length=180)
            bar.grid(row=2, column=0, sticky="ew")
            self._cat_bars[cat] = bar
            self._cat_labels[cat] = lbl

        # Live log
        log_frame = ttk.Labelframe(self, text="  LIVE LOG  ", padding=10)
        log_frame.grid(row=3, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = tk.Text(
            log_frame, wrap="word", bg=COLORS.SURFACE_2, fg=COLORS.TEXT, relief="flat",
            padx=10, pady=8, state="disabled", font=(FONTS.MONO_FALLBACK, FONTS.SIZE_MONO),
        )
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        log_scroll.grid(row=0, column=1, sticky="ns")

        for tag, color in _LOG_TAG_COLORS.items():
            self.log_text.tag_configure(tag, foreground=color)
        self.log_text.tag_configure("bold", font=(FONTS.MONO_FALLBACK, FONTS.SIZE_MONO, "bold"))

    # ------------------------------------------------------------------
    # Log helpers
    # ------------------------------------------------------------------

    def _log(self, text: str, tag: str = "status") -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------

    def _on_start(self) -> None:
        self.app.config_panel.apply_to_config()
        config: ScanConfig = self.app.config

        if self.app.adapter is None or self.app.active_backend_name != config.backend:
            from ...adapters import get_adapter
            try:
                adapter = get_adapter(config.backend, host=config.host, model=config.model,
                                       api_key=config.api_key)
            except ValueError as exc:
                messagebox.showerror("Configuration error", str(exc))
                return
            ok, message = adapter.test_connection()
            if not ok and config.backend != "mock":
                messagebox.showerror("Cannot connect", message)
                return
            self.app.set_adapter(adapter)

        all_payloads = load_payloads()
        enabled_ids = self.app.payload_panel.get_enabled_ids()
        payloads = filter_payloads(all_payloads, config.categories_enabled, enabled_ids)
        if not payloads:
            messagebox.showwarning("Nothing to scan",
                                    "No payloads are enabled. Check the Payload Library tab or "
                                    "the category checkboxes in Configuration.")
            return

        self._clear_log()
        self._log(f"Starting scan: {len(payloads)} payload(s) against "
                   f"{self.app.adapter.describe_target(config.model)}", "bold")
        self._log("=" * 70)

        self._category_counts = {c: {"total": 0, "done": 0} for c in AttackCategory}
        for p in payloads:
            self._category_counts[p.category]["total"] += 1
        self._refresh_category_bars()

        self.progress.configure(value=0, maximum=len(payloads))
        self.overall_label.configure(text=f"0 / {len(payloads)} tests")
        self._start_time = time.time()
        self._tick_timer()

        self.start_btn.configure(state="disabled")
        self.pause_btn.configure(state="normal", text="\u23f8  Pause")
        self.cancel_btn.configure(state="normal")
        self.app.set_scanning_state(True)

        controller = self.app.scan_controller
        controller.on_status = self._handle_status
        controller.on_result = self._handle_result
        controller.on_complete = self._handle_complete
        controller.on_error = self._handle_error
        controller.start(self.app.adapter, config, payloads)

    def _on_pause_resume(self) -> None:
        controller = self.app.scan_controller
        if self.pause_btn["text"].endswith("Pause"):
            controller.pause()
            self.pause_btn.configure(text="\u25b6  Resume")
            self._log("-- paused --", "status")
        else:
            controller.resume()
            self.pause_btn.configure(text="\u23f8  Pause")
            self._log("-- resumed --", "status")

    def _on_cancel(self) -> None:
        self.app.scan_controller.cancel()
        self.cancel_btn.configure(state="disabled")

    def _tick_timer(self) -> None:
        if not self.app.scan_controller.is_running:
            return
        elapsed = time.time() - self._start_time
        self.elapsed_label.configure(text=f"Elapsed: {elapsed:.1f}s")
        self._timer_job = self.after(200, self._tick_timer)

    def _refresh_category_bars(self) -> None:
        for cat, counts in self._category_counts.items():
            total, done = counts["total"], counts["done"]
            pct = (done / total * 100) if total else 0
            self._cat_bars[cat].configure(value=pct)
            self._cat_labels[cat].configure(text=f"{done} / {total}")

    # ------------------------------------------------------------------
    # Controller callbacks
    # ------------------------------------------------------------------

    def _handle_status(self, event: EngineEvent) -> None:
        self._log(event.message, "status")
        if event.total:
            self.progress.configure(value=event.index, maximum=event.total)
            self.overall_label.configure(text=f"{event.index} / {event.total} tests")

    def _handle_result(self, result: TestResult) -> None:
        if result.category is not None:
            self._category_counts[result.category]["done"] += 1
            self._refresh_category_bars()

        tag = "vulnerable" if result.vulnerable else "safe"
        marker = "VULNERABLE" if result.vulnerable else "safe"
        latency = f"{result.response.latency_ms:.0f}ms" if result.response else "n/a"
        self._log(
            f"  [{result.severity.value:<8}] {result.payload.id:<32} "
            f"conf={result.confidence:5.1f}%  {marker}  ({latency})",
            tag,
        )
        if result.vulnerable:
            preview = result.response_text.strip().replace("\n", " ")
            if len(preview) > 140:
                preview = preview[:139] + "\u2026"
            self._log(f"      -> {preview}", "status")

        self.app.results_panel.add_result(result)
        self.app.charts_panel.mark_dirty()

    def _handle_complete(self, results) -> None:
        elapsed = time.time() - self._start_time
        self.elapsed_label.configure(text=f"Elapsed: {elapsed:.1f}s (finished)")
        vulnerable_count = sum(1 for r in results if r.vulnerable)
        self._log("=" * 70)
        self._log(f"Scan complete: {len(results)} tests run, {vulnerable_count} vulnerabilities found.", "bold")

        self.start_btn.configure(state="normal")
        self.pause_btn.configure(state="disabled")
        self.cancel_btn.configure(state="disabled")
        self.app.set_scanning_state(False)
        self.app.results_panel.finalize(results)
        self.app.charts_panel.refresh(results)
        self.app.set_status(f"Scan complete \u2014 {vulnerable_count} of {len(results)} flagged vulnerable.")

    def _handle_error(self, message: str) -> None:
        self._log(f"ERROR: {message}", "error")
        messagebox.showerror("Scan error", message)
        self.start_btn.configure(state="normal")
        self.pause_btn.configure(state="disabled")
        self.cancel_btn.configure(state="disabled")
        self.app.set_scanning_state(False)
