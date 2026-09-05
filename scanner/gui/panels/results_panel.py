"""
scanner.gui.panels.results_panel
===================================

The "Results" tab: live-updating summary cards, a sortable/filterable
table of every test run so far, and a detail view for the selected
row showing the full prompt/response pair, matched signals, and
remediation advice -- the "detailed analysis tabs" called for in the
original brief.

Populated incrementally during a scan via ``add_result`` (called by
scan_panel.py as each result arrives) and re-summarized at the end via
``finalize``, so switching to this tab mid-scan already shows partial
results rather than a blank screen.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import TYPE_CHECKING, Dict, List, Optional

from ...core.models import ScanSummary, Severity, TestResult
from ..theme import COLORS, FONTS

if TYPE_CHECKING:
    from ..app import ScannerApp

_FILTERS = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]
_COLUMNS = ("severity", "name", "category", "confidence", "vulnerable", "latency")


class ResultsPanel(ttk.Frame):
    def __init__(self, parent: tk.Widget, app: "ScannerApp"):
        super().__init__(parent, padding=20)
        self.app = app
        self.results: List[TestResult] = []
        self._row_to_result: Dict[str, TestResult] = {}
        self._active_filter = "All"
        self._build()

    # ------------------------------------------------------------------

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        self._build_summary_cards().grid(row=0, column=0, sticky="ew", pady=(0, 14))
        self._build_toolbar().grid(row=1, column=0, sticky="ew", pady=(0, 10))

        body = ttk.Frame(self)
        body.grid(row=2, column=0, sticky="nsew")
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        self._build_tree(body).grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        self._build_detail(body).grid(row=0, column=1, sticky="nsew")

    def _build_summary_cards(self) -> ttk.Frame:
        row = ttk.Frame(self)
        self._cards: Dict[str, ttk.Label] = {}
        specs = [
            ("total", "Total Tests", "SurfaceValue"),
            ("vulnerable", "Vulnerabilities Found", "CriticalValue"),
            ("risk", "Risk Score", "HighValue"),
            ("latency", "Avg. Latency", "SurfaceValue"),
        ]
        for i, (key, label, style_prefix) in enumerate(specs):
            card = ttk.Frame(row, style="Card.TFrame", padding=14)
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 10, 0))
            row.columnconfigure(i, weight=1)
            value_style = "SurfaceHeading.TLabel" if style_prefix == "SurfaceValue" else f"{style_prefix}.TLabel"
            value_lbl = ttk.Label(card, text="\u2014", style=value_style, font=(FONTS.FAMILY_FALLBACK, 20, "bold"))
            value_lbl.grid(row=0, column=0, sticky="w")
            ttk.Label(card, text=label, style="SurfaceDim.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 0))
            self._cards[key] = value_lbl
        return row

    def _build_toolbar(self) -> ttk.Frame:
        row = ttk.Frame(self)
        ttk.Label(row, text="Filter:").grid(row=0, column=0, padx=(0, 8))
        self._filter_buttons: Dict[str, ttk.Button] = {}
        for i, f in enumerate(_FILTERS):
            btn = ttk.Button(row, text=f.title() if f != "All" else "All",
                              command=lambda f=f: self._set_filter(f))
            btn.grid(row=0, column=i + 1, padx=3)
            self._filter_buttons[f] = btn
        self._highlight_filter()

        ttk.Button(row, text="Export HTML Report...", command=self._export_html).grid(row=0, column=len(_FILTERS) + 1, padx=(20, 6))
        ttk.Button(row, text="Export JSON Report...", command=self._export_json).grid(row=0, column=len(_FILTERS) + 2)
        return row

    def _build_tree(self, parent: tk.Widget) -> ttk.Frame:
        frame = ttk.Frame(parent)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(frame, columns=_COLUMNS, show="headings", selectmode="browse")
        headings = {"severity": "Severity", "name": "Payload", "category": "Category",
                    "confidence": "Conf.", "vulnerable": "Result", "latency": "Latency"}
        widths = {"severity": 80, "name": 220, "category": 170, "confidence": 60, "vulnerable": 90, "latency": 70}
        for col in _COLUMNS:
            self.tree.heading(col, text=headings[col], command=lambda c=col: self._sort_by(c))
            self.tree.column(col, width=widths[col], anchor="center" if col != "name" else "w")

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        for sev_name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SAFE"):
            self.tree.tag_configure(sev_name, foreground=COLORS.for_severity(sev_name))
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self._sort_reverse = False
        return frame

    def _build_detail(self, parent: tk.Widget) -> ttk.Labelframe:
        box = ttk.Labelframe(parent, text="  FINDING DETAIL  ", padding=14)
        box.columnconfigure(0, weight=1)
        box.rowconfigure(6, weight=1)

        self.detail_title = ttk.Label(box, text="Select a result to inspect it.", style="Heading.TLabel",
                                       wraplength=360)
        self.detail_title.grid(row=0, column=0, sticky="w")
        self.detail_sub = ttk.Label(box, text="", style="Dim.TLabel", wraplength=360)
        self.detail_sub.grid(row=1, column=0, sticky="w", pady=(2, 10))

        self.detail_notes = tk.Text(box, height=4, wrap="word", bg=COLORS.BG, fg=COLORS.TEXT,
                                     relief="flat", padx=0, pady=0, borderwidth=0,
                                     font=(FONTS.FAMILY_FALLBACK, FONTS.SIZE_BODY))
        self.detail_notes.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        self.detail_notes.configure(state="disabled")

        self.detail_remediation = tk.Text(box, height=3, wrap="word", bg="#1f2937", fg=COLORS.TEXT,
                                           relief="flat", padx=8, pady=8, borderwidth=0,
                                           font=(FONTS.FAMILY_FALLBACK, FONTS.SIZE_SMALL))
        self.detail_remediation.grid(row=3, column=0, sticky="ew", pady=(0, 10))
        self.detail_remediation.configure(state="disabled")

        ttk.Label(box, text="PROMPT SENT", style="Dim.TLabel").grid(row=4, column=0, sticky="w")
        self.detail_prompt = tk.Text(box, height=6, wrap="word", bg=COLORS.SURFACE_2, fg=COLORS.TEXT,
                                      relief="flat", padx=8, pady=8, borderwidth=0,
                                      font=(FONTS.MONO_FALLBACK, FONTS.SIZE_MONO))
        self.detail_prompt.grid(row=5, column=0, sticky="ew", pady=(2, 10))
        self.detail_prompt.configure(state="disabled")

        ttk.Label(box, text="MODEL RESPONSE", style="Dim.TLabel").grid(row=6, column=0, sticky="nw")
        resp_frame = ttk.Frame(box)
        resp_frame.grid(row=7, column=0, sticky="nsew", pady=(2, 0))
        box.rowconfigure(7, weight=1)
        resp_frame.columnconfigure(0, weight=1)
        resp_frame.rowconfigure(0, weight=1)
        self.detail_response = tk.Text(resp_frame, height=8, wrap="word", bg=COLORS.SURFACE_2, fg=COLORS.TEXT,
                                        relief="flat", padx=8, pady=8, borderwidth=0,
                                        font=(FONTS.MONO_FALLBACK, FONTS.SIZE_MONO))
        resp_scroll = ttk.Scrollbar(resp_frame, orient="vertical", command=self.detail_response.yview)
        self.detail_response.configure(yscrollcommand=resp_scroll.set, state="disabled")
        self.detail_response.grid(row=0, column=0, sticky="nsew")
        resp_scroll.grid(row=0, column=1, sticky="ns")

        return box

    # ------------------------------------------------------------------
    # Data flow
    # ------------------------------------------------------------------

    def add_result(self, result: TestResult) -> None:
        self.results.append(result)
        self._refresh_cards()
        if self._matches_filter(result):
            self._insert_row(result)

    def finalize(self, results: List[TestResult]) -> None:
        self.results = list(results)
        self._refresh_cards()
        self._repopulate_tree()

    def clear(self) -> None:
        self.results = []
        self.tree.delete(*self.tree.get_children())
        self._row_to_result.clear()
        self._refresh_cards()

    def _refresh_cards(self) -> None:
        summary = ScanSummary.from_results(self.results) if self.results else None
        if summary is None:
            for lbl in self._cards.values():
                lbl.configure(text="\u2014")
            return
        self._cards["total"].configure(text=str(summary.total_tests))
        self._cards["vulnerable"].configure(text=str(summary.vulnerabilities_found))
        self._cards["risk"].configure(text=f"{summary.risk_score:.0f}")
        self._cards["latency"].configure(text=f"{summary.average_latency_ms:.0f}ms")

    # ------------------------------------------------------------------
    # Filtering / sorting / tree population
    # ------------------------------------------------------------------

    def _matches_filter(self, result: TestResult) -> bool:
        return self._active_filter == "All" or result.severity.value == self._active_filter

    def _set_filter(self, f: str) -> None:
        self._active_filter = f
        self._highlight_filter()
        self._repopulate_tree()

    def _highlight_filter(self) -> None:
        for name, btn in self._filter_buttons.items():
            btn.configure(style="Accent.TButton" if name == self._active_filter else "TButton")

    def _repopulate_tree(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._row_to_result.clear()
        for result in self.results:
            if self._matches_filter(result):
                self._insert_row(result)

    def _insert_row(self, result: TestResult) -> None:
        payload = result.payload
        latency = f"{result.response.latency_ms:.0f}ms" if result.response else "n/a"
        row_id = self.tree.insert("", "end", values=(
            result.severity.value,
            payload.name if payload else "?",
            payload.category.value if payload else "?",
            f"{result.confidence:.0f}%",
            "VULNERABLE" if result.vulnerable else "safe",
            latency,
        ), tags=(result.severity.value,))
        self._row_to_result[row_id] = result

    def _sort_by(self, column: str) -> None:
        items = [(self.tree.set(k, column), k) for k in self.tree.get_children("")]
        try:
            items.sort(key=lambda t: float(str(t[0]).rstrip("%ms")), reverse=self._sort_reverse)
        except ValueError:
            items.sort(key=lambda t: t[0], reverse=self._sort_reverse)
        for index, (_, k) in enumerate(items):
            self.tree.move(k, "", index)
        self._sort_reverse = not self._sort_reverse

    # ------------------------------------------------------------------
    # Detail view
    # ------------------------------------------------------------------

    def _on_select(self, _event: tk.Event) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        result = self._row_to_result.get(sel[0])
        if result is None:
            return
        payload = result.payload

        self.detail_title.configure(text=payload.name if payload else "Unknown")
        self.detail_sub.configure(
            text=f"{result.severity.value} \u2022 confidence {result.confidence:.0f}% \u2022 "
                 f"{payload.owasp_ref if payload else ''}"
        )

        matched = "; ".join(result.matched_patterns) if result.matched_patterns else "none"
        notes = f"{result.analysis_notes}\n\nMatched signals: {matched}"
        self._set_text(self.detail_notes, notes)
        self._set_text(self.detail_remediation,
                        result.remediation or "No remediation needed \u2014 this test did not indicate a vulnerability.")
        self._set_text(self.detail_prompt, result.prompt_sent)
        self._set_text(self.detail_response, result.response_text or "(empty response)")

    @staticmethod
    def _set_text(widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def _export_html(self) -> None:
        if not self.results:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files", "*.html")])
        if not path:
            return
        from ...reporting import write_html_report
        summary = ScanSummary.from_results(self.results, model_tested=self.app.config.model,
                                            backend=self.app.config.backend)
        write_html_report(self.results, summary, self.app.config, path)
        self.app.set_status(f"HTML report exported to {path}")
        messagebox.showinfo("Export complete", f"HTML report saved to:\n{path}")

    def _export_json(self) -> None:
        if not self.results:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if not path:
            return
        from ...reporting import write_json_report
        summary = ScanSummary.from_results(self.results, model_tested=self.app.config.model,
                                            backend=self.app.config.backend)
        write_json_report(self.results, summary, self.app.config, path)
        self.app.set_status(f"JSON report exported to {path}")
        messagebox.showinfo("Export complete", f"JSON report saved to:\n{path}")
