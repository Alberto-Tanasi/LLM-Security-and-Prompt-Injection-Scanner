"""
scanner.gui.panels.charts_panel
==================================

The "Analytics" tab: four matplotlib charts embedded directly in the
tkinter window via ``FigureCanvasTkAgg``, giving the "charts" the
original project brief called for as a hard requirement:

1. Severity distribution (donut)
2. Vulnerable vs. safe count per category (stacked bar)
3. Confidence score per test, sorted (horizontal bar, colored by severity)
4. Response latency per test (line, to spot slow outliers)

Matplotlib is configured with an explicit dark style matching
``gui/theme.py`` rather than the default light theme, so the charts
don't look like a jarring white rectangle dropped into a dark app.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING, List

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from ...core.models import Severity, TestResult
from ..theme import COLORS

if TYPE_CHECKING:
    from ..app import ScannerApp

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO, Severity.SAFE]


def _style_axes(ax) -> None:
    ax.set_facecolor(COLORS.SURFACE)
    ax.tick_params(colors=COLORS.TEXT_DIM, labelsize=8)
    for spine in ax.spines.values():
        spine.set_color(COLORS.BORDER)
    ax.title.set_color(COLORS.TEXT)
    ax.xaxis.label.set_color(COLORS.TEXT_DIM)
    ax.yaxis.label.set_color(COLORS.TEXT_DIM)


class ChartsPanel(ttk.Frame):
    def __init__(self, parent: tk.Widget, app: "ScannerApp"):
        super().__init__(parent, padding=20)
        self.app = app
        self._dirty = False
        self._results: List[TestResult] = []
        self._build()
        self._render_empty()

    # ------------------------------------------------------------------

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ttk.Label(top, text="Scan Analytics", style="Heading.TLabel").grid(row=0, column=0, sticky="w")
        self.refresh_btn = ttk.Button(top, text="\u21bb  Refresh Charts", command=self._on_refresh_click)
        self.refresh_btn.grid(row=0, column=1, padx=(16, 0))
        self.hint_label = ttk.Label(top, text="", style="Dim.TLabel")
        self.hint_label.grid(row=0, column=2, padx=(16, 0))

        self.figure = Figure(figsize=(9.5, 6.5), dpi=100, facecolor=COLORS.BG)
        self.canvas = FigureCanvasTkAgg(self.figure, master=self)
        self.canvas.get_tk_widget().grid(row=1, column=0, sticky="nsew")

    def mark_dirty(self) -> None:
        """Called by scan_panel after each new result; charts update on demand
        rather than redrawing on every single test (that would be wasteful
        for a fast-running mock scan and just adds visual noise)."""
        self._dirty = True
        self.hint_label.configure(text="New data available \u2014 click Refresh Charts.")

    def _on_refresh_click(self) -> None:
        self.refresh(self.app.results_panel.results)

    def refresh(self, results: List[TestResult]) -> None:
        self._results = list(results)
        self._dirty = False
        self.hint_label.configure(text="")
        if not self._results:
            self._render_empty()
            return

        self.figure.clear()
        self.figure.set_facecolor(COLORS.BG)
        gs = self.figure.add_gridspec(2, 2, hspace=0.55, wspace=0.35,
                                       left=0.08, right=0.97, top=0.93, bottom=0.10)

        self._draw_severity_donut(self.figure.add_subplot(gs[0, 0]))
        self._draw_category_bars(self.figure.add_subplot(gs[0, 1]))
        self._draw_confidence_bars(self.figure.add_subplot(gs[1, 0]))
        self._draw_latency_line(self.figure.add_subplot(gs[1, 1]))

        self.canvas.draw_idle()

    def _render_empty(self) -> None:
        self.figure.clear()
        self.figure.set_facecolor(COLORS.BG)
        ax = self.figure.add_subplot(111)
        ax.set_facecolor(COLORS.BG)
        ax.axis("off")
        ax.text(0.5, 0.5, "Run a scan to see analytics here.",
                ha="center", va="center", color=COLORS.TEXT_DIM, fontsize=13)
        self.canvas.draw_idle()

    # ------------------------------------------------------------------
    # Individual charts
    # ------------------------------------------------------------------

    def _draw_severity_donut(self, ax) -> None:
        counts = {}
        for r in self._results:
            counts[r.severity] = counts.get(r.severity, 0) + 1
        labels, sizes, colors = [], [], []
        for sev in _SEVERITY_ORDER:
            if counts.get(sev):
                labels.append(f"{sev.value} ({counts[sev]})")
                sizes.append(counts[sev])
                colors.append(sev.color)

        _style_axes(ax)
        ax.set_title("Severity Distribution", fontsize=10, fontweight="bold", loc="left")
        if not sizes:
            ax.axis("off")
            return
        wedges, _ = ax.pie(sizes, colors=colors, startangle=90, wedgeprops={"width": 0.42, "edgecolor": COLORS.BG})
        ax.legend(wedges, labels, loc="center left", bbox_to_anchor=(1.0, 0.5), fontsize=7,
                  frameon=False, labelcolor=COLORS.TEXT_DIM)
        ax.axis("equal")

    def _draw_category_bars(self, ax) -> None:
        _style_axes(ax)
        ax.set_title("Vulnerable vs. Safe by Category", fontsize=10, fontweight="bold", loc="left")

        by_cat: dict = {}
        for r in self._results:
            if r.category is None:
                continue
            bucket = by_cat.setdefault(r.category.value, {"vuln": 0, "safe": 0})
            bucket["vuln" if r.vulnerable else "safe"] += 1

        cats = list(by_cat.keys())
        short_labels = [c.replace("System Prompt ", "").replace("Indirect Prompt ", "").replace("Guardrail ", "")
                        for c in cats]
        vuln_vals = [by_cat[c]["vuln"] for c in cats]
        safe_vals = [by_cat[c]["safe"] for c in cats]

        y = range(len(cats))
        ax.barh(list(y), safe_vals, color=COLORS.SAFE, label="Safe", height=0.55)
        ax.barh(list(y), vuln_vals, left=safe_vals, color=COLORS.CRITICAL, label="Vulnerable", height=0.55)
        ax.set_yticks(list(y))
        ax.set_yticklabels(short_labels, fontsize=8)
        ax.legend(loc="lower right", fontsize=7, frameon=False, labelcolor=COLORS.TEXT_DIM)
        ax.invert_yaxis()

    def _draw_confidence_bars(self, ax) -> None:
        _style_axes(ax)
        ax.set_title("Confidence Score per Test", fontsize=10, fontweight="bold", loc="left")

        sorted_results = sorted(self._results, key=lambda r: r.confidence, reverse=True)[:15]
        labels = [r.payload.id if r.payload else "?" for r in sorted_results]
        values = [r.confidence for r in sorted_results]
        colors = [r.severity.color for r in sorted_results]

        y = range(len(labels))
        ax.barh(list(y), values, color=colors, height=0.6)
        ax.set_yticks(list(y))
        ax.set_yticklabels(labels, fontsize=6.5)
        ax.set_xlim(0, 100)
        ax.set_xlabel("Confidence %", fontsize=8)
        ax.invert_yaxis()
        if len(self._results) > 15:
            ax.text(1.0, -0.14, f"showing top 15 of {len(self._results)}", transform=ax.transAxes,
                    ha="right", fontsize=6.5, color=COLORS.TEXT_FAINT)

    def _draw_latency_line(self, ax) -> None:
        _style_axes(ax)
        ax.set_title("Response Latency per Test", fontsize=10, fontweight="bold", loc="left")

        latencies = [r.response.latency_ms for r in self._results if r.response and r.response.success]
        if not latencies:
            ax.axis("off")
            return
        x = range(1, len(latencies) + 1)
        ax.plot(list(x), latencies, color=COLORS.ACCENT, marker="o", markersize=3, linewidth=1.4)
        avg = sum(latencies) / len(latencies)
        ax.axhline(avg, color=COLORS.TEXT_FAINT, linestyle="--", linewidth=1)
        ax.text(0.99, 0.94, f"avg {avg:.0f}ms", transform=ax.transAxes, ha="right", va="top",
                fontsize=7, color=COLORS.TEXT_DIM)
        ax.set_xlabel("Test # (in run order)", fontsize=8)
        ax.set_ylabel("ms", fontsize=8)
