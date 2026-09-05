"""
scanner.gui.panels.payload_panel
===================================

The "Payload Library" tab: browse all payloads, filter by category,
and toggle individual payloads on/off (a finer-grained control than
the category checkboxes on the Configuration tab -- this is what lets
you, per the original brief, "test all of them, and see which to
improve on or expand").

ttk.Treeview has no native checkbox column, so this uses the common
tkinter workaround: a text column holding a checkbox glyph (\u2611 / \u2610)
that toggles when clicked, detected via ``identify_column`` /
``identify_row`` on a click event.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING, Dict

from ...core.models import Payload
from ...payloads.loader import load_payloads
from ..theme import COLORS, FONTS

if TYPE_CHECKING:
    from ..app import ScannerApp

CHECK_ON = "\u2611"
CHECK_OFF = "\u2610"

_COLUMNS = ("enabled", "id", "name", "category", "severity")


class PayloadPanel(ttk.Frame):
    def __init__(self, parent: tk.Widget, app: "ScannerApp"):
        super().__init__(parent, padding=20)
        self.app = app
        self.all_payloads = load_payloads()
        self.enabled: Dict[str, bool] = {p.id: True for p in self.all_payloads}
        self._row_to_payload: Dict[str, Payload] = {}

        self._build()
        self._populate()

    # ------------------------------------------------------------------

    def _build(self) -> None:
        self.columnconfigure(0, weight=3)
        self.columnconfigure(1, weight=2)
        self.rowconfigure(1, weight=1)

        top = ttk.Frame(self)
        top.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 12))
        ttk.Label(top, text="Filter category:").grid(row=0, column=0, padx=(0, 8))
        self.filter_var = tk.StringVar(value="All")
        filter_combo = ttk.Combobox(
            top, textvariable=self.filter_var, state="readonly", width=28,
            values=["All", "System Prompt Extraction", "Indirect Prompt Injection", "Guardrail Bypass"],
        )
        filter_combo.grid(row=0, column=1, padx=(0, 16))
        filter_combo.bind("<<ComboboxSelected>>", lambda _e: self._populate())

        ttk.Button(top, text="Select All", command=lambda: self._bulk_set(True)).grid(row=0, column=2, padx=4)
        ttk.Button(top, text="Deselect All", command=lambda: self._bulk_set(False)).grid(row=0, column=3, padx=4)
        ttk.Button(top, text="Reset to Defaults", command=self._reset_defaults).grid(row=0, column=4, padx=4)

        self.count_label = ttk.Label(top, text="", style="Dim.TLabel")
        self.count_label.grid(row=0, column=5, padx=(16, 0))

        # Tree
        tree_frame = ttk.Frame(self)
        tree_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 14))
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(tree_frame, columns=_COLUMNS, show="headings", selectmode="browse")
        self.tree.heading("enabled", text="")
        self.tree.heading("id", text="ID")
        self.tree.heading("name", text="Name")
        self.tree.heading("category", text="Category")
        self.tree.heading("severity", text="Severity")
        self.tree.column("enabled", width=34, anchor="center", stretch=False)
        self.tree.column("id", width=170, anchor="w")
        self.tree.column("name", width=230, anchor="w")
        self.tree.column("category", width=160, anchor="w")
        self.tree.column("severity", width=90, anchor="center")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        for sev_name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SAFE"):
            self.tree.tag_configure(sev_name, foreground=COLORS.for_severity(sev_name))
        self.tree.tag_configure("disabled_row", foreground=COLORS.TEXT_FAINT)

        self.tree.bind("<Button-1>", self._on_click)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # Detail panel
        detail = ttk.Labelframe(self, text="  PAYLOAD DETAIL  ", padding=16)
        detail.grid(row=1, column=1, sticky="nsew")
        detail.columnconfigure(0, weight=1)
        detail.rowconfigure(4, weight=1)

        self.detail_name = ttk.Label(detail, text="Select a payload", style="Heading.TLabel", wraplength=340)
        self.detail_name.grid(row=0, column=0, sticky="w")
        self.detail_meta = ttk.Label(detail, text="", style="Dim.TLabel", wraplength=340)
        self.detail_meta.grid(row=1, column=0, sticky="w", pady=(2, 10))

        ttk.Label(detail, text="DESCRIPTION", style="Dim.TLabel").grid(row=2, column=0, sticky="w")
        self.detail_desc = tk.Text(detail, height=4, wrap="word", bg=COLORS.SURFACE, fg=COLORS.TEXT,
                                    relief="flat", padx=0, pady=4, borderwidth=0,
                                    font=(FONTS.FAMILY_FALLBACK, FONTS.SIZE_BODY))
        self.detail_desc.grid(row=3, column=0, sticky="ew", pady=(2, 10))
        self.detail_desc.configure(state="disabled")

        ttk.Label(detail, text="PROMPT TEMPLATE", style="Dim.TLabel").grid(row=4, column=0, sticky="nw")
        prompt_frame = ttk.Frame(detail, style="Surface2.TFrame")
        prompt_frame.grid(row=5, column=0, sticky="nsew", pady=(2, 0))
        detail.rowconfigure(5, weight=1)
        prompt_frame.columnconfigure(0, weight=1)
        prompt_frame.rowconfigure(0, weight=1)
        self.detail_prompt = tk.Text(prompt_frame, height=10, wrap="word", bg=COLORS.SURFACE_2, fg=COLORS.TEXT,
                                      relief="flat", padx=8, pady=8, borderwidth=0,
                                      font=(FONTS.MONO_FALLBACK, FONTS.SIZE_MONO))
        prompt_scroll = ttk.Scrollbar(prompt_frame, orient="vertical", command=self.detail_prompt.yview)
        self.detail_prompt.configure(yscrollcommand=prompt_scroll.set, state="disabled")
        self.detail_prompt.grid(row=0, column=0, sticky="nsew")
        prompt_scroll.grid(row=0, column=1, sticky="ns")

    # ------------------------------------------------------------------

    def _populate(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._row_to_payload.clear()
        cat_filter = self.filter_var.get()

        shown = 0
        for p in self.all_payloads:
            if cat_filter != "All" and p.category.value != cat_filter:
                continue
            is_on = self.enabled.get(p.id, True)
            tag = p.severity_if_successful.value if is_on else "disabled_row"
            row_id = self.tree.insert("", "end", values=(
                CHECK_ON if is_on else CHECK_OFF, p.id, p.name, p.category.value,
                p.severity_if_successful.value,
            ), tags=(tag,))
            self._row_to_payload[row_id] = p
            shown += 1

        total_on = sum(1 for v in self.enabled.values() if v)
        self.count_label.configure(text=f"{shown} shown \u2022 {total_on}/{len(self.all_payloads)} enabled")

    def _on_click(self, event: tk.Event) -> None:
        region = self.tree.identify_region(event.x, event.y)
        if region != "cell":
            return
        col = self.tree.identify_column(event.x)
        row_id = self.tree.identify_row(event.y)
        if not row_id or col != "#1":  # "#1" == the "enabled" checkbox column
            return
        payload = self._row_to_payload.get(row_id)
        if payload is None:
            return
        self.enabled[payload.id] = not self.enabled.get(payload.id, True)
        self._populate()

    def _on_select(self, _event: tk.Event) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        payload = self._row_to_payload.get(sel[0])
        if payload is None:
            return
        self.detail_name.configure(text=payload.name)
        self.detail_meta.configure(
            text=f"{payload.category.value} \u2022 {payload.technique} \u2022 "
                 f"severity if successful: {payload.severity_if_successful.value} \u2022 {payload.owasp_ref}"
        )
        for widget, text in ((self.detail_desc, payload.description), (self.detail_prompt, payload.render())):
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.insert("1.0", text)
            widget.configure(state="disabled")

    def _bulk_set(self, value: bool) -> None:
        cat_filter = self.filter_var.get()
        for p in self.all_payloads:
            if cat_filter == "All" or p.category.value == cat_filter:
                self.enabled[p.id] = value
        self._populate()

    def _reset_defaults(self) -> None:
        self.enabled = {p.id: True for p in self.all_payloads}
        self.filter_var.set("All")
        self._populate()

    # ------------------------------------------------------------------

    def get_enabled_ids(self) -> list:
        """Returns the id list to feed into ``ScanConfig.payload_ids_enabled``."""
        return [pid for pid, on in self.enabled.items() if on]
