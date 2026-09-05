"""
scanner.gui.theme
====================

Centralized color palette, fonts, and ttk ``Style`` configuration.

Tkinter/ttk can look dated with zero effort, so this module exists to
make one deliberate aesthetic choice (a dark, GitHub-Dashboard-style
palette that reads as "security tool" rather than "tutorial app") and
apply it consistently everywhere, rather than letting every panel
invent its own colors. Import ``COLORS``/``FONTS`` for any custom
canvas or matplotlib drawing, and call ``apply_theme(root)`` once,
right after creating the root window.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class COLORS:
    BG = "#0d1117"
    SURFACE = "#161b22"
    SURFACE_2 = "#1c2128"
    SURFACE_3 = "#21262d"
    BORDER = "#30363d"
    BORDER_LIGHT = "#3d444d"

    TEXT = "#e6edf3"
    TEXT_DIM = "#8b949e"
    TEXT_FAINT = "#6e7681"

    ACCENT = "#58a6ff"
    ACCENT_HOVER = "#79b8ff"
    ACCENT_DIM = "#1f6feb"

    SUCCESS = "#3fb950"
    WARNING = "#d29922"

    # Severity palette -- kept identical to Severity.color in core/models.py
    # so a CRITICAL badge looks the same in the GUI, the HTML report, and
    # the charts. Duplicated intentionally (rather than importing core
    # from here) to keep the GUI theme module dependency-free and safe to
    # import even in contexts that don't want to pull in the full core
    # package (e.g. a quick style preview script).
    CRITICAL = "#f85149"
    HIGH = "#ff8c42"
    MEDIUM = "#d29922"
    LOW = "#7ee787"
    INFO = "#58a6ff"
    SAFE = "#3fb950"

    @staticmethod
    def for_severity(severity_value: str) -> str:
        return {
            "CRITICAL": COLORS.CRITICAL, "HIGH": COLORS.HIGH, "MEDIUM": COLORS.MEDIUM,
            "LOW": COLORS.LOW, "INFO": COLORS.INFO, "SAFE": COLORS.SAFE,
        }.get(severity_value, COLORS.TEXT_DIM)


class FONTS:
    FAMILY = "Segoe UI"
    FAMILY_FALLBACK = "Helvetica"
    MONO = "Consolas"
    MONO_FALLBACK = "Courier New"

    SIZE_TITLE = 16
    SIZE_HEADING = 12
    SIZE_BODY = 10
    SIZE_SMALL = 9
    SIZE_MONO = 9


def _pick_family(root: tk.Misc, preferred: str, fallback: str) -> str:
    try:
        available = set(tk.font.families(root))
    except Exception:
        return fallback
    return preferred if preferred in available else fallback


def apply_theme(root: tk.Tk) -> dict:
    """Configure ttk styles for the whole app. Call once on the root window.

    Returns a small dict of resolved font family names so panels can
    build ``tkfont.Font`` objects that match without re-probing.
    """
    body_family = _pick_family(root, FONTS.FAMILY, FONTS.FAMILY_FALLBACK)
    mono_family = _pick_family(root, FONTS.MONO, FONTS.MONO_FALLBACK)

    root.configure(bg=COLORS.BG)
    root.option_add("*Font", (body_family, FONTS.SIZE_BODY))
    root.option_add("*Background", COLORS.BG)
    root.option_add("*Foreground", COLORS.TEXT)

    style = ttk.Style(root)
    # 'clam' is the most style-able built-in ttk theme across platforms;
    # 'default'/'alt' ignore many of the color overrides below.
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(".", background=COLORS.BG, foreground=COLORS.TEXT,
                     font=(body_family, FONTS.SIZE_BODY), borderwidth=0)

    style.configure("TFrame", background=COLORS.BG)
    style.configure("Surface.TFrame", background=COLORS.SURFACE)
    style.configure("Surface2.TFrame", background=COLORS.SURFACE_2)
    style.configure("Card.TFrame", background=COLORS.SURFACE, relief="flat")

    style.configure("TLabel", background=COLORS.BG, foreground=COLORS.TEXT)
    style.configure("Surface.TLabel", background=COLORS.SURFACE, foreground=COLORS.TEXT)
    style.configure("Dim.TLabel", background=COLORS.BG, foreground=COLORS.TEXT_DIM)
    style.configure("SurfaceDim.TLabel", background=COLORS.SURFACE, foreground=COLORS.TEXT_DIM)
    style.configure("Title.TLabel", background=COLORS.BG, foreground=COLORS.TEXT,
                     font=(body_family, FONTS.SIZE_TITLE, "bold"))
    style.configure("Heading.TLabel", background=COLORS.BG, foreground=COLORS.TEXT,
                     font=(body_family, FONTS.SIZE_HEADING, "bold"))
    style.configure("SurfaceHeading.TLabel", background=COLORS.SURFACE, foreground=COLORS.TEXT,
                     font=(body_family, FONTS.SIZE_HEADING, "bold"))
    style.configure("Mono.TLabel", background=COLORS.SURFACE, foreground=COLORS.TEXT,
                     font=(mono_family, FONTS.SIZE_MONO))

    for name, color in (
        ("Critical", COLORS.CRITICAL), ("High", COLORS.HIGH), ("Medium", COLORS.MEDIUM),
        ("Low", COLORS.LOW), ("Info", COLORS.INFO), ("Safe", COLORS.SAFE),
    ):
        style.configure(f"{name}.TLabel", background=COLORS.SURFACE, foreground=color,
                         font=(body_family, FONTS.SIZE_BODY, "bold"))
        style.configure(f"{name}Value.TLabel", background=COLORS.SURFACE, foreground=color,
                         font=(body_family, FONTS.SIZE_TITLE, "bold"))

    # Buttons
    style.configure("TButton", background=COLORS.SURFACE_3, foreground=COLORS.TEXT,
                     font=(body_family, FONTS.SIZE_BODY), padding=(12, 7), borderwidth=1,
                     focusthickness=0, relief="flat")
    style.map("TButton",
              background=[("active", COLORS.BORDER_LIGHT), ("disabled", COLORS.SURFACE_2)],
              foreground=[("disabled", COLORS.TEXT_FAINT)])

    style.configure("Accent.TButton", background=COLORS.ACCENT_DIM, foreground="#ffffff",
                     font=(body_family, FONTS.SIZE_BODY, "bold"), padding=(14, 8))
    style.map("Accent.TButton",
              background=[("active", COLORS.ACCENT_HOVER), ("disabled", COLORS.SURFACE_2)],
              foreground=[("disabled", COLORS.TEXT_FAINT)])

    style.configure("Danger.TButton", background="#3a1618", foreground=COLORS.CRITICAL,
                     font=(body_family, FONTS.SIZE_BODY, "bold"), padding=(12, 7))
    style.map("Danger.TButton", background=[("active", "#4a1c1f")])

    # Notebook (tabs)
    style.configure("TNotebook", background=COLORS.BG, borderwidth=0, tabmargins=(4, 6, 4, 0))
    style.configure("TNotebook.Tab", background=COLORS.SURFACE, foreground=COLORS.TEXT_DIM,
                     padding=(16, 9), font=(body_family, FONTS.SIZE_BODY, "bold"), borderwidth=0)
    style.map("TNotebook.Tab",
              background=[("selected", COLORS.BG)],
              foreground=[("selected", COLORS.ACCENT)])

    # Entry / Combobox / Spinbox
    for widget in ("TEntry", "TCombobox", "TSpinbox"):
        style.configure(widget, fieldbackground=COLORS.SURFACE_2, background=COLORS.SURFACE_2,
                         foreground=COLORS.TEXT, insertcolor=COLORS.TEXT, borderwidth=1,
                         relief="flat", padding=6)
    style.map("TCombobox", fieldbackground=[("readonly", COLORS.SURFACE_2)],
               selectbackground=[("readonly", COLORS.SURFACE_2)],
               selectforeground=[("readonly", COLORS.TEXT)])

    # Checkbutton / Radiobutton
    style.configure("TCheckbutton", background=COLORS.BG, foreground=COLORS.TEXT,
                     font=(body_family, FONTS.SIZE_BODY))
    style.map("TCheckbutton", background=[("active", COLORS.BG)])
    style.configure("Surface.TCheckbutton", background=COLORS.SURFACE, foreground=COLORS.TEXT)
    style.map("Surface.TCheckbutton", background=[("active", COLORS.SURFACE)])

    # Progressbar
    style.configure("TProgressbar", background=COLORS.ACCENT, troughcolor=COLORS.SURFACE_2,
                     borderwidth=0, thickness=10)
    style.configure("Success.Horizontal.TProgressbar", background=COLORS.SUCCESS,
                     troughcolor=COLORS.SURFACE_2, borderwidth=0, thickness=10)

    # Scrollbar
    style.configure("Vertical.TScrollbar", background=COLORS.SURFACE_3, troughcolor=COLORS.SURFACE,
                     borderwidth=0, arrowsize=12)
    style.map("Vertical.TScrollbar", background=[("active", COLORS.BORDER_LIGHT)])

    # Treeview
    style.configure("Treeview", background=COLORS.SURFACE, fieldbackground=COLORS.SURFACE,
                     foreground=COLORS.TEXT, rowheight=26, borderwidth=0,
                     font=(body_family, FONTS.SIZE_BODY))
    style.configure("Treeview.Heading", background=COLORS.SURFACE_3, foreground=COLORS.TEXT_DIM,
                     font=(body_family, FONTS.SIZE_SMALL, "bold"), borderwidth=0, relief="flat")
    style.map("Treeview",
              background=[("selected", COLORS.ACCENT_DIM)],
              foreground=[("selected", "#ffffff")])
    style.map("Treeview.Heading", background=[("active", COLORS.SURFACE_3)])

    # LabelFrame
    style.configure("TLabelframe", background=COLORS.BG, borderwidth=1, relief="solid",
                     bordercolor=COLORS.BORDER)
    style.configure("TLabelframe.Label", background=COLORS.BG, foreground=COLORS.TEXT_DIM,
                     font=(body_family, FONTS.SIZE_SMALL, "bold"))

    # Scale (slider)
    style.configure("Horizontal.TScale", background=COLORS.BG, troughcolor=COLORS.SURFACE_2)

    # Separator
    style.configure("TSeparator", background=COLORS.BORDER)

    return {"body_family": body_family, "mono_family": mono_family}
