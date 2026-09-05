#!/usr/bin/env python3
"""
Entry point for the desktop GUI.

Usage:
    python run_gui.py

Requires tkinter (bundled with most Python installers; on Linux you
may need to install it separately, e.g. `sudo apt install python3-tk`)
and the packages in requirements.txt (`pip install -r requirements.txt`).

See README.md for a full walkthrough of the five tabs.
"""
from scanner.gui.app import main

if __name__ == "__main__":
    main()
