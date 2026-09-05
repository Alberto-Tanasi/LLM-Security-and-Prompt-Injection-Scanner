#!/usr/bin/env python3
"""
Entry point for the command-line interface.

Usage:
    python run_cli.py --help
    python run_cli.py --backend mock --output-html report.html
    python run_cli.py --backend ollama --model llama3.2

See README.md for full documentation.
"""
import sys

from scanner.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
