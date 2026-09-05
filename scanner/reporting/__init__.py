"""Report generation: structured JSON for tooling, styled HTML for humans."""
from .json_report import generate_json_report, write_json_report
from .html_report import generate_html_report, write_html_report

__all__ = [
    "generate_json_report", "write_json_report",
    "generate_html_report", "write_html_report",
]
