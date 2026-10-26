"""HTML + JSON reporting (DESIGN_DOC_V2 §14).

Renders a self-contained HTML report (no external assets, opens standalone in a
browser) from stored scan data, and exports findings as JSON. Jinja2
autoescaping is ON, so attacker-controlled evidence (which may itself contain
<script>) is always HTML-escaped in the report — the report can never be an XSS
vector itself.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
from dataclasses import asdict

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import ScanConfig
from .storage import Storage

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
_env = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)


def _default_config() -> ScanConfig:
    return ScanConfig(target="")


def render_html_report(storage: Storage, scan_id: int,
                       out_path: str | None = None,
                       config: ScanConfig | None = None) -> str:
    scan = storage.get_scan(scan_id)
    if scan is None:
        raise ValueError(f"no scan #{scan_id}")
    findings = storage.get_findings(scan_id)
    endpoints = [
        type("E", (), {"method": e["method"], "url": e["url"],
                       "params": [type("P", (), {"name": p["name"]})()
                                  for p in e["params"]]})()
        for e in storage.get_endpoints(scan_id)
    ]
    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        by_type[f.vuln_type.value] = by_type.get(f.vuln_type.value, 0) + 1

    # make Finding fields template-friendly (enum -> value)
    view_findings = []
    for f in findings:
        view_findings.append(type("F", (), {
            "vuln_type": f.vuln_type.value, "severity": f.severity.value,
            "confidence": f.confidence, "confidence_band": f.confidence_band,
            "url": f.url, "method": f.method, "parameter": f.parameter,
            "param_location": f.param_location.value, "payload": f.payload,
            "evidence": f.evidence,
            "reflection_context": f.reflection_context.value if f.reflection_context else None,
            "cwe": f.cwe, "remediation": f.remediation,
            "manual_review": f.manual_review,
        })())

    html = _env.get_template("report.html").render(
        scan=scan, findings=view_findings, endpoints=endpoints,
        by_severity=by_severity, by_type=by_type,
        config=config or _default_config(),
        generated_at=_dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    if out_path:
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(html)
    return html


def export_findings_json(storage: Storage, scan_id: int,
                         out_path: str | None = None) -> str:
    scan = storage.get_scan(scan_id)
    findings = storage.get_findings_raw(scan_id)
    doc = {"scan": scan, "findings": findings,
           "endpoints": storage.get_endpoints(scan_id)}
    text = json.dumps(doc, indent=2, default=str)
    if out_path:
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text)
    return text
