#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""core/hunterbug/reports.py - Generación de reportes profesionales."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .context import Context
from .models import Report


class ReportGenerator:
    """Generador de reportes profesionales para HunterBug."""

    FORMATS = {"markdown", "html", "json", "pdf", "xml", "txt", "csv"}

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    def generate(self, ctx: Context, fmt: str = "markdown", **kwargs) -> Dict[str, str]:
        """Genera reportes en múltiples formatos."""
        fmt = fmt.lower()
        if fmt not in self.FORMATS:
            fmt = "markdown"

        findings = ctx.get("findings") or []
        report = {
            "session_id": ctx.session_id,
            "target": ctx.target,
            "phase": ctx.phase,
            "status": ctx.status,
            "findings": findings,
            "stats": ctx.get("scan_stats", []),
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }

        if fmt == "markdown":
            path = self._generate_markdown(report)
        elif fmt == "html":
            path = self._generate_html(report)
        elif fmt == "json":
            path = self._generate_json(report)
        elif fmt == "csv":
            path = self._generate_csv(report)
        else:
            path = self._generate_markdown(report)

        return {"format": fmt, "path": path, "title": report["target"]}

    def _generate_markdown(self, report: Dict[str, Any]) -> str:
        """Genera un reporte en Markdown."""
        lines = []
        lines.append("# HunterBug Assessment Report")
        lines.append(f"**Target:** `{report['target']}`")
        lines.append(f"**Status:** {report['status']}")
        lines.append(f"**Generated:** {report['generated_at']}")
        lines.append("")

        # Encabezados
        findings = report.get("findings", [])
        if findings:
            lines.append("## Findings")
            lines.append("")
            for i, f in enumerate(findings, 1):
                lines.append(f"### {i}. {f.get('title', 'Unknown')}")
                lines.append(f"**Severity:** {f.get('severity', 'info')} | **Confidence:** {f.get('confidence', 'medium')}")
                lines.append(f"**Type:** {f.get('type', 'unknown')}")
                lines.append(f"**Module:** {f.get('module', 'unknown')}")
                lines.append(f"**Detail:** {f.get('detail', '')}")
                if f.get("evidence"):
                    lines.append("**Evidence:**")
                    for k, v in f["evidence"].items():
                        lines.append(f"- {k}: {v}")
                lines.append("")

        # Estadísticas
        stats = report.get("stats", [])
        if stats:
            lines.append("## Scan Statistics")
            lines.append("")
            for s in stats:
                lines.append(f"- **Scanner:** {s.get('scanner', 'unknown')}")
                lines.append(f"  **Code:** {s.get('exit_code', 'N/A')}")
                lines.append(f"  **Output:** {str(s.get('output', ''))[:200]}")
            lines.append("")

        # Resumen
        lines.append("## Summary")
        lines.append(f"- **Session:** {report['session_id']}")
        lines.append(f"- **Target:** {report['target']}")
        lines.append(f"- **Findings:** {len(findings)}")
        lines.append(f"- **Status:** {report['status']}")

        return "\n".join(lines)

    def _generate_html(self, report: Dict[str, Any]) -> str:
        """Genera un reporte en HTML."""
        findings = report.get("findings", [])
        html = [
            "<!DOCTYPE html>",
            "<html><head><meta charset='utf-8'><title>HunterBug Assessment</title></head>",
            "<body style='font-family: sans-serif; margin: 2rem;'>",
            f"<h1>HunterBug Assessment Report</h1>",
            f"<p><strong>Target:</strong> {report['target']}</p>",
            f"<p><strong>Status:</strong> {report['status']}</p>",
            f"<p><strong>Generated:</strong> {report['generated_at']}</p>",
            "<h2>Findings</h2>",
        ]
        if findings:
            for f in findings:
                html.append(f"""
                <div style='border: 1px solid #ccc; margin: 1rem; padding: 1rem;'>
                    <h3>{f.get('title', 'Unknown')}</h3>
                    <p style='color: {self._severity_color(f.get('severity', 'info'))};'>
                        Severity: {f.get('severity', 'info')} | Confidence: {f.get('confidence', 'medium')}
                    </p>
                    <p><strong>Detail:</strong> {f.get('detail', '')}</p>
                    <p><strong>Evidence:</strong> {json.dumps(f.get('evidence', {}))}</p>
                </div>
                """)
        else:
            html.append("<p>No findings.</p>")
        html.append("</body></html>")
        return "\n".join(html)

    def _generate_json(self, report: Dict[str, Any]) -> str:
        """Genera un reporte en JSON."""
        return json.dumps(report, indent=2, ensure_ascii=False)

    def _generate_csv(self, report: Dict[str, Any]) -> str:
        """Genera un reporte en CSV."""
        import csv, io
        findings = report.get("findings", [])
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Title", "Type", "Severity", "Module", "Detail", "Evidence"])
        for f in findings:
            writer.writerow([
                f.get("title", ""),
                f.get("type", ""),
                f.get("severity", ""),
                f.get("module", ""),
                f.get("detail", ""),
                str(f.get("evidence", {})),
            ])
        return output.getvalue()

    def _severity_color(self, sev: str) -> str:
        colors = {"high": "#dc2626", "medium": "#f59e0b", "low": "#16a34a", "info": "#6b7280"}
        return colors.get(sev, "#6b7280")

    def get_report_path(self, filename: str) -> str:
        """Devuelve la ruta del reporte."""
        return os.path.join(self.output_dir, filename)
