#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plugins/workflow_vulns.py - Plugin de esc�ner de vulnerabilidades (HunterBug)."""

from core.hunterbug.scanners.workflow.vulns import VulnerabilityScanner
from core.hunterbug import Context


def run(ctx: Context):
    """Ejecuta el esc�ner de vulnerabilidades."""
    vuln = VulnerabilityScanner(ctx)
    result = vuln.run()
    for v in result.get("vulns", []):
        ctx.log("info", f"Vuln: {v.get('title', 'unknown')} [{v.get('severity', 'info')}]")
    return {"findings": []}
