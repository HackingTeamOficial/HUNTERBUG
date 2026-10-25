#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plugins/webcore_ssrf.py - Plugin de detecci�n SSRF (HunterBug)."""

from core.hunterbug.scanners.webcore.ssrf import SSRFScanner
from core.hunterbug import Context


def run(ctx: Context):
    """Ejecuta el esc�ner SSRF."""
    ssrf = SSRFScanner(ctx)
    result = ssrf.run()
    if result.get("violation"):
        ctx.log("info", f"SSRF: {result.get('summary')}")
        for c in result.get("checks", []):
            if c.get("result") == "reachable":
                ctx.finding({
                    "type": "ssrf_detected",
                    "severity": "high",
                    "title": "Endpoint de red interna alcanzable",
                    "detail": f"Probado: {c.get('probe')}",
                    "confidence": "high",
                    "module": "ssrf",
                    "phase": "attack",
                    "evidence": c,
                })
    return {"findings": []}
