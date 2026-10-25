#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plugins/webcore_cors.py - Plugin de esc�ner CORS (HunterBug)."""

from core.hunterbug.scanners.webcore.cors import CORSScanner
from core.hunterbug import Context


def run(ctx: Context):
    """Ejecuta el esc�ner CORS."""
    cors = CORSScanner(ctx)
    result = cors.run()
    high = [r for r in result.get("results", []) if r.get("severity") == "high"]
    if high:
        ctx.log("info", f"CORS: {len(high)} riesgos CAMPO find!")
        for r in high:
            ctx.finding({
                "type": "cors_misconfiguration",
                "severity": "high",
                "title": "CORS wildcard con credentials",
                "detail": r.get("detail", ""),
                "confidence": "high",
                "module": "cors",
                "phase": "attack",
                "evidence": r,
            })
    return {"findings": []}
