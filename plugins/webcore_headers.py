#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plugins/webcore_headers.py - Plugin de auditor�a de headers (HunterBug)."""

from core.hunterbug.scanners.webcore.headers import HeadersAudit
from core.hunterbug import Context


def run(ctx: Context):
    """Ejecuta la auditor�a de headers."""
    headers = HeadersAudit(ctx)
    result = headers.run()
    missing = result.get("missing", [])
    if missing:
        ctx.log("info", f"Headers faltantes: {missing}")
    return {"findings": []}
