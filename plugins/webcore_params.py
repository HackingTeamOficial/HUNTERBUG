#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plugins/webcore_params.py - Plugin de descubrimiento de par�metros (HunterBug)."""

from core.hunterbug.scanners.webcore.params import ParameterDiscovery
from core.hunterbug import Context


def run(ctx: Context):
    """Ejecuta el descubrimiento de par�metros."""
    params = ParameterDiscovery(ctx)
    result = params.run()
    found = result.get("parameters", [])
    if found:
        ctx.log("info", f"Par�metros detectados: {found}")
    return {"findings": []}
