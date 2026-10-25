#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plugins/recon_subdomains.py - Plugin de enumeraci�n de subdominios."""

from core.hunterbug.scanners.recon.subdomains import SubdomainEnum
from core.hunterbug import Context


def run(ctx: Context):
    """Ejecuta la enumeraci�n de subdominios."""
    sub = SubdomainEnum(ctx)
    result = sub.run()
    subdomains = result.get("subdomains", [])
    ctx.log("info", f"Subdominios: {len(subdomains)}")
    return {"findings": []}
