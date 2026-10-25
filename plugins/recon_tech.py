#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plugins/recon_tech.py - Plugin de fingerprinting tecnol�gico (HunterBug)."""

from core.hunterbug.scanners.recon.tech import TechFingerprint
from core.hunterbug import Context


def run(ctx: Context):
    """Ejecuta el fingerprinting de tecnolog�as."""
    tech = TechFingerprint(ctx)
    result = tech.run()
    techs = result.get("technologies", [])
    if techs:
        ctx.log("info", f"Tecnolog�as detectadas: {len(techs)}")
        for t in techs:
            ctx.log("debug", f"  - {t['name']}: {t['value']}")
    return {"findings": []}
