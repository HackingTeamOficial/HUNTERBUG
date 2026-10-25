#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plugins/recon_dns.py - Plugin de reconocimiento DNS (HunterBug).

Versi�n de trabajo: imports absolutos, compatible con carga directa
y con PluginManager de HunterBugEngine.
"""

from core.hunterbug.scanners.recon.dns import DNSRecon
from core.hunterbug import Context


def run(ctx: Context):
    """Ejecuta el esc�ner de DNS."""
    dns = DNSRecon(ctx)
    result = dns.run()
    ctx.log("info", f"DNS: {len(result.get('records', []))} registros")
    return {"findings": []}
