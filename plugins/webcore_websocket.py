#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plugins/webcore_websocket.py - Plugin de esc�ner WebSocket."""

from core.hunterbug.scanners.webcore.websocket import WebSocketScanner
from core.hunterbug import Context


def run(ctx: Context):
    """Ejecuta el esc�ner WebSocket."""
    ws = WebSocketScanner(ctx)
    result = ws.run()
    if result.get("findings"):
        ctx.log("info", f"WebSocket: {len(result['findings'])} findings")
    return {"findings": []}
