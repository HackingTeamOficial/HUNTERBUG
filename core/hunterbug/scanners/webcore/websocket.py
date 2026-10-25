#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scanners/webcore/websocket.py - Esc�ner de WebSocket (WSS)."""

from typing import Any, Dict, List

from core.hunterbug.context import Context

try:
    from urllib.request import Request, urlopen
    from urllib.error import URLError
    _HTTP_AVAILABLE = True
except ImportError:
    _HTTP_AVAILABLE = False


class WebSocketScanner:
    """Esc�ner de WS/WSS: descubrimiento de endpoints WebSocket."""

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.target = ctx.target
        self._req_installed = _HTTP_AVAILABLE

    def _fetch(self, url: str, timeout: int = 12) -> Optional[Dict]:
        if not self._req_installed:
            return None
        try:
            req = Request(url, headers={"User-Agent": "Mozilla/5.0 HunterBug/2.3.0"})
            resp = urlopen(req, timeout=timeout)
            html = resp.read(20000).decode("utf-8", errors="ignore")
            return {"status": resp.status, "html": html}
        except URLError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": str(e)}

    def run(self) -> Dict[str, Any]:
        """Ejecuta el esc�ner WebSocket."""
        url = self.target if self.target.startswith("http") else f"https://{self.target}"
        result = {"target": url, "endpoints": [], "findings": []}

        # 1. Buscar endpoints WebSocket en la p�gina
        data = self._fetch(url)
        if data and "html" in data:
            html = data["html"]
            # Patrones de WS/WSS URLs
            ws_patterns = ["ws://", "wss://", "WebSocket", "websocket"]
            for pattern in ws_patterns:
                if pattern in html:
                    result["findings"].append({
                        "type": "websocket_exposure",
                        "severity": "low",
                        "title": f"Enpoint WebSocket encontrado en p�gina ({pattern})",
                        "detail": "Parece haber comunicaci�n en tiempo real configurada.",
                        "evidence": {"pattern": pattern},
                    })

        # 2. Verificar headers de seguridad comunes en WS
        # 3. Guardar resultados
        result["status"] = "ok" if not result["findings"] else "warn"
        self.ctx.append("websocket", result)
        return result
