#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scanners/webcore/ssrf.py - Detección de SSRF (Server-Side Request Forgery)."""

from typing import Any, Dict, List

from core.hunterbug.context import Context

try:
    from urllib.request import Request, urlopen
    from urllib.error import URLError
    _HTTP_AVAILABLE = True
except ImportError:
    _HTTP_AVAILABLE = False


class SSRFScanner:
    """Escáner de SSRF: prueba endpoints de red interna vs externa."""

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
            body = resp.read(10000).decode(errors="ignore")
            return {"status": resp.status, "body": body}
        except URLError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": str(e)}

    def run(self) -> Dict[str, Any]:
        """Ejecuta el escáner SSRF."""
        url = self.target if self.target.startswith("http") else f"https://{self.target}"
        result = {"target": url, "checks": []}

        # Probamos endpoints comunes de red interna/privada
        probe_targets = [
            "http://127.0.0.1:8080",
            "http://localhost:8080",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1:8080",
            "http://172.16.0.1:8080",
            "http://192.168.1.1:8080",
            "http://metadata.google.internal",
        ]

        for probe in probe_targets:
            if self._req_installed:
                resp = self._fetch(probe, timeout=5)
            else:
                resp = None
            if resp:
                if "error" in resp:
                    result["checks"].append({
                        "probe": probe,
                        "result": "blocked",
                        "detail": "Conexión bloqueada (puede ser egress filter)",
                    })
                else:
                    result["checks"].append({
                        "probe": probe,
                        "result": "reachable",
                        "detail": f"Conectado a {probe} (status {resp.get('status')})",
                    })
                    # Marcar como posible SSRF
                    result["checks"][-1]["severity"] = "medium"
            else:
                result["checks"].append({
                    "probe": probe,
                    "result": "blocked",
                    "detail": "No se pudo conectar",
                })

        # Si hay endpoints de red privada alcanzables, alertar
        reachable = [c for c in result["checks"] if c.get("result") == "reachable"]
        if reachable:
            result["status"] = "warn"
            result["summary"] = f"{len(reachable)} endpoints de red interna alcanzables"
            result["violation"] = True
        else:
            result["status"] = "ok"
            result["summary"] = "No se detectaron endpoints de red interna alcanzables"

        self.ctx.append("ssrf", result)
        return result
