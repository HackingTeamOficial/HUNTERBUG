#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scanners/webcore/cors.py - Escáner de CORS misconfigurations."""

from typing import Any, Dict, List

from core.hunterbug.context import Context

try:
    from urllib.request import Request, urlopen
    from urllib.error import URLError
    _HTTP_AVAILABLE = True
except ImportError:
    _HTTP_AVAILABLE = False


class CORSScanner:
    """Escáner de CORS misconfigurations."""

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.target = ctx.target
        self._req_installed = _HTTP_AVAILABLE

    def _fetch(self, url: str, origin: str, timeout: int = 12) -> Optional[Dict]:
        if not self._req_installed:
            return None
        try:
            headers = {"Origin": origin, "User-Agent": "Mozilla/5.0 HunterBug/2.3.0"}
            req = Request(url, headers=headers, method="GET")
            resp = urlopen(req, timeout=timeout)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return {
                "status": resp.status,
                "headers": resp_headers,
                "body": resp.read(10000).decode(errors="ignore"),
            }
        except URLError as e:
            self.ctx.log("debug", f"CORS probe error: {e}")
            return None
        except Exception as e:
            self.ctx.log("debug", f"CORS probe error: {e}")
            return None

    def run(self) -> Dict[str, Any]:
        """Ejecuta el escáner CORS."""
        url = self.target if self.target.startswith("http") else f"https://{self.target}"
        result = {"target": url, "results": []}

        origins = [
            "http://evil.example.com",
            "http://attacker.com",
            "https://trusted-trusted.com",
        ]
        for origin in origins[:3]:
            data = self._fetch(url, origin)
            if not data:
                continue

            cors_header = data["headers"].get("access-control-allow-origin", "")
            ccac = data["headers"].get("access-control-allow-credentials", "")

            # Evaluar
            is_wildcard = cors_header == "*"
            is_cred = "true" in ccac.lower()
            is_from_trusted = "trusted-trusted.com" in origin

            if is_wildcard and is_cred:
                result["results"].append({
                    "origin": origin,
                    "cors": "wildcard",
                    "severity": "high",
                    "detail": "Access-Control-Allow-Origin=* con credentials permitidos: riesgo de leakage de datos",
                    "rating": "insecure",
                })
            elif is_wildcard:
                result["results"].append({
                    "origin": origin,
                    "cors": "wildcard",
                    "severity": "medium",
                    "detail": "Access-Control-Allow-Origin=*: mayor restricción de CORS, revisar",
                    "rating": "restricted",
                })
            elif cors_header:
                result["results"].append({
                    "origin": origin,
                    "cors": "reflected",
                    "severity": "info",
                    "detail": f"Origin reflejado: {cors_header}",
                    "rating": "reflected",
                })
            else:
                result["results"].append({
                    "origin": origin,
                    "cors": "none",
                    "severity": "info",
                    "detail": "CORS absent: navegador bloqueará peticiones de terceros",
                    "rating": "restricted",
                })

        # Evaluación global
        high = [r for r in result["results"] if r["severity"] == "high"]
        medium = [r for r in result["results"] if r["severity"] == "medium"]
        info = [r for r in result["results"] if r["severity"] == "info"]

        result["summary"] = {
            "high": len(high),
            "medium": len(medium),
            "info": len(info),
        }
        result["status"] = "ok" if not high else "warn"

        self.ctx.append("cors", result)
        return result
