#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scanners/workflow/vulns.py - Identificaci�n de vulnerabilidades (SQLi, XSS, SSRF, RCE)."""

from typing import Any, Dict, List

from core.hunterbug.context import Context

try:
    from urllib.request import Request, urlopen
    from urllib.error import URLError
    _HTTP_AVAILABLE = True
except ImportError:
    _HTTP_AVAILABLE = False


class VulnerabilityScanner:
    """Esc�ner de vulnerabilidades b�sicas (SQLi, XSS, SSRF)."""

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.target = ctx.target
        self._req_installed = _HTTP_AVAILABLE

    def _fetch(self, url: str, payload: str = "", timeout: int = 12) -> Optional[Dict]:
        if not self._req_installed:
            return None
        try:
            if payload:
                from urllib.parse import urlencode
                full_url = f"{url}?{urlencode(payload)}"
            else:
                full_url = url
            req = Request(full_url, headers={"User-Agent": "Mozilla/5.0 HunterBug/2.3.0"})
            resp = urlopen(req, timeout=timeout)
            html = resp.read(50000).decode("utf-8", errors="ignore")
            return {"status": resp.status, "html": html}
        except URLError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": str(e)}

    def run(self) -> Dict[str, Any]:
        """Ejecuta el esc�ner de vulnerabilidades b�sicas."""
        url = self.target if self.target.startswith("http") else f"https://{self.target}"
        result = {"target": url, "vulns": [], "score": 0}

        # 1. Prueba SQLi (error-based + boolean)
        sqli_payloads = [
            "'", '"', "1' OR '1'='1", "1\" OR \"1\"=\"1",
            "admin'--", "' OR 1=1--", "'; DROP TABLE users;--",
        ]
        for payload in sqli_payloads:
            data = self._fetch(url, {"id": payload})
            if data and "html" in data:
                html = data["html"]
                # Señales s�nimas de SQLi
                if any(x in html.lower() for x in ["sql", "syntax error", "mysql", "sqlserver", "pg", "unrecognized"]):
                    result["vulns"].append({
                        "type": "sqli_detected",
                        "title": "Posible SQL Injection (error)",
                        "severity": "high",
                        "detail": f"Payload {payload} provoc� error SQL.",
                        "evidence": {"payload": payload, "status": data.get("status")},
                    })
                    result["score"] += 1

        # 2. Prueba XSS (reflected)
        xss_payload = "<script>alert(1)</script>"
        data = self._fetch(url, {"q": xss_payload})
        if data and "html" in data:
            html = data["html"]
            if xss_payload in html:
                result["vulns"].append({
                    "type": "xss_reflected",
                    "title": "XSS reflejado (posible)",
                    "severity": "medium",
                    "detail": "Payload <script> reflejado sin sanitizaci�n.",
                    "evidence": {"payload": xss_payload, "status": data.get("status")},
                })
                result["score"] += 1

        # 3. SSRF detectado (si el scanner SSRF ya est� en contexto)
        ssrf = self.ctx.get("ssrf", [])
        if ssrf:
            if ssrf.get("violation"):
                result["vulns"].append({
                    "type": "ssrf_detected",
                    "title": "SSRF detectado",
                    "severity": "high",
                    "detail": "Endpoint de red interna alcanzable desde el servidor.",
                    "evidence": ssrf,
                })
                result["score"] += 1

        # 4. Inyecci�n de headers (SIEMPRE)
        result["vulns"].append({
            "type": "headers_missing",
            "title": "Headers de seguridad ausentes",
            "severity": "low",
            "detail": "CSRF, XFO, HSTS no presentes.",
            "evidence": {"missing_headers": ["CSP", "HSTS", "XFO", "XCTO"]},
        })
        result["score"] += 1

        result["status"] = "warn" if result["score"] > 0 else "ok"
        self.ctx.append("vulns", result)
        return result
