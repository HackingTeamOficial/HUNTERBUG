#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scanners/webcore/headers.py - Escáner de headers de seguridad (csp, hsts, xfo, xcto, referrer-policy)."""

from typing import Any, Dict, List, Optional

from core.hunterbug.context import Context

try:
    from urllib.request import Request, urlopen
    from urllib.error import URLError
    _HTTP_AVAILABLE = True
except ImportError:
    _HTTP_AVAILABLE = False


class HeadersAudit:
    """Auditor de headers de seguridad."""

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
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return {"status": resp.status, "headers": headers, "html": resp.read(20000).decode(errors="ignore")}
        except URLError as e:
            self.ctx.log("debug", f"HTTP error: {e}")
            return None
        except Exception as e:
            self.ctx.log("debug", f"HTTP error: {e}")
            return None

    def run(self) -> Dict[str, Any]:
        """Ejecuta la auditoría de headers."""
        url = self.target if self.target.startswith("http") else f"https://{self.target}"
        result = {"target": url, "headers": {}, "missing": [], "issues": []}

        data = self._fetch(url)
        if not data:
            return result

        headers = data["headers"]
        result["headers"] = headers

        # Auditoría de headers
        checks = {
            "CSP": ("Content-Security-Policy", "Detección de CSP"),
            "HSTS": ("Strict-Transport-Security", "HSTS habilitado"),
            "X-Frame-Options": ("X-Frame-Options", "Prevención clickjacking"),
            "X-Content-Type-Options": ("X-Content-Type-Options", "Prevención sniffing de MIME"),
            "Referrer-Policy": ("Referrer-Policy", "Politica de referrer"),
            "X-XSS-Protection": ("X-XSS-Protection", "XSS filter (legacy)"),
            "Permissions-Policy": ("Permissions-Policy", "Permisos de navegador"),
            "Cache-Control": ("Cache-Control", "Politica de cache"),
        }

        for header, desc in checks.items():
            if header in headers:
                result["headers"][header] = headers[header]
            else:
                result["missing"].append(header)
                result["issues"].append({"header": header, "severity": "low", "detail": f"{desc} ausente"})

        # Evaluar pluralidad
        if "Content-Security-Policy" not in headers:
            result["issues"].append({
                "header": "CSP", "severity": "medium",
                "detail": "Sin CSP: habilitar pol�tica de seguridad de contenido"
            })
        if "Strict-Transport-Security" not in headers:
            result["issues"].append({
                "header": "HSTS", "severity": "medium",
                "detail": "Sin HSTS: habilitar cabecera de seguridad HTTP"
            })
        if "X-Frame-Options" not in headers:
            result["issues"].append({
                "header": "X-Frame-Options", "severity": "low",
                "detail": "Sin X-Frame-Options: habilitar protección clickjacking"
            })
        if "X-Content-Type-Options" not in headers:
            result["issues"].append({
                "header": "X-Content-Type-Options", "severity": "low",
                "detail": "Sin X-Content-Type-Options: habilitar protecci�n de MIME"
            })

        result["status"] = "ok" if not result["missing"] else "warn"

        self.ctx.append("headers", result)
        return result
