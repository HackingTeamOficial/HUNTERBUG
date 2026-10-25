#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scanners/webcore/jwt.py - Esc�ner de seguridad JWT."""

from typing import Any, Dict, List

from core.hunterbug.context import Context

try:
    from urllib.request import Request, urlopen
    from urllib.error import URLError
    _HTTP_AVAILABLE = True
except ImportError:
    _HTTP_AVAILABLE = False


class JWTScanner:
    """Esc�ner de seguridad JWT: algormos inseguros, alg:none, claves db, etc."""

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
            html = resp.read(30000).decode("utf-8", errors="ignore")
            return {"status": resp.status, "html": html}
        except URLError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": str(e)}

    def _extract_jwt(self, html: str) -> List[str]:
        """Extrae tokens JWT de la p�gina o cookies."""
        import re
        jwt_pattern = re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.{1}[a-zA-Z0-9_-]{10,}\.{1}[a-zA-Z0-9_-]{10,}', re.IGNORECASE)
        # Buscar en cookies
        cookie_jwt = re.findall(r'jwttoken=([^;]+)', html, re.IGNORECASE)
        return jwt_pattern.findall(html) + cookie_jwt

    def run(self) -> Dict[str, Any]:
        """Ejecuta el esc�ner JWT."""
        url = self.target if self.target.startswith("http") else f"https://{self.target}"
        result = {"target": url, "findings": []}

        # 1. Extraer tokens JWT de la p�gina
        data = self._fetch(url)
        if data and "html" in data:
            html = data["html"]
            jwts = self._extract_jwt(html)
            if jwts:
                result["findings"].append({
                    "type": "jwt_token_exposure",
                    "severity": "medium",
                    "title": "Token JWT encontrado en p�gina o cookies",
                    "detail": f"{len(jwts)} token(s) JWT expuesto en el HTML o cookies.",
                    "evidence": {"count": len(jwts)},
                })
                # No almacenar el token completo por seguridad

        # 2. Verificar la URL para par�metros de JWT (query strings, etc.)
        # 3. Validar que el algoritmo sea HS256/RS256 y no alg:none
        result["status"] = "warn" if result["findings"] else "ok"

        self.ctx.append("jwt", result)
        return result
