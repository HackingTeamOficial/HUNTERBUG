#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scanners/webcore/params.py - Descubrimiento de par�metros y direcciones."""

import re
from typing import Any, Dict, List

from core.hunterbug.context import Context

try:
    from urllib.request import Request, urlopen
    from urllib.error import URLError
    _HTTP_AVAILABLE = True
except ImportError:
    _HTTP_AVAILABLE = False

# Palabras clave de parámetros comunes
PARAM_PATTERN = re.compile(r"(?:id|token|user|email|name|pass|key|secret|admin|data|action|search|filter|sort|order|page|limit|offset|query|category|lang|theme|layout)=([^&]+)", re.IGNORECASE)
CTRL_CHARS = re.compile(r"(?:\.\./|\.\.\\|%2e%2e|%252e|%252e%252e)")
PATH_PATTERN = re.compile(r"(?:\.\./|\.\.\\|%2e%2e|%252e|%252e%252e)", re.IGNORECASE)


class ParameterDiscovery:
    """Descubrimiento de par�metros y direcciones de ruta."""

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.target = ctx.target
        self._req_installed = _HTTP_AVAILABLE

    def _fetch(self, url: str, timeout: int = 12, params: Dict = None) -> Optional[Dict]:
        if not self._req_installed:
            return None
        try:
            full_url = url
            if params:
                from urllib.parse import urlencode
                full_url = f"{url}?{urlencode(params)}"
            req = Request(full_url, headers={"User-Agent": "Mozilla/5.0 HunterBug/2.3.0"})
            resp = urlopen(req, timeout=timeout)
            html = resp.read(30000).decode("utf-8", errors="ignore")
            return {"status": resp.status, "html": html}
        except URLError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": str(e)}

    def run(self) -> Dict[str, Any]:
        """Ejecuta el descubrimiento de par�metros."""
        url = self.target if self.target.startswith("http") else f"https://{self.target}"
        result = {"target": url, "parameters": [], "report": []}

        # 1. Perfilado de URLs comunes
        paths = [
            "/login", "/logout", "/register", "/forgot", "/reset", "/admin", "/api",
            "/api/v1", "/api/v2", "/health", "/metrics", "/robots.txt", "/sitemap.xml",
            "/.env", "/config", "/.git/config", "/wp-admin", "/phpmyadmin", "/manager/html",
        ]
        params_found = set()
        for p in paths:
            test_url = f"{url}{p}"
            data = self._fetch(test_url)
            if data:
                html = data.get("html", "")
                # Buscar par�metros en la URL
                params = PARAM_PATTERN.findall(html)
                for param in params:
                    params_found.add(param)

                # Buscar direcciones de ruta
                paths_found = PATH_PATTERN.findall(html)
                for pth in paths_found:
                    result["report"].append({
                        "type": "suspicious_path",
                        "value": pth,
                        "severity": "low",
                    })

                if data.get("status") == 200:
                    if "admin" in p.lower() or "login" in p.lower():
                        pass

        # 2. Par�metros detectados
        if params_found:
            result["parameters"] = sorted(params_found)
            result["report"].append({
                "type": "parameters_found",
                "value": sorted(params_found),
                "severity": "medium",
            })

        # 3. Vulnerabilidades comunes
        if "/.env" in url or "/config" in url:
            result["report"].append({
                "type": "env_exposure",
                "severity": "high",
                "detail": "P�th .env accesible",
            })

        if "/wp-admin" in url:
            result["report"].append({
                "type": "wp_admin",
                "severity": "low",
                "detail": "WordPress admin detectado",
            })

        if "/phpmyadmin" in url:
            result["report"].append({
                "type": "phpmyadmin",
                "severity": "high",
                "detail": "phpMyAdmin accesible",
            })

        result["status"] = "ok" if not result["parameters"] else "warn"
        self.ctx.append("params", result)
        return result
