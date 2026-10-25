#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scanners/webcore/graphql.py - Esc�ner de API GraphQL."""

from typing import Any, Dict, List

from core.hunterbug.context import Context

try:
    from urllib.request import Request, urlopen
    from urllib.error import URLError
    _HTTP_AVAILABLE = True
except ImportError:
    _HTTP_AVAILABLE = False


class GraphQLScanner:
    """Esc�ner de API GraphQL: introspection, keys, endpoints."""

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.target = ctx.target
        self._req_installed = _HTTP_AVAILABLE

    def _post(self, url: str, payload: str, timeout: int = 12) -> Optional[Dict]:
        if not self._req_installed:
            return None
        try:
            req = Request(url, data=payload.encode(), headers={
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 HunterBug/2.3.0",
            })
            resp = urlopen(req, timeout=timeout)
            body = resp.read(20000).decode("utf-8", errors="ignore")
            return {"status": resp.status, "body": body}
        except URLError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": str(e)}

    def run(self) -> Dict[str, Any]:
        """Ejecuta el esc�ner GraphQL."""
        url = self.target if self.target.startswith("http") else f"https://{self.target}"
        result = {"target": url, "endpoint": None, "findings": []}

        # 1. Probar endpoints comunes de GraphQL
        graphql_endpoints = [
            "/graphql", "/api/graphql", "/graphql/v1", "/api/v1/graphql",
            "/graphql-api", "/graphql/v2", "/qgraphql", "/graphiql",
        ]

        for ep in graphql_endpoints:
            test_url = url.rstrip("/") + ep
            # Verificar si el endpoint responde
            probe = self._post(test_url, '{"query":"{__typename}"}')
            if probe and "error" not in probe:
                result["endpoint"] = ep
                result["status"] = "warn"
                break

        # 2. Si se encuentra un endpoint, probar introspection
        if result.get("endpoint"):
            introspection_payload = '''
            {"query":"{ __type(name: "User") { name fields { name type { name } } } }"}
            '''
            intro = self._post(url.rstrip("/") + result["endpoint"], introspection_payload)
            if intro and "error" not in intro:
                result["findings"].append({
                    "type": "graphql_introspection",
                    "severity": "medium",
                    "title": "GraphQL introspection habilitado",
                    "detail": "El esquema de GraphQL puede ser explotado para descubrir la estructura de la API.",
                    "evidence": {"endpoint": result["endpoint"], "introspection": True},
                })

        # 3. Verificar endpoints GraphQL en script tags y HTML
        data = self._fetch(url)
        if data and "html" in data:
            html = data["html"]
            if "graphql" in html.lower() or "graphiql" in html.lower():
                result["findings"].append({
                    "type": "graphql_admin_panel",
                    "severity": "low",
                    "title": "GraphiQL/API explorador detectado en p�gina",
                    "detail": "Parece haber un explorador de GraphQL expuesto.",
                    "evidence": {"endpoint": result.get("endpoint")},
                })

        result["status"] = "ok" if not result["findings"] else "warn"
        self.ctx.append("graphql", result)
        return result
