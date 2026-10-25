#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scanners/recon/tech.py - Fingerprinting de tecnologías."""

import re
import socket
from typing import Any, Dict, List

from core.hunterbug.context import Context


class TechFingerprint:
    """Fingerprinting de tecnologías (Server, X-Powered-By, Frameworks, CDNs)."""

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.target = ctx.target

    def run(self) -> Dict[str, Any]:
        """Ejecuta el fingerprinting de tecnologías."""
        results = {"target": self.target, "technologies": []}

        # Petición HTTP al target
        import urllib.request
        import urllib.error
        try:
            url = self.target if self.target.startswith("http") else f"https://{self.target}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 HunterBug/2.3.0"})
            resp = urllib.request.urlopen(req, timeout=15)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            html = resp.read(50000).decode("utf-8", errors="ignore")
        except Exception as e:
            self.ctx.log("warn", f"No se pudo conectar: {e}")
            return results

        # Headers típicos
        server = headers.get("server", "")
        x_powered_by = headers.get("x-powered-by", "")
        x_frame_options = headers.get("x-frame-options", "")
        x_content_type_options = headers.get("x-content-type-options", "")
        content_security_policy = headers.get("content-security-policy", "")
        strict_transport_security = headers.get("strict-transport-security", "")

        if server:
            results["technologies"].append({"name": "Server", "value": server})
        if x_powered_by:
            results["technologies"].append({"name": "X-Powered-By", "value": x_powered_by})

        # Clasificar por framework
        if "nginx" in server.lower():
            results["technologies"].append({"name": "Web Server", "value": "nginx"})
        if "apache" in server.lower():
            results["technologies"].append({"name": "Web Server", "value": "apache"})
        if "cloudflare" in server.lower():
            results["technologies"].append({"name": "CDN", "value": "Cloudflare"})

        # Frameworks por X-Powered-By
        if "express" in x_powered_by.lower():
            results["technologies"].append({"name": "Framework", "value": "Express.js"})
        if "django" in x_powered_by.lower():
            results["technologies"].append({"name": "Framework", "value": "Django"})
        if "flask" in x_powered_by.lower():
            results["technologies"].append({"name": "Framework", "value": "Flask"})
        if "spring" in x_powered_by.lower():
            results["technologies"].append({"name": "Framework", "value": "Spring"})
        if "asp.net" in x_powered_by.lower():
            results["technologies"].append({"name": "Framework", "value": "ASP.NET"})
        if "next" in html.lower() or "next.js" in x_powered_by.lower():
            results["technologies"].append({"name": "Framework", "value": "Next.js"})

        # PHP
        if "php" in headers.get("x-powered-by", "").lower():
            results["technologies"].append({"name": "Language", "value": "PHP"})
        if "php" in server.lower():
            results["technologies"].append({"name": "Language", "value": "PHP"})

        # Node.js
        if "node" in server.lower():
            results["technologies"].append({"name": "Runtime", "value": "Node.js"})

        # WordPress
        if "wordpress" in html.lower() or "wp-content" in html.lower():
            results["technologies"].append({"name": "CMS", "value": "WordPress"})

        # Kafka/others
        if "jetty" in server.lower():
            results["technologies"].append({"name": "App Server", "value": "Jetty"})

        # CDN/Proxies
        if "cloudflare" in server.lower():
            results["technologies"].append({"name": "CDN", "value": "Cloudflare"})
        if "akamai" in server.lower():
            results["technologies"].append({"name": "CDN", "value": "Akamai"})

        self.ctx.append("technologies", results["technologies"])
        return results
