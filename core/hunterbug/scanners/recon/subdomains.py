#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scanners/recon/subdomains.py - Enumeración de subdominios."""

import subprocess
from typing import Any, Dict, List

from core.hunterbug.context import Context


class SubdomainEnum:
    """Enumeración de subdominios (Subfinder/Amass/ffuf)."""

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.target = ctx.target

    def run(self) -> Dict[str, Any]:
        """Ejecuta la enumeración de subdominios."""
        config = self.ctx.get("config", {})
        scanner = config.get("subdomain_enum", "subfinder")
        results = {"target": self.target, "subdomains": []}

        self.ctx.log("info", f"Enumerando subdominios de {self.target}...")

        if scanner == "subfinder":
            cmd = ["subfinder", "-d", self.target, "-silent"]
            subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            # Subfinder instalado localmente
            try:
                proc = subprocess.run(
                    ["subfinder", "-d", self.target, "-silent"],
                    capture_output=True, text=True, timeout=120, check=False
                )
                subdomains = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
                results["subdomains"] = subdomains
                self.ctx.append("subdomains", subdomains)
                self.ctx.log("info", f"Subdominios encontrados: {len(subdomains)}")
            except Exception as e:
                self.ctx.log("warn", f"Subfinder error: {e}")

        elif scanner == "amass":
            try:
                proc = subprocess.run(
                    ["amass", "enum", "-d", self.target],
                    capture_output=True, text=True, timeout=120, check=False
                )
                subdomains = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
                results["subdomains"] = subdomains
                self.ctx.append("subdomains", subdomains)
                self.ctx.log("info", f"Subdominios encontrados: {len(subdomains)}")
            except Exception as e:
                self.ctx.log("warn", f"Amass error: {e}")

        elif scanner == "ffuf":
            try:
                proc = subprocess.run(
                    ["ffuf", "-u", f"http://{self.target}/FUZZ", "-w", "subdomains.txt",
                     "-mc", "200,204,301,302,403", "-fr", "-t", "50", "-timeout", "30s",
                     "-o", "subdomains.json"],
                    capture_output=True, text=True, timeout=120, check=False
                )
                # Guardar resultados
                import json
                with open("subdomains.json", "w") as f:
                    json.dump({"subdomains": results["subdomains"]}, f)
                self.ctx.log("info", "Subdominios guardados en subdomains.json")
            except Exception as e:
                self.ctx.log("warn", f"FFuf error: {e}")

        else:
            # Simple DNS brute-force con resolución
            import re
            import random
            words = ["www", "api", "mail", "blog", "ftp", "dev", "staging", "admin",
                     "test", "demo", "cloud", "supplier", "partner", "app", "web"]
            subdomains = [f"{w}.{self.target}" for w in words]
            # Resolver
            for sub in subdomains:
                try:
                    socket.gethostbyname(sub)
                    results["subdomains"].append(sub)
                except socket.gaierror:
                    pass
            self.ctx.append("subdomains", results["subdomains"])

        return results
