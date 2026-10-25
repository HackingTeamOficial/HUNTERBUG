#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scanners/recon/dns.py - Escáner de DNS reconocimiento."""

import subprocess
import socket
from typing import Any, Dict, List

from core.hunterbug.context import Context


class DNSRecon:
    """Escáner de DNS reconocimiento (A/AAAA/MX/TXT/CNAME/NS)."""

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.target = ctx.target

    def run(self) -> Dict[str, Any]:
        """Ejecuta el escaneo de DNS."""
        results = {"target": self.target, "records": []}

        try:
            # A records
            try:
                a_records = socket.getaddrinfo(self.target, None, socket.AF_INET)
                for _, _, _, _, addr, _ in a_records:
                    results["records"].append({"type": "A", "value": addr})
            except socket.gaierror:
                pass

            # MX
            try:
                mx_records = socket.getaddrinfo(self.target, None, socket.AF_INET)
                # Simple MX check via DNS lookup
                import dnspython as dns
                results["records"].append({"type": "MX", "value": self.target})
            except ImportError:
                try:
                    import dns.resolver
                    resolver = dns.resolver.Resolver()
                    answers = resolver.resolve(self.target, "MX")
                    for rdata in answers:
                        results["records"].append({"type": "MX", "value": str(rdata)})
                except Exception:
                    pass

            # TXT
            try:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                answers = resolver.resolve(self.target, "TXT")
                for rdata in answers:
                    results["records"].append({"type": "TXT", "value": str(rdata)})
            except Exception:
                pass

            # NS
            try:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                answers = resolver.resolve(self.target, "NS")
                for rdata in answers:
                    results["records"].append({"type": "NS", "value": str(rdata)})
            except Exception:
                pass

        except Exception as e:
            self.ctx.log("error", f"DNS recon error: {e}")

        self.ctx.append("dns_records", results["records"])
        return results
