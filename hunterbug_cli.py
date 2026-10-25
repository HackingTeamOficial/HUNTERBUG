#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HunterBug CLI - L�nea de comandos principal para HunterBug."""

import argparse
import sys
import os
import json
from datetime import datetime, timezone

# A�adir ruta al paquete
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.hunterbug.engine import HunterBugEngine
from core.hunterbug.config import Config
from core.hunterbug import Context


def main():
    parser = argparse.ArgumentParser(
        description="HunterBug 2.3.0 - AI-Powered Security Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  hunterbug scan https://target.com --profile full --out reports/
  hunterbug scan https://target.com --profile recon
  hunterbug list-profiles
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Comandos")

    # Comando scan
    scan_parser = subparsers.add_parser("scan", help="Ejecutar evaluaci�n de seguridad")
    scan_parser.add_argument("target", help="Target de evaluaci�n (host o URL)")
    scan_parser.add_argument("--profile", default="full", help="Perfil de evaluaci�n (full, recon, webapp, security_assessment)")
    scan_parser.add_argument("--config", "-c", help="Fichero de configuraci�n JSON")
    scan_parser.add_argument("--out", "-o", default="reports", help="Directorio de salida de reportes")
    scan_parser.add_argument("--no-report", action="store_true", help="No generar reportes")

    # Comando status
    subparsers.add_parser("status", help="Ver estado de la �ltima evaluaci�n")

    # Comando list-profiles
    subparsers.add_parser("list-profiles", help="Listar perfiles disponibles")

    # Comando plugins
    plugins_parser = subparsers.add_parser("plugins", help="Listar plugins disponibles")
    plugins_parser.add_argument("--detail", action="store_true", help="Detalle de cada plugin")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Inicializar motor
    engine = HunterBugEngine()
    ctx = Context(target=args.target, engine=engine, session_id="cli-" + datetime.now(timezone.utc).isoformat() + "Z")

    if args.command == "scan":
        engine.run_profile(args.profile, args.target)
        ctx.status = "completed"
        print(f"\nEvaluaci�n completada: {ctx.session_id}")
        print(f"Target: {args.target}")
        print(f"Status: {ctx.status}")
        findings = ctx.get("findings", [])
        print(f"Findings: {len(findings)}")

    elif args.command == "status":
        print("Estado: completo")
        print(f"Target: {ctx.target}")
        print(f"Session: {ctx.session_id}")
        print(f"Findings: {len(ctx.get('findings', []))}")

    elif args.command == "list-profiles":
        print("Perfiles disponibles:")
        print("  full    - Evaluaci�n completa (recon + webapp + security_assessment)")
        print("  recon   - Solo reconocimiento (DNS, subdominios, tecnolog�a)")
        print("  webapp  - Solo aplicaci�n web (headers, CORS, SSRF, par�metros)")
        print("  security_assessment - Solo seguridad (vulnerabilidades, impacto)")

    elif args.command == "plugins":
        from core.hunterbug.plugin import PluginManager
        pm = PluginManager()
        if args.detail:
            for name, meta in pm.list_plugins().items():
                print(f"  {name:25s} | {meta.get('phase', 'attack'):10s} | {meta.get('version', '1.0.0')}")
        else:
            print("Plugins disponibles:")
            for name in pm.get_available():
                print(f"  - {name}")


if __name__ == "__main__":
    main()
