#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HunterBug 1.2 CLI - Línea de comandos principal para HunterBug."""

import argparse
import sys
import os
import json
from datetime import datetime, timezone

# Agregar ruta al paquete
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hb import sqli, xss, authz, traversal, open_redirect, jwt, validacion, recon_ajax


def cmd_scan(args):
    """Ejecuta escáner contra una URL."""
    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    cabeceras = {}
    if args.cookies:
        cabeceras["Cookie"] = args.cookies
    if args.token:
        cabeceras["Authorization"] = f"Bearer {args.token}"

    resultados = {
        "url": url,
        "cabeceras": list(cabeceras.keys()),
        "modos": [],
        "hallazgos": []
    }

    # SQLi
    if not args.skip_sqli:
        resultados["modos"].append("sqli")
        r = sqli.analizar(url, cabeceras=cabeceras)
        for h in r.get("hallazgos", []):
            resultados["hallazgos"].append(h)

    # XSS
    if not args.skip_xss:
        resultados["modos"].append("xss")
        r = xss.analizar(url, cabeceras=cabeceras)
        for h in r.get("hallazgos", []):
            resultados["hallazgos"].append(h)

    # IDOR
    if not args.skip_idor:
        resultados["modos"].append("idor")
        r = authz.analizar(url, cabeceras=cabeceras)
        for h in r.get("hallazgos", []):
            resultados["hallazgos"].append(h)

    # BOLA
    if args.bola_cookies_a and args.bola_cookies_b:
        resultados["modos"].append("bola")
        r = authz.bola(url, cookies_a=args.bola_cookies_a, cookies_b=args.bola_cookies_b)
        for h in r.get("hallazgos", []):
            resultados["hallazgos"].append(h)

    # Path Traversal
    if not args.skip_traversal:
        resultados["modos"].append("traversal")
        r = traversal.analizar(url, cabeceras=cabeceras)
        for h in r.get("hallazgos", []):
            resultados["hallazgos"].append(h)

    # Open Redirect
    if not args.skip_redirect:
        resultados["modos"].append("open_redirect")
        r = open_redirect.analizar(url, cabeceras=cabeceras)
        for h in r.get("hallazgos", []):
            resultados["hallazgos"].append(h)

    # Recon AJAX
    if args.recon_ajax:
        resultados["modos"].append("recon_ajax")
        r = recon_ajax.escanear_ajax(url, cabeceras)
        resultados["recon_ajax"] = r.get("direcciones", [])

    # Reconocimiento general
    if args.recon:
        resultados["modos"].append("recon")
        r = recon_ajax.escanear_ajax(url, cabeceras)
        resultados["recon"] = r

    # Validar resultado
    proc = validacion.procesar(resultados["hallazgos"])
    resultados["resumen"] = proc["resumen"]
    resultados["hallazgos"] = proc["hallazgos"]

    # Salida
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(resultados, f, indent=2, ensure_ascii=False)
        print(f"Resultados guardados en {args.output}")
    else:
        print(json.dumps(resultados, indent=2, ensure_ascii=False, default=str))

    return 0


def cmd_test(args):
    """Prueba un endpoint específico."""
    url = args.url + args.endpoint if args.endpoint else args.url
    cabeceras = {}
    if args.cookies:
        cabeceras["Cookie"] = args.cookies

    tipos = {
        "sqli": sqli.analizar,
        "xss": xss.analizar,
        "idor": authz.analizar,
        "traversal": traversal.analizar,
        "redirect": open_redirect.analizar,
    }

    if args.tipo not in tipos:
        print(f"Tipo no soportado. Usa: {', '.join(tipos.keys())}")
        return 1

    r = tipos[args.tipo](url, cabeceras=cabeceras)
    print(json.dumps(r, indent=2, ensure_ascii=False, default=str))
    return 0


def cmd_jwt(args):
    """Analiza tokens JWT en busca de problemas."""
    if args.token:
        r = jwt.analizar_jwt(args.token)
        print(json.dumps(r, indent=2, ensure_ascii=False))
    elif args.url:
        r = jwt.escanear_urls(args.url)
        print(json.dumps(r, indent=2, ensure_ascii=False, default=str))
    else:
        print("Usa --token <jwt> o --url <url>")
        return 1
    return 0


def cmd_report(args):
    """Genera un informe a partir de un archivo de hallazgos."""
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {args.input}")
        return 1

    if isinstance(data, dict) and "hallazgos" in data:
        hallazgos = data["hallazgos"]
        proyecto = data.get("url", "")
    else:
        hallazgos = list(data) if isinstance(data, list) else []
        proyecto = ""

    proc = validacion.procesar(hallazgos)
    salida = proc["hallazgos"]

    if args.format == "html":
        import html
        html_out = ["<!DOCTYPE html><html><head><title>HunterBug Report</title></head><body>"]
        for h in salida:
            html_out.append(f"<h2>{html.escape(h.get('titulo', 'Sin titulo'))}</h2>")
            html_out.append(f"<p><strong>Severidad:</strong> {h.get('severidad', 'N/D')}</p>")
            html_out.append(f"<p><strong>CVSS:</strong> {h.get('cvss', {}).get('puntos', 'N/D')}</p>")
            html_out.append(f"<p>{html.escape(h.get('detalle', ''))}</p>")
            if h.get('recomendacion'):
                html_out.append(f"<p><em>Recomendación:</em> {html.escape(h['recomendacion'])}</p>")
            html_out.append("<hr>")
        html_out.append("</body></html>")
        print("\n".join(html_out))
    elif args.format == "md":
        for h in salida:
            print(f"## {h.get('titulo', 'Sin titulo')}\n")
            print(f"**Severidad:** {h.get('severidad')}\n")
            print(f"**CVSS:** {h.get('cvss', {}).get('puntos', 'N/D')}\n")
            print(f"**Confianza:** {h.get('confianza_calculada', 'N/D')}\n")
            print(f"{h.get('detalle', '')}\n")
            if h.get('recomendacion'):
                print(f"*{h['recomendacion']}*\n")
    else:
        print(json.dumps(salida, indent=2, ensure_ascii=False, default=str))

    return 0


def cmd_sarif(args):
    """Genera reporte en formato SARIF para GitHub Actions."""
    try:
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Archivo no encontrado: {args.input}")
        return 1

    if isinstance(data, dict) and "hallazgos" in data:
        hallazgos = data["hallazgos"]
    else:
        hallazgos = list(data) if isinstance(data, list) else []

    # Mapear severidad a level SARIF
    severity_map = {"critico": "error", "alto": "error", "medio": "warning", "bajo": "note"}

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "HunterBug", "version": "1.1", "informationUri": "https://hunterbug.example.com"}},
            "results": []
        }]
    }

    for h in hallazgos:
        rule_id = h.get("tipo", "unknown")
        severity = h.get("severidad", "info").lower()
        
        result = {
            "ruleId": rule_id,
            "level": severity_map.get(severity, "note"),
            "message": {"text": h.get("titulo", "") + ": " + h.get("detalle", "")[:200]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": h.get("url", "")}
                }
            }]
        }
        sarif["runs"][0]["results"].append(result)

    print(json.dumps(sarif, indent=2, ensure_ascii=False, default=str))
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="hunterbug",
        description="HunterBug 1.1 - Framework de evaluación de seguridad",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  hunterbug scan https://target.com --profile full --out report.json
  hunterbug scan https://target.com --sqli --xss --idor
  hunterbug test --url /api/ --tipo sqli
  hunterbug jwt --token <jwt_string>
  hunterbug report hallazgos.json --format html
  hunterbug sarif hallazgos.json > results.sarif.json
"""
    )
    subparsers = parser.add_subparsers(dest="command", help="Comandos")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Escanea una URL en busca de vulnerabilidades")
    scan_parser.add_argument("url", help="URL a escanear")
    scan_parser.add_argument("--skip-sqli", action="store_true", help="Saltar detección de SQLi")
    scan_parser.add_argument("--skip-xss", action="store_true", help="Saltar detección de XSS")
    scan_parser.add_argument("--skip-idor", action="store_true", help="Saltar detección de IDOR")
    scan_parser.add_argument("--skip-traversal", action="store_true", help="Saltar detección de Path Traversal")
    scan_parser.add_argument("--skip-redirect", action="store_true", help="Saltar detección de Open Redirect")
    scan_parser.add_argument("--recon-ajax", action="store_true", help="Incluir reconocimiento AJAX")
    scan_parser.add_argument("--recon", action="store_true", help="Escanear direcciones")
    scan_parser.add_argument("--cookies", help="Cookies para el request")
    scan_parser.add_argument("--token", help="Token de autorización (Bearer)")
    scan_parser.add_argument("--output", "-o", help="Archivo de salida (JSON)")

    # test
    test_parser = subparsers.add_parser("test", help="Prueba un endpoint específico")
    test_parser.add_argument("--url", default="https://", help="URL base")
    test_parser.add_argument("--endpoint", help="Endpoint a probar")
    test_parser.add_argument("--tipo", default="sqli", choices=["sqli", "xss", "idor", "traversal", "redirect"], help="Tipo de test")
    test_parser.add_argument("--cookies", help="Cookies para el request")

    # jwt
    jwt_parser = subparsers.add_parser("jwt", help="Analiza tokens JWT")
    jwt_parser.add_argument("--token", help="Token JWT a analizar")
    jwt_parser.add_argument("--url", help="URL para escanear tokens JWT")

    # report
    report_parser = subparsers.add_parser("report", help="Genera reporte de hallazgos")
    report_parser.add_argument("input", help="Archivo de entrada (JSON)")
    report_parser.add_argument("--format", "-f", default="json", choices=["json", "html", "md"], help="Formato de salida")

    # sarif
    sarif_parser = subparsers.add_parser("sarif", help="Genera reporte en formato SARIF para GitHub Actions")
    sarif_parser.add_argument("input", help="Archivo de entrada (JSON)")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "test":
        return cmd_test(args)
    elif args.command == "jwt":
        return cmd_jwt(args)
    elif args.command == "report":
        return cmd_report(args)
    elif args.command == "sarif":
        return cmd_sarif(args)


if __name__ == "__main__":
    sys.exit(main())
