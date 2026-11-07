"""HunterBug 1.1 — Integración con Burp Suite y ZAP.

Importa hallazgos desde los archivos de exportación de Burp (burp_results.json)
y ZAP (core.action.report), y los normaliza al formato de HunterBug para
generar reportes.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

# CSV de Burp Suite (exportado como CSV)
# "URL", "Parametros", "Tipo", "Severidad", "Confirmado", "Request", "Response"
BURP_COLUMNS = 12

# Headers de ZAP
ZAP_HEADERS = [
    "url", "alert", "risk", "description", "evidence", "parameter", 
    "other", "instance", "solution", "cweid", "source"
]


def normalizar_burp(data, source="burp"):
    """Normaliza hallazgos de Burp Suite al formato HunterBug."""
    hallazgos = []
    
    if isinstance(data, str):
        data = json.loads(data)

    for item in data if isinstance(data, list) else data.get("issues", []):
        url = item.get("url", item.get("location", ""))
        nombre = item.get("name", item.get("alert", "Hallazgo"))
        severidad = item.get("severity", item.get("risk", "info")).lower()
        descripcion = item.get("description", item.get("issue", ""))
        parametro = item.get("parameter", item.get("param", ""))
        
        # Mapear tipo
        tipo_raw = item.get("type", item.get("alert", "")).lower()
        tipo_map = {
            "sqli": "sqli",
            "xss": "xss", 
            "idor": "idor",
            "path traversal": "lfi",
            "file inclusion": "lfi",
            "open redirect": "open_redirect",
            "ssrf": "ssrf",
            "xxe": "xxe"
        }
        tipo = None
        for key, val in tipo_map.items():
            if key in tipo_raw:
                tipo = val
                break
        tipo = tipo or "otro"

        h = {
            "tipo": tipo,
            "titulo": nombre,
            "detalle": descripcion,
            "url": url,
            "parametro": parametro,
            "severidad": severidad,
            "cwe": item.get("cwe", item.get("cweid")),
            "owasp": item.get("owasp"),
            "evidencia": {
                "request": item.get("request", ""),
                "response": item.get("response", item.get("evidence", "")),
                "contexto": item.get("context", "")
            },
            "fuente": source
        }
        hallazgos.append(h)

    return {"url": data.get("url", "import_burp"), "hallazgos": hallazgos, "total": len(hallazgos)}


def normalizar_zap(data):
    """Normaliza hallazgos de ZAP al formato HunterBug."""
    hallazgos = []
    
    if isinstance(data, str):
        data = json.loads(data)

    alerts = data if isinstance(data, list) else data.get("alerts", [])
    
    for alert in alerts:
        url = alert.get("url", "")
        nombre = alert.get("alert", "Hallazgo ZAP")
        severidad = alert.get("risk", "low").lower()
        descripcion = alert.get("description", "")
        parametro = alert.get("parameter", "")
        
        # Mapear tipo
        tipo = alert.get("pluginid", "").lower()
        if "sql" in tipo or "sqli" in tipo.lower():
            tipo = "sqli"
        elif "xss" in tipo.lower():
            tipo = "xss"
        elif "idor" in tipo.lower() or "authorization" in tipo.lower():
            tipo = "idor"
        elif "redirect" in tipo.lower():
            tipo = "open_redirect"
        elif "path" in tipo.lower() or "file" in tipo.lower():
            tipo = "lfi"
        else:
            tipo = "otro"

        h = {
            "tipo": tipo,
            "titulo": nombre,
            "detalle": descripcion,
            "url": url,
            "parametro": parametro,
            "severidad": severidad,
            "cwe": alert.get("cweid"),
            "owasp": alert.get("owasp"),
            "evidencia": {
                "request": alert.get("request", ""),
                "response": alert.get("evidence", ""),
                "contexto": alert.get("instance", "")
            },
            "fuente": "zap"
        }
        hallazgos.append(h)

    return {"url": "zap_import", "hallazgos": hallazgos, "total": len(hallazgos)}


def parse_csv_burp(filepath):
    """Parsea archivo CSV de Burp Suite."""
    import csv
    hallazgos = []
    
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get("URL", "")
            nombre = row.get("Issue", row.get("Type", ""))
            severidad = row.get("Severity", "info").lower()
            
            h = {
                "tipo": "otro",
                "titulo": nombre,
                "detalle": row.get("Description", ""),
                "url": url,
                "parametro": row.get("Parameter", ""),
                "severidad": severidad,
                "cwe": row.get("CWE", ""),
                "evidencia": {
                    "request": row.get("Request", ""),
                    "response": row.get("Response", "")[:500]
                },
                "fuente": "burp_csv"
            }
            hallazgos.append(h)

    return {"url": filepath, "hallazgos": hallazgos, "total": len(hallazgos)}


def importar_burp_file(filepath, format_type="json"):
    """Importa archivo de Burp/ZAP desde disco."""
    if format_type == "json":
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return normalizar_burp(data)
    elif format_type == "csv":
        return parse_csv_burp(filepath)
    else:
        raise ValueError(f"Formato no soportado: {format_type}")


def merge_results(*results):
    """Combina múltiples resultados importados eliminando duplicados."""
    todos = []
    vistos = set()
    
    for r in results:
        for h in r.get("hallajgos", []):
            key = (h.get("tipo"), h.get("url"), h.get("parametro"))
            if key not in vistos:
                vistos.add(key)
                todos.append(h)
    
    return {
        "url": "merged",
        "hallazgos": todos,
        "total": len(todos),
        "fuentes": [r.get("fuente", "unknown") for r in results]
    }


if __name__ == "__main__":
    import sys
    import os
    
    if len(sys.argv) < 3:
        print("Uso: python hunterbug_integration.py <burp.json|zap.json> <burp|zap>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    source = sys.argv[2].lower()
    
    with open(filepath, "r") as f:
        data = json.load(f)
    
    if source == "burp":
        result = normalizar_burp(data)
    elif source == "zap":
        result = normalizar_zap(data)
    else:
        print(f"Fuente desconocida: {source}")
        sys.exit(1)
    
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))