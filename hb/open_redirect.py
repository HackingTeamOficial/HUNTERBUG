"""HunterBug 1.1 — detector de Open Redirect.

Un Open Redirect ocurre cuando una aplicación web redirige el navegador a un
dominio arbitrario basado en entrada sin validar. El impacto es phishing: un
enlace verdaderamente legítimo se convierte en la homing page del atacante.

Tipo: XSS reflejado de bajo impacto con fines de phishing.
"""

from __future__ import annotations

import re
import urllib.parse

from . import net, vulns

PAUSA = 0.12
TIMEOUT = 12

_re_redirect = re.compile(
    r"^https?://(?P<host>[^\s/'<>\"|]+)(?P<path>/[^\s'<>]*)?$",
    re.I
)


def _peticion(url, cabeceras=None):
    return net.peticion_http(url, cabeceras=cabeceras, timeout=TIMEOUT)


def _analizar_redirect(url, cabeceras=None):
    """Analiza si una URL redirige a un host externo."""
    r = _peticion(url, cabeceras)
    if r.status == 0:
        return None, r

    # 1. header Location
    location = r.cabecera("location")
    if location:
        try:
            # Normalizar URL relativa
            base = urllib.parse.urlsplit(url)
            loc_url = urllib.parse.urljoin(base.scheme + "://" + base.netloc, location)
            loc_host = urllib.parse.urlsplit(loc_url).hostname or ""
            orig_host = base.hostname or ""
            if loc_host and loc_host != orig_host and not loc_host.endswith("." + orig_host):
                return {"tipo": "redirect", "location": loc_url, "host": loc_host,
                        "origen": url, "status": r.status}, r
        except Exception:
            pass

    # 2. cuerpo HTML con JS window.location o meta refresh
    body = r.cuerpo or ""
    for match in re.finditer(r'(?:window\.location|location\.href|meta\s*http-equiv["\']?refresh["\']?)\s*[=:]\s*["\']([^"\']+)["\']', body, re.I):
        loc = match.group(1)
        try:
            loc_url = urllib.parse.urljoin(url, loc)
            loc_host = urllib.parse.urlsplit(loc_url).hostname or ""
            orig_host = urllib.parse.urlsplit(url).hostname or ""
            if loc_host and loc_host != orig_host and not loc_host.endswith("." + orig_host):
                return {"tipo": "redirect-js", "location": loc_url, "host": loc_host,
                        "origen": url, "status": r.status, "patron": match.group(0)[:80]}, r
        except Exception:
            pass

    # 3. meta refresh
    for match in re.finditer(r'<meta\s+http-equiv=["\']?refresh["\']?\s+content=["\']?(\d+);url=["\']?([^"\']+)["\']?', body, re.I):
        loc = match.group(2)
        try:
            loc_url = urllib.parse.urljoin(url, loc)
            loc_host = urllib.parse.urlsplit(loc_url).hostname or ""
            orig_host = urllib.parse.urlsplit(url).hostname or ""
            if loc_host and loc_host != orig_host and not loc_host.endswith("." + orig_host):
                return {"tipo": "redirect-meta", "location": loc_url, "host": loc_host,
                        "origen": url, "status": r.status, "segundos": int(match.group(1))}, r
        except Exception:
            pass

    return None, r


RE_PATTERN_REDIRECT = re.compile(
    r"[?&](?:url|redirect|next|return|r|target|goto|forward|continue)=([^&\s]+)",
    re.I
)


def analizar(url, cabeceras=None, pausa=PAUSA, log=None):
    """Detecta Open Redirect en una URL o parámetro."""
    log = log or (lambda t, n="info": None)

    hallazgos = []

    # 1. probar la URL base
    result, _ = _analizar_redirect(url, cabeceras)
    if result:
        result.setdefault("severidad", "medio")
        result["titulo"] = "Open Redirect: URL redirige externa"
        result["detalle"] = (
            "El parametro o endpoint redirige a un host externo (%s). "
            "Esto permite que un enlace valido redirija a un sitio del atacante,"
            " util para phishing o rapiñas de credenciales."
        ) % result["host"]
        result["recomendacion"] = "Validar que los parametros de redireccion"
        result["cwe"] = "CWE-601"
        result["owasp"] = "A01:2021"
        result["confianza"] = 75
        result["evidencia"] = result
        hallazgos.append(result)
        log("    Open Redirect externo: %s -> %s" % (url, result["location"]))

    # 2. buscar patrones en parametros y probarlos
    params = vulns.parametros_de(url)
    for nombre, valor in params:
        if not any(k in nombre.lower() for k in ("url", "redirect", "next", "return",
                                                  "r", "target", "goto", "forward",
                                                  "continue")):
            continue

        for payload in ["//evil.com", "https://evil.com", "http://evil.com/x",
                        "\\evil.com", "///evil.com", "https://%00evil.com",
                        "https://evil.com%00.evil.org", "https://x.evil.com"]:
            url_test = f"{url.split('?')[0]}?{nombre}={urllib.parse.quote(payload, safe='')}"
            result, _ = _analizar_redirect(url_test, cabeceras)
            if result:
                result["parametro"] = nombre
                result["original"] = valor
                hallazgos.append(result)
                log("    Open Redirect en %s: %s -> %s" % (nombre, payload, result["location"]))
                break  # un payload basta
        if len(hallazgos) > len(hallazgos) - len(params):  # evita bucle
            break

    # 3. probar rutas con patrón de placeholder
    for pattern in ["/r/", "/goto/", "/redirect/", "/next/", "/url/"]:
        test_url = url.rstrip("/") + pattern + "https://evil.com"
        result, _ = _analizar_redirect(test_url, cabeceras)
        if result:
            result["parametro"] = pattern.rstrip("/").split("/")[-2] or "url"
            result["ruta"] = pattern
            result["tipo"] = "ruta-dinamica"
            hallazgos.append(result)
            log("    Open Redirect detectado en ruta: %s" % pattern)

    return {
        "url": url,
        "hallazgos": hallazgos,
        "resumen": {
            "vulnerable": bool(hallazgos),
            "total": len(hallazgos),
            "parametros_probados": len(params)
        }
    }


def __main__():
    """Modo standalone para pruebas."""
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com/?url=https://evil.com"
    r = analizar(url)
    print("Hallazgos:", len(r["hallazgos"]))
    for h in r["hallazgos"]:
        print("  -", h.get("titulo"), ":", h.get("evidencia", {}).get("location", h.get("ruta")))