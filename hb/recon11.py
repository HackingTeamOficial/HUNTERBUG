"""HunterBug 1.1 — reconocimiento para bug bounty.

Amplía la superficie conocida sin salirse del alcance ni cargar al objetivo:

  * **Subdominios pasivos** por Certificate Transparency (crt.sh): no toca el
    objetivo, solo consulta registros públicos de certificados.
  * **Nombres del certificado** (SAN): el propio TLS del objetivo suele
    declarar subdominios que nadie ha mirado.
  * **Rutas declaradas** en `robots.txt` y `sitemap.xml`, que muchas veces
    apuntan a paneles y entornos que no deberían estar publicados.
  * **Parámetros ocultos** extraídos del JavaScript: nombres de campos que la
    web usa y que no aparecen en la URL, candidatos directos a IDOR y mass
    assignment.
  * **Puntos de entrada** para formularios y llamadas a API encontradas en el
    HTML.
"""

from __future__ import annotations

import json
import re
import urllib.parse

from . import net

TIMEOUT = 15


def _texto(r):
    return (r.cuerpo or "") if r is not None else ""


# ---------------------------------------------------------------------------
# Subdominios por Certificate Transparency
# ---------------------------------------------------------------------------
def subdominios_crtsh(dominio, timeout=TIMEOUT):
    """Consulta crt.sh. Es pasivo: no envía tráfico al objetivo."""
    dominio = str(dominio or "").strip().lower()
    if not dominio:
        return {"dominio": "", "subdominios": [], "fuente": "crt.sh",
                "error": "sin dominio"}
    url = "https://crt.sh/?q=%25.%s&output=json" % urllib.parse.quote(dominio)
    r = net.peticion_http(url, timeout=timeout, seguir=1)
    if r.status != 200 or not _texto(r).strip():
        return {"dominio": dominio, "subdominios": [], "fuente": "crt.sh",
                "error": r.error or "sin respuesta (%d)" % r.status}
    try:
        datos = json.loads(_texto(r))
    except (ValueError, TypeError):
        return {"dominio": dominio, "subdominios": [], "fuente": "crt.sh",
                "error": "respuesta no es JSON"}

    vistos = set()
    for entrada in datos if isinstance(datos, list) else []:
        nombre = str(entrada.get("name_value") or "")
        for linea in nombre.split("\n"):
            linea = linea.strip().lower().lstrip("*.")
            if not linea or "@" in linea:
                continue
            if linea == dominio or linea.endswith("." + dominio):
                vistos.add(linea)
    return {"dominio": dominio, "subdominios": sorted(vistos),
            "fuente": "crt.sh", "error": "", "total": len(vistos)}


# ---------------------------------------------------------------------------
# Nombres del certificado
# ---------------------------------------------------------------------------
def nombres_certificado(host, puerto=443):
    """Lee los SAN del certificado TLS del objetivo."""
    r = net.peticion_http("https://%s:%d/" % (host, puerto), timeout=TIMEOUT)
    tls = getattr(r, "tls", None) or {}
    sujeto = tls.get("sujeto") or {}
    nombre = sujeto.get("commonName") or ""
    return {"host": host, "common_name": nombre,
            "sans": [], "error": "" if tls else "sin TLS o sin certificado"}


def san_desde_texto(blob):
    """Extrae nombres DNS de un volcado de certificado (SAN)."""
    return sorted(set(n.strip().lower().lstrip("*.")
                      for n in re.findall(
                          r"(?:DNS:|dNSName:)\s*([A-Za-z0-9.*_-]+)", blob)))


# ---------------------------------------------------------------------------
# robots.txt y sitemap.xml
# ---------------------------------------------------------------------------
def rutas_de_robots(base):
    r = net.peticion_http(base.rstrip("/") + "/robots.txt", timeout=TIMEOUT)
    if r.status != 200:
        return {"url": base, "rutas": [], "sitemaps": [], "error": ""}
    rutas, sitemaps = [], []
    for linea in _texto(r).splitlines():
        linea = linea.strip()
        if linea.lower().startswith("disallow:") or \
                linea.lower().startswith("allow:"):
            valor = linea.split(":", 1)[1].strip()
            if valor and valor != "/":
                rutas.append(valor)
        elif linea.lower().startswith("sitemap:"):
            sitemaps.append(linea.split(":", 1)[1].strip())
    return {"url": base, "rutas": sorted(set(rutas)),
            "sitemaps": sorted(set(sitemaps)), "error": ""}


def rutas_de_sitemap(base, maximo=200):
    r = net.peticion_http(base.rstrip("/") + "/sitemap.xml", timeout=TIMEOUT)
    if r.status != 200:
        return {"url": base, "rutas": [], "error": ""}
    locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", _texto(r), re.I)
    rutas = []
    for loc in locs[:maximo]:
        try:
            u = urllib.parse.urlsplit(loc)
            rutas.append(u.path or "/")
        except Exception:
            continue
    return {"url": base, "rutas": sorted(set(rutas)), "error": ""}


# ---------------------------------------------------------------------------
# Parámetros ocultos en JavaScript
# ---------------------------------------------------------------------------
RE_PARAM_JS = [
    r"[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=",
    r"[\"']([a-zA-Z_][a-zA-Z0-9_]{1,30})[\"']\s*:\s*",
    r"params\.([a-zA-Z_][a-zA-Z0-9_]{1,30})",
    r"getParameter\(\s*[\"']([a-zA-Z_][a-zA-Z0-9_]{1,30})[\"']",
    r"set\([\"']([a-zA-Z_][a-zA-Z0-9_]{1,30})[\"']",
]
RUIDO = {"class", "id", "style", "type", "name", "value", "href", "src",
         "width", "height", "title", "text", "html", "body", "div", "span",
         "click", "change", "keydown", "keyup", "focus", "blur", "load",
         "true", "false", "null", "undefined", "function", "return", "var",
         "let", "const", "this", "window", "document", "data", "json",
         "string", "number", "boolean", "object", "array", "length"}


def parametros_en_js(cuerpo, maximo=40):
    """Nombres de parámetro que el JavaScript usa o envía."""
    encontrados = set()
    for patron in RE_PARAM_JS:
        for m in re.finditer(patron, cuerpo or ""):
            nombre = m.group(1)
            if len(nombre) < 3 or nombre.lower() in RUIDO:
                continue
            encontrados.add(nombre)
    return sorted(encontrados)[:maximo]


def endpoints_en_js(cuerpo, maximo=40):
    """Rutas de API que aparecen en el JavaScript."""
    rutas = set()
    for m in re.finditer(r"[\"'](/(?:api|v\d|rest|graphql)[A-Za-z0-9_\-/{}\.]*)"
                         r"[\"']", cuerpo or ""):
        rutas.add(m.group(1))
    return sorted(rutas)[:maximo]


# ---------------------------------------------------------------------------
# Formularios y puntos de entrada
# ---------------------------------------------------------------------------
def formularios(cuerpo):
    """Formularios del HTML con su acción, método y campos."""
    salida = []
    for m in re.finditer(r"<form([^>]*)>(.*?)</form>", cuerpo or "",
                         re.I | re.S):
        attrs, interior = m.group(1), m.group(2)
        accion = re.search(r"action\s*=\s*[\"']([^\"']*)[\"']", attrs, re.I)
        metodo = re.search(r"method\s*=\s*[\"']?(\w+)", attrs, re.I)
        campos = re.findall(r"<input[^>]*name\s*=\s*[\"']([^\"']+)[\"']",
                            interior, re.I)
        salida.append({"accion": accion.group(1) if accion else "",
                       "metodo": (metodo.group(1) if metodo else "GET").upper(),
                       "campos": campos})
    return salida


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------
def reconocer(base, cabeceras=None, log=None, con_ct=True, con_cert=True,
              con_robots=True, con_js=True):
    """Ejecuta el reconocimiento completo sobre un objetivo."""
    log = log or (lambda t, n="info": None)
    base = base.rstrip("/")
    try:
        host = urllib.parse.urlsplit(base if "//" in base else "//" + base
                                     ).hostname or ""
    except Exception:
        host = ""

    salida = {"base": base, "host": host, "subdominios": [], "sans": [],
              "rutas": [], "parametros": [], "endpoints": [], "formularios": [],
              "tecnologias": {}, "errores": []}

    r = net.peticion_http(base + "/", cabeceras=cabeceras, timeout=TIMEOUT,
                          seguir=1)
    cuerpo = _texto(r)

    if con_robots:
        rob = rutas_de_robots(base)
        if rob["rutas"]:
            log("robots.txt declara %d ruta(s)" % len(rob["rutas"]))
            salida["rutas"] += [{"origen": "robots.txt", "ruta": x}
                                for x in rob["rutas"]]
        sm = rutas_de_sitemap(base)
        if sm["rutas"]:
            log("sitemap.xml declara %d ruta(s)" % len(sm["rutas"]))
            salida["rutas"] += [{"origen": "sitemap.xml", "ruta": x}
                                for x in sm["rutas"][:60]]

    if con_js and cuerpo:
        params = parametros_en_js(cuerpo)
        if params:
            log("JavaScript: %d parámetro(s) oculto(s)" % len(params))
            salida["parametros"] = params
        salida["endpoints"] = endpoints_en_js(cuerpo)
        salida["formularios"] = formularios(cuerpo)

    if con_cert and host:
        try:
            c = nombres_certificado(host)
            salida["sans"] = c.get("sans") or []
        except Exception as e:
            salida["errores"].append("certificado: %s" % str(e)[:80])

    if con_ct and host:
        try:
            ct = subdominios_crtsh(host)
            if ct.get("error"):
                salida["errores"].append("crt.sh: %s" % ct["error"])
            else:
                salida["subdominios"] = ct["subdominios"]
                log("crt.sh: %d subdominio(s) pasivo(s)"
                    % len(ct["subdominios"]))
        except Exception as e:
            salida["errores"].append("crt.sh: %s" % str(e)[:80])

    salida["resumen"] = {
        "subdominios": len(salida["subdominios"]),
        "sans": len(salida["sans"]),
        "rutas": len(salida["rutas"]),
        "parametros": len(salida["parametros"]),
        "endpoints": len(salida["endpoints"]),
        "formularios": len(salida["formularios"]),
    }
    return salida
