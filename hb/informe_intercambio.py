"""HunterBug - formatos de intercambio con otras herramientas.

  * HAR 1.2      — OWASP ZAP lo importa de forma nativa
                   (Import/Export add-on → Import HAR), y también lo leen
                   Chrome DevTools, Burp (con extensión) y la mayoría de
                   proxies.
  * SARIF 2.1.0  — lo consumen el escaneo de código de GitHub, GitLab y Azure
                   DevOps, y el add-on SARIF de ZAP. Es el formato puente con
                   los pipelines de CI.
  * Burp XML     — el mismo XML que exporta Burp Suite ("Report selected
                   issues" → XML). Lo ingieren las herramientas que leen
                   exportaciones de Burp (Invicti, Metasploit, Dradis…).
  * ZAP XML      — el informe XML clásico de OWASP ZAP.

Ninguno de estos formatos se inventa: se escriben contra la estructura que
esperan los lectores, y las pruebas comprueban que parsean y que llevan los
campos obligatorios.
"""

from __future__ import annotations

import html
import json
import re
import time
import urllib.parse

VERSION = "1.0"
HERRAMIENTA = "HunterBug %s" % VERSION

# Caracteres que XML 1.0 prohibe (y que el cuerpo HTTP en bruto puede traer,
# p. ej. un byte NUL en un binario). Se quitan antes de serializar.
_RE_CONTROL = re.compile(
    "[^\u0009\u000a\u000d\u0020-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")


def limpiar_control(texto):
    """Elimina los caracteres de control que no admite XML/HTML."""
    return _RE_CONTROL.sub("", str(texto if texto is not None else ""))


def limpiar_profundo(obj):
    """Aplica `limpiar_control` a todas las cadenas de una estructura."""
    if isinstance(obj, str):
        return limpiar_control(obj)
    if isinstance(obj, dict):
        return {limpiar_control(k): limpiar_profundo(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [limpiar_profundo(v) for v in obj]
    return obj

# severidad HunterBug -> severidad de Burp/ZAP (que no tienen "crítico")
BURP_SEV = {"critico": "High", "alto": "High", "medio": "Medium",
            "bajo": "Low", "info": "Information"}
BURP_CONF = {"critico": "Certain", "alto": "Firm", "medio": "Tentative",
             "bajo": "Tentative", "info": "Certain"}
ZAP_RISK = {"critico": 3, "alto": 3, "medio": 2, "bajo": 1, "info": 0}
ZAP_CONF = {"critico": 3, "alto": 3, "medio": 2, "bajo": 2, "info": 3}
ZAP_RISK_NOMBRE = {3: "High", 2: "Medium", 1: "Low", 0: "Informational"}
SARIF_NIVEL = {"critico": "error", "alto": "error", "medio": "warning",
               "bajo": "note", "info": "note"}


# ---------------------------------------------------------------------------
# Ayudas
# ---------------------------------------------------------------------------

def _cdata(texto):
    """Envuelve en CDATA partiendo las secuencias ']]>' que lo romperian."""
    t = limpiar_control(texto)
    t = t.replace("]]>", "]]]]><![CDATA[>")
    return "<![CDATA[%s]]>" % t


def _xml_attr(texto):
    return html.escape(limpiar_control(texto), quote=True)


def _cwe_numero(cwe):
    m = re.search(r"(\d+)", str(cwe or ""))
    return int(m.group(1)) if m else 0


def _host_puerto(url):
    try:
        u = urllib.parse.urlsplit(url if "//" in url else "//" + url)
        return u.hostname or "", u.port or (443 if u.scheme == "https" else 80), \
            u.scheme or "http"
    except Exception:
        return "", 0, "http"


def _cookies_de(cabeceras):
    salida = []
    for k, v in cabeceras:
        if k.lower() == "cookie":
            for trozo in str(v).split(";"):
                n, _, val = trozo.strip().partition("=")
                if n:
                    salida.append({"name": n.strip(), "value": val.strip()})
    return salida


def _parsear_cabeceras(lineas):
    cabeceras = []
    for linea in lineas:
        if ":" in linea:
            k, _, v = linea.partition(":")
            cabeceras.append((k.strip(), v.strip()))
    return cabeceras


def parsear_peticion(texto):
    """Trocea una petición HTTP en bruto. Devuelve un dict."""
    if not texto:
        return None
    texto = str(texto).replace("\r\n", "\n")
    cabeza, _, cuerpo = texto.partition("\n\n")
    lineas = [l for l in cabeza.split("\n") if l.strip()]
    if not lineas:
        return None
    primera = lineas[0].split()
    metodo = primera[0] if primera else "GET"
    ruta = primera[1] if len(primera) > 1 else "/"
    version = primera[2] if len(primera) > 2 else "HTTP/1.1"
    return {"metodo": metodo, "ruta": ruta, "version": version,
            "cabeceras": _parsear_cabeceras(lineas[1:]), "cuerpo": cuerpo.strip()}


def parsear_respuesta(texto):
    """Trocea una respuesta HTTP en bruto. Devuelve un dict."""
    if not texto:
        return None
    texto = str(texto).replace("\r\n", "\n")
    cabeza, _, cuerpo = texto.partition("\n\n")
    lineas = [l for l in cabeza.split("\n") if l.strip()]
    if not lineas:
        return None
    primera = lineas[0].split(None, 2)
    try:
        status = int(primera[1]) if len(primera) > 1 else 0
    except ValueError:
        status = 0
    motivo = primera[2] if len(primera) > 2 else ""
    version = primera[0] if primera else "HTTP/1.1"
    return {"version": version, "status": status, "motivo": motivo,
            "cabeceras": _parsear_cabeceras(lineas[1:]), "cuerpo": cuerpo}


def _entradas_trafico(datos):
    """Empareja cada petición con su respuesta."""
    return datos.get("trafico") or []


# ---------------------------------------------------------------------------
# HAR 1.2
# ---------------------------------------------------------------------------

def a_har(datos):
    """Devuelve el HAR como estructura dict (JSON-serializable)."""
    meta = datos["meta"]
    entradas = []
    ahora = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())

    for t in _entradas_trafico(datos):
        url = t.get("url", "")
        pet = parsear_peticion(t.get("peticion")) or {}
        res = parsear_respuesta(t.get("respuesta")) or {}
        host, puerto, esquema = _host_puerto(url)
        u = urllib.parse.urlsplit(url if "//" in url else "//" + url)
        consulta = []
        for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True):
            consulta.append({"name": k, "value": v})

        cab_pet = [{"name": k, "value": v}
                   for k, v in (pet.get("cabeceras") or [])]
        cab_res = [{"name": k, "value": v}
                   for k, v in (res.get("cabeceras") or [])]
        if not cab_pet:
            cab_pet = [{"name": "Host", "value": host}]

        request = {
            "method": pet.get("metodo") or t.get("metodo") or "GET",
            "url": url,
            "httpVersion": pet.get("version") or "HTTP/1.1",
            "cookies": _cookies_de(pet.get("cabeceras") or []),
            "headers": cab_pet,
            "queryString": consulta,
            "headersSize": -1,
            "bodySize": len(pet.get("cuerpo") or "") or -1,
        }
        if pet.get("cuerpo"):
            ctype = ""
            for k, v in (pet.get("cabeceras") or []):
                if k.lower() == "content-type":
                    ctype = v
            request["postData"] = {"mimeType": ctype or "application/octet-stream",
                                   "text": pet["cuerpo"]}

        cuerpo_res = res.get("cuerpo") or ""
        ctype_res = ""
        for k, v in (res.get("cabeceras") or []):
            if k.lower() == "content-type":
                ctype_res = v
        response = {
            "status": res.get("status") or t.get("status") or 0,
            "statusText": res.get("motivo") or "",
            "httpVersion": res.get("version") or "HTTP/1.1",
            "cookies": [],
            "headers": cab_res,
            "content": {
                "size": len(cuerpo_res),
                "mimeType": ctype_res or "text/html",
                "text": cuerpo_res[:200000],
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": len(cuerpo_res),
        }
        if not cab_res:
            response["headers"] = [{"name": "Content-Type",
                                    "value": ctype_res or "text/html"}]

        ms = float(t.get("ms") or 0.0)
        entradas.append({
            "startedDateTime": ahora,
            "time": ms,
            "request": request,
            "response": response,
            "cache": {},
            "timings": {"send": 0.0, "wait": ms, "receive": 0.0},
            "serverIPAddress": t.get("ip", ""),
            "_hunterbug": {"host": host, "port": puerto, "scheme": esquema},
        })

    return {
        "log": {
            "version": "1.2",
            "creator": {"name": HERRAMIENTA, "version": VERSION,
                        "comment": "Evaluación de %s" % meta["objetivo"]},
            "pages": [{
                "startedDateTime": ahora,
                "id": "page_1",
                "title": "HunterBug — %s" % meta["objetivo"],
                "pageTimings": {"onContentLoad": -1, "onLoad": -1},
            }] if entradas else [],
            "entries": entradas,
        }
    }


def escribir_har(datos, ruta):
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(a_har(datos), f, ensure_ascii=False, indent=2)
    return ruta


# ---------------------------------------------------------------------------
# Burp Suite XML
# ---------------------------------------------------------------------------

DTD_BURP = """<!DOCTYPE issues [
<!ELEMENT issues (issue*)>
<!ATTLIST issues burpVersion CDATA "0" exportTime CDATA "0">
<!ELEMENT issue (serialNumber,type,name,host,path,location,severity,confidence,
issueBackground?,remediationBackground?,issueDetail?,requestresponse?)>
<!ELEMENT serialNumber (#PCDATA)>
<!ELEMENT type (#PCDATA)>
<!ELEMENT name (#PCDATA)>
<!ELEMENT host (#PCDATA)>
<!ATTLIST host ip CDATA "">
<!ELEMENT path (#PCDATA)>
<!ELEMENT location (#PCDATA)>
<!ELEMENT severity (#PCDATA)>
<!ELEMENT confidence (#PCDATA)>
<!ELEMENT issueBackground (#PCDATA)>
<!ELEMENT remediationBackground (#PCDATA)>
<!ELEMENT issueDetail (#PCDATA)>
<!ELEMENT requestresponse (request?,response?)>
<!ELEMENT request (#PCDATA)>
<!ATTLIST request base64 CDATA "false">
<!ELEMENT response (#PCDATA)>
<!ATTLIST response base64 CDATA "false">
]>"""


def _trafico_para_url(datos, url):
    for t in _entradas_trafico(datos):
        if t.get("url") == url:
            return t
    return None


def a_burp_xml(datos):
    meta = datos["meta"]
    sello = time.strftime("%a %b %d %H:%M:%S %Z %Y", time.localtime())
    o = ['<?xml version="1.0"?>', DTD_BURP,
         '<issues burpVersion="2024.1.1" exportTime="%s">' % _xml_attr(sello)]

    for i, h in enumerate(datos["hallazgos"], start=1):
        url = h.get("url") or meta["objetivo"]
        host, _, esquema = _host_puerto(url)
        try:
            ruta = urllib.parse.urlsplit(
                url if "//" in url else "//" + url).path or "/"
        except Exception:
            ruta = "/"
        ip = ""
        tr = _trafico_para_url(datos, url)
        if tr and tr.get("ip"):
            ip = tr["ip"]

        detalle = []
        if h.get("id"):
            detalle.append("Identificador del chequeo: %s" % h["id"])
        if h.get("categoria"):
            detalle.append("Categoría: %s" % h["categoria"])
        if h.get("parametro"):
            detalle.append("Parámetro afectado: %s" % h["parametro"])
        if h.get("cwe"):
            detalle.append("CWE: %s" % h["cwe"])
        if h.get("owasp"):
            detalle.append("OWASP Top 10: %s" % h["owasp"])
        detalle.append("Severidad original en HunterBug: %s"
                       % h["severidad"])
        if h.get("detalle"):
            detalle.append("")
            detalle.append(h["detalle"])
        ev = h.get("evidencia") or {}
        if ev:
            detalle.append("")
            detalle.append("Evidencia:")
            for k, v in ev.items():
                if isinstance(v, (list, tuple)):
                    v = ", ".join(str(z) for z in v)
                elif isinstance(v, dict):
                    v = json.dumps(v, ensure_ascii=False)
                detalle.append("  %s: %s" % (k, str(v)[:800]))

        o.append("<issue>")
        o.append("<serialNumber>%d</serialNumber>" % i)
        o.append("<type>%d</type>" % (1048832 + i))
        o.append("<name>%s</name>" % _cdata(h["titulo"]))
        o.append('<host ip="%s">%s://%s</host>'
                 % (_xml_attr(ip), _xml_attr(esquema), _xml_attr(host)))
        o.append("<path>%s</path>" % _cdata(ruta))
        o.append("<location>%s</location>" % _cdata(url))
        o.append("<severity>%s</severity>"
                 % BURP_SEV.get(h["severidad"], "Information"))
        o.append("<confidence>%s</confidence>"
                 % BURP_CONF.get(h["severidad"], "Tentative"))
        o.append("<issueBackground>%s</issueBackground>" % _cdata(
            "Comprobación realizada por %s. Categoría: %s.%s"
            % (HERRAMIENTA, h.get("categoria", ""),
               (" Referencia: " + h["owasp"]) if h.get("owasp") else "")))
        o.append("<remediationBackground>%s</remediationBackground>" % _cdata(
            h.get("recomendacion") or "Revisar y corregir según las buenas "
            "prácticas del marco correspondiente."))
        o.append("<issueDetail>%s</issueDetail>" % _cdata("\n".join(detalle)))
        if tr:
            o.append("<requestresponse>")
            o.append('<request base64="false">%s</request>'
                     % _cdata(tr.get("peticion") or ""))
            o.append('<response base64="false">%s</response>'
                     % _cdata(tr.get("respuesta") or ""))
            o.append("</requestresponse>")
        o.append("</issue>")

    o.append("</issues>")
    return "\n".join(o)


def escribir_burp_xml(datos, ruta):
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(a_burp_xml(datos))
    return ruta


# ---------------------------------------------------------------------------
# OWASP ZAP XML
# ---------------------------------------------------------------------------

def a_zap_xml(datos):
    meta = datos["meta"]
    sello = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
    host, puerto, esquema = _host_puerto(meta["objetivo"])

    o = ['<?xml version="1.0" encoding="UTF-8" standalone="no"?>',
         '<OWASPZAPReport version="2.14.0" generated="%s">' % _xml_attr(sello)]
    o.append('<site name="%s" host="%s" port="%d" ssl="%s">'
             % (_xml_attr(meta["objetivo"]), _xml_attr(host), puerto,
                "true" if esquema == "https" else "false"))
    o.append("<alerts>")

    for i, h in enumerate(datos["hallazgos"], start=1):
        url = h.get("url") or meta["objetivo"]
        riesgo = ZAP_RISK.get(h["severidad"], 0)
        conf = ZAP_CONF.get(h["severidad"], 2)
        desc = ["<p>%s</p>" % html.escape(h.get("detalle", ""))]
        if h.get("categoria"):
            desc.append("<p>Categoría: %s</p>" % html.escape(h["categoria"]))
        if h.get("cwe"):
            desc.append("<p>CWE: %s</p>" % html.escape(h["cwe"]))
        ev = h.get("evidencia") or {}
        if ev:
            desc.append("<p><strong>Evidencia</strong></p><ul>")
            for k, v in ev.items():
                if isinstance(v, (list, tuple)):
                    v = ", ".join(str(z) for z in v)
                elif isinstance(v, dict):
                    v = json.dumps(v, ensure_ascii=False)
                desc.append("<li>%s: %s</li>"
                            % (html.escape(str(k)),
                               html.escape(str(v)[:500])))
            desc.append("</ul>")
        sol = "<p>%s</p>" % html.escape(
            h.get("recomendacion") or "Revisar y corregir la configuración.")

        o.append("<alertitem>")
        o.append("<pluginid>%d</pluginid>" % (90000 + i))
        o.append("<alertRef>%d</alertRef>" % (90000 + i))
        o.append("<alert>%s</alert>" % _cdata(h["titulo"]))
        o.append("<name>%s</name>" % _cdata(h["titulo"]))
        o.append("<riskcode>%d</riskcode>" % riesgo)
        o.append("<confidence>%d</confidence>" % conf)
        o.append("<riskdesc>%s (%s)</riskdesc>"
                 % (ZAP_RISK_NOMBRE.get(riesgo, "Informational"),
                    {3: "High", 2: "Medium", 1: "Low", 0: "False Positive"}
                    .get(conf, "Medium")))
        o.append("<confidencedesc>%s</confidencedesc>"
                 % {3: "High", 2: "Medium", 1: "Low"}.get(conf, "Medium"))
        o.append("<desc>%s</desc>" % _cdata("".join(desc)))
        o.append("<instances>")
        o.append("<instance>")
        o.append("<uri>%s</uri>" % _cdata(url))
        o.append("<method>GET</method>")
        o.append("<param>%s</param>" % _cdata(h.get("parametro", "")))
        primera = ""
        for v in (h.get("evidencia") or {}).values():
            primera = str(v)[:200]
            break
        o.append("<evidence>%s</evidence>" % _cdata(primera))
        o.append("</instance>")
        o.append("</instances>")
        o.append("<count>1</count>")
        o.append("<solution>%s</solution>" % _cdata(sol))
        o.append("<otherinfo>%s</otherinfo>"
                 % _cdata("Identificador HunterBug: %s" % h.get("id", "")))
        o.append("<reference>%s</reference>"
                 % _cdata(h.get("owasp") or
                          "https://owasp.org/www-project-top-ten/"))
        o.append("<cweid>%d</cweid>" % _cwe_numero(h.get("cwe")))
        o.append("<wascid>0</wascid>")
        o.append("<sourceid>%d</sourceid>" % i)
        o.append("</alertitem>")

    o.append("</alerts>")
    o.append("</site>")
    o.append("</OWASPZAPReport>")
    return "\n".join(o)


def escribir_zap_xml(datos, ruta):
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(a_zap_xml(datos))
    return ruta


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------

def a_sarif(datos):
    meta = datos["meta"]
    reglas = []
    indice = {}
    for h in datos["hallazgos"]:
        rid = h.get("id") or h["titulo"]
        if rid in indice:
            continue
        indice[rid] = len(reglas)
        props = {"severity": h["severidad"], "categoria": h.get("categoria", ""),
                 "tool": HERRAMIENTA}
        if h.get("cwe"):
            props["cwe"] = h["cwe"]
        if h.get("owasp"):
            props["owasp"] = h["owasp"]
        regla = {
            "id": rid,
            "name": re.sub(r"[^A-Za-z0-9]+", "", str(rid)) or "Regla",
            "shortDescription": {"text": h["titulo"][:200]},
            "fullDescription": {"text": (h.get("detalle") or h["titulo"])[:1000]},
            "defaultConfiguration": {"level": SARIF_NIVEL.get(h["severidad"],
                                                              "note")},
            "properties": props,
        }
        if h.get("recomendacion"):
            regla["help"] = {"text": h["recomendacion"][:2000]}
        if h.get("cwe"):
            num = _cwe_numero(h["cwe"])
            if num:
                regla["relationships"] = [{
                    "target": {"id": "CWE-%d" % num, "toolComponent":
                               {"name": "CWE"}},
                    "kinds": ["superset"],
                }]
        reglas.append(regla)

    resultados = []
    for h in datos["hallazgos"]:
        rid = h.get("id") or h["titulo"]
        props = {"severity": h["severidad"], "categoria": h.get("categoria", ""),
                 "herramienta": HERRAMIENTA}
        if h.get("cwe"):
            props["cwe"] = h["cwe"]
        if h.get("owasp"):
            props["owasp"] = h["owasp"]
        if h.get("parametro"):
            props["parametro"] = h["parametro"]
        if h.get("evidencia"):
            props["evidencia"] = {k: (", ".join(str(z) for z in v)
                                      if isinstance(v, (list, tuple))
                                      else str(v)[:500])
                                  for k, v in h["evidencia"].items()}

        r = {
            "ruleId": rid,
            "ruleIndex": indice.get(rid, 0),
            "level": SARIF_NIVEL.get(h["severidad"], "note"),
            "message": {"text": (h.get("detalle") or h["titulo"])[:1500]},
            "properties": props,
        }
        url = h.get("url") or meta["objetivo"]
        r["locations"] = [{
            "physicalLocation": {
                "artifactLocation": {"uri": url},
                "region": {"startLine": 1},
            },
            "logicalLocations": [{"fullyQualifiedName": rid,
                                  "kind": "member"}],
        }]
        tr = _trafico_para_url(datos, url)
        if tr:
            pet = parsear_peticion(tr.get("peticion")) or {}
            res = parsear_respuesta(tr.get("respuesta")) or {}
            esquema = "https" if url.startswith("https") else "http"
            r["webRequest"] = {
                "protocol": esquema,
                "method": pet.get("metodo") or "GET",
                "target": url,
                "headers": {k: v for k, v in (pet.get("cabeceras") or [])},
            }
            if pet.get("cuerpo"):
                r["webRequest"]["body"] = {"text": pet["cuerpo"][:5000]}
            r["webResponse"] = {
                "protocol": esquema,
                "statusCode": res.get("status") or tr.get("status") or 0,
                "headers": {k: v for k, v in (res.get("cabeceras") or [])},
            }
            if res.get("cuerpo"):
                r["webResponse"]["body"] = {"text": res["cuerpo"][:5000]}
        resultados.append(r)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "HunterBug",
                "fullName": HERRAMIENTA,
                "version": VERSION,
                "informationUri": "https://github.com/HackingTeamOficial/HUNTERBUG",
                "rules": reglas,
            }},
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                              time.gmtime()),
                "commandLine": "HunterBug %s" % meta["objetivo"],
            }],
            "results": resultados,
            "properties": {
                "objetivo": meta["objetivo"],
                "autorizado": meta["autorizado"],
                "puntuacion": (datos.get("puntuacion") or {}).get("puntos"),
                "letra": (datos.get("puntuacion") or {}).get("letra"),
                "hallazgos": len(datos["hallazgos"]),
            },
        }],
    }


def escribir_sarif(datos, ruta):
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(a_sarif(datos), f, ensure_ascii=False, indent=2)
    return ruta
