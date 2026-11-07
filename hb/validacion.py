"""HunterBug 1.1 — validación, priorización y deduplicación de hallazgos.

Un bug hunter no entrega una lista de hallazgos: entrega hallazgos que puede
defender. Este módulo hace el trabajo que va entre "el detector dijo algo" y
"esto se reporta":

  * **Confianza** (0-100) con motivos explícitos, no un número inventado: sube
    si hay evidencia reproducible, si la técnica es determinista, si el
    hallazgo se confirmó con más de una prueba; baja si es un diferencial
    débil, un reflejo sin ejecución o una simple ausencia de cabecera.
  * **CVSS 3.1 estimado** por tipo de fallo (vector + puntuación), para no
    tener que calcularlo a mano en cada reporte.
  * **Prioridad** P1-P4 combinando severidad y confianza, que es lo que ordena
    de verdad el trabajo.
  * **Deduplicación**: el mismo fallo detectado por el catálogo, por el módulo
    dedicado y por el informe no son tres hallazgos, es uno.
  * **Revisión de falsos positivos conocidos**: casos donde la evidencia no
    sostiene la severidad que se le puso.
"""

from __future__ import annotations

import re
import urllib.parse

# ---------------------------------------------------------------------------
# CVSS 3.1 estimado por tipo
# ---------------------------------------------------------------------------
# (vector, puntuación base) — valores conservadores y defendibles
CVSS_POR_TIPO = {
    "sqli": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "rce": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "deserialization": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "xxe": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", 8.2),
    "ssti": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "ssrf": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N", 8.6),
    "traversal": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "lfi": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "idor": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    "bola": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    "xss": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "dom-xss": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "xss-reflejo": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", 3.1),
    "csrf": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3),
    "open-redirect": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3),
    "crlf": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "nosql": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1),
    "ldap": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", 8.2),
    "fuga": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "fuga-tecnologia": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    "cabecera-ausente": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", 3.1),
    "cve": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "enumeracion": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
}

# respaldo por severidad cuando el tipo no está en la tabla
CVSS_POR_SEVERIDAD = {
    "critico": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    "alto": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    "medio": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4),
    "bajo": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", 3.1),
    "info": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
}

# técnicas deterministas: si la evidencia está, el fallo existe
TIPOS_DETERMINISTAS = {"sqli", "xxe", "ssti", "traversal", "lfi", "crlf",
                       "rce", "deserialization", "fuga", "cve", "nosql",
                       "ldap"}
# técnicas de diferencial: necesitan más de una prueba para ser sólidas
TIPOS_DIFERENCIALES = {"xss", "idor", "bola", "ssrf", "csrf", "open-redirect",
                       "dom-xss", "enumeracion"}


def _tipo_de(h):
    t = str(h.get("tipo") or h.get("categoria") or "").lower()
    if t:
        return t
    cwe = str(h.get("cwe") or "")
    mapa = {"89": "sqli", "79": "xss", "639": "idor", "22": "traversal",
            "918": "ssrf", "611": "xxe", "1336": "ssti", "93": "crlf",
            "601": "open-redirect", "943": "nosql", "90": "ldap"}
    m = re.search(r"(\d+)", cwe)
    return mapa.get(m.group(1), "") if m else ""


def cvss_estimado(h):
    """Vector y puntuación CVSS 3.1 estimados para el hallazgo."""
    t = _tipo_de(h)
    if t in CVSS_POR_TIPO:
        vector, puntos = CVSS_POR_TIPO[t]
    else:
        sev = str(h.get("severidad", "info")).lower()
        vector, puntos = CVSS_POR_SEVERIDAD.get(sev, CVSS_POR_SEVERIDAD["info"])
    # si el propio hallazgo trae un CVSS (los CVE), se respeta
    ev = h.get("evidencia") or {}
    if ev.get("cvss"):
        try:
            puntos = float(str(ev["cvss"]).split()[0])
        except (ValueError, IndexError):
            pass
    return {"vector": vector, "puntos": round(float(puntos), 1),
            "version": "3.1", "estimado": not bool(ev.get("cvss"))}


def _nivel_cvss(puntos):
    if puntos >= 9.0:
        return "crítico"
    if puntos >= 7.0:
        return "alto"
    if puntos >= 4.0:
        return "medio"
    if puntos > 0.0:
        return "bajo"
    return "informativo"


# ---------------------------------------------------------------------------
# Confianza
# ---------------------------------------------------------------------------
def puntuar_confianza(h):
    """Devuelve (0-100, [motivos]) explicando la puntuación."""
    tipo = _tipo_de(h)
    ev = h.get("evidencia") or {}
    motivos = []
    puntos = 40

    if h.get("confianza") is not None:
        try:
            puntos = int(h["confianza"])
            motivos.append("el detector ya la estimó en %d" % puntos)
        except (TypeError, ValueError):
            pass

    if tipo in TIPOS_DETERMINISTAS:
        puntos += 20
        motivos.append("técnica determinista: la evidencia por sí sola "
                       "demuestra el fallo")
    elif tipo in TIPOS_DIFERENCIALES:
        motivos.append("técnica de diferencial: depende del comportamiento "
                       "observado")

    if ev:
        puntos += 10
        motivos.append("adjunta evidencia reproducible (%d campo(s))"
                       % len(ev))
        # evidencia con la marca o el payload concreto: más sólido.
        # Hay que mirar CLAVES y valores: la clave dice qué se demostró.
        blob = " ".join(list(ev.keys()) + [str(v) for v in ev.values()])
        if re.search(r"payload|extracto|marca|coincidencia|fragmento", blob,
                     re.I):
            puntos += 8
            motivos.append("la evidencia incluye la carga útil o el extracto "
                           "exacto")
        if ev.get("pares_de_acuerdo") or ev.get("columnas") or \
                ev.get("segundos_medidos"):
            puntos += 7
            motivos.append("el hallazgo se confirmó con más de una prueba")

    if h.get("recomendacion"):
        puntos += 3

    # penalizaciones
    if ev.get("escapado"):
        puntos -= 25
        motivos.append("la propia evidencia dice que la salida está escapada: "
                       "sin ejecución posible")
    if tipo == "xss-reflejo":
        puntos -= 30
        motivos.append("reflejo sin ejecución demostrada: no es un XSS "
                       "confirmado")
    if tipo == "dom-xss":
        puntos -= 15
        motivos.append("DOM XSS por análisis estático: falta confirmarlo en "
                       "un navegador")
    if tipo in ("cabecera-ausente", "fuga-tecnologia") or \
            str(h.get("severidad")) == "info":
        puntos -= 15
        motivos.append("es una debilidad de configuración, no una "
                       "vulnerabilidad explotable por sí sola")
    if not ev:
        puntos -= 20
        motivos.append("sin evidencia adjunta: no se puede reproducir")

    puntos = max(0, min(100, puntos))
    return puntos, motivos


def prioridad(h, confianza=None):
    """P1 (ahora) a P4 (cuando se pueda)."""
    sev = str(h.get("severidad", "info")).lower()
    conf = confianza if confianza is not None else puntuar_confianza(h)[0]
    cv = cvss_estimado(h)["puntos"]

    if sev == "critico" and conf >= 70:
        return "P1"
    if cv >= 9.0 and conf >= 70:
        return "P1"
    if sev in ("critico", "alto") and conf >= 60:
        return "P2"
    if cv >= 7.0 and conf >= 50:
        return "P2"
    if sev in ("alto", "medio") and conf >= 40:
        return "P3"
    return "P4"


# ---------------------------------------------------------------------------
# Falsos positivos conocidos
# ---------------------------------------------------------------------------
def revisar_falso_positivo(h):
    """Devuelve (es_dudoso, motivo) si la evidencia no sostiene la severidad."""
    tipo = _tipo_de(h)
    sev = str(h.get("severidad", "info")).lower()
    ev = h.get("evidencia") or {}

    if tipo == "xss" and ev.get("escapado"):
        return True, ("se marca como XSS pero la propia evidencia dice que la "
                      "salida está escapada")
    if tipo == "xss" and sev == "alto" and not ev.get("payload"):
        return True, "XSS de severidad alta sin la carga útil en la evidencia"
    if tipo in ("idor", "bola") and sev in ("alto", "critico") and \
            not ev.get("similitud") and not ev.get("cobertura_datos_a_en_b"):
        return True, ("IDOR/BOLA de severidad alta sin la comparación de "
                      "respuestas que lo sostenga")
    if tipo == "sqli" and sev == "critico" and not ev.get("coincidencia") \
            and not ev.get("payload"):
        return True, "SQLi crítico sin el error ni la carga útil en evidencia"
    if tipo in ("cabecera-ausente", "fuga-tecnologia") and sev in ("alto",
                                                                   "critico"):
        return True, ("una cabecera ausente no sostiene severidad alta por sí "
                      "sola")
    if ev.get("status") in (0, None) and tipo in TIPOS_DETERMINISTAS:
        return True, "sin respuesta del servidor que demuestre el fallo"
    return False, ""


# ---------------------------------------------------------------------------
# Deduplicación
# ---------------------------------------------------------------------------
def _clave(h):
    """Clave de identidad: mismo fallo = mismo tipo, misma URL y parámetro."""
    url = str(h.get("url") or "")
    try:
        u = urllib.parse.urlsplit(url if "//" in url else "//" + url)
        ruta = u.path.rstrip("/") or "/"
        host = (u.hostname or "").lower()
    except Exception:
        ruta, host = url, ""
    tipo = _tipo_de(h)
    # agrupa xss y dom-xss como el mismo fallo de inyección de script
    if tipo == "dom-xss":
        tipo = "xss"
    if tipo == "xss-reflejo":
        tipo = "xss-reflejo"
    param = str(h.get("parametro") or "").lower()
    titulo = re.sub(r"[^a-z0-9]+", "", str(h.get("titulo", "")).lower())[:40]
    return (host, ruta, tipo, param, titulo)


def deduplicar(hallazgos):
    """Une hallazgos repetidos y devuelve (lista, informe de fusiones)."""
    grupos = {}
    orden = []
    for h in hallazgos:
        k = _clave(h)
        if k not in grupos:
            grupos[k] = []
            orden.append(k)
        grupos[k].append(h)

    salida = []
    fusiones = []
    for k in orden:
        grupo = grupos[k]
        if len(grupo) == 1:
            salida.append(grupo[0])
            continue
        # se queda el de mayor confianza y se le unen las evidencias
        grupo.sort(key=lambda x: puntuar_confianza(x)[0], reverse=True)
        base = dict(grupo[0])
        evidencia = dict(base.get("evidencia") or {})
        fuentes = []
        for otro in grupo[1:]:
            for ek, ev_ in (otro.get("evidencia") or {}).items():
                if ek not in evidencia:
                    evidencia["%s (%s)" % (ek, _tipo_de(otro) or "otro")] = ev_
            if otro.get("modulo"):
                fuentes.append(otro["modulo"])
        if fuentes:
            evidencia["detectado_tambien_por"] = ", ".join(sorted(set(fuentes)))
        base["evidencia"] = evidencia
        base["duplicados_fusionados"] = len(grupo)
        salida.append(base)
        fusiones.append({"clave": k, "fusionados": len(grupo),
                         "conservado": base.get("titulo", "")})
    return salida, fusiones


# ---------------------------------------------------------------------------
# Proceso completo
# ---------------------------------------------------------------------------
ORDEN_PRIORIDAD = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}


def procesar(hallazgos, deduplicar_primero=True):
    """Deduplica, puntúa, calcula CVSS y ordena por prioridad."""
    originales = len(hallazgos)
    fusiones = []
    if deduplicar_primero:
        hallazgos, fusiones = deduplicar(hallazgos)

    salida = []
    for h in hallazgos:
        conf, motivos = puntuar_confianza(h)
        cv = cvss_estimado(h)
        dudoso, motivo_duda = revisar_falso_positivo(h)
        item = dict(h)
        item["confianza_calculada"] = conf
        item["motivos_confianza"] = motivos
        item["cvss"] = cv
        item["nivel_cvss"] = _nivel_cvss(cv["puntos"])
        item["prioridad"] = prioridad(h, conf)
        item["revisar"] = dudoso
        item["motivo_revision"] = motivo_duda
        salida.append(item)

    salida.sort(key=lambda x: (ORDEN_PRIORIDAD.get(x["prioridad"], 9),
                               -x["cvss"]["puntos"],
                               -x["confianza_calculada"]))
    return {
        "hallazgos": salida,
        "resumen": {
            "originales": originales,
            "tras_deduplicar": len(salida),
            "fusionados": originales - len(salida),
            "por_prioridad": {p: len([x for x in salida
                                      if x["prioridad"] == p])
                              for p in ("P1", "P2", "P3", "P4")},
            "a_revisar": len([x for x in salida if x["revisar"]]),
            "confianza_media": round(
                sum(x["confianza_calculada"] for x in salida) / len(salida), 1)
            if salida else 0.0,
        },
        "fusiones": fusiones,
    }
