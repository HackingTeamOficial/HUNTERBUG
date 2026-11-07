"""HunterBug 1.1 — utilidades de bug bounty: alcance y reportes.

Dos cosas que se hacen a mano en cada programa y que aquí van resueltas:

  * **Comprobar el alcance** antes de lanzar nada. Un `*.ejemplo.com` con
    exclusiones (`!dev.ejemplo.com`) es lo normal en un programa, y probar
    fuera de alcance no es un error técnico: es un problema serio. Este módulo
    parsea el alcance tal y como se copia de HackerOne o Bugcrowd y dice si una
    URL entra o no, con el motivo.
  * **Redactar el reporte** con la estructura que esperan las plataformas
    (título, severidad, resumen, pasos, impacto, evidencia, remediación), en
    Markdown listo para pegar, y con el CVSS y la confianza ya calculados.
"""

from __future__ import annotations

import re
import urllib.parse

from . import validacion

# ---------------------------------------------------------------------------
# Alcance
# ---------------------------------------------------------------------------
RE_URL = re.compile(r"^(?:https?://)?([^/\s:]+)", re.I)


def _normalizar_regla(linea):
    """Convierte una línea de alcance en una regla."""
    original = linea.strip()
    if not original or original.startswith("#"):
        return None
    excluir = False
    texto = original
    # formatos habituales de exclusión
    if texto.startswith("!"):
        excluir = True
        texto = texto[1:].strip()
    elif re.match(r"^(out[\s_-]?of[\s_-]?scope|oos)\s*[:=]", texto, re.I):
        excluir = True
        texto = re.split(r"[:=]", texto, 1)[1].strip()
    # quitar anotaciones tipo "  # comentario" o " - nota"
    texto = re.split(r"\s+#|\s+-\s+|\s+\(", texto)[0].strip()
    # quitar esquema y ruta
    if "://" in texto:
        texto = texto.split("://", 1)[1]
    texto = texto.split("/")[0].split("?")[0].strip().lower()
    if not texto or texto in ("*", "any", "all"):
        return {"regla": original, "patron": "*", "excluir": excluir,
                "comodin": True}
    return {"regla": original, "patron": texto, "excluir": excluir,
            "comodin": texto.startswith("*.")}


def cargar_alcance(texto):
    """Parsea un alcance copiado de la plataforma. Devuelve la lista de reglas."""
    reglas = []
    for linea in str(texto or "").splitlines():
        regla = _normalizar_regla(linea)
        if regla:
            reglas.append(regla)
    return reglas


def _host_de(url):
    try:
        u = urllib.parse.urlsplit(url if "//" in url else "//" + url)
        return (u.hostname or "").lower(), (u.port or
                                            (443 if u.scheme == "https"
                                             else 80))
    except Exception:
        return "", 0


def _coincide(host, patron):
    if patron == "*":
        return True
    if patron.startswith("*."):
        base = patron[2:]
        return host == base or host.endswith("." + base)
    if patron.startswith("."):
        base = patron[1:]
        return host == base or host.endswith("." + base)
    return host == patron


def en_alcance(url, reglas, puertos_extra=()):
    """Decide si la URL está dentro del alcance declarado.

    Devuelve (dentro, motivo, regla). Las exclusiones ganan siempre a las
    inclusiones: es como funcionan los programas.
    """
    host, puerto = _host_de(url)
    if not host:
        return False, "no se pudo extraer el host de la URL", ""
    if not reglas:
        return False, "no hay alcance declarado: confírmalo antes de probar", ""

    # 1) exclusiones primero
    for r in reglas:
        if r["excluir"] and _coincide(host, r["patron"]):
            return (False,
                    "'%s' está EXCLUIDO por la regla '%s'"
                    % (host, r["regla"]), r["regla"])

    # 2) inclusiones
    for r in reglas:
        if not r["excluir"] and _coincide(host, r["patron"]):
            motivo = "'%s' entra por la regla '%s'" % (host, r["regla"])
            if r["comodin"]:
                motivo += " (comodín de subdominios)"
            return True, motivo, r["regla"]

    return (False,
            "'%s' no coincide con ninguna regla de inclusión del alcance"
            % host, "")


def comprobar_lista(urls, reglas):
    """Comprueba varias URLs y devuelve el parte completo."""
    dentro, fuera = [], []
    for u in urls:
        ok, motivo, regla = en_alcance(u, reglas)
        (dentro if ok else fuera).append({"url": u, "motivo": motivo,
                                          "regla": regla})
    return {"dentro": dentro, "fuera": fuera,
            "resumen": {"total": len(urls), "dentro": len(dentro),
                        "fuera": len(fuera),
                        "reglas": len(reglas)}}


# ---------------------------------------------------------------------------
# Reporte para la plataforma
# ---------------------------------------------------------------------------
SEV_PLATAFORMA = {"critico": "critical", "alto": "high", "medio": "medium",
                  "bajo": "low", "info": "informational"}


def _primera_evidencia(h, limite=1200):
    ev = h.get("evidencia") or {}
    lineas = []
    for k, v in ev.items():
        if isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in v)
        elif isinstance(v, dict):
            import json
            v = json.dumps(v, ensure_ascii=False, indent=1)
        lineas.append("- **%s**: `%s`" % (k, str(v)[:limite]))
    return "\n".join(lineas)


def _pasos(h):
    """Pasos de reproducción a partir de lo que sabemos del hallazgo."""
    pasos = []
    url = h.get("url") or ""
    param = h.get("parametro") or ""
    ev = h.get("evidencia") or {}
    payload = ev.get("payload") or ev.get("carga") or ""

    if url:
        pasos.append("Abre o envía una petición a: `%s`" % url)
    if payload and param:
        pasos.append("Sustituye el parámetro `%s` por la carga útil: `%s`"
                     % (param, payload))
    elif payload:
        pasos.append("Usa la carga útil: `%s`" % payload)
    if ev.get("payloads"):
        pasos.append("Cargas útiles probadas: %s"
                     % ", ".join("`%s`" % p for p in ev["payloads"][:6]))
    if ev.get("status"):
        pasos.append("La respuesta es `%s`." % ev["status"])
    if not pasos:
        pasos.append("Reproduce la petición que se describe en la evidencia.")
    return pasos


def _impacto(h):
    tipo = str(h.get("tipo", "")).lower()
    impactos = {
        "sqli": ("Lectura y modificación arbitraria de la base de datos: datos "
                 "de todos los usuarios, credenciales y, según los permisos "
                 "del usuario de base de datos, ejecución de código en el "
                 "servidor."),
        "xss": ("Ejecución de JavaScript en el navegador de la víctima: robo "
                "de sesión y de tokens, acciones en su nombre y redirección a "
                "sitios maliciosos."),
        "dom-xss": ("Ejecución de JavaScript en el navegador de la víctima a "
                    "partir de datos controlables desde la URL."),
        "idor": ("Acceso a datos de otros usuarios cambiando un "
                 "identificador: exposición de información personal y, si "
                 "aplica, modificación de datos ajenos."),
        "bola": ("Acceso a objetos de otras cuentas a través de la API: "
                 "exposición de datos entre inquilinos y fuga de información."),
        "ssrf": ("El servidor realiza peticiones en nombre del atacante: "
                 "acceso a la red interna y a metadatos del proveedor cloud."),
        "traversal": ("Lectura de ficheros arbitrarios del servidor, incluidos "
                      "configuración y credenciales."),
        "lfi": "Inclusión de ficheros locales: lectura de código y configuración.",
        "open-redirect": ("Redirección a un dominio del atacante: phishing con "
                          "la confianza del dominio legítimo y robo de tokens "
                          "en flujos OAuth."),
    }
    return impactos.get(tipo, "Compromiso de la confidencialidad, integridad o "
                              "disponibilidad del servicio, según el fallo "
                              "descrito.")


def reporte_hackerone(h, programa=""):
    """Markdown con la estructura que espera HackerOne."""
    cv = h.get("cvss") or validacion.cvss_estimado(h)
    conf = h.get("confianza_calculada")
    if conf is None:
        conf = validacion.puntuar_confianza(h)[0]
    sev = SEV_PLATAFORMA.get(str(h.get("severidad", "info")).lower(),
                             "informational")
    L = []
    L.append("## %s" % h.get("titulo", "Hallazgo"))
    L.append("")
    L.append("**Severidad:** %s (CVSS %.1f) · **Confianza:** %d/100 · "
             "**Prioridad:** %s"
             % (sev, cv["puntos"], conf,
                h.get("prioridad") or validacion.prioridad(h, conf)))
    L.append("")
    if programa:
        L.append("**Programa:** %s" % programa)
        L.append("")
    L.append("### Resumen")
    L.append("")
    L.append(h.get("detalle", ""))
    L.append("")
    L.append("### Pasos para reproducir")
    L.append("")
    for i, p in enumerate(_pasos(h), start=1):
        L.append("%d. %s" % (i, p))
    L.append("")
    L.append("### Evidencia")
    L.append("")
    L.append(_primera_evidencia(h) or "- (sin evidencia adjunta)")
    L.append("")
    L.append("### Impacto")
    L.append("")
    L.append(_impacto(h))
    L.append("")
    L.append("### Remediación sugerida")
    L.append("")
    L.append(h.get("recomendacion") or "Corregir según las buenas prácticas "
                                       "del marco correspondiente.")
    L.append("")
    L.append("### Referencias")
    L.append("")
    if h.get("cwe"):
        L.append("- %s" % h["cwe"])
    if h.get("owasp"):
        L.append("- OWASP Top 10: %s" % h["owasp"])
    L.append("- CVSS 3.1: `%s`" % cv["vector"])
    L.append("")
    return "\n".join(L)


def reporte_bugcrowd(h, programa=""):
    """Markdown con la estructura que espera Bugcrowd (VRT)."""
    cv = h.get("cvss") or validacion.cvss_estimado(h)
    conf = h.get("confianza_calculada")
    if conf is None:
        conf = validacion.puntuar_confianza(h)[0]
    L = []
    L.append("# %s" % h.get("titulo", "Hallazgo"))
    L.append("")
    L.append("| Campo | Valor |")
    L.append("|---|---|")
    L.append("| Severidad | %s |"
             % str(h.get("severidad", "info")).capitalize())
    L.append("| CVSS 3.1 | %.1f (`%s`) |" % (cv["puntos"], cv["vector"]))
    L.append("| Confianza | %d/100 |" % conf)
    if h.get("cwe"):
        L.append("| CWE | %s |" % h["cwe"])
    if h.get("owasp"):
        L.append("| OWASP | %s |" % h["owasp"])
    if programa:
        L.append("| Programa | %s |" % programa)
    L.append("")
    L.append("## Descripción")
    L.append("")
    L.append(h.get("detalle", ""))
    L.append("")
    L.append("## Reproducción")
    L.append("")
    for i, p in enumerate(_pasos(h), start=1):
        L.append("%d. %s" % (i, p))
    L.append("")
    L.append("## Prueba de concepto")
    L.append("")
    L.append(_primera_evidencia(h) or "(sin evidencia adjunta)")
    L.append("")
    L.append("## Impacto")
    L.append("")
    L.append(_impacto(h))
    L.append("")
    L.append("## Solución propuesta")
    L.append("")
    L.append(h.get("recomendacion") or "Aplicar las buenas prácticas "
                                       "correspondientes.")
    L.append("")
    return "\n".join(L)


def reporte_generico(h):
    """Markdown neutro, para pegar donde haga falta."""
    return reporte_hackerone(h)


def reportes(hallazgos, programa="", plataforma="hackerone"):
    """Genera un reporte por hallazgo (y los une con separadores)."""
    funcion = {"hackerone": reporte_hackerone,
               "bugcrowd": reporte_bugcrowd,
               "generico": reporte_generico}.get(plataforma, reporte_hackerone)
    partes = []
    for h in hallazgos:
        partes.append(funcion(h, programa))
        partes.append("\n---\n")
    return "\n".join(partes)


def tabla_resumen(hallazgos):
    """Tabla Markdown con todos los hallazgos, para el índice del reporte."""
    L = ["| # | Prioridad | Severidad | CVSS | Confianza | Hallazgo | URL |",
         "|---|---|---|---|---|---|---|"]
    for i, h in enumerate(hallazgos, start=1):
        cv = (h.get("cvss") or validacion.cvss_estimado(h))["puntos"]
        conf = h.get("confianza_calculada")
        if conf is None:
            conf = validacion.puntuar_confianza(h)[0]
        # la prioridad puede no venir calculada: se calcula aquí
        prio = h.get("prioridad") or validacion.prioridad(h, conf)
        L.append("| %d | %s | %s | %.1f | %d | %s | `%s` |"
                 % (i, prio,
                    str(h.get("severidad", "")).capitalize(), cv, conf,
                    str(h.get("titulo", ""))[:60].replace("|", "/"),
                    str(h.get("url", ""))[:70]))
    return "\n".join(L)
