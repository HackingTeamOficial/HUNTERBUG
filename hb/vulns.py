"""HunterBug - detectores de vulnerabilidades web.

Diseno NO destructivo y de bajo volumen, pensado para pruebas autorizadas:
- SQLi: basado en errores y diferencial booleano (sin time-based ni DoS)
- XSS:  reflexion de marcador unico (reflejado)
- IDOR: comparacion de acceso a objetos entre identificadores y sesiones
- BOLA: comparacion de acceso a objetos de API entre dos credenciales

Todas las funciones aceptan `pausa` para limitar la tasa de peticiones.
"""

from __future__ import annotations

import random
import re
import string
import time
import urllib.parse

from . import net

PAUSA_DEFECTO = 0.25      # segundos entre peticiones (moderado, no agresivo)
MAX_PARAMS = 12
MAX_PAYLOADS = 6


def parametros_de(url):
    """Devuelve [(nombre, valor)] de la query string."""
    q = urllib.parse.urlsplit(url).query
    if not q:
        return []
    return [(k, v[0] if v else "") for k, v in urllib.parse.parse_qs(q, keep_blank_values=True).items()]


def _sustituir_param(url, nombre, valor):
    p = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
    nueva = [(k, valor if k == nombre else v) for k, v in q]
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path,
                                    urllib.parse.urlencode(nueva), p.fragment))


# --------------------------------------------------------------------------
# SQLi
# --------------------------------------------------------------------------

FIRMAS_ERROR_SQL = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning:\s*mysql", "MySQL"),
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"microsoft ole db provider for sql server", "MSSQL"),
    (r"odbc sql server driver", "MSSQL"),
    (r"pg_query\(\)|postgresql.*error", "PostgreSQL"),
    (r"psql:.*error|syntax error at or near", "PostgreSQL"),
    (r"ora-\d{4,5}", "Oracle"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"sqlite3?\.(operational|programming)error", "SQLite"),
    (r"sqlite error", "SQLite"),
    (r"jdbc.*sqlexception", "Java JDBC"),
    (r"org\.hibernate", "Hibernate"),
    (r"syntax error.*sql", "SQL generico"),
    (r"division by zero", "SQL generico"),
]

PAYLOADS_ERROR = ["'", "\"", "')", "';", "\\", "'--", "\"--)", "1'"]
PAYLOADS_BOOL = [(" AND 1=1", " AND 1=2"), ("' AND '1'='1", "' AND '1'='2"),
                 (" AND 1=1--", " AND 1=2--")]


def _longitud_normalizada(texto):
    """Longitud quitando el ruido del propio payload reflejado."""
    return len(re.sub(r"\s+", " ", texto or ""))


def probar_sqli(url, cabeceras=None, pausa=PAUSA_DEFECTO, log=None, max_params=MAX_PARAMS):
    """Deteccion de SQLi por errores y diferencial booleano. No destructivo."""
    hallazgos = []
    params = parametros_de(url)[:max_params]
    if not params:
        if log:
            log("SQLi: la URL no tiene parametros en la query string", "aviso")
        return hallazgos

    base = net.peticion_http(url, cabeceras=cabeceras, timeout=12)
    if not base.ok and base.status == 0:
        if log:
            log("SQLi: no se pudo obtener la linea base: " + base.error, "error")
        return hallazgos
    if log:
        log("SQLi: linea base %d, %d bytes" % (base.status, base.cuerpo_bytes), "info")

    for nombre, valor in params:
        # --- fase 1: errores ---
        for pay in PAYLOADS_ERROR[:MAX_PAYLOADS]:
            if not valor:
                objetivo = pay
            else:
                objetivo = valor + pay
            u = _sustituir_param(url, nombre, objetivo)
            r = net.peticion_http(u, cabeceras=cabeceras, timeout=12)
            time.sleep(pausa)
            cuerpo = (r.cuerpo or "").lower()
            for patron, motor in FIRMAS_ERROR_SQL:
                if re.search(patron, cuerpo):
                    hallazgos.append({
                        "tipo": "sqli", "severidad": "critico",
                        "titulo": "Inyeccion SQL (basada en errores) en '%s'" % nombre,
                        "detalle": "El parametro '%s' refleja un error de %s al inyectar %r"
                                   % (nombre, motor, pay),
                        "url": u, "parametro": nombre,
                        "evidencia": {"payload": pay, "motor": motor,
                                      "fragmento": _extracto(r.cuerpo, patron)},
                        "recomendacion": "Usar consultas parametrizadas (prepared statements) "
                                         "y validacion estricta de entrada.",
                    })
                    if log:
                        log("SQLi CONFIRMADO (error %s) en %s" % (motor, nombre), "exito")
                    break
            else:
                continue
            break

        if any(h["parametro"] == nombre for h in hallazgos):
            continue

        # --- fase 2: diferencial booleano ---
        for v1, v2 in PAYLOADS_BOOL:
            u1 = _sustituir_param(url, nombre, (valor or "1") + v1)
            r1 = net.peticion_http(u1, cabeceras=cabeceras, timeout=12)
            time.sleep(pausa)
            u2 = _sustituir_param(url, nombre, (valor or "1") + v2)
            r2 = net.peticion_http(u2, cabeceras=cabeceras, timeout=12)
            time.sleep(pausa)

            if r1.status != r2.status and r1.status in (200, 500) and r2.status in (200, 500):
                hallazgos.append({
                    "tipo": "sqli", "severidad": "alto",
                    "titulo": "SQLi probable (diferencial booleano) en '%s'" % nombre,
                    "detalle": "Las condiciones verdadera/falsa devuelven codigos distintos "
                               "(%d vs %d) en el parametro '%s'"
                               % (r1.status, r2.status, nombre),
                    "url": u1, "parametro": nombre,
                    "evidencia": {"verdadero": {"url": u1, "status": r1.status,
                                                "bytes": r1.cuerpo_bytes},
                                  "falso": {"url": u2, "status": r2.status,
                                            "bytes": r2.cuerpo_bytes}},
                    "recomendacion": "Consultas parametrizadas; revisar el manejo de errores.",
                })
                if log:
                    log("SQLi probable (booleano) en %s" % nombre, "exito")
                break
            d = abs(_longitud_normalizada(r1.cuerpo) - _longitud_normalizada(r2.cuerpo))
            if d > 40 and r1.cuerpo != r2.cuerpo:
                hallazgos.append({
                    "tipo": "sqli", "severidad": "medio",
                    "titulo": "SQLi posible (respuesta difiere segun condicion) en '%s'" % nombre,
                    "detalle": "Diferencia de %d caracteres entre condicion verdadera y falsa "
                               "en '%s' (confirmar manualmente)" % (d, nombre),
                    "url": u1, "parametro": nombre,
                    "evidencia": {"delta_caracteres": d,
                                  "verdadero_bytes": r1.cuerpo_bytes,
                                  "falso_bytes": r2.cuerpo_bytes},
                    "recomendacion": "Verificar manualmente; usar consultas parametrizadas.",
                })
                if log:
                    log("SQLi posible (delta %d) en %s" % (d, nombre), "aviso")
                break
    return hallazgos


def _extracto(texto, patron, margen=90):
    if not texto:
        return ""
    m = re.search(patron, texto, re.IGNORECASE)
    if not m:
        return texto[:margen]
    a = max(0, m.start() - margen // 2)
    return re.sub(r"\s+", " ", texto[a:m.end() + margen]).strip()


# --------------------------------------------------------------------------
# XSS reflejado
# --------------------------------------------------------------------------

PAYLOADS_XSS = [
    '<hbmk{ID}>',
    '"><hbmk{ID}>',
    "'><hbmk{ID}>",
    '<img src=x onerror=hbmk{ID}>',
    'javascript:hbmk{ID}',
    '<svg/onload=hbmk{ID}>',
]


def probar_xss(url, cabeceras=None, pausa=PAUSA_DEFECTO, log=None, max_params=MAX_PARAMS):
    """XSS reflejado: inyecta un marcador unico y comprueba si vuelve sin escapar."""
    hallazgos = []
    params = parametros_de(url)[:max_params]
    if not params:
        if log:
            log("XSS: la URL no tiene parametros en la query string", "aviso")
        return hallazgos

    base = net.peticion_http(url, cabeceras=cabeceras, timeout=12)
    if log:
        log("XSS: linea base %d, %d bytes" % (base.status, base.cuerpo_bytes), "info")

    for nombre, valor in params:
        for plantilla in PAYLOADS_XSS[:MAX_PAYLOADS]:
            marca = "hb" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
            pay = plantilla.replace("{ID}", marca)
            u = _sustituir_param(url, nombre, pay)
            r = net.peticion_http(u, cabeceras=cabeceras, timeout=12)
            time.sleep(pausa)
            cuerpo = r.cuerpo or ""
            if marca not in cuerpo:
                continue

            escapado = ("&lt;hbmk" in cuerpo.replace(marca, "") or
                        "&quot;" in cuerpo or "&#" in cuerpo)
            if pay in cuerpo and not escapado:
                hallazgos.append({
                    "tipo": "xss", "severidad": "alto",
                    "titulo": "XSS reflejado en '%s'" % nombre,
                    "detalle": "El payload vuelve sin escapar en el cuerpo de la respuesta "
                               "del parametro '%s'" % nombre,
                    "url": u, "parametro": nombre,
                    "evidencia": {"payload": pay,
                                  "fragmento": _extracto(cuerpo, re.escape(marca))},
                    "recomendacion": "Escapar la salida segun contexto, aplicar CSP estricta "
                                     "y validar la entrada.",
                })
                if log:
                    log("XSS reflejado CONFIRMADO en %s" % nombre, "exito")
                break
            if marca in cuerpo:
                hallazgos.append({
                    "tipo": "xss", "severidad": "bajo",
                    "titulo": "Reflexion de entrada sin ejecucion clara en '%s'" % nombre,
                    "detalle": "El marcador se refleja pero parece escapado o en contexto "
                               "no ejecutable; revisar manualmente",
                    "url": u, "parametro": nombre,
                    "evidencia": {"payload": pay,
                                  "fragmento": _extracto(cuerpo, re.escape(marca))},
                    "recomendacion": "Confirmar el contexto y escapar la salida.",
                })
                if log:
                    log("XSS: reflexion (posible, revisar) en %s" % nombre, "aviso")
                break
    return hallazgos


# --------------------------------------------------------------------------
# IDOR / BOLA
# --------------------------------------------------------------------------

def _tokens(texto):
    return set(re.findall(r"[A-Za-z0-9@._-]{3,}", (texto or "").lower()))


def _similitud(a, b):
    """Jaccard sobre tokens: 1.0 = identico, 0.0 = nada en comun."""
    ta, tb = _tokens(a), _tokens(b)
    if not ta and not tb:
        return 1.0
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / float(len(ta | tb))


def _firma_respuesta(r):
    """Huella para comparar respuestas sin depender del cuerpo exacto."""
    return (r.status, r.cuerpo_bytes, len(_tokens(r.cuerpo)))


def comparar_acceso(url_a, url_b, cabeceras_a=None, cabeceras_b=None,
                    etiqueta_a="A", etiqueta_b="B", pausa=PAUSA_DEFECTO, log=None,
                    tipo="idor"):
    """Pide dos recursos y compara: detecta acceso indebido a objetos ajenos.

    Casos de uso:
      - IDOR: misma sesion, dos identificadores distintos (url_a / url_b).
      - BOLA: dos credenciales distintas sobre el mismo objeto.
    """
    ra = net.peticion_http(url_a, cabeceras=cabeceras_a, timeout=12)
    time.sleep(pausa)
    rb = net.peticion_http(url_b, cabeceras=cabeceras_b, timeout=12)

    if log:
        log("%s -> %d (%d bytes) | %s -> %d (%d bytes)"
            % (etiqueta_a, ra.status, ra.cuerpo_bytes,
               etiqueta_b, rb.status, rb.cuerpo_bytes), "info")

    hallazgos = []
    if ra.status == 0 or rb.status == 0:
        hallazgos.append({
            "tipo": "error", "severidad": "info",
            "titulo": "No se pudo contactar con el objetivo",
            "detalle": ra.error or rb.error, "url": url_a,
            "evidencia": {}, "recomendacion": "",
        })
        return hallazgos

    sim = _similitud(ra.cuerpo, rb.cuerpo)
    ambas_ok = ra.status in (200, 201, 202, 203) and rb.status in (200, 201, 202, 203)

    if ra.status in (200, 201, 202, 203) and rb.status in (401, 403):
        hallazgos.append({
            "tipo": tipo, "severidad": "info",
            "titulo": "Control de autorizacion correcto entre credenciales",
            "detalle": "%s obtiene %d y %s recibe %d: la autorizacion por objeto "
                       "funciona como deberia." % (etiqueta_a, ra.status,
                                                   etiqueta_b, rb.status),
            "url": url_a,
            "evidencia": {etiqueta_a: ra.status, etiqueta_b: rb.status},
            "recomendacion": "Sin accion: comportamiento esperado.",
        })
    elif ambas_ok and sim < 0.90:
        hallazgos.append({
            "tipo": tipo, "severidad": "alto",
            "titulo": ("Acceso a objeto ajeno (IDOR)" if tipo == "idor"
                       else "Fuga de datos entre credenciales (BOLA)"),
            "detalle": "Las dos peticiones devuelven 2xx con contenido claramente "
                       "distinto (similitud %.0f%%): se alcanza un objeto que no "
                       "corresponde al solicitante." % (sim * 100),
            "url": url_a,
            "evidencia": {etiqueta_a: {"url": url_a, "status": ra.status,
                                       "bytes": ra.cuerpo_bytes},
                          etiqueta_b: {"url": url_b, "status": rb.status,
                                       "bytes": rb.cuerpo_bytes},
                          "similitud": round(sim, 3),
                          "extracto_a": (ra.cuerpo or "")[:300],
                          "extracto_b": (rb.cuerpo or "")[:300]},
            "recomendacion": "Comprobar la propiedad del objeto en el servidor en cada "
                             "peticion (no confiar en el identificador del cliente).",
        })
    elif ambas_ok and sim >= 0.90:
        hallazgos.append({
            "tipo": tipo, "severidad": "medio",
            "titulo": "Respuestas casi identicas para objetos o credenciales distintas",
            "detalle": "Similitud %.0f%% entre las dos respuestas. Puede ser un recurso "
                       "publico legitimo o una fuga de datos entre cuentas; confirmar "
                       "manualmente." % (sim * 100),
            "url": url_a,
            "evidencia": {etiqueta_a: ra.status, etiqueta_b: rb.status,
                          "similitud": round(sim, 3),
                          "extracto_a": (ra.cuerpo or "")[:200]},
            "recomendacion": "Verificar que el objeto no expone datos de otra cuenta.",
        })
    else:
        hallazgos.append({
            "tipo": tipo, "severidad": "info",
            "titulo": "Sin diferencia concluyente entre las dos peticiones",
            "detalle": "%s -> %d, %s -> %d (similitud %.0f%%)"
                       % (etiqueta_a, ra.status, etiqueta_b, rb.status, sim * 100),
            "url": url_a,
            "evidencia": {etiqueta_a: ra.status, etiqueta_b: rb.status,
                          "similitud": round(sim, 3)},
            "recomendacion": "Probar con identificadores mas separados o con dos cuentas.",
        })
    return hallazgos


def probar_idor(url_patron, id_a, id_b, cabeceras=None, pausa=PAUSA_DEFECTO, log=None):
    """IDOR: misma sesion, dos identificadores. url_patron debe contener {id}."""
    if "{id}" not in url_patron:
        if log:
            log("IDOR: el patron debe contener {id}, p. ej. https://x/api/user/{id}", "error")
        return []
    ua = url_patron.replace("{id}", str(id_a))
    ub = url_patron.replace("{id}", str(id_b))
    if log:
        log("IDOR: comparando %s vs %s" % (ua, ub), "info")
    return comparar_acceso(ua, ub, cabeceras, cabeceras,
                           "id=" + str(id_a), "id=" + str(id_b), pausa, log,
                           tipo="idor")


def probar_bola(url, cookies_a=None, cookies_b=None, token_a=None, token_b=None,
                pausa=PAUSA_DEFECTO, log=None):
    """BOLA: mismo objeto de API, dos credenciales distintas."""
    ha, hb = {}, {}
    if cookies_a:
        ha["Cookie"] = cookies_a
    if cookies_b:
        hb["Cookie"] = cookies_b
    if token_a:
        ha["Authorization"] = token_a if token_a.lower().startswith(("bearer", "basic")) \
            else "Bearer " + token_a
    if token_b:
        hb["Authorization"] = token_b if token_b.lower().startswith(("bearer", "basic")) \
            else "Bearer " + token_b
    if log:
        log("BOLA: mismo recurso con dos credenciales", "info")
    return comparar_acceso(url, url, ha, hb, "cuenta-A", "cuenta-B", pausa, log,
                           tipo="bola")


# --------------------------------------------------------------------------
# Barrido automatico
# --------------------------------------------------------------------------

def analizar_url(url, cabeceras=None, pausa=PAUSA_DEFECTO, log=None,
                 hacer_sqli=True, hacer_xss=True):
    """Ejecuta los detectores aplicables a una URL con parametros."""
    todos = []
    if hacer_sqli:
        if log:
            log("--- SQLi ---", "info")
        todos += probar_sqli(url, cabeceras, pausa, log)
    if hacer_xss:
        if log:
            log("--- XSS ---", "info")
        todos += probar_xss(url, cabeceras, pausa, log)
    return todos
