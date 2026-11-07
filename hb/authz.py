"""HunterBug 1.1 — motor de IDOR y BOLA.

IDOR (referencia directa insegura a objetos) y BOLA (autorización a nivel de
objeto en APIs) son el mismo fallo visto desde dos sitios: el servidor te
entrega un objeto que no es tuyo porque no comprueba la propiedad, solo que
estés autenticado.

Lo que aporta este motor frente a comparar dos IDs a mano:

  * **Descubre los objetos** de la URL sola: enteros en la ruta, UUID, hashes y
    valores numéricos en parámetros, cada uno con su posición exacta.
  * **Evalúa si el identificador es predecible**: un entero secuencial o un
    UUID v1 (que lleva la marca de tiempo dentro) se enumeran trivialmente; un
    UUID v4 no.
  * **Enumera vecinos de forma acotada** (por defecto 3 por lado) y compara con
    similitud Jaccard: si el vecino devuelve contenido distinto y con pinta de
    dato real, es candidato; si devuelve 403 o la misma página, no.
  * **BOLA con dos credenciales**: si la respuesta con la credencial B es
    prácticamente idéntica a la de A, el servidor no distingue de quién es el
    objeto.
"""

from __future__ import annotations

import re
import time
import urllib.parse

from . import net, vulns

PAUSA = 0.15

RE_ENTERO = re.compile(r"^\d{1,12}$")
RE_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-([0-9a-f])[0-9a-f]{3}-"
                     r"[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
RE_HEX = re.compile(r"^[0-9a-f]{16,64}$", re.I)
RE_B64 = re.compile(r"^[A-Za-z0-9+/]{12,}={0,2}$")

# páginas que NO son un objeto: si el vecino devuelve esto, no es IDOR
PISTAS_ERROR = [
    "not found", "no encontrado", "no existe", "forbidden", "prohibido",
    "access denied", "acceso denegado", "unauthorized", "no autorizado",
    "error 404", "error 403", "page not found", "404 not found",
    "no tiene permisos", "sin permisos", "invalid id", "id invalido",
]


def _texto(r):
    return (r.cuerpo or "") if r is not None else ""


def _peticion(url, cabeceras=None, timeout=12):
    return net.peticion_http(url, cabeceras=cabeceras, timeout=timeout)


def _parece_error(cuerpo):
    bajo = cuerpo.lower()
    return any(p in bajo for p in PISTAS_ERROR)


# ---------------------------------------------------------------------------
# Descubrimiento de objetos
# ---------------------------------------------------------------------------
def descubrir_objetos(url):
    """Localiza los identificadores de objeto que hay en la URL."""
    partes = urllib.parse.urlsplit(url if "//" in url else "//" + url)
    objetos = []

    # en la ruta
    segmentos = [s for s in partes.path.split("/") if s]
    for i, seg in enumerate(segmentos):
        if RE_ENTERO.match(seg):
            objetos.append({"donde": "ruta", "posicion": i, "valor": seg,
                            "tipo": "entero"})
        elif RE_UUID.match(seg):
            objetos.append({"donde": "ruta", "posicion": i, "valor": seg,
                            "tipo": "uuid"})
        elif RE_HEX.match(seg):
            objetos.append({"donde": "ruta", "posicion": i, "valor": seg,
                            "tipo": "hex"})

    # en los parámetros
    for nombre, valor in vulns.parametros_de(url):
        if RE_ENTERO.match(valor):
            objetos.append({"donde": "parametro", "posicion": nombre,
                            "valor": valor, "tipo": "entero"})
        elif RE_UUID.match(valor):
            objetos.append({"donde": "parametro", "posicion": nombre,
                            "valor": valor, "tipo": "uuid"})
        elif RE_HEX.match(valor):
            objetos.append({"donde": "parametro", "posicion": nombre,
                            "valor": valor, "tipo": "hex"})
    return objetos


def evaluar_identificador(valor):
    """Dice si el identificador es predecible y por qué."""
    valor = str(valor or "")
    if RE_ENTERO.match(valor):
        n = int(valor)
        return {"tipo": "entero", "predecible": True,
                "motivo": ("Entero secuencial (%d): los vecinos %d y %d son "
                           "triviales de probar." % (n, n - 1, n + 1)),
                "vecinos": [str(n - 1), str(n + 1)]}
    m = RE_UUID.match(valor)
    if m:
        version = m.group(1).lower()
        if version == "1":
            return {"tipo": "uuid-v1", "predecible": True,
                    "motivo": ("UUID v1: lleva la marca de tiempo y el MAC "
                               "dentro, así que se pueden generar UUID "
                               "válidos cercanos en el tiempo."),
                    "vecinos": []}
        if version == "4":
            return {"tipo": "uuid-v4", "predecible": False,
                    "motivo": "UUID v4 aleatorio: no es enumerable.",
                    "vecinos": []}
        return {"tipo": "uuid-v%s" % version, "predecible": False,
                "motivo": "UUID de versión %s." % version, "vecinos": []}
    if RE_HEX.match(valor):
        return {"tipo": "hex", "predecible": False,
                "motivo": "Hash hexadecimal: no enumerable directamente.",
                "vecinos": []}
    return {"tipo": "desconocido", "predecible": False,
            "motivo": "No parece un identificador enumerable.", "vecinos": []}


def _sustituir_objeto(url, objeto, nuevo):
    """Devuelve la URL con ese objeto cambiado por `nuevo`."""
    partes = urllib.parse.urlsplit(url if "//" in url else "//" + url)
    if objeto["donde"] == "ruta":
        segmentos = partes.path.split("/")
        # los segmentos no vacíos, en orden
        idx = -1
        for i, s in enumerate(segmentos):
            if s:
                idx += 1
                if idx == objeto["posicion"]:
                    segmentos[i] = str(nuevo)
                    break
        ruta = "/".join(segmentos)
        consulta = partes.query
    else:
        ruta = partes.path
        pares = urllib.parse.parse_qsl(partes.query, keep_blank_values=True)
        consulta = urllib.parse.urlencode(
            [(k, (str(nuevo) if k == objeto["posicion"] else v))
             for k, v in pares])
    return urllib.parse.urlunsplit((partes.scheme or "http", partes.netloc,
                                    ruta, consulta, ""))


# ---------------------------------------------------------------------------
# Enumeración acotada
# ---------------------------------------------------------------------------
def _vecinos_de(objeto, max_vecinos=3):
    """Valores vecinos razonables para enumerar."""
    if objeto["tipo"] == "entero":
        n = int(objeto["valor"])
        salida = []
        for d in range(1, max_vecinos + 1):
            salida.append(str(n + d))
            if n - d > 0:
                salida.append(str(n - d))
        return salida
    return []


def enumerar(url, cabeceras=None, pausa=PAUSA, log=None, max_vecinos=3):
    """Prueba vecinos del identificador y decide si hay IDOR."""
    log = log or (lambda t, n="info": None)
    objetos = descubrir_objetos(url)
    if not objetos:
        return {"url": url, "objetos": [], "hallazgos": [],
                "resumen": {"objetos": 0, "idor": False}}

    base = _peticion(url, cabeceras)
    cuerpo_base = _texto(base)
    if base.status == 0:
        return {"url": url, "objetos": objetos, "hallazgos": [],
                "resumen": {"objetos": len(objetos), "idor": False,
                            "error": base.error}}

    hallazgos = []
    detalles = []

    for obj in objetos[:3]:
        info = evaluar_identificador(obj["valor"])
        vecinos = _vecinos_de(obj, max_vecinos)
        log("Objeto %s en %s: %s (%s)"
            % (obj["valor"], obj["donde"], info["tipo"],
               "predecible" if info["predecible"] else "no enumerable"))
        if not vecinos:
            detalles.append({"objeto": obj, "info": info, "probados": 0,
                             "accesibles": 0})
            continue

        # sonda de control: un id que seguro no existe. Si un vecino se parece
        # a esta respuesta, es la página de "no existe", no un objeto real.
        u_control = _sustituir_objeto(url, obj, "99999999")
        r_control = _peticion(u_control, cabeceras)
        cuerpo_control = _texto(r_control)
        time.sleep(pausa)

        accesibles = []
        for v in vecinos:
            u = _sustituir_objeto(url, obj, v)
            r = _peticion(u, cabeceras)
            time.sleep(pausa)
            if r.status not in (200, 201, 206):
                continue
            cuerpo = _texto(r)
            if _parece_error(cuerpo) or len(cuerpo) < 20:
                continue
            if cuerpo_control and \
                    vulns._similitud(cuerpo, cuerpo_control) >= 0.90:
                continue          # es la misma página de "no existe"
            sim = vulns._similitud(cuerpo_base, cuerpo)
            if sim >= 0.995:
                continue          # el ID se ignora: misma página siempre
            accesibles.append({"id": v, "url": u, "status": r.status,
                               "bytes": r.cuerpo_bytes,
                               "similitud_con_base": round(sim, 3)})
            log("  vecino %s accesible (%d bytes, similitud %.2f)"
                % (v, r.cuerpo_bytes, sim))

        detalles.append({"objeto": obj, "info": info,
                         "probados": len(vecinos),
                         "accesibles": len(accesibles),
                         "detalle": accesibles[:4]})

        if accesibles:
            a = accesibles[0]
            hallazgos.append({
                "tipo": "idor", "severidad": "alto",
                "titulo": "IDOR: acceso a objetos de otros usuarios",
                "detalle": ("El identificador %s de la URL es predecible (%s) "
                            "y %d de %d vecinos probados devuelven contenido "
                            "distinto y con pinta de dato real (por ejemplo "
                            "%s, %d bytes). No se ha comprobado la propiedad "
                            "del objeto."
                            % (obj["valor"], info["motivo"], len(accesibles),
                               len(vecinos), a["id"], a["bytes"])),
                "url": a["url"], "parametro": str(obj["posicion"]),
                "cwe": "CWE-639", "owasp": "A01:2021",
                "confianza": 70,
                "recomendacion": (
                    "Comprobar en el servidor que el usuario autenticado es "
                    "propietario del objeto en cada petición, no solo que la "
                    "sesión sea válida. Usar identificadores opacos cuando el "
                    "objeto no tenga por qué ser público."),
                "evidencia": {"identificador": obj["valor"],
                              "tipo_identificador": info["tipo"],
                              "motivo_predecible": info["motivo"],
                              "vecinos_probados": vecinos,
                              "vecinos_accesibles": accesibles[:4],
                              "status_base": base.status},
            })

    return {
        "url": url, "objetos": detalles,
        "hallazgos": hallazgos,
        "resumen": {"objetos": len(objetos),
                    "idor": bool(hallazgos),
                    "accesibles": sum(d.get("accesibles", 0) for d in detalles)},
    }


# ---------------------------------------------------------------------------
# BOLA con dos credenciales
# ---------------------------------------------------------------------------
def _cabeceras_credencial(cookies=None, token=None):
    h = {}
    if cookies:
        h["Cookie"] = cookies
    if token:
        h["Authorization"] = token if " " in token else "Bearer " + token
    return h


def bola(url, cookies_a=None, token_a=None, cookies_b=None, token_b=None,
         pausa=PAUSA, log=None):
    """Compara la misma URL con dos identidades distintas."""
    log = log or (lambda t, n="info": None)
    ha = _cabeceras_credencial(cookies_a, token_a)
    hb = _cabeceras_credencial(cookies_b, token_b)
    if not ha or not hb:
        return {"url": url, "hallazgos": [],
                "resumen": {"bola": False, "motivo": "faltan credenciales"}}

    ra = _peticion(url, ha)
    time.sleep(pausa)
    rb = _peticion(url, hb)

    if ra.status == 0 or rb.status == 0:
        return {"url": url, "hallazgos": [],
                "resumen": {"bola": False, "motivo": "sin respuesta"}}

    cuerpo_a, cuerpo_b = _texto(ra), _texto(rb)
    sim = vulns._similitud(cuerpo_a, cuerpo_b)

    # Cobertura: qué parte de los datos de A aparecen en la respuesta de B.
    # Es la señal correcta cuando B ve un superconjunto (más campos), caso en
    # el que la similitud baja aunque el acceso sea total.
    tok_a = set(vulns._tokens(cuerpo_a))
    tok_b = set(vulns._tokens(cuerpo_b))
    cobertura = (len(tok_a & tok_b) / len(tok_a)) if tok_a else 0.0

    log("Credencial A: %d %d bytes | B: %d %d bytes | similitud %.2f | "
        "cobertura %.2f"
        % (ra.status, ra.cuerpo_bytes, rb.status, rb.cuerpo_bytes, sim,
           cobertura))

    hallazgos = []
    # B recibe el objeto de A: o casi idéntico, o un superconjunto de sus datos
    if ra.status in (200, 201) and rb.status in (200, 201) and \
            (sim >= 0.85 or cobertura >= 0.80):
        hallazgos.append({
            "tipo": "bola", "severidad": "alto",
            "titulo": "BOLA: la credencial B lee el objeto de A",
            "detalle": ("Con la credencial A la respuesta es %d (%d bytes) y "
                        "con la credencial B es %d (%d bytes): el %.0f%% de "
                        "los datos de A aparecen también en la respuesta de B "
                        "(similitud %.0f%%). El servidor autentica pero no "
                        "comprueba de quién es el objeto."
                        % (ra.status, ra.cuerpo_bytes, rb.status,
                           rb.cuerpo_bytes, cobertura * 100, sim * 100)),
            "url": url, "parametro": "",
            "cwe": "CWE-639", "owasp": "A01:2021", "confianza": 88,
            "recomendacion": ("Autorización a nivel de objeto: comprobar la "
                              "propiedad en cada operación, no solo la sesión."),
            "evidencia": {"status_a": ra.status, "bytes_a": ra.cuerpo_bytes,
                          "status_b": rb.status, "bytes_b": rb.cuerpo_bytes,
                          "similitud": round(sim, 3),
                          "cobertura_datos_a_en_b": round(cobertura, 3),
                          "extracto_b": cuerpo_b[:300]},
        })
    # B recibe 200 con datos distintos: también es acceso (a otro objeto)
    elif ra.status in (200, 201) and rb.status in (200, 201) and sim < 0.85:
        hallazgos.append({
            "tipo": "bola", "severidad": "medio",
            "titulo": "Posible BOLA: B obtiene respuesta propia en el objeto de A",
            "detalle": ("La credencial B recibe %d con contenido distinto al de "
                        "A (similitud %.0f%%, cobertura %.0f%%). Puede ser "
                        "correcto (cada uno ve lo suyo) o que B esté viendo "
                        "otro objeto: hay que revisarlo a mano."
                        % (rb.status, sim * 100, cobertura * 100)),
            "url": url, "parametro": "",
            "cwe": "CWE-639", "owasp": "A01:2021", "confianza": 40,
            "recomendacion": ("Confirmar manualmente qué objeto devuelve cada "
                              "credencial."),
            "evidencia": {"status_a": ra.status, "status_b": rb.status,
                          "similitud": round(sim, 3),
                          "cobertura_datos_a_en_b": round(cobertura, 3)},
        })
    return {
        "url": url, "hallazgos": hallazgos,
        "resumen": {"bola": bool(hallazgos), "similitud": round(sim, 3),
                    "cobertura": round(cobertura, 3),
                    "status_a": ra.status, "status_b": rb.status},
    }


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------
def analizar(url, cabeceras=None, pausa=PAUSA, log=None, max_vecinos=3,
             cookies_a=None, token_a=None, cookies_b=None, token_b=None):
    """Ejecuta el descubrimiento, la enumeración y, si hay credenciales, BOLA."""
    log = log or (lambda t, n="info": None)
    enum = enumerar(url, cabeceras, pausa, log, max_vecinos)
    hallazgos = list(enum["hallazgos"])

    res_bola = {}
    if (cookies_a or token_a) and (cookies_b or token_b):
        res_bola = bola(url, cookies_a, token_a, cookies_b, token_b, pausa, log)
        hallazgos += res_bola["hallazgos"]

    return {
        "url": url,
        "objetos": enum["objetos"],
        "hallazgos": hallazgos,
        "bola": res_bola,
        "resumen": {"objetos": enum["resumen"]["objetos"],
                    "idor": enum["resumen"]["idor"],
                    "bola": bool(res_bola.get("hallazgos")),
                    "hallazgos": len(hallazgos)},
    }
