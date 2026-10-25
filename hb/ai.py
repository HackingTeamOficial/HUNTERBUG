"""HunterBug - motor de IA: razonamiento sobre el grafo.

Usa Ollama (local) si esta disponible. Si no lo esta, aplica un motor de
reglas determinista para no dejar al analista sin conclusiones.
"""

from __future__ import annotations

import json
import urllib.request

OLLAMA = "http://127.0.0.1:11434"

SISTEMA = (
    "Eres un analista senior de seguridad ofensiva que trabaja en programas de "
    "bug bounty y pruebas autorizadas. Recibes la superficie de ataque observada "
    "en un objetivo. Responde SIEMPRE en espanol, de forma concreta y accionable. "
    "Estructura la respuesta asi:\n"
    "1) LECTURA DEL GRAFO: que es lo mas relevante de lo observado.\n"
    "2) CADENA DE ATAQUE: pasos concretos encadenando hallazgos.\n"
    "3) PRIORIDAD: los 3 puntos que atacaria primero y por que.\n"
    "4) SIGUIENTES PRUEBAS: comandos o peticiones concretas a lanzar.\n"
    "No inventes hallazgos que no esten en los datos. Si falta informacion, dilo."
)


def modelos_ollama(base=OLLAMA, timeout=4.0):
    """Lista de modelos locales instalados."""
    try:
        req = urllib.request.Request(base.rstrip("/") + "/api/tags",
                                     headers={"User-Agent": "HunterBug/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        return [m.get("name", "") for m in data.get("models", []) if m.get("name")]
    except Exception:
        return []


def ollama_vivo(base=OLLAMA, timeout=3.0):
    return bool(modelos_ollama(base, timeout))


def preguntar(modelo, pregunta, base=OLLAMA, timeout=180.0, sistema=SISTEMA):
    """Chat simple contra Ollama. Devuelve (texto, error)."""
    cuerpo = json.dumps({
        "model": modelo,
        "messages": [{"role": "system", "content": sistema},
                     {"role": "user", "content": pregunta}],
        "stream": False,
        "options": {"temperature": 0.3, "num_predict": 1200},
    }).encode("utf-8")
    req = urllib.request.Request(base.rstrip("/") + "/api/chat", data=cuerpo,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "HunterBug/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        return (data.get("message", {}) or {}).get("content", "").strip(), ""
    except Exception as e:
        return "", str(e)


# --------------------------------------------------------------------------
# Motor de reglas (respaldo sin IA)
# --------------------------------------------------------------------------

PESO_SEV = {"critico": 100, "alto": 60, "medio": 30, "bajo": 12, "info": 2}


def heuristica(resumen, hallazgos):
    """Analisis determinista del grafo y los hallazgos."""
    por_tipo = resumen.get("por_tipo", {})
    orden = {"critico": 0, "alto": 1, "medio": 2, "bajo": 3, "info": 4}
    hs = sorted(hallazgos or [],
                key=lambda h: orden.get(h.get("severidad", "info"), 5))

    criticos = [h for h in hs if h.get("severidad") == "critico"]
    altos = [h for h in hs if h.get("severidad") == "alto"]
    medios = [h for h in hs if h.get("severidad") == "medio"]
    cves = [h for h in hs if h.get("tipo") == "cve"]

    riesgo = min(100, sum(PESO_SEV.get(h.get("severidad", "info"), 0) for h in hs) // 2)

    out = []
    out.append("1) LECTURA DEL GRAFO")
    out.append("   Nodos %d / aristas %d. Superficie: %s."
               % (resumen.get("nodos", 0), resumen.get("aristas", 0),
                  ", ".join("%s=%s" % (k, v) for k, v in sorted(por_tipo.items())) or "vacia"))
    puertos = por_tipo.get("puerto", 0)
    tecnologias = por_tipo.get("tecnologia", 0)
    if puertos:
        out.append("   %d puerto(s) expuesto(s): cada servicio adicional amplia la "
                   "superficie y merece identificacion de version." % puertos)
    if tecnologias:
        out.append("   %d tecnologia(s) identificada(s): son el punto de partida "
                   "para el mapeo a CVE." % tecnologias)
    out.append("   Indice de riesgo calculado: %d/100." % riesgo)

    out.append("")
    out.append("2) CADENA DE ATAQUE PROBABLE")
    cadena = []
    if cves:
        cadena.append("Empezar por %d CVE conocido(s) (%s): si la version es la "
                      "afectada, el exploit publico es el camino mas corto."
                      % (len(cves), ", ".join(str((c.get('evidencia') or {}).get('cve', '?'))
                                              for c in cves[:4])))
    tipos = {h.get("tipo") for h in hs}
    if "sqli" in tipos:
        cadena.append("SQLi confirmada: encadenar con extraccion de esquema y, si hay "
                      "privilegios, lectura de ficheros o escritura.")
    if "xss" in tipos:
        cadena.append("XSS reflejado: buscar el contexto de sesion (cookies sin "
                      "HttpOnly) para escalar a robo de sesion.")
    if "idor" in tipos or "bola" in tipos:
        cadena.append("Fallo de autorizacion por objeto (IDOR/BOLA): enumerar "
                      "identificadores adyacentes para medir el alcance real.")
    if "cabecera-ausente" in tipos:
        cadena.append("Cabeceras ausentes (CSP/HSTS): facilitan el encadenado de XSS "
                      "y los ataques de intermediario.")
    if not cadena:
        cadena.append("Sin hallazgos confirmados todavia: la superficie observada no "
                      "muestra una via directa. Profundiza en parametros y endpoints.")
    out += ["   - " + c for c in cadena]

    out.append("")
    out.append("3) PRIORIDAD")
    if hs:
        for h in hs[:3]:
            out.append("   [%s] %s" % (str(h.get("severidad", "")).upper(),
                                       h.get("titulo", "")))
    else:
        out.append("   Aun no hay hallazgos que priorizar.")

    out.append("")
    out.append("4) SIGUIENTES PRUEBAS")
    if criticos:
        out.append("   - Confirmar manualmente los criticos antes de reportar y "
                   "capturar evidencia reproducible.")
    if cves:
        out.append("   - Verificar la version exacta del producto con una peticion "
                   "de identificacion antes de citar el CVE.")
    if "xss" not in tipos:
        out.append("   - Probar XSS en cada parametro reflejado y en cabeceras "
                   "(Referer, User-Agent) que se pinten en la respuesta.")
    if "sqli" not in tipos:
        out.append("   - Probar SQLi en los parametros numericos y en los filtros "
                   "de ordenacion/paginacion.")
    out.append("   - Revisar IDOR/BOLA en endpoints con identificador de objeto "
               "usando dos cuentas del mismo rol.")
    out.append("   - Comprobar autorizacion horizontal y vertical en la API "
               "(roles bajos sobre recursos de rol alto).")

    return "\n".join(out)


def analizar(resumen, hallazgos, modelo="", base=OLLAMA, log=None, timeout=180.0):
    """Devuelve (texto, motor_usado). Intenta Ollama y cae a las reglas."""
    if log:
        log("IA: preparando analisis del grafo (%d nodos, %d hallazgos)"
            % (resumen.get("nodos", 0), len(hallazgos or [])), "info")

    texto_local = heuristica(resumen, hallazgos)

    if modelo:
        prompt = (resumen.get("texto", "") +
                  "\n\nHALLAZGOS YA NORMALIZADOS:\n" +
                  "\n".join("[%s] %s" % (h.get("severidad", "?"), h.get("titulo", ""))
                            for h in (hallazgos or [])[:60]))
        if log:
            log("IA: consultando a Ollama con el modelo '%s'..." % modelo, "info")
        texto, err = preguntar(modelo, prompt, base, timeout)
        if texto:
            if log:
                log("IA: respuesta recibida de %s (%d caracteres)" % (modelo, len(texto)),
                    "exito")
            return texto, "ollama:" + modelo
        if log:
            log("IA: Ollama no respondio (%s). Uso el motor de reglas." % err[:80], "aviso")
    elif log:
        log("IA: sin modelo local seleccionado. Uso el motor de reglas.", "aviso")

    return texto_local, "reglas-locales"
