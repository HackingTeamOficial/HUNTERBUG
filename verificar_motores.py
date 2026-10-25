"""Verificacion de los motores de HunterBug 2.4.

Comprueba con datos reales:
  - detectores SQLi / XSS / IDOR / BOLA contra un servidor vulnerable local
  - auditoria de cabeceras y fingerprint contra ese servidor
  - base CVE local + comparacion de versiones
  - grafo de superficie de ataque y motor de IA por reglas
  - red real: DNS y HTTP contra example.com
"""

from __future__ import annotations

import sys
import traceback

sys.path.insert(0, ".")

from hb import net, vulns, cve, graph, ai, events
from banco_pruebas import ServidorPrueba

fallos = []
ok = 0


def check(nombre, condicion, extra=""):
    global ok
    if condicion:
        ok += 1
        print("  [OK]   %s %s" % (nombre, extra))
    else:
        fallos.append(nombre)
        print("  [FALLO] %s %s" % (nombre, extra))


def seccion(t):
    print("\n=== %s ===" % t)


log_lineas = []
def log(texto, nivel="info"):
    log_lineas.append((nivel, texto))

bus = events.Bus()

try:
    with ServidorPrueba() as srv:
        base = srv.base
        print("servidor vulnerable local en", base)

        # ---------------- SQLi ----------------
        seccion("SQLi (basado en errores)")
        h = vulns.probar_sqli(base + "/buscar?q=telefono", log=log)
        err = [x for x in h if "error" in x["titulo"].lower()]
        check("SQLi por errores detectado", len(err) >= 1,
              "-> %s" % (err[0]["titulo"] if err else "nada"))
        if err:
            check("SQLi severidad critico", err[0]["severidad"] == "critico",
                  "-> " + err[0]["severidad"])
            check("SQLi identifica el motor",
                  "MySQL" in str(err[0]["evidencia"].get("motor")),
                  "-> " + str(err[0]["evidencia"].get("motor")))
            check("SQLi aporta evidencia con fragmento",
                  bool(err[0]["evidencia"].get("fragmento")),
                  "-> " + str(err[0]["evidencia"].get("fragmento"))[:60])

        seccion("SQLi (diferencial booleano)")
        h2 = vulns.probar_sqli(base + "/item?id=1", log=log)
        check("SQLi diferencial detectado", len(h2) >= 1,
              "-> %s" % (h2[0]["titulo"] if h2 else "nada"))

        # ---------------- XSS ----------------
        seccion("XSS reflejado")
        hx = vulns.probar_xss(base + "/saludo?name=hola", log=log)
        alto = [x for x in hx if x["severidad"] == "alto"]
        check("XSS reflejado detectado", len(alto) >= 1,
              "-> %s" % (alto[0]["titulo"] if alto else "nada"))
        if alto:
            check("XSS incluye el payload usado",
                  "<" in alto[0]["evidencia"]["payload"],
                  "-> " + alto[0]["evidencia"]["payload"])

        # ---------------- IDOR ----------------
        seccion("IDOR")
        hi = vulns.probar_idor(base + "/api/usuario/{id}", 1, 2, log=log)
        idor = [x for x in hi if x["tipo"] == "idor"]
        check("IDOR detectado", len(idor) >= 1,
              "-> %s" % (idor[0]["titulo"] if idor else "nada"))
        if idor:
            check("IDOR marca severidad alto", idor[0]["severidad"] == "alto",
                  "-> " + idor[0]["severidad"])
            check("IDOR adjunta extractos de ambas respuestas",
                  bool(idor[0]["evidencia"].get("extracto_a")) and
                  bool(idor[0]["evidencia"].get("extracto_b")),
                  "-> %s" % idor[0]["evidencia"]["extracto_a"][:50])

        # ---------------- BOLA ----------------
        seccion("BOLA")
        hb1 = vulns.probar_bola(base + "/api/cuenta/1", token_a="tokenA",
                                token_b="tokenB", log=log)
        check("BOLA detecta autorizacion correcta (informativo)",
              any(x["severidad"] == "info" for x in hb1),
              "-> " + (hb1[0]["titulo"] if hb1 else "nada"))

        hb2 = vulns.probar_bola(base + "/api/fuga/1", token_a="tokenA",
                                token_b="tokenB", log=log)
        alto_b = [x for x in hb2 if x["severidad"] in ("alto", "medio")]
        check("BOLA detecta fuga entre credenciales", len(alto_b) >= 1,
              "-> %s" % (alto_b[0]["titulo"] if alto_b else "nada"))

        # ---------------- cabeceras / tecnologia ----------------
        seccion("Cabeceras y tecnologia")
        r = net.peticion_http(base + "/")
        check("HTTP en crudo captura peticion", "GET / HTTP/1.1" in r.peticion_cruda)
        check("HTTP en crudo captura respuesta", r.respuesta_cruda.startswith("HTTP/1.1"))
        hc = net.auditar_cabeceras(r)
        check("Auditoria encuentra cabeceras ausentes", len(hc) >= 4,
              "-> %d hallazgos" % len(hc))
        check("Detecta fuga de tecnologia (X-Powered-By)",
              any("x-powered-by" in str(x["titulo"]).lower() or
                  "x-powered-by" in str(x.get("evidencia", {})).lower() for x in hc),
              "-> " + str([x["titulo"] for x in hc if "revela" in x["titulo"]]))

        # ---------------- CVE ----------------
        seccion("CVE")
        tec = {"Server": "Apache/2.4.49 (Unix)", "X-Powered-By": "PHP/7.4.3"}
        hcv = cve.buscar_cves_por_tecnologias(tec, log=log)
        check("CVE local: Apache 2.4.49 -> CVE-2021-41773",
              any("CVE-2021-41773" in x["titulo"] for x in hcv),
              "-> %d coincidencias" % len(hcv))
        tec_ok = {"Server": "Apache/2.4.60"}
        hcv2 = cve.buscar_cves_por_tecnologias(tec_ok, log=log)
        check("CVE local: version parcheada NO se marca",
              not any("CVE-2021-41773" in x["titulo"] for x in hcv2),
              "-> %d coincidencias" % len(hcv2))
        check("Comparacion de versiones correcta",
              cve.version_en_rango("2.4.49", "2.4.49", "2.4.50") and
              not cve.version_en_rango("2.4.50", "2.4.49", "2.4.50") and
              not cve.version_en_rango("2.4.48", "2.4.49", "2.4.50"),
              "-> rangos semiabiertos")
        est = cve.estadisticas_base()
        check("Base CVE cargada", est["total"] >= 30,
              "-> %d CVEs (%d criticos)" % (est["total"], est["criticos"]))

        # ---------------- grafo ----------------
        seccion("Grafo de superficie de ataque")
        g = graph.construir_desde_resultados(
            "objetivo.test",
            dns={"A": ["10.0.0.5"], "NS": ["ns1.test"]},
            puertos=[{"puerto": 80, "servicio": "http", "banner": "PruebaSrv/1.0"},
                     {"puerto": 22, "servicio": "ssh", "banner": "OpenSSH_6.6.1p1"}],
            tecnologias=tec,
            hallazgos=err + alto + idor + hcv,
            subdominios=["api.objetivo.test"])
        res = g.resumen()
        check("Grafo tiene nodos", res["nodos"] >= 8, "-> %s" % res)
        check("Grafo tiene aristas", res["aristas"] >= 8, "-> %d aristas" % res["aristas"])
        pos = g.layout_fuerza(iteraciones=60)
        check("Layout calcula posiciones para todos los nodos",
              len(pos) == len(g.nodos), "-> %d posiciones" % len(pos))
        check("Layout dentro de los limites",
              all(0 <= x <= 1200 and 0 <= y <= 700 for x, y in pos.values()),
              "-> coordenadas acotadas")
        resumen_txt = g.resumen_para_ia()
        check("Resumen para IA no vacio", len(resumen_txt) > 200,
              "-> %d caracteres" % len(resumen_txt))
        check("Resumen incluye los CVE", "CVE-" in resumen_txt)

        # ---------------- IA ----------------
        seccion("Motor de IA")
        texto, motor = ai.analizar(res, [x for x in (err + alto + idor + hcv)],
                                   modelo="", log=log)
        check("IA produce analisis", len(texto) > 300,
              "-> %d caracteres" % len(texto))
        check("IA indica el motor usado", motor == "reglas-locales", "-> " + motor)
        for etiqueta in ("1) LECTURA DEL GRAFO", "2) CADENA DE ATAQUE",
                         "3) PRIORIDAD", "4) SIGUIENTES PRUEBAS"):
            check("Analisis contiene '%s'" % etiqueta, etiqueta in texto)
        check("Analisis cita los CVE encontrados", "CVE-" in texto)

        # ---------------- eventos ----------------
        seccion("Bus de eventos")
        bus.log("dns", "hola", "info")
        bus.hallazgo("sqli", {"titulo": "x", "severidad": "alto"})
        bus.progreso("puertos", 55)
        evs = bus.drenar()
        check("Bus entrega eventos en orden", len(evs) == 3, "-> %d" % len(evs))
        check("Bus conserva historial", len(bus.historial()) == 3)
        check("Bus filtra por tipo", len(bus.historial(events.HALLAZGO)) == 1)

except Exception:
    fallos.append("excepcion general")
    traceback.print_exc()

# ---------------- red real ----------------
seccion("Red real (example.com)")
try:
    rr = net.peticion_http("https://example.com", seguir=1)
    check("HTTPS real responde 200", rr.status == 200,
          "-> %d en %.2fs" % (rr.status, rr.tiempo))
    check("TLS negociado", bool(rr.tls.get("version")),
          "-> %s %s" % (rr.tls.get("version"), rr.tls.get("cipher")))
    check("IP resuelta", bool(rr.ip), "-> " + rr.ip)
    d = net.recon_dns("example.com")
    check("DNS real devuelve registros A", len(d.get("A", [])) >= 1,
          "-> %s" % d.get("A", [])[:2])
    check("DNS real devuelve NS", len(d.get("NS", [])) >= 1,
          "-> %s" % d.get("NS", [])[:2])
except Exception:
    fallos.append("red real")
    traceback.print_exc()

print("\n" + "=" * 60)
print("PRUEBAS OK: %d | FALLOS: %d" % (ok, len(fallos)))
if fallos:
    for f in fallos:
        print("   - " + f)
    sys.exit(1)
print("TODOS LOS MOTORES VERIFICADOS CORRECTAMENTE")
