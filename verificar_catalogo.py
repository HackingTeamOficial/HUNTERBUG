"""Verificacion del catalogo de 203 chequeos de HunterBug 1.0.

Ejecuta el catalogo completo contra el laboratorio vulnerable local, con un
objetivo por familia de fallo, y comprueba que:
  * cada chequeo esperado dispara en el objetivo que le corresponde,
  * ninguno dispara donde no debe (guardas contra falsos positivos),
  * las metricas y la puntuacion cuadran,
  * funciona igual contra un objetivo real y sin autorizacion.
"""

from __future__ import annotations

import sys
import time
import traceback

sys.path.insert(0, ".")

from hb import checks, metrics
from banco_pruebas import ServidorPrueba

fallos = []
ok = 0


def check(nombre, cond, extra=""):
    global ok
    if cond:
        ok += 1
        print("  [OK]    %s %s" % (nombre, extra))
    else:
        fallos.append(nombre)
        print("  [FALLO] %s %s" % (nombre, extra))


def seccion(t):
    print("\n=== %s ===" % t)
    sys.stdout.flush()


# --------------------------------------------------------------------------
seccion("Catalogo")
res = checks.resumen_catalogo()
check("El catalogo tiene 200 o mas chequeos", res["total"] >= 200,
      "-> %d" % res["total"])
check("Hay chequeos activos y pasivos",
      res["activos"] > 0 and res["pasivos"] > 0,
      "-> %d activos / %d pasivos" % (res["activos"], res["pasivos"]))
ids = [c["id"] for c in checks.CATALOGO]
check("No hay identificadores duplicados", len(ids) == len(set(ids)))
check("Todos los chequeos tienen categoria valida",
      all(c["categoria"] in dict(checks.CATEGORIAS) for c in checks.CATALOGO))
check("Todas las categorias tienen chequeos",
      all(res["por_categoria"].get(c) for c, _ in checks.CATEGORIAS),
      "-> %s" % res["por_categoria"])

# --------------------------------------------------------------------------
OBJETIVOS = {
    "/buscar?q=test": (
        ["HDR-02", "HDR-03", "HDR-04", "HDR-05", "HDR-06", "HDR-07", "HDR-08",
         "HDR-36", "HDR-37", "HDR-38",
         "CKI-01", "CKI-02", "CKI-03", "CKI-07", "CKI-08", "CKI-12",
         "CRS-02", "CRS-03", "CRS-04", "CRS-06", "CRS-07",
         "MTH-01", "MTH-02", "MTH-03", "MTH-04", "MTH-05", "MTH-08",
         "CON-01", "CON-02", "CON-03", "CON-04", "CON-05", "CON-06", "CON-08",
         "CON-09", "CON-10", "CON-12", "CON-13", "CON-14", "CON-15", "CON-19",
         "CON-20", "CON-21", "CON-23", "CON-24",
         "FUG-01", "FUG-02", "FUG-03", "FUG-04", "FUG-05", "FUG-06", "FUG-07",
         "FUG-08", "FUG-09", "FUG-10", "FUG-11", "FUG-12", "FUG-14", "FUG-15",
         "FUG-16", "FUG-17", "FUG-19", "FUG-20", "FUG-22",
         "TEC-01", "TEC-05", "TEC-06",
         "PAR-01", "PAR-06", "PAR-09", "PAR-24", "PAR-27", "PAR-34", "PAR-37",
         "PAR-40"],
        ["PAR-10", "PAR-11", "PAR-12", "PAR-13", "PAR-15", "PAR-28",
         "PAR-20", "PAR-21", "HDR-01", "HDR-14"],
    ),
    "/item?id=1": (
        ["PAR-02", "PAR-30", "PAR-34", "HDR-02", "CKI-01", "CRS-02", "MTH-01"],
        ["PAR-10", "PAR-11", "PAR-12", "PAR-13", "PAR-15", "PAR-20", "PAR-21"],
    ),
    "/plantilla?name=x": (
        ["PAR-10", "PAR-11", "PAR-34", "HDR-02", "CKI-01"],
        ["PAR-12", "PAR-13", "PAR-15", "PAR-20", "PAR-21"],
    ),
    "/crlf?next=x": (
        ["PAR-12", "HDR-02", "CKI-01", "CRS-02"],
        ["PAR-10", "PAR-11", "PAR-13", "PAR-15", "PAR-20", "PAR-21"],
    ),
    "/fichero?file=x": (
        ["PAR-13", "HDR-02", "CKI-01"],
        ["PAR-10", "PAR-11", "PAR-12", "PAR-15", "PAR-20", "PAR-21"],
    ),
    "/redir?url=/": (
        ["PAR-15", "PAR-12", "PAR-38", "HDR-02", "CKI-01", "CRS-02"],
        ["PAR-10", "PAR-11", "PAR-13", "PAR-20", "PAR-21", "PAR-28"],
    ),
    "/hpp?a=1": (
        ["PAR-34", "HDR-02", "CKI-01", "CRS-02"],
        ["PAR-10", "PAR-11", "PAR-12", "PAR-13", "PAR-15", "PAR-20", "PAR-21"],
    ),
    "/precio?p=10": (
        ["PAR-30", "HDR-02", "CKI-01"],
        ["PAR-10", "PAR-11", "PAR-12", "PAR-13", "PAR-15", "PAR-20", "PAR-21"],
    ),
    "/error500": (
        ["CON-16", "CON-17", "CON-18", "RSP-12", "PAR-03", "PAR-04", "PAR-05",
         "HDR-02", "CKI-01"],
        ["PAR-10", "PAR-11", "PAR-12", "PAR-13", "PAR-15", "PAR-20", "PAR-21"],
    ),
    "/panel": (
        ["CON-01", "CON-02", "CON-03", "CON-04", "CON-05", "CON-06", "CON-08",
         "CON-09", "CON-10", "CON-12", "CON-13", "CON-14", "CON-15", "CON-19",
         "CON-20", "CON-21", "CON-23", "CON-24", "TEC-01", "TEC-05", "TEC-06",
         "HDR-02", "CKI-01", "CRS-02"],
        ["PAR-10", "PAR-11", "PAR-12", "PAR-13", "PAR-15", "PAR-20", "PAR-21",
         "PAR-28"],
    ),
    "/usuario?email=x": (
        ["PAR-28", "PAR-24", "HDR-02", "CKI-01", "CRS-02"],
        ["PAR-10", "PAR-11", "PAR-12", "PAR-13", "PAR-15", "PAR-20", "PAR-21"],
    ),
}

with ServidorPrueba() as srv:
    base = srv.base
    print("\nlaboratorio en", base)

    seccion("Ejecucion del catalogo completo por objetivo")
    resultados_globales = []
    peticiones_total = 0
    errores_global = []
    t0 = time.time()

    for ruta, (esperados, prohibidos) in OBJETIVOS.items():
        hallazgos, resultados, ctx = checks.ejecutar(
            base + ruta, autorizado=True, pausa=0.0)
        disparados = {r["id"] for r in resultados if r["estado"] == "fallo"}
        errores = {r["id"] for r in resultados if r["estado"] == "error"}
        peticiones_total += ctx.peticiones
        errores_global += sorted(errores)
        resultados_globales += resultados

        faltan = [i for i in esperados if i not in disparados]
        check("%-18s dispara sus chequeos (%d)" % (ruta, len(esperados)),
              not faltan, "-> faltan %s" % faltan[:8])
        mal = [i for i in prohibidos if i in disparados]
        check("%-18s sin falsos positivos" % ruta, not mal,
              "-> disparan %s" % mal[:8])
        check("%-18s sin errores internos" % ruta, not errores,
              "-> %s" % sorted(errores)[:5])
        check("%-18s ejecuta todo el catalogo" % ruta,
              len(resultados) == res["total"],
              "-> %d de %d" % (len(resultados), res["total"]))

    print("\n      %d objetivos | %d peticiones | %.1f s"
          % (len(OBJETIVOS), peticiones_total, time.time() - t0))
    check("Ningun error interno en ningun objetivo", not errores_global,
          "-> %s" % errores_global[:6])

    seccion("Cobertura del catalogo")
    distintos = {r["id"] for r in resultados_globales if r["estado"] == "fallo"}
    check("Mas de 100 chequeos distintos disparan", len(distintos) >= 100,
          "-> %d distintos" % len(distintos))
    check("Ningun chequeo ha quedado en estado de error",
          "error" not in {r["estado"] for r in resultados_globales})

    seccion("Metricas y puntuacion (objetivo principal)")
    h_main, res_main, ctx_main = checks.ejecutar(base + "/buscar?q=test",
                                                 autorizado=True, pausa=0.0)
    p, filas = metrics.cuadro(res_main, ctx=ctx_main)
    print("      puntuacion %s/100 (%s) | fallos %s"
          % (p["puntos"], p["letra"], p["por_severidad"]))
    check("La puntuacion esta en rango", 0 <= p["puntos"] <= 100,
          "-> %s" % p["puntos"])
    check("El laboratorio vulnerable suspende con nota muy baja",
          p["letra"] == "F" and p["puntos"] < 15.0,
          "-> letra %s (%s puntos)" % (p["letra"], p["puntos"]))
    check("La puntuacion es discriminativa (no se satura en 0)",
          0.5 < p["puntos"] < 15.0, "-> %s puntos" % p["puntos"])
    check("La cobertura es la maxima posible sobre HTTP",
          p["cobertura"] >= 85.0, "-> %.1f%%" % p["cobertura"])
    check("Cuenta los fallos por severidad",
          sum(p["por_severidad"].values()) == p["estados"]["fallo"],
          "-> %s" % p["por_severidad"])
    check("Desglose por categoria presente", len(p["categorias"]) >= 10,
          "-> %d categorias" % len(p["categorias"]))
    check("El cuadro tiene muchas filas", len(filas) >= 30,
          "-> %d filas" % len(filas))
    check("El cuadro incluye las peticiones",
          any("Peticiones" in f[0] for f in filas))
    check("El cuadro incluye la respuesta",
          any("Respuesta · status" in f[0] for f in filas))
    texto = metrics.texto_puntuacion(p)
    check("El resumen textual se genera", len(texto) > 300,
          "-> %d caracteres" % len(texto))

    seccion("Evidencia en los hallazgos")
    sin_evidencia = [h["id_check"] for h in h_main if not h.get("evidencia")]
    check("Todo hallazgo lleva evidencia", not sin_evidencia,
          "-> %s" % sin_evidencia[:8])
    sin_detalle = [h["id_check"] for h in h_main
                   if len(str(h.get("detalle", ""))) < 15]
    check("Todo hallazgo lleva detalle util", not sin_detalle,
          "-> %s" % sin_detalle[:8])
    con_cwe = [h for h in h_main if h.get("cwe")]
    check("Los hallazgos llevan CWE", len(con_cwe) >= len(h_main) * 0.9,
          "-> %d de %d" % (len(con_cwe), len(h_main)))
    con_rec = [h for h in h_main if h.get("recomendacion")]
    check("Los hallazgos llevan recomendacion",
          len(con_rec) >= len(h_main) * 0.9,
          "-> %d de %d" % (len(con_rec), len(h_main)))

    seccion("Chequeos exclusivos de HTTPS")
    https_ids = {c["id"] for c in checks.CATALOGO if c["solo_https"]}
    check("Hay chequeos exclusivos de HTTPS", len(https_ids) >= 10,
          "-> %d (%s...)" % (len(https_ids), sorted(https_ids)[:5]))
    check("En HTTP se omiten en lugar de fallar",
          all(r["estado"] != "fallo" for r in res_main if r["id"] in https_ids))

    seccion("Ejecucion sin autorizacion (solo pasivo)")
    h2, r2, ctx2 = checks.ejecutar(base + "/buscar?q=test", autorizado=False,
                                   pausa=0.0)
    d2 = {r["id"] for r in r2 if r["estado"] == "fallo"}
    o2 = {r["id"] for r in r2 if r["estado"] == "omitido"}
    check("Sin autorizacion se omiten los activos", len(o2) >= 60,
          "-> %d omitidos" % len(o2))
    check("Sin autorizacion no se disparan activos",
          not any(checks.por_id(cid)["activo"] for cid in d2),
          "-> %s" % sorted(d2)[:6])
    check("Sin autorizacion siguen los pasivos", len(d2) >= 20,
          "-> %d pasivos disparados" % len(d2))
    p2 = metrics.puntuacion(r2)
    check("La cobertura baja sin autorizacion", p2["cobertura"] < 70,
          "-> %.1f%%" % p2["cobertura"])

# --------------------------------------------------------------------------
seccion("Objetivo real (example.com, solo pasivo)")
try:
    h3, r3, ctx3 = checks.ejecutar("https://example.com", autorizado=False,
                                    pausa=0.0)
    d3 = {r["id"] for r in r3 if r["estado"] == "fallo"}
    e3 = [r for r in r3 if r["estado"] == "error"]
    p3 = metrics.puntuacion(r3)
    check("Se ejecuta contra un sitio real", len(r3) == res["total"],
          "-> %d chequeos" % len(r3))
    check("Sin errores internos en un sitio real", not e3,
          "-> %s" % [r["id"] for r in e3][:6])
    check("Detecta cabeceras ausentes en example.com", len(d3) >= 3,
          "-> %s" % sorted(d3)[:8])
    check("Puntuacion calculada en real", 0 <= p3["puntos"] <= 100,
          "-> %s/100 (%s)" % (p3["puntos"], p3["letra"]))
    check("El objetivo real puntua claramente mejor que el laboratorio roto",
          p3["puntos"] > p["puntos"] + 30,
          "-> real %s frente a laboratorio %s"
          % (p3["puntos"], p["puntos"]))
    check("TLS analizado en real",
          any(r["id"].startswith("TLS-") and r["estado"] == "ok" for r in r3),
          "-> version negociada correctamente")
except Exception:
    fallos.append("objetivo real")
    traceback.print_exc()

print("\n" + "=" * 64)
print("PRUEBAS OK: %d | FALLOS: %d" % (ok, len(fallos)))
if fallos:
    for f in fallos[:40]:
        print("   - " + str(f))
    sys.exit(1)
print("CATALOGO DE %d CHEQUEOS VERIFICADO" % res["total"])
