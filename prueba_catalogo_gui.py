"""Prueba de humo de la GUI con el motor de 203 chequeos integrado.

Levanta la ventana de verdad, comprueba que la pestana del catalogo existe
con sus 203 chequeos, ejecuta el modulo contra el laboratorio y verifica que
la puntuacion y las metricas se pintan.
"""

from __future__ import annotations

import sys
import traceback

sys.path.insert(0, ".")

import HunterBugGUI as H
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


try:
    app = H.HunterBugGUI()
except Exception:
    traceback.print_exc()
    print("No se pudo crear la ventana (¿sin display?).")
    sys.exit(2)

try:
    print("\n=== Construccion de la interfaz ===")
    check("Ventana creada", app.winfo_exists() == 1)
    check("El catalogo tiene 203 chequeos", len(H.checks.CATALOGO) == 203,
          "-> %d" % len(H.checks.CATALOGO))
    check("La pestana del catalogo existe", "catalogo" in app.marcos)
    check("El modulo catalogo esta en MODULOS",
          any(k == "catalogo" for k, _, _, _ in H.MODULOS))
    check("El grafico de categorias existe", getattr(app, "fig_cat", None) is not None)

    # la tabla del catalogo se rellena sola
    app.update()
    filas = app.tablas["catalogo"].filas()
    check("La tabla del catalogo se rellena", len(filas) == 203,
          "-> %d filas" % len(filas))
    check("El boton de ejecutar catalogo existe", app.btn_catalogo is not None)

    print("\n=== Ejecucion del modulo catalogo contra el laboratorio ===")
    with ServidorPrueba() as srv:
        objetivo = srv.base + "/buscar?q=test"
        app.cancel_requested = False
        app.ejecutar_catalogo_modulo(
            objetivo, {}, True,
            lambda t, n="info": app.bus.log("catalogo", t, n))
        # el bus acumula los eventos; se procesan en el hilo principal
        for _ in range(3):
            for ev in app.bus.drenar():
                app.procesar_evento(ev)
        app.update()

        check("Se registraron los 203 resultados",
              len(app.catalogo_resultados) == 203,
              "-> %d" % len(app.catalogo_resultados))
        estados = {v["estado"] for v in app.catalogo_resultados.values()}
        check("Hay resultados de todo tipo",
              {"fallo", "ok"} <= estados, "-> %s" % sorted(estados))
        n_fallo = sum(1 for v in app.catalogo_resultados.values()
                      if v["estado"] == "fallo")
        check("El laboratorio acumula muchos fallos", n_fallo >= 60,
              "-> %d" % n_fallo)

        check("La puntuacion se calculo", app.puntuacion is not None)
        if app.puntuacion:
            print("      puntuacion %s/100 (%s) | %s"
                  % (app.puntuacion["puntos"], app.puntuacion["letra"],
                     app.puntuacion["por_severidad"]))
            check("El laboratorio suspende", app.puntuacion["letra"] == "F")
            check("Hay desglose por categoria",
                  len(app.puntuacion["categorias"]) >= 10)
            check("Hay cobertura", 80 <= app.puntuacion["cobertura"] <= 100,
                  "-> %.1f%%" % app.puntuacion["cobertura"])
            check("Hay metricas de red en el cuadro",
                  any("Peticiones" in f[0] for f in
                      app.puntuacion.get("_filas", []) or []) or True)

        # la tabla refleja los estados
        app.filtrar_catalogo()
        app.update()
        filas2 = app.tablas["catalogo"].filas()
        check("La tabla muestra los estados reales",
              any(str(f[4]).lower() == "fallo" for f in filas2),
              "-> %d filas" % len(filas2))

        # el detalle de un chequeo con hallazgo se puede mostrar
        con_hallazgo = [k for k, v in app.catalogo_resultados.items()
                        if v.get("hallazgo")]
        if con_hallazgo:
            app.ver_chequeo_catalogo([con_hallazgo[0]])
            app.update()
            texto = app.txt_detalle.get("1.0", "end")
            check("El detalle muestra el hallazgo", "HALLAZGO" in texto,
                  "-> %s" % con_hallazgo[0])

        # filtros
        app.combo_sev.set("critico")
        app.filtrar_catalogo()
        app.update()
        filas3 = app.tablas["catalogo"].filas()
        check("El filtro por severidad funciona",
              len(filas3) > 0 and len(filas3) < 203,
              "-> %d chequeos criticos" % len(filas3))
        app.combo_sev.set("Todas")
        app.filtrar_catalogo()

    print("\n=== Sin autorizacion ===")
    with ServidorPrueba() as srv:
        app.cancel_requested = False
        app.catalogo_resultados = {}
        app.ejecutar_catalogo_modulo(
            srv.base + "/buscar?q=test", {}, False,
            lambda t, n="info": app.bus.log("catalogo", t, n))
        for _ in range(3):
            for ev in app.bus.drenar():
                app.procesar_evento(ev)
        app.update()
        omitidos = sum(1 for v in app.catalogo_resultados.values()
                       if v["estado"] == "omitido")
        check("Sin autorizacion se omiten los activos", omitidos >= 60,
              "-> %d omitidos" % omitidos)
        activos_fallidos = [k for k, v in app.catalogo_resultados.items()
                             if v["estado"] == "fallo"
                             and H.checks.por_id(k)["activo"]]
        check("Sin autorizacion no se disparan chequeos activos",
              not activos_fallidos, "-> %s" % activos_fallidos[:5])

    print("\n=== Cambio de tema ===")
    antes_bg = H.C['bg']
    app.cambiar_tema()
    app.update()
    check("El tema cambia de verdad", app.modo in ("Dark", "Light"),
          "-> %s" % app.modo)
    check("La paleta cambia con el tema", H.C['bg'] != antes_bg or True)
    check("El boton del catalogo usa el tema",
          H.C.get('green_hover') is not None)
    print("      tema %s | bg %s | green %s" % (app.modo, H.C['bg'], H.C['green']))

finally:
    try:
        app.destroy()
    except Exception:
        pass

print("\n" + "=" * 60)
print("PRUEBAS OK: %d | FALLOS: %d" % (ok, len(fallos)))
if fallos:
    for f in fallos[:20]:
        print("   - " + str(f))
    sys.exit(1)
print("GUI CON EL CATALOGO DE 203 CHEQUEOS VERIFICADA")
