"""Prueba de la pestana de informes de la GUI.

Levanta la ventana, ejecuta una evaluacion real contra el laboratorio y
comprueba que se pueden descargar TODOS los formatos desde la interfaz.
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
import xml.etree.ElementTree as ET

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
except Exception as e:
    print("No se pudo crear la ventana:", e)
    sys.exit(2)

try:
    print("=== Construccion de la pestana ===")
    check("La pestana de informe existe", "informe" in app.marcos)
    check("Hay un boton por formato",
          len(app.btn_formato) == len(H.FORMATOS_INFORME),
          "-> %d botones" % len(app.btn_formato))
    check("Estan los formatos pedidos",
          {"html", "pdf", "har", "sarif", "burp", "zap"} <=
          set(app.btn_formato))
    check("Existe el area de resultado", app.txt_informe is not None)
    check("La carpeta de informes se crea", os.path.isdir(H.dir_informes()),
          "-> %s" % H.dir_informes())

    with ServidorPrueba() as srv:
        objetivo = srv.base + "/buscar?q=test"
        app.entry_target.delete(0, "end")
        app.entry_target.insert(0, objetivo)
        app.var_autorizado.set(True)

        print("\n=== Evaluacion real ===")
        app.cancel_requested = False
        app.catalogo_resultados = {}
        app.hallazgos = []
        app.ejecutar_catalogo_modulo(
            objetivo, {}, True,
            lambda t, n="info": app.bus.log("catalogo", t, n))
        for _ in range(3):
            for ev in app.bus.drenar():
                app.procesar_evento(ev)
        app.update()
        # trafico real para que el HAR tenga contenido
        from hb import net
        r = net.peticion_http(objetivo, timeout=10, seguir=1)
        app.bus.http("http", objetivo, r.status, r.peticion_cruda,
                     r.respuesta_cruda, r.tiempo * 1000, tls=r.tls)
        for ev in app.bus.drenar():
            app.procesar_evento(ev)
        app.update()
        app._actualizar_estado_informe()
        app.update()

        check("Se recogieron hallazgos", len(app.hallazgos) > 0,
              "-> %d" % len(app.hallazgos))
        check("Se recogio el trafico HTTP", len(app.http_historial) > 0,
              "-> %d" % len(app.http_historial))
        check("El estado de la pestana refleja los datos",
              "Listo para generar" in app.lbl_informe_estado.cget("text"),
              "-> %s" % app.lbl_informe_estado.cget("text")[:70])

        datos = app._datos_para_informe()
        check("Los datos del informe se construyen", datos is not None)
        check("Los datos llevan el objetivo",
              datos and datos["meta"]["objetivo"] == objetivo)
        check("Los datos llevan los chequeos del catalogo",
              datos and len(datos["resultados"]) == 203,
              "-> %d" % (len(datos["resultados"]) if datos else 0))
        check("Los datos llevan la puntuacion",
              datos and datos["puntuacion"].get("puntos") is not None)
        check("Los datos llevan el trafico para el HAR",
              datos and len(datos["trafico"]) > 0)

        print("\n=== Generacion de cada formato desde la GUI ===")
        carpeta = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "_informes_gui")
        if not os.path.isdir(carpeta):
            os.makedirs(carpeta)
        for clave, nombre, _, _ in H.FORMATOS_INFORME:
            destino = os.path.join(carpeta, "prueba." + clave)
            try:
                ruta, detalle = app._generar(clave, destino)
                existe = os.path.exists(ruta)
                peso = os.path.getsize(ruta) / 1024.0 if existe else 0
                check("Se genera %s desde la GUI" % nombre.upper(), existe,
                      "-> %.0f KB, %s" % (peso, detalle))
                if not existe:
                    continue
                # validez basica por formato
                if clave == "html":
                    t = io.open(ruta, encoding="utf-8").read()
                    check("  HTML completo", t.startswith("<!DOCTYPE html>")
                          and "</html>" in t)
                elif clave == "pdf":
                    check("  PDF valido", H.hb_pdfmin.es_pdf_valido(ruta),
                          "-> %d paginas" % H.hb_pdfmin.paginas_pdf(ruta))
                elif clave in ("json", "har", "sarif"):
                    j = json.load(io.open(ruta, encoding="utf-8"))
                    check("  %s parsea" % clave.upper(), isinstance(j, dict))
                elif clave in ("burp", "zap"):
                    ET.fromstring(io.open(ruta, encoding="utf-8").read())
                    check("  %s parsea" % clave.upper(), True)
                elif clave == "markdown":
                    check("  Markdown con contenido",
                          len(io.open(ruta, encoding="utf-8").read()) > 3000)
                elif clave == "csv":
                    import csv as _csv
                    with io.open(ruta, encoding="utf-8", newline="") as f:
                        n_filas = len(list(_csv.reader(f)))
                    check("  CSV con una fila por hallazgo",
                          n_filas == len(app.hallazgos) + 1,
                          "-> %d filas para %d hallazgos"
                          % (n_filas, len(app.hallazgos)))
            except Exception as e:
                check("Se genera %s desde la GUI" % nombre.upper(), False,
                      "-> %s: %s" % (type(e).__name__, str(e)[:120]))

        print("\n=== Boton 'generar todos' ===")
        antes = set(os.listdir(H.dir_informes()))
        app.generar_todos_los_informes()
        esperado = 240          # hasta 2 minutos: el PDF del navegador tarda
        for _ in range(esperado):
            app.update()
            time.sleep(0.5)
            if not app.informe_generando:
                break
        for ev in app.bus.drenar():
            app.procesar_evento(ev)
        app.update()
        time.sleep(0.5)
        app.update()
        despues = set(os.listdir(H.dir_informes()))
        nuevos = despues - antes
        check("El boton genera todos los formatos", len(nuevos) >= 9,
              "-> %d ficheros nuevos" % len(nuevos))
        extensiones = {os.path.splitext(f)[1].lstrip(".") for f in nuevos}
        check("Estan todas las extensiones (Markdown en .md, XML distintos)",
              {"html", "pdf", "json", "md", "csv", "har", "sarif", "xml"}
              <= extensiones, "-> %s" % sorted(extensiones))
        check("Burp y ZAP no se pisan (ambos .xml pero con nombre propio)",
              len([f for f in nuevos if f.endswith(".xml")]) == 2,
              "-> %s" % sorted(f for f in nuevos if f.endswith(".xml")))
        check("Se rehabilita el boton al terminar",
              str(app.btn_informe_todos.cget("state")) == "normal",
              "-> %s" % app.btn_informe_todos.cget("state"))
        check("Los botones por formato vuelven a estar activos",
              all(str(b.cget("state")) == "normal"
                  for b in app.btn_formato.values()))
        texto = app.txt_informe.get("1.0", "end")
        check("El registro de la pestana informa del resultado",
              "Terminado" in texto and "[OK]" in texto,
              "-> %s" % texto.strip().splitlines()[-1][:90]
              if texto.strip() else "")

        print("\n=== Sin evaluacion previa ===")
        app.hallazgos = []
        app.catalogo_resultados = {}
        app.puntuacion = None
        d = app._datos_para_informe()
        check("Sin datos, el informe se puede generar igual (vacio)",
              d is not None and len(d["hallazgos"]) == 0)
        ruta_v = os.path.join(carpeta, "vacio.html")
        app._generar("html", ruta_v)
        check("El informe vacio se escribe",
              "No se registraron hallazgos"
              in io.open(ruta_v, encoding="utf-8").read())

    print("\n=== Tema ===")
    app.cambiar_tema()
    app.update()
    check("El cambio de tema sigue funcionando", app.modo in ("Dark", "Light"),
          "-> %s" % app.modo)
    check("El area de resultado del informe se retematiza",
          app.txt_informe.cget("bg") == H.C["bg"],
          "-> %s" % app.txt_informe.cget("bg"))

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
print("PESTANA DE INFORMES VERIFICADA")
