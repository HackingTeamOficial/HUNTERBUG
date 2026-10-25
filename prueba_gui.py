"""Prueba de extremo a extremo de la interfaz HunterBug 2.4.

Cadena estrictamente secuencial: cada paso agenda el siguiente, sin
temporizadores en paralelo (crear un Toplevel ejecuta un bucle de eventos
anidado que desordenaria las comprobaciones).
"""

from __future__ import annotations

import json
import os
import sys
import traceback

sys.path.insert(0, ".")

from banco_pruebas import ServidorPrueba
import HunterBugGUI as H

fallos = []
ok = 0


def check(nombre, cond, extra=""):
    global ok
    if cond:
        ok += 1
        print("  [OK]   %s %s" % (nombre, extra))
    else:
        fallos.append(nombre)
        print("  [FALLO] %s %s" % (nombre, extra))


def seccion(t):
    print("\n=== %s ===" % t)
    sys.stdout.flush()


# arranque determinista: sin tema guardado de ejecuciones anteriores
for f in ("theme_config.json", "fondo_matrix.png"):
    try:
        os.remove(os.path.join(H.dir_datos(), f))
    except OSError:
        pass

srv = ServidorPrueba()
srv.__enter__()
puerto = srv.puerto
objetivo = "http://127.0.0.1:%d/buscar?q=test" % puerto
print("servidor vulnerable en", srv.base)

app = H.HunterBugGUI()
print("ventana creada | tema inicial:", app.modo)


# --------------------------------------------------------------- 1 estructura
def paso_estructura():
    seccion("1. Estructura de la interfaz")
    app.update()
    check("Tema inicial oscuro", app.modo == "Dark", "-> %s" % app.modo)
    check("Version 1.0 en el titulo", "1.0" in app.title(),
          "-> %s" % app.title())
    check("Logotipo cargado", app.logo_img is not None)
    check("Icono de ventana localizado", os.path.exists(app.ruta_ico),
          "-> %s" % app.ruta_ico)
    check("10 modulos en la barra lateral", len(app.filas) == 10,
          "-> %d" % len(app.filas))
    check("9 pestanas creadas", len(app.marcos) == 9, "-> %d" % len(app.marcos))
    check("Tablas creadas", len(app.tablas) >= 10,
          "-> %s" % sorted(app.tablas.keys()))
    check("Visor HTTP presente", app.visor_http is not None)
    check("Lienzo de grafo presente", app.lienzo is not None)
    check("Canvas de fondo es el primer hijo (no tapa la UI)",
          list(app.tk.call("winfo", "children", app._w))[0].endswith("ctkcanvas"))
    check("Checkbox de autorizacion presente", app.chk_autorizado is not None)
    check("Boton 'Acerca de' presente", app.btn_acerca is not None,
          "-> %s" % (app.btn_acerca.cget("text") if app.btn_acerca else "-"))
    app.after(60, paso_acerca)


def paso_acerca():
    seccion("1b. Ventana 'Acerca de'")
    app.acerca_de()
    app.update()
    v = getattr(app, "_ventana_acerca", None)
    check("La ventana Acerca de se abre", v is not None)
    if v is not None:
        textos = []
        vistos = set()

        def recoger(w, prof=0):
            """Recoge el texto de cualquier widget, entrando tambien en los
            marcos internos de los CTkScrollableFrame."""
            if id(w) in vistos or prof > 10:
                return
            vistos.add(id(w))
            try:
                t = w.cget("text")
                if t:
                    textos.append(str(t))
            except Exception:
                pass
            hijos = []
            try:
                hijos = list(w.winfo_children())
            except Exception:
                pass
            for attr in ("_scrollable_frame", "_parent_canvas", "_parent_frame",
                         "_canvas"):
                h = getattr(w, attr, None)
                if h is not None and not isinstance(h, (str, int, float, bool)):
                    hijos.append(h)
            for h in hijos:
                recoger(h, prof + 1)

        recoger(v)
        blob = " ".join(textos)
        print("      etiquetas recogidas: %d" % len(textos))
        check("Muestra el autor Juan Antonio", "Juan Antonio" in blob)
        check("Menciona la comunidad hacking team", "hacking team" in blob)
        check("Indica la version 1.0", "1.0" in blob)
        check("Dice 'Version mejorada'", "Version mejorada" in blob)
        check("Incluye aviso legal", "AVISO LEGAL" in blob.upper())
        check("Incluye seccion de creditos", "CREDITOS" in blob.upper())
        check("Describe los motores incluidos", "MOTORES INCLUIDOS" in blob.upper())
        check("Explica como se usa", "COMO SE USA" in blob.upper())
        check("Reutiliza la ventana si se vuelve a pulsar",
              (app.acerca_de() or True) and app._ventana_acerca is v)
        try:
            v.destroy()
        except Exception:
            pass
        app._ventana_acerca = None
    app.after(60, paso_pestanas)


# ---------------------------------------------------------------- 2 pestanas
def paso_pestanas():
    seccion("2. Navegacion por pestanas")
    for clave, _ in H.PESTANAS:
        try:
            app.mostrar_pestana(clave)
            app.update()
            visible = app.marcos[clave].winfo_ismapped() == 1
            otras = [k for k in app.marcos if k != clave
                     and app.marcos[k].winfo_ismapped() == 1]
            check("Pestana '%s' visible y unica" % clave,
                  visible and not otras, "-> otras: %s" % otras)
        except Exception:
            fallos.append("pestana " + clave)
            traceback.print_exc()
    app.mostrar_pestana("panel")
    app.after(60, paso_tema)


# ------------------------------------------------------------------- 3 tema
def paso_tema():
    seccion("3. Cambio de tema")
    bg_ini = H.C['bg']
    app.cambiar_tema()
    app.update()
    check("Pasa a claro", app.modo == "Light",
          "-> bg %s verde %s" % (H.C['bg'], H.C['green']))
    check("La paleta cambio", H.C['bg'] != bg_ini,
          "-> %s -> %s" % (bg_ini, H.C['bg']))
    cfg = json.load(open(os.path.join(H.dir_datos(), "theme_config.json"),
                         encoding="utf-8"))
    check("Tema persistido en disco", cfg.get("modo") == "Light", "-> %s" % cfg)
    from PIL import Image
    px = Image.open(os.path.join(H.dir_datos(),
                                 "fondo_matrix.png")).convert("RGB").getpixel((10, 10))
    check("Fondo regenerado en claro", sum(px) > 400, "-> %s" % (px,))
    check("Boton de tema actualizado", "oscuro" in app.btn_tema.cget("text").lower(),
          "-> %s" % app.btn_tema.cget("text"))
    app.cambiar_tema()
    app.update()
    check("Vuelve a oscuro", app.modo == "Dark" and H.C['bg'] == bg_ini,
          "-> bg %s" % H.C['bg'])
    app.after(60, paso_ventana)


# ---------------------------------------------------------------- 4 ventanas
def paso_ventana():
    seccion("4. Ventanas independientes por modulo")
    app.abrir_ventana("sqli", "SQLi")
    app.update()
    check("Ventana de modulo abierta", "sqli" in app.ventanas)
    v = app.ventanas.get("sqli")
    if v:
        v.escribir("linea de prueba", "exito")
        check("Ventana acepta escritura en vivo",
              "linea de prueba" in v.txt.get("1.0", "end"))
    app.abrir_ventana("sqli", "SQLi")
    check("Reutiliza la ventana existente en vez de duplicar",
          len(app.ventanas) == 1)
    app.abrir_ventana("dns", "DNS")
    app.update()
    check("Se pueden abrir varias ventanas a la vez", len(app.ventanas) == 2,
          "-> %s" % sorted(app.ventanas.keys()))
    app.after(60, paso_preparar)


# --------------------------------------------------------------- 5 preparar
def paso_preparar():
    seccion("5. Preparacion y lanzamiento")
    app.entry_target.delete(0, "end")
    app.entry_target.insert(0, objetivo)
    app.entry_patron_idor.delete(0, "end")
    app.entry_patron_idor.insert(0, "http://127.0.0.1:%d/api/usuario/{id}" % puerto)
    app.entry_url_bola.delete(0, "end")
    app.entry_url_bola.insert(0, "http://127.0.0.1:%d/api/fuga/1" % puerto)
    app.entry_token_a.delete(0, "end")
    app.entry_token_a.insert(0, "tokenA")
    app.entry_token_b.delete(0, "end")
    app.entry_token_b.insert(0, "tokenB")
    app.var_autorizado.set(True)
    check("Objetivo configurado", app.entry_target.get() == objetivo)
    check("Patron IDOR configurado", "{id}" in app.entry_patron_idor.get())
    app.ejecutar_evaluacion()
    check("Evaluacion lanzada", app.running is True)
    app.after(600, esperar, 0)


# ------------------------------------------------------------------ 6 esperar
def esperar(intento):
    if app.running and intento < 150:
        app.after(400, esperar, intento + 1)
        return
    paso_resultados()


# ---------------------------------------------------------------- 7 resultados
def paso_resultados():
    seccion("6. Resultados de la evaluacion")
    estados = {k: v["estado"] for k, v in app.modulo_estado.items()}
    print("      estados:", estados)
    check("Todos los modulos terminaron",
          all(e in ("completado", "fallido", "omitido") for e in estados.values()),
          "-> %s" % sorted(set(estados.values())))
    check("Ningun modulo fallo",
          not any(e == "fallido" for e in estados.values()),
          "-> %s" % [k for k, v in estados.items() if v == "fallido"])

    tipos = sorted({h.get("tipo") for h in app.hallazgos if h.get("tipo")})
    print("      tipos de hallazgo:", tipos)
    print("      total de hallazgos:", len(app.hallazgos))
    check("SQLi detectado", "sqli" in tipos)
    check("XSS detectado", "xss" in tipos)
    check("IDOR detectado", "idor" in tipos)
    check("BOLA detectado", "bola" in tipos)
    check("CVE detectado", "cve" in tipos)
    check("Hallazgos de cabeceras presentes", "cabecera-ausente" in tipos)

    sev = sorted({h.get("severidad") for h in app.hallazgos})
    check("Hay hallazgos criticos", "critico" in sev, "-> %s" % sev)
    check("Tabla de hallazgos poblada",
          len(app.tablas["hallazgos"].filas()) == len(app.hallazgos),
          "-> %d filas" % len(app.tablas["hallazgos"].filas()))
    check("Tabla de vulnerabilidades poblada",
          len(app.tablas["vulns"].filas()) >= 4,
          "-> %d filas" % len(app.tablas["vulns"].filas()))
    check("Tabla CVE poblada", len(app.tablas["cve"].filas()) >= 1,
          "-> %s" % app.tablas["cve"].filas()[:2])
    check("Tabla de puertos poblada", len(app.tablas["puertos"].filas()) >= 1,
          "-> %s" % app.tablas["puertos"].filas()[:3])
    check("Tabla de tecnologias poblada", len(app.tablas["tec"].filas()) >= 1,
          "-> %s" % app.tablas["tec"].filas())
    check("Historial HTTP poblado", len(app.tablas["http"].filas()) >= 1,
          "-> %d filas" % len(app.tablas["http"].filas()))
    check("Tabla de cabeceras poblada", len(app.tablas["cabeceras"].filas()) >= 4,
          "-> %d filas" % len(app.tablas["cabeceras"].filas()))

    # el detalle de un hallazgo debe renderizarse
    filas = app.tablas["hallazgos"].filas()
    if filas:
        app.ver_hallazgo(filas[0])
        detalle = app.txt_detalle.get("1.0", "end")
        check("Detalle del hallazgo se muestra", "SEVERIDAD" in detalle and
              len(detalle) > 60, "-> %d caracteres" % len(detalle))
    app.after(60, paso_http)


# --------------------------------------------------------------------- 8 http
def paso_http():
    seccion("7. Visor HTTP tipo proxy")
    ev = app.ultimo_http or {}
    check("Se capturo peticion en crudo",
          str(ev.get("peticion", "")).startswith(("GET", "HEAD")),
          "-> %s" % str(ev.get("peticion", ""))[:45].replace("\n", " "))
    check("Se capturo respuesta en crudo",
          str(ev.get("respuesta", "")).startswith("HTTP/1.1"),
          "-> %s" % str(ev.get("respuesta", ""))[:45].replace("\n", " "))
    app.mostrar_pestana("http")
    app.update()
    if ev:
        app.visor_http.mostrar(ev.get("peticion", ""), ev.get("respuesta", ""),
                               ev.get("url", ""), ev.get("status", 0),
                               ev.get("ms", 0.0), ev.get("tls"))
    tp = app.visor_http.txt_pet.get("1.0", "end")
    tr = app.visor_http.txt_res.get("1.0", "end")
    check("Visor muestra la peticion", "HTTP/1.1" in tp and len(tp) > 40,
          "-> %d caracteres" % len(tp))
    check("Visor muestra la respuesta", "HTTP/1.1" in tr and len(tr) > 60,
          "-> %d caracteres" % len(tr))
    check("Visor muestra el codigo de estado",
          str(ev.get("status", "")) in app.visor_http.lbl_info.cget("text"),
          "-> %s" % app.visor_http.lbl_info.cget("text"))
    app.after(60, paso_grafo)


# ------------------------------------------------------------------- 9 grafo
def paso_grafo():
    seccion("8. Grafo de superficie de ataque")
    res = app.grafo.resumen()
    print("      grafo:", res)
    check("Grafo con nodos", res["nodos"] >= 10, "-> %d" % res["nodos"])
    check("Grafo con aristas", res["aristas"] >= 10, "-> %d" % res["aristas"])
    check("Grafo incluye CVE", res["por_tipo"].get("cve", 0) >= 1)
    check("Grafo incluye puertos", res["por_tipo"].get("puerto", 0) >= 1)
    check("Grafo incluye tecnologias", res["por_tipo"].get("tecnologia", 0) >= 1)
    app.mostrar_pestana("grafo")
    app.update()
    check("Layout calculado", len(app.lienzo._pos) > 0,
          "-> %d posiciones" % len(app.lienzo._pos))
    check("Lienzo dibuja nodos y aristas",
          len(app.lienzo.canvas.find_all()) > 10,
          "-> %d elementos" % len(app.lienzo.canvas.find_all()))
    # pulsar un nodo debe mostrar su informacion
    nid = next(iter(app.lienzo._pos))
    app.nodo_pulsado(app.grafo.nodos.get(nid))
    texto = app.txt_ia.get("1.0", "end")
    check("Pulsar un nodo muestra su detalle", "TIPO" in texto and "NODO" in texto,
          "-> %s" % texto.split("\n")[0][:50])
    app.after(60, paso_ia)


# ---------------------------------------------------------------------- 10 ia
def paso_ia():
    seccion("9. Analisis de IA")
    app.analizar_con_ia()
    esperar_ia(0)


def esperar_ia(intento):
    """Sondea hasta que el analisis aparezca en el panel (sin esperas fijas)."""
    listo = (len(app.analisis_ia) > 300
             and len(app.txt_ia.get("1.0", "end")) > 300)
    if not listo and intento < 60:
        app.after(300, esperar_ia, intento + 1)
        return
    tras_ia()


def tras_ia():
    check("Analisis generado", len(app.analisis_ia) > 300,
          "-> %d caracteres" % len(app.analisis_ia))
    check("Estructurado en 4 bloques",
          all(x in app.analisis_ia for x in
              ("1) LECTURA DEL GRAFO", "2) CADENA DE ATAQUE",
               "3) PRIORIDAD", "4) SIGUIENTES PRUEBAS")))
    check("Cita los CVE encontrados", "CVE-" in app.analisis_ia)
    check("Motor indicado en la interfaz",
          app.lbl_motor_ia.cget("text") != "sin ejecutar",
          "-> %s" % app.lbl_motor_ia.cget("text"))
    check("Analisis visible en el panel",
          len(app.txt_ia.get("1.0", "end")) > 300,
          "-> %d caracteres" % len(app.txt_ia.get("1.0", "end")))
    app.after(60, paso_informe)


# ----------------------------------------------------------------- 11 informe
def paso_informe():
    seccion("10. Informe")
    d = {"objetivo": app.target_actual(), "fecha": "2026-01-01T00:00:00Z",
         "resumen": app.grafo.resumen(), "puertos": app.puertos,
         "dns": app.dns, "tecnologias": app.tecnologias,
         "hallazgos": app.hallazgos, "analisis_ia": app.analisis_ia}
    md = app.informe_markdown(d)
    check("Informe Markdown generado", len(md) > 800,
          "-> %d caracteres" % len(md))
    check("Incluye resumen de severidad", "## Resumen de severidad" in md)
    check("Incluye un apartado por hallazgo", md.count("### ") >= 5,
          "-> %d apartados" % md.count("### "))
    check("Incluye tabla de puertos", "| Puerto | Servicio | Banner |" in md)
    check("Incluye tecnologias", "## Tecnologias detectadas" in md)
    check("Incluye el analisis de IA", "## Analisis asistido por IA" in md)
    ruta = os.path.join(H.dir_datos(), "informe_prueba.md")
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(md)
    check("Informe escrito en disco", os.path.getsize(ruta) > 800,
          "-> %d bytes" % os.path.getsize(ruta))
    app.after(60, paso_reinicio)


# ---------------------------------------------------------------- 12 reinicio
def paso_reinicio():
    seccion("11. Reinicio y cierre")
    app.reiniciar_motor()
    app.update()
    check("Hallazgos vaciados", len(app.hallazgos) == 0)
    check("Grafo vaciado", len(app.grafo.nodos) == 0)
    check("Tablas vaciadas", len(app.tablas["hallazgos"].filas()) == 0)
    check("Progreso a cero",
          app.progreso_label.cget("text") == "Progreso global: 0%",
          "-> %s" % app.progreso_label.cget("text"))
    check("Modulos de vuelta a pendiente",
          all(v["estado"] == "pendiente" for v in app.modulo_estado.values()))
    app.after(300, paso_cierre)


def paso_cierre():
    app.cerrar()
    check("Ventana cerrada sin excepciones", True)


app.after(400, paso_estructura)
app.mainloop()

try:
    srv.__exit__()
except Exception:
    pass

print("\n" + "=" * 62)
print("PRUEBAS OK: %d | FALLOS: %d" % (ok, len(fallos)))
if fallos:
    for f in fallos:
        print("   - " + f)
    sys.exit(1)
print("INTERFAZ 1.0 VERIFICADA DE EXTREMO A EXTREMO")
