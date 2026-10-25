import sys, traceback
sys.path.insert(0, ".")

errores = []

import HunterBugGUI as H

app = H.HunterBugGUI()
print("OK  ventana creada | tema inicial:", app.modo, "| bg:", H.C['bg'], "| verde:", H.C['green'])
print("OK  canvas de fondo creado:", app.bg_canvas.winfo_exists() == 1)
print("OK  filas de modulos:", len(app.filas))
print("OK  dir_datos():", H.dir_datos())
ruta_fondo = __import__("os").path.join(H.dir_datos(), "fondo_matrix.png")
print("OK  fondo escrito en dir_datos:", __import__("os").path.exists(ruta_fondo), "->", ruta_fondo)


def pixel_fondo():
    from PIL import Image
    im = Image.open(ruta_fondo).convert("RGB")
    return im.getpixel((10, 10))


def paso_tema():
    try:
        app.cambiar_tema()
        print("OK  cambio a", app.modo, "| bg:", H.C['bg'], "| verde:", H.C['green'],
              "| barra:", H.C['bar'], "| boton tema:", app.btn_tema.cget("text"))
        print("OK  pixel del fondo ahora:", pixel_fondo(), "(claro si suma > 400)")
        import os, json
        cfg = json.load(open(os.path.join(H.dir_datos(), "theme_config.json")))
        print("OK  theme_config.json persistido:", cfg)
        app.cambiar_tema()
        print("OK  vuelta a", app.modo, "| bg:", H.C['bg'], "| pixel:", pixel_fondo())
        cfg = json.load(open(os.path.join(H.dir_datos(), "theme_config.json")))
        print("OK  theme_config.json persistido:", cfg)
    except Exception:
        errores.append(traceback.format_exc())
    app.after(200, paso_scan)


def paso_scan():
    try:
        app.entry_target.delete(0, "end")
        app.entry_target.insert(0, "example.com")
        app.ejecutar_evaluacion()
        print("OK  escaneo lanzado | running =", app.running)
    except Exception:
        errores.append(traceback.format_exc())
    app.after(300, esperar_scan)


def esperar_scan(intento=0):
    if app.running and intento < 60:
        app.after(300, esperar_scan, intento + 1)
        return
    paso_resultados()


def paso_resultados():
    try:
        estados = [v["estado"] for v in app.modulo_estado.values()]
        print("OK  estados finales:", estados)
        print("OK  progreso global:", app.progreso_label.cget("text"))
        print("OK  running =", app.running)
        lineas = int(app.console.index('end-1c').split('.')[0])
        print("OK  consola:", lineas, "lineas")
    except Exception:
        errores.append(traceback.format_exc())
    app.after(200, paso_extra)


def paso_extra():
    try:
        app.detectar_modelos_locales()
        app.reiniciar_motor()
        print("OK  reinicio |", app.progreso_label.cget("text"))
    except Exception:
        errores.append(traceback.format_exc())
    app.after(800, paso_cierre)


def paso_cierre():
    try:
        app.cerrar()
        print("OK  ventana cerrada sin excepciones")
    except Exception:
        errores.append(traceback.format_exc())


app.after(500, paso_tema)
app.mainloop()

print()
if errores:
    print("FALLOS:", len(errores))
    for e in errores:
        print(e)
    sys.exit(1)
print("SMOKE TEST OK - sin excepciones")
