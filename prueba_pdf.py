"""Prueba del generador de PDF sin dependencias (hb/pdfmin.py)."""

import os
import re
import sys

sys.path.insert(0, ".")

from hb import pdfmin

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


D = os.path.dirname(os.path.abspath(__file__))
salida = os.path.join(D, "_prueba_pdf.pdf")

print("=== Construccion ===")
doc = pdfmin.PDF("Informe de prueba", "HunterBug", "prueba", "pdf, prueba")
doc.titulo_documento("HUNTERBUG 1.0 — Informe de evaluacion",
                     "Objetivo: https://ejemplo.test  ·  Acentos: áéíóúñÑü¿¡")
doc.titulo("1. Resumen ejecutivo")
doc.parrafo("Este parrafo comprueba el salto de linea automatico con acentos "
            "castellanos (áéíóúñ), simbolos raros <>&\"' y comillas «» y una "
            "URL muy larga que debe partirse por caracteres: "
            "https://ejemplo.test/api/v1/usuarios/1234567890/"
            "facturas/2026/01/detalle?incluir=movimientos&formato=json")
doc.subtitulo("Metricas")
doc.clave_valor([("Puntuacion", "42,5 / 100 (E)"),
                 ("Cobertura", "189 de 203 chequeos (93,1%)"),
                 ("Criticos", "8"), ("Altos", "17")])
doc.subtitulo("Puntuacion por categoria")
for etiqueta, valor in (("cabeceras", 18.0), ("contenido", 55.4),
                        ("parametros", 72.1), ("tls", 100.0)):
    doc.barra(etiqueta, valor, color="#c0392b" if valor < 40 else "#0b3d2c")
doc.subtitulo("Tabla de hallazgos")
doc.tabla(["ID", "Titulo", "Severidad", "CWE"],
          [["HDR-02", "Falta la cabecera Content-Security-Policy", "alto",
            "CWE-1021"],
           ["FUG-02", "Fichero .env expuesto", "critico", "CWE-538"],
           ["PAR-10", "SSTI evaluado en 'name'", "critico", "CWE-1336"],
           ["CON-01", "Comentario HTML con contrasena", "bajo", "CWE-615"]],
          [60, 300, 80, 80])
doc.subtitulo("Evidencia")
doc.caja([("FUG-02 — Fichero .env expuesto", True),
          ("Ruta: /.env | status: 200 | 84 bytes", False),
          ("Extracto: APP_ENV=production DB_PASSWORD=Sup3rS3cret0", False)],
         color="#fef2f2", borde="#fca5a5")
doc.parrafo("Fin del informe.")
ruta = doc.guardar(salida)
print("      escrito:", ruta, "%.1f KB" % (os.path.getsize(ruta) / 1024))

print("\n=== Validacion estructural ===")
check("El fichero existe", os.path.exists(ruta))
check("Es un PDF valido (cabecera, EOF, paginas)", pdfmin.es_pdf_valido(ruta))
check("Cuenta de paginas >= 1", pdfmin.paginas_pdf(ruta) >= 1,
      "-> %d" % pdfmin.paginas_pdf(ruta))

datos = open(ruta, "rb").read()
check("Termina en %%EOF", datos.rstrip().endswith(b"%%EOF"))
check("Declara la fuente Helvetica", b"/BaseFont /Helvetica" in datos)
check("Declara WinAnsiEncoding", b"/WinAnsiEncoding" in datos)
check("Incluye metadatos de titulo", b"/Title (Informe de prueba)" in datos)

# el xref debe apuntar exactamente a cada objeto
m = re.search(rb"startxref\s+(\d+)", datos)
inicio = int(m.group(1))
check("startxref apunta a la tabla xref", datos[inicio:inicio + 4] == b"xref",
      "-> %r" % datos[inicio:inicio + 4])

cabecera = datos[inicio:inicio + 400].split(b"\n")
declarados = []
for linea in cabecera[2:]:
    mm = re.match(rb"^(\d{10}) (\d{5}) ([nf])", linea)
    if mm:
        declarados.append((int(mm.group(1)), mm.group(3)))
check("La tabla xref declara objetos", len(declarados) >= 5,
      "-> %d entradas" % len(declarados))

malos = []
for i, (off, tipo) in enumerate(declarados):
    if tipo == b"n":
        esperado = b"%d 0 obj" % i
        if not datos[off:off + len(esperado)] == esperado:
            malos.append((i, off, datos[off:off + 20]))
check("Todos los offsets del xref son correctos", not malos,
      "-> %s" % malos[:3])

print("\n=== Troceado de texto ===")
lineas = pdfmin.partir_texto("palabra " * 200, 9.5, 400)
check("Trocea un parrafo largo en varias lineas", len(lineas) > 5,
      "-> %d lineas" % len(lineas))
check("Ninguna linea supera el ancho",
      all(pdfmin.ancho_texto(l, 9.5) <= 400.5 for l in lineas))
larga = pdfmin.partir_texto("x" * 500, 9.5, 200)
check("Parte palabras sin espacios (URLs largas)",
      all(pdfmin.ancho_texto(l, 9.5) <= 200.5 for l in larga))
check("Los acentos se miden con la anchura de su letra base",
      abs(pdfmin.ancho_texto("aeiou", 10) - pdfmin.ancho_texto("áéíóú", 10)) < 0.6)

print("\n=== Escapes peligrosos ===")
doc2 = pdfmin.PDF("Escapes")
doc2.parrafo('Parentesis ) y ( y barra \\ y comillas " y <xml> & entidades')
doc2.parrafo("Nulos y control: \x00 \x01 fin")
ruta2 = os.path.join(D, "_prueba_pdf2.pdf")
doc2.guardar(ruta2)
check("Sobrevive a caracteres peligrosos", pdfmin.es_pdf_valido(ruta2))
d2 = open(ruta2, "rb").read()
check("Escapa el parentesis en el contenido", rb"\(" in d2 or rb"\)" in d2)
os.remove(ruta2)

print("\n=== Navegador headless ===")
nav = pdfmin.buscar_navegador()
check("Hay navegador disponible o se admite su ausencia", True,
      "-> %s" % (nav or "ninguno (se usara el generador propio)"))

print("\n" + "=" * 60)
print("PRUEBAS OK: %d | FALLOS: %d" % (ok, len(fallos)))
print("PDF de muestra:", ruta)
if fallos:
    for f in fallos[:20]:
        print("   - " + str(f))
    sys.exit(1)
print("GENERADOR DE PDF VERIFICADO")
