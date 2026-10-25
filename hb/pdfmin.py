"""HunterBug - generador de PDF sin dependencias externas.

Escribe PDF 1.4 a mano usando las fuentes base-14 (Helvetica), de modo que el
informe en PDF se puede generar siempre, aunque no haya navegador ni libreria
de PDF instalada. Si hay un navegador headless disponible, el informe se
genera antes con `html_a_pdf()`, que da una fidelidad perfecta respecto al
HTML; este modulo es el camino garantizado.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

ANCHO = 595.28          # A4 en puntos
ALTO = 841.89
MARGEN = 46.0
ANCHO_UTIL = ANCHO - 2 * MARGEN

# Anchuras AFM de Helvetica / Helvetica-Bold (unidades de 1/1000 em)
_W_REG = {
    " ": 278, "!": 278, '"': 355, "#": 556, "$": 556, "%": 889, "&": 667,
    "'": 191, "(": 333, ")": 333, "*": 389, "+": 584, ",": 278, "-": 333,
    ".": 278, "/": 278, ":": 278, ";": 278, "<": 584, "=": 584, ">": 584,
    "?": 556, "@": 1015, "[": 278, "\\": 278, "]": 278, "^": 469, "_": 556,
    "`": 333, "{": 334, "|": 260, "}": 334, "~": 584,
    "A": 667, "B": 667, "C": 722, "D": 722, "E": 667, "F": 611, "G": 778,
    "H": 722, "I": 278, "J": 500, "K": 667, "L": 556, "M": 833, "N": 722,
    "O": 778, "P": 667, "Q": 778, "R": 722, "S": 667, "T": 611, "U": 722,
    "V": 667, "W": 944, "X": 667, "Y": 667, "Z": 611,
    "a": 556, "b": 556, "c": 500, "d": 556, "e": 556, "f": 278, "g": 556,
    "h": 556, "i": 222, "j": 222, "k": 500, "l": 222, "m": 833, "n": 556,
    "o": 556, "p": 556, "q": 556, "r": 333, "s": 500, "t": 278, "u": 556,
    "v": 500, "w": 722, "x": 500, "y": 500, "z": 500,
}
_W_BOLD = {
    " ": 278, "!": 333, '"': 474, "#": 556, "$": 556, "%": 889, "&": 722,
    "'": 238, "(": 333, ")": 333, "*": 389, "+": 584, ",": 278, "-": 333,
    ".": 278, "/": 278, ":": 333, ";": 333, "<": 584, "=": 584, ">": 584,
    "?": 611, "@": 975, "[": 333, "\\": 278, "]": 333, "^": 584, "_": 556,
    "`": 333, "{": 389, "|": 280, "}": 389, "~": 584,
    "A": 722, "B": 722, "C": 722, "D": 722, "E": 667, "F": 611, "G": 778,
    "H": 722, "I": 278, "J": 556, "K": 722, "L": 611, "M": 833, "N": 722,
    "O": 778, "P": 667, "Q": 778, "R": 722, "S": 667, "T": 611, "U": 722,
    "V": 667, "W": 944, "X": 667, "Y": 667, "Z": 611,
    "a": 556, "b": 611, "c": 556, "d": 611, "e": 556, "f": 333, "g": 611,
    "h": 611, "i": 278, "j": 278, "k": 556, "l": 278, "m": 889, "n": 611,
    "o": 611, "p": 611, "q": 611, "r": 389, "s": 556, "t": 333, "u": 611,
    "v": 556, "w": 778, "x": 556, "y": 556, "z": 500,
}
for _d in (_W_REG, _W_BOLD):
    for _c in "0123456789":
        _d[_c] = 556

# las letras acentuadas comparten anchura con su letra base
_ACENTOS = {
    "á": "a", "à": "a", "ä": "a", "â": "a", "ã": "a", "å": "a",
    "é": "e", "è": "e", "ë": "e", "ê": "e",
    "í": "i", "ì": "i", "ï": "i", "î": "i",
    "ó": "o", "ò": "o", "ö": "o", "ô": "o", "õ": "o",
    "ú": "u", "ù": "u", "ü": "u", "û": "u",
    "ñ": "n", "ç": "c", "ý": "y",
    "Á": "A", "À": "A", "Ä": "A", "Â": "A", "Ã": "A",
    "É": "E", "È": "E", "Ë": "E", "Ê": "E",
    "Í": "I", "Ì": "I", "Ï": "I", "Î": "I",
    "Ó": "O", "Ò": "O", "Ö": "O", "Ô": "O", "Õ": "O",
    "Ú": "U", "Ù": "U", "Ü": "U", "Û": "U",
    "Ñ": "N", "Ç": "C", "Ý": "Y",
    "¿": "?", "¡": "!", "º": "o", "ª": "a",
    "–": "-", "—": "-", "“": '"', "”": '"', "‘": "'", "’": "'",
    "…": ".", "€": "E", "·": ".", "°": "o",
}


def ancho_texto(texto, tam, negrita=False):
    tabla = _W_BOLD if negrita else _W_REG
    total = 0
    for c in texto:
        if c in tabla:
            total += tabla[c]
        elif c in _ACENTOS:
            total += tabla.get(_ACENTOS[c], 556)
        else:
            total += 556
    return total / 1000.0 * tam


def partir_texto(texto, tam, ancho, negrita=False):
    """Trocea el texto en lineas que caben en `ancho` puntos."""
    lineas = []
    for parrafo in str(texto).split("\n"):
        if not parrafo.strip():
            lineas.append("")
            continue
        actual = ""
        for palabra in parrafo.split(" "):
            prueba = palabra if not actual else actual + " " + palabra
            if ancho_texto(prueba, tam, negrita) <= ancho or not actual:
                actual = prueba
            else:
                lineas.append(actual)
                actual = palabra
            # palabras larguisimas (URLs): partir por caracteres
            while ancho_texto(actual, tam, negrita) > ancho and len(actual) > 1:
                corte = len(actual)
                while corte > 1 and ancho_texto(actual[:corte], tam,
                                                negrita) > ancho:
                    corte -= 1
                lineas.append(actual[:corte])
                actual = actual[corte:]
        lineas.append(actual)
    return lineas


def _esc(texto):
    return (str(texto).replace("\\", r"\\").replace("(", r"\(")
            .replace(")", r"\)").replace("\r", " "))


def _latin1(texto):
    """WinAnsiEncoding: los bytes van en latin-1."""
    return _esc(texto).encode("latin-1", "replace").decode("latin-1")


def _hex_rgb(color):
    c = str(color).lstrip("#")
    if len(c) == 3:
        c = "".join(x * 2 for x in c)
    try:
        r = int(c[0:2], 16) / 255.0
        g = int(c[2:4], 16) / 255.0
        b = int(c[4:6], 16) / 255.0
    except Exception:
        r = g = b = 0.0
    return r, g, b


class PDF:
    """Documento PDF sencillo con parrafos, titulos, tablas y cajas."""

    def __init__(self, titulo="", autor="HunterBug", asunto="", palabras=""):
        self.meta = {"titulo": titulo, "autor": autor, "asunto": asunto,
                     "palabras": palabras}
        self.paginas = []
        self._nueva_pagina()

    # ------------------------------------------------------------- estructura
    def _nueva_pagina(self):
        self.ops = []
        self.paginas.append(self.ops)
        self.y = ALTO - MARGEN

    def salto_pagina(self):
        self._nueva_pagina()

    def necesita(self, alto):
        if self.y - alto < MARGEN + 22:
            self._nueva_pagina()
            return True
        return False

    def espacio(self, h=6.0):
        self.y -= h

    # --------------------------------------------------------------- dibujo
    def _rect(self, x, y, w, h, color):
        r, g, b = _hex_rgb(color)
        self.ops.append("%.3f %.3f %.3f rg %.2f %.2f %.2f %.2f re f"
                        % (r, g, b, x, y, w, h))

    def _linea(self, x1, y1, x2, y2, color, grosor=0.6):
        r, g, b = _hex_rgb(color)
        self.ops.append("%.3f %.3f %.3f RG %.2f w %.2f %.2f m %.2f %.2f l S"
                        % (r, g, b, grosor, x1, y1, x2, y2))

    def _texto_en(self, texto, x, y, tam, negrita=False, color="#000000"):
        r, g, b = _hex_rgb(color)
        fuente = "/F2" if negrita else "/F1"
        self.ops.append("BT %.3f %.3f %.3f rg %s %.2f Tf 1 0 0 1 %.2f %.2f Tm "
                        "(%s) Tj ET"
                        % (r, g, b, fuente, tam, x, y, _latin1(texto)))

    # -------------------------------------------------------------- elementos
    def titulo_documento(self, texto, subtitulo="", color="#0b3d2c"):
        self.espacio(10)
        for linea in partir_texto(texto, 22, ANCHO_UTIL, True):
            self.necesita(28)
            self._texto_en(linea, MARGEN, self.y - 22, 22, True, color)
            self.y -= 28
        if subtitulo:
            for linea in partir_texto(subtitulo, 11, ANCHO_UTIL):
                self._texto_en(linea, MARGEN, self.y - 11, 11, False, "#555555")
                self.y -= 15
        self.y -= 4
        self._linea(MARGEN, self.y, ANCHO - MARGEN, self.y, color, 1.2)
        self.y -= 14

    def titulo(self, texto, color="#0b3d2c", tam=14):
        self.necesita(tam + 16)
        self.espacio(8)
        self._texto_en(texto, MARGEN, self.y - tam, tam, True, color)
        self.y -= tam + 5
        self._linea(MARGEN, self.y, ANCHO - MARGEN, self.y, "#cccccc", 0.5)
        self.y -= 10

    def subtitulo(self, texto, color="#1f2937", tam=11):
        self.necesita(tam + 10)
        self.espacio(5)
        self._texto_en(texto, MARGEN, self.y - tam, tam, True, color)
        self.y -= tam + 6

    def parrafo(self, texto, tam=9.5, color="#111111", sangria=0.0,
                negrita=False):
        ancho = ANCHO_UTIL - sangria
        for linea in partir_texto(texto, tam, ancho, negrita):
            self.necesita(tam + 3)
            self._texto_en(linea, MARGEN + sangria, self.y - tam, tam, negrita,
                           color)
            self.y -= tam + 2.6
        self.y -= 2

    def vinetas(self, elementos, tam=9.5, color="#111111"):
        for e in elementos:
            lineas = partir_texto(e, tam, ANCHO_UTIL - 14)
            for i, linea in enumerate(lineas):
                self.necesita(tam + 3)
                x = MARGEN + (0 if i == 0 else 10)
                marca = "•  " if i == 0 else ""
                self._texto_en(marca + linea, x, self.y - tam, tam, False, color)
                self.y -= tam + 2.4
            self.y -= 1.5

    def clave_valor(self, pares, tam=9.0, ancho_clave=150.0):
        for clave, valor in pares:
            lineas = partir_texto(valor, tam, ANCHO_UTIL - ancho_clave - 8)
            alto = max(1, len(lineas)) * (tam + 2.4)
            self.necesita(alto)
            self._texto_en(str(clave), MARGEN, self.y - tam, tam, True,
                           "#444444")
            for i, linea in enumerate(lineas):
                self._texto_en(linea, MARGEN + ancho_clave, self.y - tam, tam,
                               False, "#111111")
                if i < len(lineas) - 1:
                    self.y -= tam + 2.4
            self.y -= tam + 3.2

    def tabla(self, cabeceras, filas, anchos, tam=8.4, color_cabecera="#0b3d2c"):
        total = sum(anchos)
        if total > ANCHO_UTIL:
            factor = ANCHO_UTIL / total
            anchos = [a * factor for a in anchos]

        def dibujar_cabecera():
            celdas = [partir_texto(str(c), tam, a - 8, True)
                      for c, a in zip(cabeceras, anchos)]
            alto = max(1, max(len(c) for c in celdas)) * (tam + 2.2) + 7
            self.necesita(alto)
            self._rect(MARGEN, self.y - alto, ANCHO_UTIL, alto, color_cabecera)
            x = MARGEN + 4
            for lineas, a in zip(celdas, anchos):
                yy = self.y - tam - 2
                for linea in lineas:
                    self._texto_en(linea, x, yy, tam, True, "#ffffff")
                    yy -= tam + 2.2
                x += a
            self.y -= alto

        def separadores(y_sup, alto):
            x = MARGEN
            for a in anchos[:-1]:
                x += a
                self._linea(x, y_sup, x, y_sup - alto, "#e5e7eb", 0.4)

        dibujar_cabecera()
        alterno = False
        for fila in filas:
            celdas = [partir_texto(str(c), tam, a - 8) for c, a in
                      zip(fila, anchos)]
            alto = max(1, max(len(c) for c in celdas)) * (tam + 2.4) + 6
            if self.necesita(alto):
                dibujar_cabecera()
                alterno = False
            if alterno:
                self._rect(MARGEN, self.y - alto, ANCHO_UTIL, alto, "#f3f4f6")
            alterno = not alterno
            separadores(self.y, alto)
            x = MARGEN + 4
            for lineas, a in zip(celdas, anchos):
                yy = self.y - tam - 2
                for linea in lineas:
                    self._texto_en(linea, x, yy, tam, False, "#111111")
                    yy -= tam + 2.4
                x += a
            self.y -= alto
        self._linea(MARGEN, self.y, ANCHO - MARGEN, self.y, "#cccccc", 0.5)
        self.y -= 8

    def caja(self, lineas, color="#f9fafb", borde="#d1d5db", tam=9.0,
             color_texto="#111111"):
        """Bloque con fondo y borde; cada elemento es (texto, negrita)."""
        if isinstance(lineas, str):
            lineas = [(lineas, False)]
        preparadas = []
        for texto, negrita in lineas:
            for linea in partir_texto(texto, tam, ANCHO_UTIL - 16, negrita):
                preparadas.append((linea, negrita))
        alto = len(preparadas) * (tam + 2.6) + 10
        self.necesita(alto + 4)
        self._rect(MARGEN, self.y - alto, ANCHO_UTIL, alto, color)
        self._linea(MARGEN, self.y - alto, MARGEN, self.y, borde, 0.7)
        yy = self.y - tam - 5
        for linea, negrita in preparadas:
            self._texto_en(linea, MARGEN + 8, yy, tam, negrita, color_texto)
            yy -= tam + 2.6
        self.y -= alto + 6

    def barra(self, etiqueta, valor, maximo=100.0, color="#0b3d2c",
              ancho_total=None, tam=8.6):
        ancho_total = ancho_total or (ANCHO_UTIL - 190)
        self.necesita(tam + 8)
        self._texto_en(etiqueta[:38], MARGEN, self.y - tam, tam, False,
                       "#333333")
        x = MARGEN + 120
        w = ancho_total
        alto = 9.0
        self._rect(x, self.y - alto, w, alto, "#e5e7eb")
        prop = 0 if maximo <= 0 else max(0.0, min(1.0, valor / maximo))
        if prop > 0:
            self._rect(x, self.y - alto, w * prop, alto, color)
        self._texto_en("%.1f" % valor, x + w + 8, self.y - tam, tam, True,
                       "#111111")
        self.y -= alto + 5

    # ------------------------------------------------------------- escritura
    def _contenido(self, ops):
        return ("\n".join(ops) + "\n").encode("latin-1", "replace")

    def guardar(self, ruta):
        """Escribe el PDF y devuelve la ruta."""
        objetos = []
        n_paginas = len(self.paginas)
        # 1 catalogo, 2 pages, 3 F1, 4 F2, luego una pagina + un contenido c/u
        ids_paginas = []
        for i in range(n_paginas):
            ids_paginas.append(5 + i * 2)

        objetos.append(b"<< /Type /Catalog /Pages 2 0 R >>")
        hijos = " ".join("%d 0 R" % i for i in ids_paginas)
        objetos.append(("<< /Type /Pages /Count %d /Kids [%s] >>"
                        % (n_paginas, hijos)).encode("latin-1"))
        objetos.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
                       b"/Encoding /WinAnsiEncoding >>")
        objetos.append(b"<< /Type /Font /Subtype /Type1 "
                       b"/BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding "
                       b">>")

        for i in range(n_paginas):
            contenido = self._contenido(self.paginas[i])
            id_cont = ids_paginas[i] + 1
            objetos.append(("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f "
                            "%.2f] /Resources << /Font << /F1 3 0 R /F2 4 0 R "
                            ">> >> /Contents %d 0 R >>"
                            % (ANCHO, ALTO, id_cont)).encode("latin-1"))
            objetos.append(b"<< /Length %d >>\nstream\n" % len(contenido)
                           + contenido + b"endstream")

        salida = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for i, cuerpo in enumerate(objetos, start=1):
            offsets.append(len(salida))
            salida += b"%d 0 obj\n" % i + cuerpo + b"\nendobj\n"

        inicio_xref = len(salida)
        n = len(objetos) + 1
        salida += b"xref\n0 %d\n" % n
        salida += b"0000000000 65535 f \n"
        for off in offsets:
            salida += ("%010d 00000 n \n" % off).encode("latin-1")
        info = ("<< /Title (%s) /Author (%s) /Subject (%s) /Keywords (%s) "
                "/Producer (HunterBug) >>"
                % (_latin1(self.meta["titulo"]), _latin1(self.meta["autor"]),
                   _latin1(self.meta["asunto"]),
                   _latin1(self.meta["palabras"]))).encode("latin-1")
        id_info = len(objetos) + 1
        salida += b"%d 0 obj\n" % id_info + info + b"\nendobj\n"
        salida += (b"trailer\n<< /Size %d /Root 1 0 R /Info %d 0 R >>\n"
                   b"startxref\n%d\n%%%%EOF\n"
                   % (id_info + 1, id_info, inicio_xref))

        with open(ruta, "wb") as f:
            f.write(bytes(salida))
        return ruta


# ---------------------------------------------------------------------------
# HTML -> PDF con navegador headless (mejor fidelidad)
# ---------------------------------------------------------------------------

NAVEGADORES = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]


def buscar_navegador():
    """Devuelve la ruta del primer navegador headless disponible."""
    for ruta in NAVEGADORES:
        if os.path.exists(ruta):
            return ruta
    for nombre in ("msedge", "chrome", "chromium", "chromium-browser",
                   "google-chrome", "headless_shell"):
        p = shutil.which(nombre)
        if p:
            return p
    return None


def html_a_pdf(html, ruta_pdf, timeout=90):
    """Convierte HTML a PDF con el navegador del sistema.

    Devuelve la ruta del PDF, o None si no hay navegador o falla.
    """
    nav = buscar_navegador()
    if not nav:
        return None
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(suffix=".html", prefix="hb_informe_")
        os.close(fd)
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(html)
        if os.path.exists(ruta_pdf):
            os.remove(ruta_pdf)
        cmd = [nav, "--headless=new", "--disable-gpu", "--no-sandbox",
               "--no-pdf-header-footer", "--run-all-compositor-stages-before-draw",
               "--virtual-time-budget=8000",
               "--print-to-pdf=" + os.path.abspath(ruta_pdf),
               "file:///" + tmp.replace("\\", "/").lstrip("/")]
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        if os.path.exists(ruta_pdf) and os.path.getsize(ruta_pdf) > 1000:
            return ruta_pdf
        return None
    except Exception:
        return None
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def es_pdf_valido(ruta):
    """Comprueba que el fichero es un PDF con al menos una pagina."""
    try:
        with open(ruta, "rb") as f:
            datos = f.read()
    except OSError:
        return False
    if not datos.startswith(b"%PDF-"):
        return False
    if b"%%EOF" not in datos[-2048:]:
        return False
    if b"/Type /Page" not in datos and b"/Type/Page" not in datos:
        return False
    return True


def paginas_pdf(ruta):
    """Cuenta las paginas de un PDF leyendo su estructura (sin dependencias)."""
    try:
        with open(ruta, "rb") as f:
            datos = f.read()
    except OSError:
        return 0
    import re
    m = re.search(rb"/Type\s*/Pages\s*/Count\s+(\d+)", datos)
    if m:
        return int(m.group(1))
    return len(re.findall(rb"/Type\s*/Page[^s]", datos))
