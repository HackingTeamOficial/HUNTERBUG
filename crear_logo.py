"""Genera el logotipo de HunterBug (PNG + ICO multi-resolucion).

Concepto: mira de punto (scope) con un insecto en el centro = "cazamos bugs".
El nivel de detalle se adapta al tamano: a 16-32 px se simplifica a anillo +
silueta gruesa con antenas cortas para que siga leyendose; a partir de 48 px
aparece el insecto completo. Se dibuja con supersampling x4 y contorno oscuro
para separar el insecto del anillo.
"""

from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFilter

VERDE = (0, 255, 65, 255)
VERDE_MED = (0, 214, 45, 255)
FONDO = (6, 9, 7, 255)
SEPARADOR = (4, 6, 5, 255)

SS = 4
BASE = 256


def _nivel(tam):
    if tam >= 96:
        return "alto"
    if tam >= 48:
        return "medio"
    return "bajo"


def _redondo(d, caja, radio, **kw):
    d.rounded_rectangle(caja, radius=radio, **kw)


def dibujar(tam):
    """Dibuja el logotipo al tamano pedido."""
    nivel = _nivel(tam)
    s = tam * SS
    u = s / 256.0
    c = s / 2.0
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # ---------------- fondo ----------------
    _redondo(d, (0, 0, s - 1, s - 1), int(58 * u), fill=FONDO)

    # resplandor radial suave detras del insecto
    if nivel != "bajo":
        halo = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        rr = int(80 * u)
        ImageDraw.Draw(halo).ellipse((c - rr, c - rr, c + rr, c + rr),
                                     fill=(0, 255, 90, 44))
        halo = halo.filter(ImageFilter.GaussianBlur(int(16 * u)))
        img = Image.alpha_composite(img, halo)
        d = ImageDraw.Draw(img)

    # marco exterior fino
    _redondo(d, (int(4 * u), int(4 * u), s - 1 - int(4 * u), s - 1 - int(4 * u)),
             int(54 * u), outline=(0, 120, 34, 255), width=max(1, int(3 * u)))

    # ---------------- anillo de mira ----------------
    r = int(94 * u)
    grosor = max(3, int(13 * u if nivel == "bajo" else 11 * u))
    d.ellipse((c - r, c - r, c + r, c + r), outline=VERDE, width=grosor)

    # marcas de mira (N, S, E, O) cruzando el anillo
    lm = max(3, int(15 * u if nivel == "bajo" else 13 * u))
    for (x0, y0, x1, y1) in ((c, c - r - lm, c, c - r + lm),
                             (c, c + r - lm, c, c + r + lm),
                             (c - r - lm, c, c - r + lm, c),
                             (c + r - lm, c, c + r + lm, c)):
        d.line([(x0, y0), (x1, y1)], fill=VERDE, width=grosor)

    # ---------------- insecto ----------------
    def silueta(color, extra=0.0):
        if nivel == "bajo":
            # a tamano minimo: cuerpo mas ancho, para que no parezca una barra
            bw = (56 + extra) * u
            bh = (54 + extra) * u
        else:
            bw = (44 + extra) * u
            bh = (60 + extra) * u
        cy = c + 10 * u
        _redondo(d, (c - bw / 2, cy - bh / 2, c + bw / 2, cy + bh / 2),
                 int(bw / 2), fill=color)
        hr = ((24 if nivel == "bajo" else 23) + extra / 2) * u
        hc = cy - bh / 2 + (4 if nivel == "bajo" else 2) * u
        d.ellipse((c - hr, hc - hr, c + hr, hc + hr), fill=color)

    # contorno oscuro: separa el insecto del anillo
    silueta(SEPARADOR, extra=12 * u if nivel == "bajo" else 10 * u)

    if nivel != "bajo":
        # patas (3 pares)
        gw = max(3, int(8 * u))
        for signo in (-1, 1):
            for dy, largo, caida in ((-14, 28, 13), (2, 32, 0), (18, 28, -11)):
                x0 = c + signo * 21 * u
                y0 = c + (dy + 6) * u
                d.line([(x0, y0), (x0 + signo * largo * u, y0 + caida * u)],
                       fill=VERDE_MED, width=gw)
        # antenas
        aw = max(3, int(6 * u))
        for signo in (-1, 1):
            x0 = c + signo * 10 * u
            y0 = c - 44 * u
            x1 = x0 + signo * 17 * u
            y1 = y0 - 21 * u
            d.line([(x0, y0), (x1, y1)], fill=VERDE_MED, width=aw)
            rr = max(3, int(6 * u))
            d.ellipse((x1 - rr, y1 - rr, x1 + rr, y1 + rr), fill=VERDE)

    silueta(VERDE)

    if nivel == "bajo":
        # a tamano minimo: antenas cortas y gruesas, bien visibles
        aw = max(3, int(11 * u))
        for signo in (-1, 1):
            x0 = c + signo * 13 * u
            y0 = c - 32 * u
            d.line([(x0, y0), (x0 + signo * 21 * u, y0 - 26 * u)],
                   fill=VERDE, width=aw)
    else:
        # separacion cabeza/cuerpo: da volumen
        d.line([(c - 13 * u, c - 12 * u), (c + 13 * u, c - 12 * u)],
               fill=SEPARADOR, width=max(2, int(5 * u)))

    # ---------------- barrido tenue ----------------
    barrido = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    ImageDraw.Draw(barrido).rectangle((0, int(c - 3 * u), s, int(c + 3 * u)),
                                      fill=(0, 255, 120, 22))
    img = Image.alpha_composite(img, barrido)

    return img.resize((tam, tam), Image.LANCZOS)


def main():
    raiz = os.path.dirname(os.path.abspath(__file__))
    carpeta = os.path.join(raiz, "assets")
    os.makedirs(carpeta, exist_ok=True)

    grande = dibujar(BASE)
    grande.save(os.path.join(carpeta, "hunterbug_logo.png"))
    dibujar(96).save(os.path.join(carpeta, "hunterbug_logo_96.png"))
    dibujar(48).save(os.path.join(carpeta, "hunterbug_logo_48.png"))

    ruta_ico = os.path.join(carpeta, "hunterbug.ico")
    grande.save(ruta_ico, format="ICO",
                sizes=[(16, 16), (24, 24), (32, 32), (48, 48),
                       (64, 64), (128, 128), (256, 256)])

    print("logo PNG:",
          os.path.getsize(os.path.join(carpeta, "hunterbug_logo.png")), "bytes")
    print("icono ICO:", os.path.getsize(ruta_ico), "bytes")
    with Image.open(ruta_ico) as im:
        print("tamanos:", sorted(im.info.get("sizes", [])))


if __name__ == "__main__":
    main()
