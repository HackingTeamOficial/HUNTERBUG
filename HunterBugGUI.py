#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HunterBug 1.0 - Framework de evaluacion de seguridad.

Interfaz con pestanas por categoria, resultados en tiempo real y ventanas
independientes por modulo. Version mejorada creada para la comunidad
hacking team by Juan Antonio.
"""

import json
import os
import random
import sys
import threading
import time
import tkinter as tk
from datetime import datetime, timezone
from tkinter import filedialog, messagebox, simpledialog

import customtkinter as ctk
from PIL import Image, ImageDraw, ImageFont, ImageTk

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from hb import ai, cve, events, graph, net, vulns, checks, metrics
from hb import informe as hb_informe
from hb import informe_intercambio as hb_intercambio
from hb import pdfmin as hb_pdfmin
from hb.ui_widgets import Tabla, VisorHTTP, LienzoGrafo, VentanaModulo

TEMAS = {
    "Dark": {
        'bg': '#050505', 'bg2': '#0a0a0a', 'panel': '#1a1a1a', 'panel2': '#222222',
        'green': '#00ff41', 'green_dim': '#00cc29', 'green_hover': '#33ff66',
        'blue': '#3399ff', 'yellow': '#ffdd55', 'orange': '#ff9944',
        'text': '#e2e8f0', 'text2': '#94a3b8', 'text3': '#64748b',
        'red': '#ff3333', 'cyan': '#00d4ff',
        'bar': '#0d0d0d', 'btn': '#1f1f1f', 'btn_hover': '#2a2a2a',
        'plot_bg': '#0a0a0a', 'grid': '#334155',
    },
    "Light": {
        'bg': '#f5f5f5', 'bg2': '#ffffff', 'panel': '#e8e8e8', 'panel2': '#dcdcdc',
        'green': '#0a7d2c', 'green_dim': '#086122', 'green_hover': '#0d9938',
        'blue': '#1d4ed8', 'yellow': '#9a7b00', 'orange': '#b35900',
        'text': '#111111', 'text2': '#444444', 'text3': '#777777',
        'red': '#c00000', 'cyan': '#0055aa',
        'bar': '#e0e0e0', 'btn': '#d5d5d5', 'btn_hover': '#c5c5c5',
        'plot_bg': '#ffffff', 'grid': '#bbbbbb',
    },
}

C = dict(TEMAS["Dark"])
RUTA_BASE = os.path.dirname(os.path.abspath(__file__))

FORMATOS_INFORME = [
    ("html", "HTML",
     "Informe completo con toda la evidencia, listo para abrir o imprimir.",
     "Cualquier navegador"),
    ("pdf", "PDF",
     "El mismo informe en PDF, para enviar o archivar.",
     "Adobe, navegador, Word"),
    ("json", "JSON",
     "Todos los datos de la evaluacion en crudo.",
     "Scripts, automatizacion"),
    ("markdown", "Markdown",
     "Texto plano para pegar en el reporte o en una wiki.",
     "HackerOne, Bugcrowd, Obsidian"),
    ("csv", "CSV",
     "Una fila por hallazgo, con la evidencia aplanada.",
     "Excel, Google Sheets"),
    ("har", "HAR 1.2",
     "Trafico HTTP capturado, con peticiones y respuestas en bruto.",
     "OWASP ZAP (Importar > Import HAR), DevTools, Burp con extension"),
    ("sarif", "SARIF 2.1.0",
     "Formato estandar de resultados de analisis de seguridad.",
     "GitHub/GitLab/Azure code scanning, add-on SARIF de ZAP"),
    ("burp", "Burp XML",
     "El mismo XML que exporta Burp Suite con sus issues.",
     "Invicti, Metasploit, Dradis, Burp Pro"),
    ("zap", "ZAP XML",
     "El informe XML clasico de OWASP ZAP.",
     "Lectores de informes de ZAP"),
]

# extension real de cada formato (el Markdown va en .md, no en .markdown)
EXTENSION_INFORME = {
    "html": "html", "pdf": "pdf", "json": "json", "markdown": "md",
    "csv": "csv", "har": "har", "sarif": "sarif", "burp": "xml",
    "zap": "xml",
}

MODULOS = [
    ("dns",     "DNS",              "Registros A, AAAA, MX, TXT, NS, SOA, CAA", False),
    ("ip",      "IP / Reversa",     "Resolucion directa e inversa",             False),
    ("http",    "HTTP / Cabeceras", "Peticion, respuesta, TLS y auditoria",    False),
    ("cve",     "CVE",              "Mapeo de tecnologia a vulnerabilidades",  False),
    ("puertos", "Puertos",          "TCP, banner y servicio",                  True),
    ("sqli",    "SQLi",             "Inyeccion SQL (errores y booleana)",      True),
    ("xss",     "XSS",              "Cross-site scripting reflejado",          True),
    ("idor",    "IDOR",             "Acceso a objetos ajenos",                 True),
    ("bola",    "BOLA",             "Autorizacion por objeto en API",          True),
    ("catalogo", "Catalogo",        "Motor completo de 203 chequeos",           True),
]

PESTANAS = [
    ("panel", "Panel"),
    ("recon", "Reconocimiento"),
    ("http",  "HTTP"),
    ("vulns", "Vulnerabilidades"),
    ("catalogo", "Catalogo"),
    ("informe", "Informe"),
    ("cve",   "CVE"),
    ("grafo", "Grafo / IA"),
    ("log",   "Registro"),
]


def dir_datos():
    """Carpeta persistente: junto al .exe si esta congelado, si no junto al .py."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return RUTA_BASE


def dir_informes():
    """Carpeta donde se guardan los informes generados."""
    d = os.path.join(dir_datos(), "informes")
    if not os.path.isdir(d):
        try:
            os.makedirs(d)
        except OSError:
            return dir_datos()
    return d


def abrir_carpeta(ruta):
    """Abre una carpeta en el explorador del sistema."""
    try:
        if sys.platform.startswith("win"):
            os.startfile(ruta)
        elif sys.platform == "darwin":
            import subprocess
            subprocess.Popen(["open", ruta])
        else:
            import subprocess
            subprocess.Popen(["xdg-open", ruta])
        return True
    except Exception:
        return False


def ruta_recurso(rel):
    """Ruta a un recurso empaquetado (assets) dentro del .exe o del proyecto."""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        p = os.path.join(base, rel)
        if os.path.exists(p):
            return p
    return os.path.join(RUTA_BASE, rel)


def aplicar_icono(ventana, ruta_ico):
    """Pone el logotipo como icono de la ventana (Windows)."""
    if not ruta_ico or not os.path.exists(ruta_ico):
        return
    try:
        ventana.iconbitmap(ruta_ico)
        return
    except Exception:
        pass
    try:
        from PIL import ImageTk as _ITk
        img = _ITk.PhotoImage(Image.open(ruta_ico))
        ventana.iconphoto(True, img)
        ventana._icono_ref = img
    except Exception:
        pass


def generar_fondo(w, h, ruta):
    img = Image.new("RGB", (w, h), C['bg'])
    d = ImageDraw.Draw(img)
    r0, g0, b0 = Image.new("RGB", (1, 1), C['bg']).getpixel((0, 0))
    r1, g1, b1 = Image.new("RGB", (1, 1), C['panel']).getpixel((0, 0))
    for y in range(h):
        t = y / max(1, h - 1)
        d.line([(0, y), (w, y)], fill=(int(r0 + (r1 - r0) * t),
                                       int(g0 + (g1 - g0) * t),
                                       int(b0 + (b1 - b0) * t)))
    try:
        font = ImageFont.truetype("C:/Windows/Fonts/courier.ttf", 15)
    except Exception:
        font = ImageFont.load_default()
    for _ in range(140):
        x = random.randint(0, max(1, w - 20))
        y = random.randint(0, max(1, h - 20))
        largo = random.randint(20, 110)
        col = C['green'] if random.random() > 0.5 else C['green_dim']
        d.line([(x, y), (x + largo, y)], fill=col, width=1)
    cmds = ["hunterbug scan target.com --profile full",
            "nmap -sV -Pn target.com", "nuclei -u https://target.com",
            "ffuf -w wl.txt -u https://target.com/FUZZ",
            "sqlmap -u 'https://target.com/i?id=1' --batch"]
    for cmd in cmds:
        x = random.randint(0, max(1, w - 340))
        y = random.randint(0, max(1, h - 40))
        d.text((x, y), cmd, fill=C['cyan'], font=font)
    img.save(ruta)


class HunterBugGUI(ctk.CTk):
    # ------------------------------------------------------------------ init
    def __init__(self):
        super().__init__()
        self.title("HUNTERBUG 1.0 - Framework de Evaluacion de Seguridad")
        self.geometry("1560x960")
        self.minsize(1180, 760)

        self.running = False
        self.cancel_requested = False
        self._vivo = True
        self._after_fondo = None
        self._img_ref = None
        self.widgets_tema = []

        self.bus = events.Bus()
        self.grafo = graph.Grafo()
        self.hallazgos = []
        self.puertos = []
        self.dns = {}
        self.ips = []
        self.tecnologias = {}
        self.http_historial = []
        self.ventanas = {}
        self.pestana_activa = "panel"
        self.modulo_estado = {k: {"estado": "pendiente", "progreso": 0,
                                  "inicio": None, "fin": None}
                              for k, _, _, _ in MODULOS}
        self.total_modulos = len(MODULOS)
        self.ultimo_http = None
        self.analisis_ia = ""
        self.catalogo_resultados = {}
        self.puntuacion = None
        self._catalogo_pendiente = 0

        self.modo = self.leer_tema_guardado()
        C.update(TEMAS[self.modo])
        ctk.set_appearance_mode(self.modo)
        ctk.set_default_color_theme("dark-blue" if self.modo == "Dark" else "blue")

        self.ruta_ico = ruta_recurso(os.path.join("assets", "hunterbug.ico"))
        self.logo_img = self.cargar_logo(40)

        self.crear_fondo_canvas()
        self.crear_barra_superior()
        self.crear_cuerpo()
        self.protocol("WM_DELETE_WINDOW", self.cerrar)
        aplicar_icono(self, self.ruta_ico)

        self.aplicar_tema()
        self.refrescar_fondo()
        self.registrar("HunterBug 1.0 listo. Tema: %s." % self.modo, "exito")
        self.registrar("Uso exclusivo en pruebas autorizadas. Marca la casilla de "
                       "autorizacion para lanzar los modulos activos.", "aviso")
        self.after(120, self.procesar_eventos)

    # ------------------------------------------------------------- utilidades
    def cargar_logo(self, tam):
        """Carga el logotipo como imagen de CustomTkinter."""
        try:
            ruta = ruta_recurso(os.path.join("assets", "hunterbug_logo.png"))
            if not os.path.exists(ruta):
                return None
            im = Image.open(ruta).convert("RGBA")
            im = im.resize((tam, tam), Image.LANCZOS)
            return ctk.CTkImage(light_image=im, dark_image=im, size=(tam, tam))
        except Exception:
            return None

    def reg(self, widget, **roles):
        self.widgets_tema.append((widget, roles))
        return widget

    def leer_tema_guardado(self):
        try:
            with open(os.path.join(dir_datos(), "theme_config.json"),
                      "r", encoding="utf-8") as f:
                modo = json.load(f).get("modo", "Dark")
            return modo if modo in TEMAS else "Dark"
        except Exception:
            return "Dark"

    def guardar_tema(self):
        try:
            with open(os.path.join(dir_datos(), "theme_config.json"),
                      "w", encoding="utf-8") as f:
                json.dump({"modo": self.modo}, f)
        except Exception:
            pass

    def cambiar_tema(self):
        self.modo = "Light" if self.modo == "Dark" else "Dark"
        C.update(TEMAS[self.modo])
        ctk.set_appearance_mode(self.modo)
        ctk.set_default_color_theme("dark-blue" if self.modo == "Dark" else "blue")
        self.guardar_tema()
        self.btn_tema.configure(text="Modo claro" if self.modo == "Dark"
                                else "Modo oscuro")
        self.lbl_status.configure(text="Estado: tema %s"
                                  % ("oscuro" if self.modo == "Dark" else "claro"))
        self.aplicar_tema()
        self.refrescar_fondo()
        self.mostrar_pestana(self.pestana_activa)

    def aplicar_tema(self):
        for widget, roles in self.widgets_tema:
            try:
                widget.configure(**{a: C[c] for a, c in roles.items()})
            except Exception:
                pass
        for tabla in getattr(self, "tablas", {}).values():
            try:
                tabla.aplicar_tema(C)
            except Exception:
                pass
        for w in (getattr(self, "visor_http", None), getattr(self, "lienzo", None)):
            try:
                w.aplicar_tema(C)
            except Exception:
                pass
        for ventana in self.ventanas.values():
            try:
                ventana.aplicar_tema(C)
            except Exception:
                pass
        for txt in (getattr(self, "console", None), getattr(self, "txt_log", None),
                    getattr(self, "txt_ia", None), getattr(self, "txt_detalle", None),
                    getattr(self, "txt_vulns", None),
                    getattr(self, "txt_informe", None)):
            if txt is None:
                continue
            try:
                txt.configure(bg=C['bg'], fg=C['text'], insertbackground=C['green'])
                for etiqueta, color in (("info", C['text3']), ("exito", C['green']),
                                        ("error", C['red']), ("aviso", C['cyan'])):
                    txt.tag_config(etiqueta, foreground=color)
            except Exception:
                pass
        try:
            self.fig.patch.set_facecolor(C['plot_bg'])
            self.ax_sev.set_facecolor(C['plot_bg'])
            self.ax_sev.tick_params(colors=C['text2'], labelsize=8)
            self.ax_sev.title.set_color(C['green'])
            for sp in self.ax_sev.spines.values():
                sp.set_color(C['grid'])
            self.canvas.draw()
        except Exception:
            pass
        # grafico de puntuacion por categoria (pestana del catalogo)
        if getattr(self, "fig_cat", None) is not None:
            try:
                self.fig_cat.patch.set_facecolor(C['plot_bg'])
                self.ax_cat.set_facecolor(C['plot_bg'])
                self.ax_cat.tick_params(colors=C['text2'], labelsize=6)
                for sp in self.ax_cat.spines.values():
                    sp.set_color(C['grid'])
                self.canvas_cat.draw()
            except Exception:
                pass

    def crear_fondo_canvas(self):
        self.bg_canvas = ctk.CTkCanvas(self, width=1400, height=900,
                                       bg=C['bg'], highlightthickness=0, bd=0)
        self.bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)

    def refrescar_fondo(self):
        try:
            ruta = os.path.join(dir_datos(), "fondo_matrix.png")
            generar_fondo(1400, 900, ruta)
            self._img_ref = ImageTk.PhotoImage(Image.open(ruta))
            self.bg_canvas.delete("all")
            self.bg_canvas.configure(bg=C['bg'])
            self.bg_canvas.create_image(700, 450, image=self._img_ref)
        except Exception as e:
            print("[FONDO] error:", e)

    def registrar(self, texto, nivel="info", modulo=None):
        self.bus.log(modulo or "nucleo", texto, nivel)

    # --------------------------------------------------------- barra superior
    def crear_barra_superior(self):
        barra = ctk.CTkFrame(self, height=54, corner_radius=0)
        self.reg(barra, fg_color='bar')
        barra.pack(fill="x", side="top")
        barra.pack_propagate(False)

        if self.logo_img is not None:
            self.reg(ctk.CTkLabel(barra, image=self.logo_img, text=""),
                     fg_color='bar').place(x=16, y=8)
            x_texto = 66
        else:
            x_texto = 20

        self.reg(ctk.CTkLabel(barra, text="HUNTERBUG 1.0",
                              font=ctk.CTkFont(family="Consolas", size=18,
                                               weight="bold")),
                 fg_color='bar', text_color='green').place(x=x_texto, y=6)
        self.reg(ctk.CTkLabel(barra,
                              text="Version mejorada para la comunidad hacking team",
                              font=ctk.CTkFont(family="Consolas", size=8)),
                 fg_color='bar', text_color='text3').place(x=x_texto + 1, y=31)

        self.reg(ctk.CTkButton(barra, text="Buscar target", width=130,
                               font=ctk.CTkFont(family="Consolas", size=10,
                                                weight="bold"),
                               command=self.abrir_buscar_target),
                 fg_color='green', hover_color='green_dim',
                 text_color='bg').place(x=392, y=12)

        self.btn_tema = self.reg(
            ctk.CTkButton(barra, text="Modo claro", width=118,
                          font=ctk.CTkFont(family="Consolas", size=10),
                          command=self.cambiar_tema),
            fg_color='btn', hover_color='btn_hover', text_color='text')
        self.btn_tema.place(x=534, y=12)

        self.reg(ctk.CTkButton(barra, text="Reiniciar", width=104,
                               font=ctk.CTkFont(family="Consolas", size=10),
                               command=self.reiniciar_motor),
                 fg_color='btn', hover_color='btn_hover',
                 text_color='text').place(x=660, y=12)

        self.reg(ctk.CTkButton(barra, text="Exportar informe", width=146,
                               font=ctk.CTkFont(family="Consolas", size=10),
                               command=self.exportar_informe),
                 fg_color='btn', hover_color='btn_hover',
                 text_color='text').place(x=772, y=12)

        self.btn_acerca = self.reg(
            ctk.CTkButton(barra, text="Acerca de", width=112,
                          font=ctk.CTkFont(family="Consolas", size=10,
                                           weight="bold"),
                          command=self.acerca_de),
            fg_color='blue', hover_color='blue', text_color='bg')
        self.btn_acerca.place(x=926, y=12)

        self.lbl_status = self.reg(
            ctk.CTkLabel(barra, text="Estado: listo",
                         font=ctk.CTkFont(family="Consolas", size=9,
                                          weight="bold")),
            fg_color='bar', text_color='text3')
        self.lbl_status.place(x=1052, y=20)

        self.reg(ctk.CTkLabel(barra, text=datetime.now().strftime("%H:%M %d/%m/%Y"),
                              font=ctk.CTkFont(family="Consolas", size=8)),
                 fg_color='bar', text_color='text3').place(relx=1.0, x=-20, y=22,
                                                           anchor="e")

    # ---------------------------------------------------------------- cuerpo
    def crear_cuerpo(self):
        self.cuerpo = ctk.CTkFrame(self, corner_radius=0)
        self.reg(self.cuerpo, fg_color='bg')
        self.cuerpo.pack(fill="both", expand=True)
        self.crear_lateral()
        self.crear_derecha()

    def crear_lateral(self):
        lado = ctk.CTkFrame(self.cuerpo, width=300, corner_radius=0)
        self.reg(lado, fg_color='bg')
        lado.pack(fill="y", side="left")
        lado.pack_propagate(False)

        self.reg(ctk.CTkLabel(lado, text="MODULOS",
                              font=ctk.CTkFont(family="Consolas", size=11,
                                               weight="bold")),
                 fg_color='bg', text_color='green').pack(pady=(14, 2))
        self.reg(ctk.CTkLabel(lado, text="estado / progreso / duracion",
                              font=ctk.CTkFont(family="Consolas", size=8)),
                 fg_color='bg', text_color='text3').pack(pady=(0, 8))

        self.lista_modulos = self.reg(
            ctk.CTkScrollableFrame(lado, corner_radius=0), fg_color='bg2')
        self.lista_modulos.pack(fill="both", expand=True, padx=6, pady=(0, 10))

        self.filas = {}
        for clave, nombre, desc, activo in MODULOS:
            fila = self.reg(ctk.CTkFrame(self.lista_modulos, corner_radius=6),
                            fg_color='panel')
            fila.pack(fill="x", padx=2, pady=3)

            cab = self.reg(ctk.CTkFrame(fila, corner_radius=0), fg_color='panel')
            cab.pack(fill="x", padx=8, pady=(7, 0))
            self.reg(ctk.CTkLabel(cab, text=nombre,
                                  font=ctk.CTkFont(family="Consolas", size=10,
                                                   weight="bold")),
                     fg_color='panel', text_color='green').pack(side="left")
            if activo:
                self.reg(ctk.CTkLabel(cab, text="activo",
                                      font=ctk.CTkFont(family="Consolas", size=7,
                                                       weight="bold")),
                         fg_color='panel', text_color='cyan').pack(side="right")

            self.reg(ctk.CTkLabel(fila, text=desc,
                                  font=ctk.CTkFont(family="Consolas", size=7)),
                     fg_color='panel', text_color='text2').pack(anchor="w",
                                                                padx=8, pady=(0, 3))
            lbl = self.reg(ctk.CTkLabel(fila, text="pendiente  |  0%  |  0.0s",
                                        font=ctk.CTkFont(family="Consolas", size=8)),
                           fg_color='panel', text_color='text3')
            lbl.pack(anchor="w", padx=8)

            barra = self.reg(ctk.CTkProgressBar(fila, height=6),
                             fg_color='bg2', progress_color='green')
            barra.set(0)
            barra.pack(fill="x", padx=8, pady=(3, 4))

            pie = self.reg(ctk.CTkFrame(fila, corner_radius=0), fg_color='panel')
            pie.pack(fill="x", padx=8, pady=(0, 7))
            self.reg(ctk.CTkButton(pie, text="Abrir ventana", width=110, height=22,
                                   font=ctk.CTkFont(family="Consolas", size=8),
                                   command=lambda c=clave, n=nombre:
                                   self.abrir_ventana(c, n)),
                     fg_color='btn', hover_color='btn_hover',
                     text_color='text2').pack(side="left")

            self.filas[clave] = (fila, lbl, barra, nombre)

    def crear_derecha(self):
        der = self.reg(ctk.CTkFrame(self.cuerpo, corner_radius=0), fg_color='bg')
        der.pack(fill="both", expand=True, side="right")
        self.crear_config(der)
        self.crear_pestanas(der)

    def crear_config(self, padre):
        panel = self.reg(ctk.CTkFrame(padre, corner_radius=10), fg_color='panel')
        panel.pack(fill="x", padx=14, pady=(14, 6))

        cab = self.reg(ctk.CTkFrame(panel, corner_radius=0), fg_color='panel')
        cab.pack(fill="x", padx=14, pady=(10, 6))
        self.reg(ctk.CTkLabel(cab, text="OBJETIVO Y EJECUCION",
                              font=ctk.CTkFont(family="Consolas", size=12,
                                               weight="bold")),
                 fg_color='panel', text_color='green').pack(side="left")
        self.var_autorizado = tk.BooleanVar(value=False)
        self.chk_autorizado = self.reg(
            ctk.CTkCheckBox(cab,
                            text="Tengo autorizacion para probar este objetivo",
                            variable=self.var_autorizado,
                            font=ctk.CTkFont(family="Consolas", size=9),
                            checkbox_width=18, checkbox_height=18),
            fg_color='green', hover_color='green_dim', text_color='text2',
            border_color='text3')
        self.chk_autorizado.pack(side="right")

        fila = self.reg(ctk.CTkFrame(panel, corner_radius=0), fg_color='panel')
        fila.pack(fill="x", padx=14, pady=(0, 8))

        def campo(etiqueta, valor="", ancho=260):
            marco = self.reg(ctk.CTkFrame(fila, corner_radius=0), fg_color='panel')
            marco.pack(side="left", fill="x", expand=True, padx=(0, 10))
            self.reg(ctk.CTkLabel(marco, text=etiqueta,
                                  font=ctk.CTkFont(family="Consolas", size=8,
                                                   weight="bold")),
                     fg_color='panel', text_color='text2').pack(anchor="w")
            e = self.reg(ctk.CTkEntry(marco, width=ancho,
                                      font=ctk.CTkFont(family="Consolas", size=10)),
                         fg_color='bg2', text_color='text', border_color='text3')
            e.pack(fill="x", pady=(2, 0))
            if valor:
                e.insert(0, valor)
            return e

        self.entry_target = campo("TARGET", "example.com")

        marco_p = self.reg(ctk.CTkFrame(fila, corner_radius=0), fg_color='panel')
        marco_p.pack(side="left", padx=(0, 10))
        self.reg(ctk.CTkLabel(marco_p, text="PERFIL",
                              font=ctk.CTkFont(family="Consolas", size=8,
                                               weight="bold")),
                 fg_color='panel', text_color='text2').pack(anchor="w")
        self.perfil = self.reg(
            ctk.CTkOptionMenu(marco_p, values=["full", "recon", "webapp", "api"],
                              width=130,
                              font=ctk.CTkFont(family="Consolas", size=10),
                              command=self.cambiar_perfil),
            fg_color='bg2', text_color='text', button_color='btn',
            button_hover_color='btn_hover')
        self.perfil.set("full")
        self.perfil.pack(pady=(2, 0))

        marco_ia = self.reg(ctk.CTkFrame(fila, corner_radius=0), fg_color='panel')
        marco_ia.pack(side="left", padx=(0, 10))
        self.reg(ctk.CTkLabel(marco_ia, text="MODELO IA (OLLAMA)",
                              font=ctk.CTkFont(family="Consolas", size=8,
                                               weight="bold")),
                 fg_color='panel', text_color='text2').pack(anchor="w")
        linea_ia = self.reg(ctk.CTkFrame(marco_ia, corner_radius=0), fg_color='panel')
        linea_ia.pack(pady=(2, 0))
        self.ai_provider = self.reg(
            ctk.CTkOptionMenu(linea_ia, values=["ollama", "vllm", "hermes"],
                              width=110,
                              font=ctk.CTkFont(family="Consolas", size=10),
                              command=self.cambiar_proveedor),
            fg_color='bg2', text_color='text', button_color='btn',
            button_hover_color='btn_hover')
        self.ai_provider.set("ollama")
        self.ai_provider.pack(side="left")
        self.ai_model = self.reg(ctk.CTkEntry(linea_ia, width=180,
                                              font=ctk.CTkFont(family="Consolas",
                                                               size=10)),
                                 fg_color='bg2', text_color='text',
                                 border_color='text3')
        self.ai_model.insert(0, "llama3.1:8b")
        self.ai_model.pack(side="left", padx=(6, 0))

        acciones = self.reg(ctk.CTkFrame(panel, corner_radius=0), fg_color='panel')
        acciones.pack(fill="x", padx=14, pady=(0, 12))
        self.btn_ejecutar = self.reg(
            ctk.CTkButton(acciones, text="EJECUTAR EVALUACION", height=36,
                          font=ctk.CTkFont(family="Consolas", size=12,
                                           weight="bold"),
                          command=self.ejecutar_evaluacion),
            fg_color='green', hover_color='green_dim', text_color='bg')
        self.btn_ejecutar.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.btn_parar = self.reg(
            ctk.CTkButton(acciones, text="DETENER", width=120, height=36,
                          font=ctk.CTkFont(family="Consolas", size=11,
                                           weight="bold"),
                          command=self.parar_evaluacion),
            fg_color='red', hover_color='red', text_color='bg')
        self.btn_parar.pack(side="left", padx=(0, 8))
        self.btn_parar.configure(state="disabled")
        self.reg(ctk.CTkButton(acciones, text="Detectar modelos locales", width=180,
                               height=36,
                               font=ctk.CTkFont(family="Consolas", size=10),
                               command=self.detectar_modelos_locales),
                 fg_color='btn', hover_color='btn_hover',
                 text_color='text').pack(side="left", padx=(0, 8))
        self.reg(ctk.CTkButton(acciones, text="Analizar con IA", width=150,
                               height=36,
                               font=ctk.CTkFont(family="Consolas", size=10,
                                                weight="bold"),
                               command=self.analizar_con_ia),
                 fg_color='blue', hover_color='blue',
                 text_color='bg').pack(side="left")

    def crear_pestanas(self, padre):
        barra = self.reg(ctk.CTkFrame(padre, corner_radius=0), fg_color='bg')
        barra.pack(fill="x", padx=14, pady=(4, 0))
        self.botones_pestana = {}
        for clave, titulo in PESTANAS:
            b = self.reg(ctk.CTkButton(barra, text=titulo, width=148, height=30,
                                       font=ctk.CTkFont(family="Consolas",
                                                        size=10, weight="bold"),
                                       command=lambda c=clave:
                                       self.mostrar_pestana(c)),
                         fg_color='btn', hover_color='btn_hover', text_color='text2')
            b.pack(side="left", padx=(0, 6))
            self.botones_pestana[clave] = b

        self.contenedor = self.reg(ctk.CTkFrame(padre, corner_radius=10),
                                   fg_color='panel')
        self.contenedor.pack(fill="both", expand=True, padx=14, pady=(6, 14))

        self.tablas = {}
        self.marcos = {}
        for clave, _ in PESTANAS:
            self.marcos[clave] = self.reg(ctk.CTkFrame(self.contenedor,
                                                       corner_radius=0),
                                          fg_color='panel')

        self.construir_panel()
        self.construir_recon()
        self.construir_http()
        self.construir_vulns()
        self.construir_catalogo()
        self.construir_informe()
        self.construir_cve()
        self.construir_grafo()
        self.construir_log()
        self.mostrar_pestana("panel")

    def mostrar_pestana(self, clave):
        self.pestana_activa = clave
        for k, marco in self.marcos.items():
            if k == clave:
                marco.pack(fill="both", expand=True)
            else:
                marco.pack_forget()
        for k, boton in self.botones_pestana.items():
            if k == clave:
                boton.configure(fg_color=C['green'], text_color=C['bg'])
            else:
                boton.configure(fg_color=C['btn'], text_color=C['text2'])
        if clave == "grafo" and self.grafo.nodos and not self.lienzo._pos:
            self.reorganizar_grafo()

    # ------------------------------------------------------- pestana: panel
    def construir_panel(self):
        m = self.marcos["panel"]
        sup = self.reg(ctk.CTkFrame(m, corner_radius=0), fg_color='panel')
        sup.pack(fill="x", padx=12, pady=(12, 6))
        self.progreso_label = self.reg(
            ctk.CTkLabel(sup, text="Progreso global: 0%",
                         font=ctk.CTkFont(family="Consolas", size=10,
                                          weight="bold")),
            fg_color='panel', text_color='green')
        self.progreso_label.pack(anchor="w")
        self.progreso_barra = self.reg(ctk.CTkProgressBar(sup, height=10),
                                       fg_color='bg2', progress_color='green')
        self.progreso_barra.set(0)
        self.progreso_barra.pack(fill="x", pady=(4, 0))
        self.lbl_resumen = self.reg(
            ctk.CTkLabel(sup, text="Sin datos todavia.",
                         font=ctk.CTkFont(family="Consolas", size=9)),
            fg_color='panel', text_color='text2')
        self.lbl_resumen.pack(anchor="w", pady=(6, 0))

        cuerpo = self.reg(ctk.CTkFrame(m, corner_radius=0), fg_color='panel')
        cuerpo.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        izq = self.reg(ctk.CTkFrame(cuerpo, corner_radius=8), fg_color='bg2')
        izq.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.reg(ctk.CTkLabel(izq, text="HALLAZGOS EN TIEMPO REAL",
                              font=ctk.CTkFont(family="Consolas", size=10,
                                               weight="bold")),
                 fg_color='bg2', text_color='green').pack(anchor="w", padx=8,
                                                          pady=(8, 4))
        self.tablas["hallazgos"] = Tabla(izq,
                                         ["Severidad", "Tipo", "Titulo", "URL"],
                                         [90, 100, 340, 300], alto=14)
        self.tablas["hallazgos"].pack(fill="both", expand=True, padx=6, pady=(0, 8))
        self.tablas["hallazgos"].al_seleccionar(self.ver_hallazgo)

        der = self.reg(ctk.CTkFrame(cuerpo, corner_radius=8, width=440),
                       fg_color='bg2')
        der.pack(side="right", fill="y")
        der.pack_propagate(False)
        self.reg(ctk.CTkLabel(der, text="SEVERIDAD",
                              font=ctk.CTkFont(family="Consolas", size=10,
                                               weight="bold")),
                 fg_color='bg2', text_color='green').pack(anchor="w", padx=8,
                                                          pady=(8, 4))
        self.fig = Figure(figsize=(4.0, 2.4), dpi=100)
        self.ax_sev = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, der)
        self.canvas.get_tk_widget().pack(fill="x", padx=8, pady=(0, 8))

        self.reg(ctk.CTkLabel(der, text="DETALLE DEL HALLAZGO",
                              font=ctk.CTkFont(family="Consolas", size=10,
                                               weight="bold")),
                 fg_color='bg2', text_color='green').pack(anchor="w", padx=8)
        self.txt_detalle = tk.Text(der, height=13, wrap="word", bd=0,
                                   font=("Consolas", 9))
        self.txt_detalle.pack(fill="both", expand=True, padx=8, pady=(2, 8))
        self.txt_detalle.configure(state="disabled")

    # ------------------------------------------------------- pestana: recon
    def construir_recon(self):
        m = self.marcos["recon"]
        sup = self.reg(ctk.CTkFrame(m, corner_radius=0), fg_color='panel')
        sup.pack(fill="x", padx=12, pady=(12, 6))
        self.reg(ctk.CTkLabel(sup, text="RECONOCIMIENTO: DNS, IP Y PUERTOS",
                              font=ctk.CTkFont(family="Consolas", size=11,
                                               weight="bold")),
                 fg_color='panel', text_color='green').pack(side="left")
        self.lbl_recon = self.reg(ctk.CTkLabel(sup, text="",
                                               font=ctk.CTkFont(family="Consolas",
                                                                size=9)),
                                  fg_color='panel', text_color='text2')
        self.lbl_recon.pack(side="right")

        cuerpo = self.reg(ctk.CTkFrame(m, corner_radius=0), fg_color='panel')
        cuerpo.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        izq = self.reg(ctk.CTkFrame(cuerpo, corner_radius=8), fg_color='bg2')
        izq.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.reg(ctk.CTkLabel(izq, text="REGISTROS DNS",
                              font=ctk.CTkFont(family="Consolas", size=10,
                                               weight="bold")),
                 fg_color='bg2', text_color='green').pack(anchor="w", padx=8,
                                                          pady=(8, 4))
        self.tablas["dns"] = Tabla(izq, ["Tipo", "Valor"], [80, 430], alto=11)
        self.tablas["dns"].pack(fill="both", expand=True, padx=6, pady=(0, 8))
        self.reg(ctk.CTkLabel(izq, text="IP Y RESOLUCION INVERSA",
                              font=ctk.CTkFont(family="Consolas", size=10,
                                               weight="bold")),
                 fg_color='bg2', text_color='green').pack(anchor="w", padx=8)
        self.tablas["ip"] = Tabla(izq, ["IP", "Reversa"], [190, 320], alto=5)
        self.tablas["ip"].pack(fill="x", padx=6, pady=(2, 8))

        der = self.reg(ctk.CTkFrame(cuerpo, corner_radius=8), fg_color='bg2')
        der.pack(side="right", fill="both", expand=True)
        self.reg(ctk.CTkLabel(der, text="PUERTOS Y SERVICIOS",
                              font=ctk.CTkFont(family="Consolas", size=10,
                                               weight="bold")),
                 fg_color='bg2', text_color='green').pack(anchor="w", padx=8,
                                                          pady=(8, 4))
        self.tablas["puertos"] = Tabla(der, ["Puerto", "Servicio", "Banner"],
                                       [80, 110, 330], alto=11)
        self.tablas["puertos"].pack(fill="both", expand=True, padx=6, pady=(0, 8))
        self.reg(ctk.CTkLabel(der, text="TECNOLOGIAS IDENTIFICADAS",
                              font=ctk.CTkFont(family="Consolas", size=10,
                                               weight="bold")),
                 fg_color='bg2', text_color='green').pack(anchor="w", padx=8)
        self.tablas["tec"] = Tabla(der, ["Producto", "Evidencia"], [170, 340],
                                   alto=5)
        self.tablas["tec"].pack(fill="x", padx=6, pady=(2, 8))

    # -------------------------------------------------------- pestana: http
    def construir_http(self):
        m = self.marcos["http"]
        sup = self.reg(ctk.CTkFrame(m, corner_radius=0), fg_color='panel')
        sup.pack(fill="x", padx=12, pady=(12, 6))
        self.reg(ctk.CTkLabel(sup, text="PETICION Y RESPUESTA HTTP",
                              font=ctk.CTkFont(family="Consolas", size=11,
                                               weight="bold")),
                 fg_color='panel', text_color='green').pack(side="left")
        self.reg(ctk.CTkButton(sup, text="Repetir ultima", width=120, height=28,
                               font=ctk.CTkFont(family="Consolas", size=9),
                               command=self.repetir_http),
                 fg_color='btn', hover_color='btn_hover',
                 text_color='text').pack(side="right")
        self.entry_url_http = self.reg(
            ctk.CTkEntry(sup, width=420,
                         font=ctk.CTkFont(family="Consolas", size=10)),
            fg_color='bg2', text_color='text', border_color='text3')
        self.entry_url_http.pack(side="right", padx=8)
        self.reg(ctk.CTkButton(sup, text="Pedir", width=80, height=28,
                               font=ctk.CTkFont(family="Consolas", size=9,
                                                weight="bold"),
                               command=self.pedir_http_manual),
                 fg_color='green', hover_color='green_dim',
                 text_color='bg').pack(side="right")

        cuerpo = self.reg(ctk.CTkFrame(m, corner_radius=0), fg_color='panel')
        cuerpo.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.visor_http = VisorHTTP(cuerpo, alto=16)
        self.visor_http.pack(fill="both", expand=True)

        pie = self.reg(ctk.CTkFrame(cuerpo, corner_radius=8), fg_color='bg2')
        pie.pack(fill="x", pady=(8, 0))
        self.reg(ctk.CTkLabel(pie, text="HISTORIAL DE PETICIONES",
                              font=ctk.CTkFont(family="Consolas", size=10,
                                               weight="bold")),
                 fg_color='bg2', text_color='green').pack(anchor="w", padx=8,
                                                          pady=(8, 4))
        self.tablas["http"] = Tabla(pie, ["Metodo", "URL", "Codigo", "ms"],
                                    [70, 560, 80, 70], alto=4)
        self.tablas["http"].pack(fill="x", padx=6, pady=(0, 8))
        self.tablas["http"].al_seleccionar(self.ver_http_historial)
        self.reg(ctk.CTkLabel(pie, text="AUDITORIA DE CABECERAS",
                              font=ctk.CTkFont(family="Consolas", size=10,
                                               weight="bold")),
                 fg_color='bg2', text_color='green').pack(anchor="w", padx=8)
        self.tablas["cabeceras"] = Tabla(pie, ["Severidad", "Hallazgo", "Motivo"],
                                         [90, 320, 380], alto=4)
        self.tablas["cabeceras"].pack(fill="x", padx=6, pady=(2, 8))

    # ------------------------------------------------------- pestana: vulns
    def construir_vulns(self):
        m = self.marcos["vulns"]
        cfg = self.reg(ctk.CTkFrame(m, corner_radius=8), fg_color='bg2')
        cfg.pack(fill="x", padx=12, pady=(12, 6))
        self.reg(ctk.CTkLabel(cfg, text="PARAMETROS PARA IDOR Y BOLA",
                              font=ctk.CTkFont(family="Consolas", size=10,
                                               weight="bold")),
                 fg_color='bg2', text_color='green').pack(anchor="w", padx=10,
                                                          pady=(8, 4))

        def mini(padre, etiqueta, valor="", ancho=230):
            marco = self.reg(ctk.CTkFrame(padre, corner_radius=0), fg_color='bg2')
            marco.pack(side="left", padx=(0, 10))
            self.reg(ctk.CTkLabel(marco, text=etiqueta,
                                  font=ctk.CTkFont(family="Consolas", size=8,
                                                   weight="bold")),
                     fg_color='bg2', text_color='text2').pack(anchor="w")
            e = self.reg(ctk.CTkEntry(marco, width=ancho,
                                      font=ctk.CTkFont(family="Consolas", size=9)),
                         fg_color='bg', text_color='text', border_color='text3')
            e.pack(fill="x", pady=(2, 0))
            if valor:
                e.insert(0, valor)
            return e

        f1 = self.reg(ctk.CTkFrame(cfg, corner_radius=0), fg_color='bg2')
        f1.pack(fill="x", padx=10, pady=(0, 4))
        self.entry_patron_idor = mini(f1, "PATRON IDOR (usa {id})",
                                      "https://ejemplo.test/api/usuario/{id}", 300)
        self.entry_id_a = mini(f1, "ID A", "1", 70)
        self.entry_id_b = mini(f1, "ID B", "2", 70)
        self.entry_url_bola = mini(f1, "URL BOLA",
                                   "https://ejemplo.test/api/cuenta/1", 300)

        f2 = self.reg(ctk.CTkFrame(cfg, corner_radius=0), fg_color='bg2')
        f2.pack(fill="x", padx=10, pady=(0, 4))
        self.entry_token_a = mini(f2, "TOKEN A (Bearer)", "", 210)
        self.entry_token_b = mini(f2, "TOKEN B (Bearer)", "", 210)
        self.entry_cookie_a = mini(f2, "COOKIE A", "", 210)
        self.entry_cookie_b = mini(f2, "COOKIE B", "", 210)

        f3 = self.reg(ctk.CTkFrame(cfg, corner_radius=0), fg_color='bg2')
        f3.pack(fill="x", padx=10, pady=(0, 8))
        self.entry_cabeceras = mini(f3, "CABECERAS EXTRA (Clave: valor; Clave2: valor2)",
                                    "", 780)

        cuerpo = self.reg(ctk.CTkFrame(m, corner_radius=0), fg_color='panel')
        cuerpo.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        izq = self.reg(ctk.CTkFrame(cuerpo, corner_radius=8), fg_color='bg2')
        izq.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.reg(ctk.CTkLabel(izq, text="HALLAZGOS POR CATEGORIA",
                              font=ctk.CTkFont(family="Consolas", size=10,
                                               weight="bold")),
                 fg_color='bg2', text_color='green').pack(anchor="w", padx=8,
                                                          pady=(8, 4))
        self.tablas["vulns"] = Tabla(izq, ["Severidad", "Categoria", "Titulo",
                                           "Parametro"],
                                     [90, 100, 380, 130], alto=15)
        self.tablas["vulns"].pack(fill="both", expand=True, padx=6, pady=(0, 8))
        self.tablas["vulns"].al_seleccionar(self.ver_hallazgo)

        der = self.reg(ctk.CTkFrame(cuerpo, corner_radius=8, width=430),
                       fg_color='bg2')
        der.pack(side="right", fill="y")
        der.pack_propagate(False)
        self.reg(ctk.CTkLabel(der, text="TRAZA DE LAS PRUEBAS ACTIVAS",
                              font=ctk.CTkFont(family="Consolas", size=10,
                                               weight="bold")),
                 fg_color='bg2', text_color='green').pack(anchor="w", padx=8,
                                                          pady=(8, 4))
        self.txt_vulns = tk.Text(der, wrap="word", bd=0, font=("Consolas", 9))
        self.txt_vulns.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.txt_vulns.configure(state="disabled")

    # ---------------------------------------------------- pestana: catalogo
    def construir_catalogo(self):
        """Pestana del motor de 203 chequeos: estado de cada uno, puntuacion
        de seguridad y metricas de la evaluacion."""
        m = self.marcos["catalogo"]

        sup = self.reg(ctk.CTkFrame(m, corner_radius=0), fg_color='panel')
        sup.pack(fill="x", padx=12, pady=(12, 6))
        self.reg(ctk.CTkLabel(sup, text="MOTOR DE 203 CHEQUEOS DE SEGURIDAD",
                              font=ctk.CTkFont(family="Consolas", size=10,
                                               weight="bold")),
                 fg_color='panel', text_color='green').pack(anchor="w")

        # --- puntuacion y metricas
        marc = self.reg(ctk.CTkFrame(m, corner_radius=8), fg_color='bg2')
        marc.pack(fill="x", padx=12, pady=(0, 6))
        izq = self.reg(ctk.CTkFrame(marc, corner_radius=0), fg_color='bg2')
        izq.pack(side="left", fill="both", expand=True, padx=10, pady=8)
        self.lbl_puntuacion = self.reg(
            ctk.CTkLabel(izq, text="-- / 100",
                         font=ctk.CTkFont(family="Consolas", size=26,
                                          weight="bold")),
            fg_color='bg2', text_color='text')
        self.lbl_puntuacion.pack(anchor="w")
        self.lbl_letra = self.reg(
            ctk.CTkLabel(izq, text="Sin evaluar",
                         font=ctk.CTkFont(family="Consolas", size=10,
                                          weight="bold")),
            fg_color='bg2', text_color='text2')
        self.lbl_letra.pack(anchor="w")
        self.barra_puntuacion = self.reg(ctk.CTkProgressBar(izq, height=12),
                                         fg_color='bg', progress_color='green')
        self.barra_puntuacion.set(0)
        self.barra_puntuacion.pack(fill="x", pady=(8, 4))
        self.lbl_metricas = self.reg(
            ctk.CTkLabel(izq, text="Ejecuta el catalogo para ver metricas.",
                         font=ctk.CTkFont(family="Consolas", size=9)),
            fg_color='bg2', text_color='text2', justify="left")
        self.lbl_metricas.pack(anchor="w")

        # --- grafico por categoria
        der = self.reg(ctk.CTkFrame(marc, corner_radius=8), fg_color='bg2')
        der.pack(side="right", fill="both", padx=(0, 10), pady=8)
        self.reg(ctk.CTkLabel(der, text="PUNTUACION POR CATEGORIA",
                              font=ctk.CTkFont(family="Consolas", size=9,
                                               weight="bold")),
                 fg_color='bg2', text_color='green').pack(anchor="w", padx=8,
                                                          pady=(8, 0))
        self.fig_cat = Figure(figsize=(4.2, 2.1), dpi=100)
        self.ax_cat = self.fig_cat.add_subplot(111)
        self.canvas_cat = FigureCanvasTkAgg(self.fig_cat, der)
        self.canvas_cat.get_tk_widget().pack(fill="both", expand=True,
                                             padx=8, pady=(0, 8))

        # --- filtros
        filt = self.reg(ctk.CTkFrame(m, corner_radius=8), fg_color='bg2')
        filt.pack(fill="x", padx=12, pady=(0, 6))
        self.reg(ctk.CTkLabel(filt, text="Categoria",
                              font=ctk.CTkFont(family="Consolas", size=8,
                                               weight="bold")),
                 fg_color='bg2', text_color='text2').pack(side="left", padx=(8, 2))
        self.combo_cat = self.reg(
            ctk.CTkComboBox(filt, width=150, state="readonly",
                            font=ctk.CTkFont(family="Consolas", size=9)),
            fg_color='bg', text_color='text', border_color='text3')
        self.combo_cat.pack(side="left", padx=(0, 10))
        self.reg(ctk.CTkLabel(filt, text="Severidad",
                              font=ctk.CTkFont(family="Consolas", size=8,
                                               weight="bold")),
                 fg_color='bg2', text_color='text2').pack(side="left", padx=(0, 2))
        self.combo_sev = self.reg(
            ctk.CTkComboBox(filt, width=110, state="readonly",
                            font=ctk.CTkFont(family="Consolas", size=9)),
            fg_color='bg', text_color='text', border_color='text3')
        self.combo_sev.pack(side="left", padx=(0, 10))
        self.btn_catalogo = self.reg(
            ctk.CTkButton(filt, text="EJECUTAR CATALOGO", width=170, height=28,
                          font=ctk.CTkFont(family="Consolas", size=9,
                                           weight="bold"),
                          command=self.ejecutar_evaluacion),
            fg_color='green', hover_color='green_hover', text_color='bg')
        self.btn_catalogo.pack(side="left", padx=(6, 0))
        self.btn_csv = self.reg(
            ctk.CTkButton(filt, text="EXPORTAR CSV", width=130, height=28,
                          font=ctk.CTkFont(family="Consolas", size=9,
                                           weight="bold"),
                          command=self.exportar_catalogo),
            fg_color='btn', hover_color='btn_hover', text_color='text2')
        self.btn_csv.pack(side="left", padx=(6, 0))

        # --- tabla de chequeos
        cuerpo = self.reg(ctk.CTkFrame(m, corner_radius=0), fg_color='panel')
        cuerpo.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.tablas["catalogo"] = Tabla(
            cuerpo, ["ID", "Chequeo", "Categoria", "Severidad", "Estado", "CWE"],
            [70, 400, 110, 80, 100, 90], alto=20)
        self.tablas["catalogo"].pack(fill="both", expand=True, padx=6, pady=6)
        self.tablas["catalogo"].al_seleccionar(self.ver_chequeo_catalogo)

        # --- rellenar filtros y tabla
        cats = ["Todas"] + [n for _, n in checks.CATEGORIAS]
        self.combo_cat.configure(values=cats)
        self.combo_cat.set("Todas")
        sevs = ["Todas", "critico", "alto", "medio", "bajo", "info"]
        self.combo_sev.configure(values=sevs)
        self.combo_sev.set("Todas")
        self.combo_cat.configure(command=lambda _v: self.filtrar_catalogo())
        self.combo_sev.configure(command=lambda _v: self.filtrar_catalogo())
        self.catalogo_resultados = {}
        self.poblar_catalogo()

    def poblar_catalogo(self):
        """Carga los 203 chequeos en la tabla, en estado pendiente."""
        t = self.tablas["catalogo"]
        t.limpiar()
        for c in checks.CATALOGO:
            t.agregar([c["id"], c["nombre"], c["categoria"],
                       c["severidad"].upper(), "PENDIENTE", c["cwe"] or "-"],
                      etiqueta="info")

    def filtrar_catalogo(self):
        cat = self.combo_cat.get()
        sev = self.combo_sev.get()
        t = self.tablas["catalogo"]
        t.limpiar()
        for c in checks.CATALOGO:
            if cat != "Todas" and c["categoria"] != cat.lower():
                continue
            if sev != "Todas" and c["severidad"] != sev:
                continue
            estado = self.catalogo_resultados.get(c["id"], {}).get("estado", "PENDIENTE")
            t.agregar([c["id"], c["nombre"], c["categoria"],
                       c["severidad"].upper(), estado, c["cwe"] or "-"],
                      etiqueta=self._etiqueta_estado(estado))

    @staticmethod
    def _etiqueta_estado(estado):
        return {"fallo": "critico", "ok": "ok", "omitido": "bajo",
                "error": "alto", "cancelado": "medio",
                "PENDIENTE": "info"}.get(estado, "info")

    def ver_chequeo_catalogo(self, valores):
        if not valores:
            return
        cid = valores[0]
        c = checks.por_id(cid)
        if not c:
            return
        r = self.catalogo_resultados.get(cid, {})
        lineas = ["CHEQUEO %s" % cid, "Nombre: %s" % c["nombre"],
                  "Categoria: %s | Severidad: %s" % (c["categoria"],
                                                    c["severidad"]),
                  "Activo: %s | Solo HTTPS: %s" % (c["activo"], c["solo_https"]),
                  "CWE: %s | OWASP: %s" % (c["cwe"] or "-", c["owasp"] or "-")]
        if r.get("hallazgo"):
            h = r["hallazgo"]
            lineas += ["", "HALLAZGO:", str(h.get("titulo", "")),
                       str(h.get("detalle", ""))[:600],
                       "", "Evidencia:"]
            ev = h.get("evidencia") or {}
            for k, v in list(ev.items())[:12]:
                lineas.append("  %s: %s" % (k, str(v)[:180]))
        elif r.get("detalle"):
            lineas += ["", "Detalle: %s" % r["detalle"]]
        self.fijar_texto(self.txt_detalle, "\n".join(lineas))

    def exportar_catalogo(self):
        """Guarda el resultado del catalogo en CSV."""
        if not self.catalogo_resultados:
            messagebox.showinfo("Catálogo",
                                "Todavía no hay resultados. Ejecuta el catálogo.")
            return
        ruta = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            initialfile="hunterbug_catalogo.csv")
        if not ruta:
            return
        try:
            import csv
            with open(ruta, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["id", "chequeo", "categoria", "severidad", "estado",
                            "cwe", "owasp", "titulo", "detalle"])
                for c in checks.CATALOGO:
                    r = self.catalogo_resultados.get(c["id"], {})
                    h = r.get("hallazgo") or {}
                    w.writerow([c["id"], c["nombre"], c["categoria"],
                                c["severidad"], r.get("estado", "PENDIENTE"),
                                c["cwe"], c["owasp"],
                                h.get("titulo", ""), h.get("detalle", "")])
            messagebox.showinfo("Catálogo", "CSV guardado en:\n%s" % ruta)
        except Exception as e:
            messagebox.showerror("Error", "No se pudo guardar: %s" % e)

    def pintar_metricas(self, p, filas):
        self.lbl_puntuacion.configure(text="%s / 100" % p["puntos"])
        color = {'A': 'green', 'B': 'green', 'C': 'yellow', 'D': 'yellow',
                 'E': 'orange', 'F': 'red'}.get(p["letra"], 'text')
        self.lbl_puntuacion.configure(text_color=C.get(color, C['text']))
        self.lbl_letra.configure(
            text="Calificacion %s (%s)" % (p["letra"], p["descripcion"]),
            text_color=C.get(color, C['text2']))
        self.barra_puntuacion.set(p["puntos"] / 100.0)
        self.barra_puntuacion.configure(
            progress_color=C.get(color, C['green']))

        resumen = ["Cobertura: %d de %d chequeos (%.1f%%)"
                   % (p["ejecutados"],
                      p["ejecutados"] + p["estados"].get("omitido", 0)
                      + p["estados"].get("error", 0) + p["estados"].get("cancelado", 0),
                      p["cobertura"])]
        resumen.append("Fallos: " + ", ".join(
            "%s=%d" % (s, p["por_severidad"].get(s, 0))
            for s in ("critico", "alto", "medio", "bajo", "info")))
        for nombre, valor in filas:
            if nombre.startswith(("Peticiones", "Bytes", "Tiempo total",
                                  "Ritmo", "Respuesta · status",
                                  "Respuesta · ip")):
                resumen.append("%s: %s" % (nombre, valor))
        self.lbl_metricas.configure(text="\n".join(resumen))

        # grafico por categoria
        self.ax_cat.clear()
        cats = [c for c in p["categorias"]]
        if cats:
            nombres = [c["categoria"][:14] for c in cats]
            valores = [c["puntos"] for c in cats]
            colores = ['#ff5555' if v < 40 else '#ff9944' if v < 70
                       else '#66ddaa' for v in valores]
            self.ax_cat.barh(nombres, valores, color=colores)
            self.ax_cat.set_xlim(0, 100)
            self.ax_cat.set_xlabel("puntos", fontsize=7)
            self.ax_cat.tick_params(labelsize=6)
            for i, v in enumerate(valores):
                self.ax_cat.text(v + 1, i, "%.0f" % v, fontsize=6, va="center")
        self.fig_cat.tight_layout()
        self.canvas_cat.draw()

    # ----------------------------------------------------- pestana: informe
    def construir_informe(self):
        """Pestana para descargar el informe de la evaluacion en todos los
        formatos: HTML y PDF con la evidencia completa, y los formatos de
        intercambio (HAR, SARIF, Burp, ZAP) para otras herramientas."""
        m = self.marcos["informe"]

        sup = self.reg(ctk.CTkFrame(m, corner_radius=0), fg_color='panel')
        sup.pack(fill="x", padx=12, pady=(12, 6))
        self.reg(ctk.CTkLabel(sup, text="INFORME DE LA EVALUACION",
                              font=ctk.CTkFont(family="Consolas", size=10,
                                               weight="bold")),
                 fg_color='panel', text_color='green').pack(anchor="w")
        self.lbl_informe_estado = self.reg(
            ctk.CTkLabel(sup, text="Sin datos todavia. Ejecuta una evaluacion "
                                   "y vuelve aqui para descargar el informe.",
                         font=ctk.CTkFont(family="Consolas", size=9)),
            fg_color='panel', text_color='text2', justify="left")
        self.lbl_informe_estado.pack(anchor="w", pady=(3, 0))

        acciones = self.reg(ctk.CTkFrame(m, corner_radius=8), fg_color='bg2')
        acciones.pack(fill="x", padx=12, pady=(0, 6))
        self.btn_informe_todos = self.reg(
            ctk.CTkButton(acciones, text="GENERAR TODOS LOS FORMATOS",
                          width=240, height=30,
                          font=ctk.CTkFont(family="Consolas", size=9,
                                           weight="bold"),
                          command=self.generar_todos_los_informes),
            fg_color='green', hover_color='green_hover', text_color='bg')
        self.btn_informe_todos.pack(side="left", padx=(8, 6), pady=8)
        self.reg(ctk.CTkButton(acciones, text="ABRIR CARPETA DE INFORMES",
                               width=200, height=30,
                               font=ctk.CTkFont(family="Consolas", size=9,
                                                weight="bold"),
                               command=lambda: abrir_carpeta(dir_informes())),
                 fg_color='btn', hover_color='btn_hover',
                 text_color='text2').pack(side="left", padx=(0, 6), pady=8)
        self.lbl_informe_dir = self.reg(
            ctk.CTkLabel(acciones, text=dir_informes(),
                         font=ctk.CTkFont(family="Consolas", size=8)),
            fg_color='bg2', text_color='text3')
        self.lbl_informe_dir.pack(side="left", padx=(6, 0))

        cuerpo = self.reg(ctk.CTkFrame(m, corner_radius=0), fg_color='panel')
        cuerpo.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        izq = self.reg(ctk.CTkScrollableFrame(cuerpo, corner_radius=8),
                       fg_color='bg2')
        izq.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.reg(ctk.CTkLabel(izq, text="FORMATOS DISPONIBLES",
                              font=ctk.CTkFont(family="Consolas", size=10,
                                               weight="bold")),
                 fg_color='bg2', text_color='green').pack(anchor="w",
                                                          padx=8, pady=(8, 4))

        self.btn_formato = {}
        for clave, nombre, desc, lector in FORMATOS_INFORME:
            fila = self.reg(ctk.CTkFrame(izq, corner_radius=6),
                            fg_color='bg')
            fila.pack(fill="x", padx=6, pady=3)
            b = self.reg(
                ctk.CTkButton(fila, text="DESCARGAR", width=110, height=26,
                              font=ctk.CTkFont(family="Consolas", size=9,
                                               weight="bold"),
                              command=lambda c=clave: self.descargar_informe(c)),
                fg_color='green', hover_color='green_hover', text_color='bg')
            b.pack(side="left", padx=6, pady=6)
            self.btn_formato[clave] = b
            texto = self.reg(ctk.CTkFrame(fila, corner_radius=0), fg_color='bg')
            texto.pack(side="left", fill="x", expand=True, padx=(0, 8))
            self.reg(ctk.CTkLabel(texto, text="%s — %s" % (nombre, desc),
                                  font=ctk.CTkFont(family="Consolas", size=9,
                                                   weight="bold"),
                                  anchor="w", justify="left"),
                     fg_color='bg', text_color='text').pack(anchor="w")
            self.reg(ctk.CTkLabel(texto, text="Lo lee: %s" % lector,
                                  font=ctk.CTkFont(family="Consolas", size=8),
                                  anchor="w", justify="left"),
                     fg_color='bg', text_color='text3').pack(anchor="w")

        der = self.reg(ctk.CTkFrame(cuerpo, corner_radius=8, width=430),
                       fg_color='bg2')
        der.pack(side="right", fill="y")
        der.pack_propagate(False)
        self.reg(ctk.CTkLabel(der, text="RESULTADO DE LA GENERACION",
                              font=ctk.CTkFont(family="Consolas", size=10,
                                               weight="bold")),
                 fg_color='bg2', text_color='green').pack(anchor="w", padx=8,
                                                          pady=(8, 4))
        self.txt_informe = tk.Text(der, wrap="word", bd=0,
                                   font=("Consolas", 9))
        self.txt_informe.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.txt_informe.configure(state="disabled")

        self.informe_ultimo = None
        self.informe_generando = False

    # --- datos del informe
    def _datos_para_informe(self):
        """Reune el estado actual de la aplicacion en la estructura del informe.

        Debe llamarse SIEMPRE desde el hilo principal: lee widgets de Tk.
        """
        objetivo = (self.entry_target.get().strip()
                    or self.target_actual() or "")
        if not objetivo:
            return None
        if not objetivo.startswith(("http://", "https://")):
            objetivo = "https://" + objetivo
        resultados = [v for v in self.catalogo_resultados.values() if v.get("id")]
        # completa los campos que solo estan en el catalogo
        for r in resultados:
            c = checks.por_id(r.get("id"))
            if c:
                r.setdefault("nombre", c["nombre"])
                r.setdefault("categoria", c["categoria"])
                r.setdefault("severidad", c["severidad"])
                r.setdefault("cwe", c["cwe"])
                r.setdefault("owasp", c["owasp"])
                r.setdefault("estado", "PENDIENTE")
        puntuacion = self.puntuacion
        if puntuacion is None and resultados:
            puntuacion = metrics.puntuacion(resultados)
        filas = []
        if puntuacion:
            try:
                _, filas = metrics.cuadro(resultados, ctx=None)
            except Exception:
                filas = []
        return hb_informe.construir_datos(
            objetivo,
            hallazgos=self.hallazgos,
            resultados=resultados,
            puntuacion=puntuacion,
            filas_metricas=filas,
            dns=self.dns,
            ips=self.ips,
            puertos=self.puertos,
            tecnologias=self.tecnologias,
            http_historial=self.http_historial,
            cves=[h for h in self.hallazgos
                  if str(h.get("tipo", "")).lower() == "cve"
                  or str(h.get("id", "")).upper().startswith("CVE")],
            grafo=self.grafo,
            autorizado=bool(self.var_autorizado.get()),
            perfil=self.perfil.get(),
            duracion=getattr(self, "duracion_evaluacion", 0.0))

    def _escribir_informe(self, texto, nivel="info"):
        try:
            self.txt_informe.configure(state="normal")
            self.txt_informe.insert("end", texto + "\n", nivel)
            self.txt_informe.see("end")
            self.txt_informe.configure(state="disabled")
        except Exception:
            pass

    def _actualizar_estado_informe(self):
        n = len(self.hallazgos)
        n_cat = len(self.catalogo_resultados)
        if not n and not n_cat:
            self.lbl_informe_estado.configure(
                text="Sin datos todavia. Ejecuta una evaluacion y vuelve aqui "
                     "para descargar el informe.")
            return
        self.lbl_informe_estado.configure(
            text="Listo para generar: %d hallazgo(s) y %d chequeo(s) "
                 "registrados. Objetivo: %s"
                 % (n, n_cat, self.entry_target.get().strip() or "-"))

    # --- generacion
    def _generar(self, clave, ruta, datos=None):
        """Genera un formato concreto. Devuelve (ruta, detalle).

        `datos` se calcula fuera si la llamada viene de un hilo de trabajo:
        `_datos_para_informe()` lee widgets de Tk y no es seguro llamarlo
        desde otro hilo.
        """
        if datos is None:
            datos = self._datos_para_informe()
        if datos is None:
            raise RuntimeError("no hay objetivo; ejecuta una evaluacion primero")
        if clave == "html":
            hb_informe.escribir_html(datos, ruta)
            return ruta, "informe completo con toda la evidencia"
        if clave == "pdf":
            r, metodo = hb_informe.a_pdf(datos, ruta)
            return r, ("generado con el navegador del sistema"
                       if metodo == "navegador" else
                       "generado con el motor propio (sin navegador)")
        if clave == "json":
            hb_informe.a_json(datos, ruta)
            return ruta, "datos crudos"
        if clave == "markdown":
            hb_informe.escribir_markdown(datos, ruta)
            return ruta, "texto para pegar en el reporte"
        if clave == "csv":
            hb_informe.a_csv(datos, ruta)
            return ruta, "una fila por hallazgo"
        if clave == "har":
            hb_intercambio.escribir_har(datos, ruta)
            return ruta, ("%d peticion(es) — importable en OWASP ZAP"
                          % len(datos["trafico"]))
        if clave == "sarif":
            hb_intercambio.escribir_sarif(datos, ruta)
            return ruta, "%d resultado(s)" % len(datos["hallazgos"])
        if clave == "burp":
            hb_intercambio.escribir_burp_xml(datos, ruta)
            return ruta, "%d issue(s) en formato Burp" % len(datos["hallazgos"])
        if clave == "zap":
            hb_intercambio.escribir_zap_xml(datos, ruta)
            return ruta, "%d alerta(s) en formato ZAP" % len(datos["hallazgos"])
        raise RuntimeError("formato desconocido: %s" % clave)

    def descargar_informe(self, clave):
        if self.informe_generando:
            messagebox.showinfo("Informe",
                                "Ya se esta generando un informe. Espera.")
            return
        datos = self._datos_para_informe()
        if datos is None:
            messagebox.showinfo("Informe",
                                "Primero ejecuta una evaluacion sobre un objetivo.")
            return
        nombre = hb_informe.nombre_por_defecto(
            datos["meta"]["objetivo"], EXTENSION_INFORME.get(clave, clave),
            dir_informes(), etiqueta=clave)
        inicial = os.path.basename(nombre)
        ruta = filedialog.asksaveasfilename(
            defaultextension="." + EXTENSION_INFORME.get(clave, clave),
            initialfile=inicial, initialdir=dir_informes(),
            filetypes=[(clave.upper(), "*." + EXTENSION_INFORME.get(clave, clave)),
                       ("Todos", "*.*")])
        if not ruta:
            return
        self._lanzar_generacion([(clave, ruta)], datos)

    def generar_todos_los_informes(self):
        if self.informe_generando:
            messagebox.showinfo("Informe",
                                "Ya se esta generando un informe. Espera.")
            return
        datos = self._datos_para_informe()
        if datos is None:
            messagebox.showinfo("Informe",
                                "Primero ejecuta una evaluacion sobre un objetivo.")
            return
        objetivo = datos["meta"]["objetivo"]
        carpeta = dir_informes()
        trabajos = [(c, hb_informe.nombre_por_defecto(
            objetivo, EXTENSION_INFORME.get(c, c), carpeta, etiqueta=c))
            for c, _, _, _ in FORMATOS_INFORME]
        self._lanzar_generacion(trabajos, datos)

    def _lanzar_generacion(self, trabajos, datos=None):
        """Genera los informes en un hilo.

        El hilo NO toca widgets ni llama a `after()`: publica en el bus y el
        hilo principal los consume en `procesar_evento` (Tk no es thread-safe).
        """
        if datos is None:
            datos = self._datos_para_informe()
        if datos is None:
            return
        self.informe_generando = True
        self.btn_informe_todos.configure(state="disabled")
        for b in self.btn_formato.values():
            b.configure(state="disabled")
        self._escribir_informe(
            ">>> Generando %d informe(s)..." % len(trabajos), "aviso")

        def tarea():
            hechos = []
            for clave, ruta in trabajos:
                try:
                    r, detalle = self._generar(clave, ruta, datos)
                    peso = os.path.getsize(r) / 1024.0
                    hechos.append((clave, r, detalle, peso, None))
                    self.bus.publicar("informe_log",
                                      texto="[OK]  %-9s %s  (%.0f KB, %s)"
                                            % (clave.upper(),
                                               os.path.basename(r), peso,
                                               detalle),
                                      nivel="exito")
                except Exception as e:
                    hechos.append((clave, None, str(e), 0, e))
                    self.bus.publicar("informe_log",
                                      texto="[ERROR] %-9s %s"
                                            % (clave.upper(), str(e)[:160]),
                                      nivel="error")
            self.bus.publicar("informe_fin", hechos=hechos)

        threading.Thread(target=tarea, daemon=True).start()

    def _fin_generacion(self):
        self.informe_generando = False
        self.btn_informe_todos.configure(state="normal")
        for b in self.btn_formato.values():
            b.configure(state="normal")
        ok = [h for h in (self.informe_ultimo or []) if h[1]]
        mal = [h for h in (self.informe_ultimo or []) if not h[1]]
        self._escribir_informe(
            ">>> Terminado: %d informe(s) generado(s), %d con error."
            % (len(ok), len(mal)),
            "exito" if not mal else "aviso")
        self._escribir_informe("    Carpeta: %s" % dir_informes())
        self.lbl_status.configure(text="Estado: informes generados")

    # --------------------------------------------------------- pestana: cve
    def construir_cve(self):
        m = self.marcos["cve"]
        sup = self.reg(ctk.CTkFrame(m, corner_radius=0), fg_color='panel')
        sup.pack(fill="x", padx=12, pady=(12, 6))
        self.reg(ctk.CTkLabel(sup, text="VULNERABILIDADES CONOCIDAS (CVE)",
                              font=ctk.CTkFont(family="Consolas", size=11,
                                               weight="bold")),
                 fg_color='panel', text_color='green').pack(side="left")
        est = cve.estadisticas_base()
        self.reg(ctk.CTkLabel(sup, text="Base local: %d CVEs (%d criticos)"
                                        % (est["total"], est["criticos"]),
                              font=ctk.CTkFont(family="Consolas", size=9)),
                 fg_color='panel', text_color='text2').pack(side="right")

        busca = self.reg(ctk.CTkFrame(m, corner_radius=8), fg_color='bg2')
        busca.pack(fill="x", padx=12, pady=(0, 6))
        self.reg(ctk.CTkLabel(busca, text="BUSCAR EN EL NVD (en linea)",
                              font=ctk.CTkFont(family="Consolas", size=9,
                                               weight="bold")),
                 fg_color='bg2', text_color='green').pack(anchor="w", padx=10,
                                                          pady=(8, 2))
        f = self.reg(ctk.CTkFrame(busca, corner_radius=0), fg_color='bg2')
        f.pack(fill="x", padx=10, pady=(0, 8))
        self.entry_nvd = self.reg(ctk.CTkEntry(f, width=520,
                                               font=ctk.CTkFont(family="Consolas",
                                                                size=10)),
                                  fg_color='bg', text_color='text',
                                  border_color='text3')
        self.entry_nvd.pack(side="left")
        self.entry_nvd.insert(0, "apache 2.4.49")
        self.reg(ctk.CTkButton(f, text="Buscar en NVD", width=140, height=30,
                               font=ctk.CTkFont(family="Consolas", size=10,
                                                weight="bold"),
                               command=self.buscar_nvd),
                 fg_color='green', hover_color='green_dim',
                 text_color='bg').pack(side="left", padx=8)
        self.reg(ctk.CTkButton(f, text="Mapear mis tecnologias", width=190, height=30,
                               font=ctk.CTkFont(family="Consolas", size=10),
                               command=self.mapear_tecnologias),
                 fg_color='btn', hover_color='btn_hover',
                 text_color='text').pack(side="left")

        self.tablas["cve"] = Tabla(m, ["Severidad", "CVE", "Titulo", "CVSS"],
                                   [90, 150, 540, 70], alto=17)
        self.tablas["cve"].pack(fill="both", expand=True, padx=18, pady=(0, 12))
        self.tablas["cve"].al_seleccionar(self.ver_hallazgo)

    # -------------------------------------------------------- pestana: grafo
    def construir_grafo(self):
        m = self.marcos["grafo"]
        sup = self.reg(ctk.CTkFrame(m, corner_radius=0), fg_color='panel')
        sup.pack(fill="x", padx=12, pady=(12, 6))
        self.reg(ctk.CTkLabel(sup, text="GRAFO DE SUPERFICIE DE ATAQUE",
                              font=ctk.CTkFont(family="Consolas", size=11,
                                               weight="bold")),
                 fg_color='panel', text_color='green').pack(side="left")
        self.reg(ctk.CTkButton(sup, text="Reorganizar", width=120, height=28,
                               font=ctk.CTkFont(family="Consolas", size=9),
                               command=self.reorganizar_grafo),
                 fg_color='btn', hover_color='btn_hover',
                 text_color='text').pack(side="right", padx=(6, 0))
        self.reg(ctk.CTkButton(sup, text="Analizar con IA", width=140, height=28,
                               font=ctk.CTkFont(family="Consolas", size=9,
                                                weight="bold"),
                               command=self.analizar_con_ia),
                 fg_color='blue', hover_color='blue',
                 text_color='bg').pack(side="right")

        cuerpo = self.reg(ctk.CTkFrame(m, corner_radius=0), fg_color='panel')
        cuerpo.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        izq = self.reg(ctk.CTkFrame(cuerpo, corner_radius=8), fg_color='bg2')
        izq.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.lienzo = LienzoGrafo(izq)
        self.lienzo.pack(fill="both", expand=True, padx=6, pady=6)
        self.lienzo.al_pulsar_nodo = self.nodo_pulsado

        der = self.reg(ctk.CTkFrame(cuerpo, corner_radius=8, width=480),
                       fg_color='bg2')
        der.pack(side="right", fill="y")
        der.pack_propagate(False)
        cab = self.reg(ctk.CTkFrame(der, corner_radius=0), fg_color='bg2')
        cab.pack(fill="x", padx=8, pady=(8, 2))
        self.reg(ctk.CTkLabel(cab, text="ANALISIS DE IA",
                              font=ctk.CTkFont(family="Consolas", size=10,
                                               weight="bold")),
                 fg_color='bg2', text_color='green').pack(side="left")
        self.lbl_motor_ia = self.reg(ctk.CTkLabel(cab, text="sin ejecutar",
                                                  font=ctk.CTkFont(family="Consolas",
                                                                   size=8)),
                                     fg_color='bg2', text_color='text3')
        self.lbl_motor_ia.pack(side="right")
        self.txt_ia = tk.Text(der, wrap="word", bd=0, font=("Consolas", 9))
        self.txt_ia.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.txt_ia.configure(state="disabled")

    # ---------------------------------------------------------- pestana: log
    def construir_log(self):
        m = self.marcos["log"]
        sup = self.reg(ctk.CTkFrame(m, corner_radius=0), fg_color='panel')
        sup.pack(fill="x", padx=12, pady=(12, 6))
        self.reg(ctk.CTkLabel(sup, text="REGISTRO COMPLETO",
                              font=ctk.CTkFont(family="Consolas", size=11,
                                               weight="bold")),
                 fg_color='panel', text_color='green').pack(side="left")
        self.var_autoscroll = tk.BooleanVar(value=True)
        self.reg(ctk.CTkCheckBox(sup, text="Autoscroll",
                                 variable=self.var_autoscroll,
                                 font=ctk.CTkFont(family="Consolas", size=9),
                                 checkbox_width=16, checkbox_height=16),
                 fg_color='green', hover_color='green_dim', text_color='text2',
                 border_color='text3').pack(side="right")
        self.reg(ctk.CTkButton(sup, text="Vaciar", width=90, height=26,
                               font=ctk.CTkFont(family="Consolas", size=9),
                               command=self.vaciar_log),
                 fg_color='btn', hover_color='btn_hover',
                 text_color='text').pack(side="right", padx=8)

        self.txt_log = tk.Text(m, wrap="word", bd=0, font=("Consolas", 9))
        self.txt_log.pack(fill="both", expand=True, padx=18, pady=(0, 12))
        self.console = self.txt_log

    # ------------------------------------------------------- flujo de eventos
    def procesar_eventos(self):
        if not self._vivo:
            return
        try:
            for ev in self.bus.drenar():
                self.procesar_evento(ev)
        except Exception as e:
            print("[EVENTOS] error:", e)
        try:
            self.after(120, self.procesar_eventos)
        except Exception:
            pass

    def procesar_evento(self, ev):
        tipo = ev.get("tipo")
        if tipo == events.LOG:
            modulo = ev.get("modulo")
            nivel = ev.get("nivel", "info")
            texto = ev.get("texto", "")
            marca = time.strftime("%H:%M:%S")
            self.escribir_log("[%s] %-8s %s" % (marca, modulo, texto), nivel)
            v = self.ventanas.get(modulo)
            if v is not None:
                v.escribir("%s  %s" % (marca, texto), nivel)
            if modulo in ("sqli", "xss", "idor", "bola", "catalogo"):
                self.escribir_vulns("[%s] %s" % (marca, texto), nivel)
        elif tipo == events.HALLAZGO:
            self.agregar_hallazgo(ev.get("modulo"), ev.get("hallazgo") or {})
        elif tipo == events.METRICAS:
            self.pintar_metricas(ev.get("puntuacion") or {},
                                 ev.get("filas") or [])
            self.filtrar_catalogo()
        elif tipo == events.CATALOGO:
            # los 203 eventos se acumulan; la tabla se repinta de forma
            # agregada para no ahogar el hilo de interfaz
            entrada = self.catalogo_resultados.setdefault(ev["id"], {})
            entrada.update({
                "id": ev["id"],
                "estado": ev.get("estado", "PENDIENTE"),
                "hallazgo": ev.get("hallazgo"),
                "detalle": ev.get("detalle", "")})
            if "nombre" not in entrada and ev.get("nombre"):
                entrada["nombre"] = ev["nombre"]
            self._catalogo_pendiente = getattr(self, "_catalogo_pendiente", 0) + 1
            if self._catalogo_pendiente >= 25:
                self._catalogo_pendiente = 0
                self.filtrar_catalogo()
        elif tipo == "informe_log":
            self._escribir_informe(ev.get("texto", ""),
                                   ev.get("nivel", "info"))
        elif tipo == "informe_fin":
            self.informe_ultimo = ev.get("hechos") or []
            self._fin_generacion()
        elif tipo == events.PROGRESO:
            self.actualizar_modulo(ev.get("modulo"), pct=ev.get("pct"))
        elif tipo == events.ESTADO:
            self.actualizar_modulo(ev.get("modulo"), estado=ev.get("estado"))
        elif tipo == events.HTTP:
            self.registrar_http(ev)
        elif tipo == "dns_fila":
            self.tablas["dns"].agregar([ev.get("tipo"), ev.get("valor")])
            t = ev.get("tipo")
            v = str(ev.get("valor", ""))
            if t in ("A", "AAAA") and v:
                self.anadir_activo_al_grafo("ip", v, registro=t)
            elif v:
                self.anadir_activo_al_grafo("endpoint", "%s %s" % (t, v[:40]),
                                            registro=t)
        elif tipo == "ip_fila":
            self.tablas["ip"].agregar([ev.get("ip"), ev.get("reversa") or "-"])
            if ev.get("ip"):
                self.anadir_activo_al_grafo("ip", ev["ip"],
                                            reversa=ev.get("reversa") or "")
        elif tipo == "puerto_fila":
            self.tablas["puertos"].agregar([ev.get("puerto"), ev.get("servicio"),
                                            ev.get("banner")], "ok")
            puerto = ev.get("puerto")
            nid = self.anadir_activo_al_grafo(
                "puerto", "tcp/%s" % puerto, puerto=puerto,
                banner=str(ev.get("banner", ""))[:80])
            if ev.get("servicio") and nid:
                nid_s = self.grafo.nodo(
                    self.grafo.id_nodo("servicio", ev["servicio"]), "servicio",
                    ev["servicio"])
                self.grafo.arista(nid, nid_s, "ejecuta")
        elif tipo == "tec_fila":
            self.tablas["tec"].agregar([ev.get("producto"), ev.get("evidencia")])
            if ev.get("producto"):
                self.anadir_activo_al_grafo("tecnologia", str(ev["producto"]),
                                            evidencia=str(ev.get("evidencia", ""))[:120])
        elif tipo == "modelos_listos":
            modelos = ev.get("modelos") or []
            if modelos:
                self.ai_model.delete(0, "end")
                self.ai_model.insert(0, modelos[0])
                self.lbl_status.configure(text="Modelos locales: %d" % len(modelos))
        elif tipo == "ia_listo":
            self.analisis_ia = ev.get("texto", "")
            self.lbl_motor_ia.configure(text=ev.get("motor", ""))
            self.fijar_texto(self.txt_ia, self.analisis_ia)

    def escribir_log(self, linea, nivel="info"):
        try:
            self.txt_log.insert("end", linea + "\n", nivel)
            if self.var_autoscroll.get():
                self.txt_log.see("end")
        except Exception:
            pass

    def escribir_vulns(self, linea, nivel="info"):
        try:
            self.txt_vulns.configure(state="normal")
            self.txt_vulns.insert("end", linea + "\n", nivel)
            self.txt_vulns.see("end")
            self.txt_vulns.configure(state="disabled")
        except Exception:
            pass

    def vaciar_log(self):
        try:
            self.txt_log.delete("1.0", "end")
        except Exception:
            pass

    # ------------------------------------------------------------- modulos UI
    def actualizar_modulo(self, clave, pct=None, estado=None):
        if clave not in self.filas:
            return
        fila, lbl, barra, nombre = self.filas[clave]
        est = self.modulo_estado.setdefault(clave, {"estado": "pendiente",
                                                    "progreso": 0,
                                                    "inicio": None, "fin": None})
        if estado:
            est["estado"] = estado
            if estado == "ejecutando":
                est["inicio"] = time.time()
            elif estado in ("completado", "fallido"):
                est["fin"] = time.time()
        if pct is not None:
            est["progreso"] = int(pct)
            barra.set(min(1.0, max(0.0, pct / 100.0)))
        dur = 0.0
        if est["inicio"]:
            dur = (est["fin"] or time.time()) - est["inicio"]
        color = {"completado": C['green'], "ejecutando": C['cyan'],
                 "fallido": C['red'], "omitido": C['text3']}.get(est["estado"],
                                                                 C['text3'])
        lbl.configure(text="%s  |  %d%%  |  %.1fs"
                           % (est["estado"], est["progreso"], dur),
                      text_color=color)
        barra.configure(progress_color=color)
        v = self.ventanas.get(clave)
        if v is not None:
            v.estado(est["estado"], color)

    def progreso_global(self):
        total = sum(v["progreso"] for v in self.modulo_estado.values())
        return int(total / (self.total_modulos * 100.0) * 100)

    def fijar_progreso_global(self):
        pct = self.progreso_global()
        self.progreso_barra.set(pct / 100.0)
        self.progreso_label.configure(text="Progreso global: %d%%" % pct)

    # ----------------------------------------------------------- hallazgos
    def agregar_hallazgo(self, modulo, h):
        if not h:
            return
        h["modulo"] = modulo
        self.hallazgos.append(h)
        sev = h.get("severidad", "info")
        tipo = h.get("tipo", "")
        self.tablas["hallazgos"].agregar([sev.upper(), tipo, h.get("titulo", ""),
                                          str(h.get("url", ""))[:120]], sev)
        if tipo in ("sqli", "xss", "idor", "bola", "cve", "ssti", "ssrf",
                    "traversal", "rce", "desbordamiento", "fuga", "enumeracion",
                    "authz"):
            self.tablas["vulns"].agregar([sev.upper(), tipo.upper(),
                                          h.get("titulo", ""),
                                          h.get("parametro", "")], sev)
        if tipo == "cve":
            self.tablas["cve"].agregar([sev.upper(),
                                        (h.get("evidencia") or {}).get("cve", ""),
                                        h.get("titulo", ""),
                                        str((h.get("evidencia") or {}).get("cvss", ""))],
                                       sev)
        if tipo in ("cabecera-ausente", "hsts-debil", "csp-debil", "fuga-tecnologia"):
            self.tablas["cabeceras"].agregar([sev.upper(), h.get("titulo", ""),
                                              str(h.get("detalle", ""))[:200]], sev)
        self.actualizar_grafica()
        self.actualizar_resumen()
        self.anadir_al_grafo(h)

    def nodo_objetivo(self):
        return self.grafo.nodo(
            self.grafo.id_nodo("objetivo", self.target_actual()),
            "objetivo", self.target_actual())

    def anadir_activo_al_grafo(self, tipo, etiqueta, **datos):
        """Añade un activo (IP, puerto, servicio, tecnologia) al grafo."""
        obj = self.nodo_objetivo()
        nid = self.grafo.nodo(self.grafo.id_nodo(tipo, etiqueta), tipo,
                              str(etiqueta), **datos)
        self.grafo.arista(obj, nid, tipo)
        self.actualizar_resumen()
        return nid

    def anadir_al_grafo(self, h):
        sev = h.get("severidad", "info")
        titulo = str(h.get("titulo", ""))[:60]
        nid = self.grafo.nodo(self.grafo.id_nodo("hallazgo", titulo), "hallazgo",
                              titulo, severidad=sev,
                              detalle=str(h.get("detalle", ""))[:200],
                              tipo_h=h.get("tipo", ""),
                              url=str(h.get("url", ""))[:120])
        nid_obj = self.nodo_objetivo()
        self.grafo.arista(nid_obj, nid, "hallazgo")
        cve_id = (h.get("evidencia") or {}).get("cve")
        if cve_id:
            nid_c = self.grafo.nodo(self.grafo.id_nodo("cve", cve_id), "cve",
                                    cve_id,
                                    cvss=(h.get("evidencia") or {}).get("cvss", 0))
            self.grafo.arista(nid, nid_c, "cve")

    def actualizar_grafica(self):
        self.ax_sev.clear()
        conteo = {"critico": 0, "alto": 0, "medio": 0, "bajo": 0, "info": 0}
        for h in self.hallazgos:
            s = h.get("severidad", "info")
            if s in conteo:
                conteo[s] += 1
        etiquetas = [k for k, v in conteo.items() if v > 0] or ["sin datos"]
        valores = [v for v in conteo.values() if v > 0] or [1]
        colores = {"critico": "#ff2222", "alto": "#ff6600", "medio": "#ffcc00",
                   "bajo": "#66cc66", "info": "#8899aa"}
        self.ax_sev.barh(etiquetas, valores,
                         color=[colores.get(e, C['text3']) for e in etiquetas])
        self.ax_sev.set_title("Hallazgos por severidad", color=C['green'],
                              fontsize=9)
        self.ax_sev.tick_params(labelsize=8, colors=C['text2'])
        for sp in self.ax_sev.spines.values():
            sp.set_color(C['grid'])
        self.fig.tight_layout()
        try:
            self.canvas.draw()
        except Exception:
            pass

    def actualizar_resumen(self):
        conteo = {}
        for h in self.hallazgos:
            s = h.get("severidad", "info")
            conteo[s] = conteo.get(s, 0) + 1
        res = self.grafo.resumen()
        self.lbl_resumen.configure(
            text="Hallazgos: %d  (%s)   |   Grafo: %d nodos / %d aristas   |   "
                 "Puertos: %d   |   Tecnologias: %d"
                 % (len(self.hallazgos),
                    ", ".join("%s=%d" % (k, v) for k, v in sorted(conteo.items())) or "-",
                    res["nodos"], res["aristas"], len(self.puertos),
                    len(self.tecnologias)))

    def ver_hallazgo(self, valores):
        if not valores:
            return
        titulo = valores[2] if len(valores) > 2 else ""
        for h in self.hallazgos:
            if str(h.get("titulo", ""))[:120] == titulo or h.get("titulo") == titulo:
                t = ["TITULO:     " + str(h.get("titulo", "")),
                     "TIPO:       " + str(h.get("tipo", "")),
                     "SEVERIDAD:  " + str(h.get("severidad", "")).upper()]
                if h.get("url"):
                    t.append("URL:        " + str(h["url"]))
                if h.get("parametro"):
                    t.append("PARAMETRO:  " + str(h["parametro"]))
                t += ["", "DETALLE:", "  " + str(h.get("detalle", ""))]
                ev = h.get("evidencia") or {}
                if ev:
                    t += ["", "EVIDENCIA:"]
                    for k, v in ev.items():
                        v_txt = json.dumps(v, ensure_ascii=False) if isinstance(
                            v, (dict, list)) else str(v)
                        t.append("  %s: %s" % (k, v_txt[:500]))
                if h.get("recomendacion"):
                    t += ["", "RECOMENDACION:", "  " + str(h["recomendacion"])]
                self.fijar_texto(self.txt_detalle, "\n".join(t))
                return
        self.fijar_texto(self.txt_detalle, "Sin detalle para la fila seleccionada.")

    def fijar_texto(self, widget, texto):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", texto)
        widget.configure(state="disabled")

    # ---------------------------------------------------------------- HTTP
    def registrar_http(self, ev):
        self.http_historial.append(ev)
        self.ultimo_http = ev
        peticion = ev.get("peticion", "")
        metodo = peticion.split()[0] if peticion else "GET"
        self.tablas["http"].agregar([metodo, str(ev.get("url", ""))[:110],
                                     str(ev.get("status", "")),
                                     "%.0f" % (ev.get("ms", 0) * 1000)])
        if self.pestana_activa == "http":
            self.visor_http.mostrar(peticion, ev.get("respuesta", ""),
                                    ev.get("url", ""), ev.get("status", 0),
                                    ev.get("ms", 0.0), ev.get("tls"))

    def ver_http_historial(self, valores):
        if not valores:
            return
        url = valores[1]
        for ev in reversed(self.http_historial):
            if str(ev.get("url", ""))[:110] == url:
                self.visor_http.mostrar(ev.get("peticion", ""),
                                        ev.get("respuesta", ""),
                                        ev.get("url", ""), ev.get("status", 0),
                                        ev.get("ms", 0.0), ev.get("tls"))
                return

    def pedir_http_manual(self):
        url = self.entry_url_http.get().strip()
        if not url:
            messagebox.showinfo("HTTP", "Escribe una URL en el campo de la pestana "
                                        "HTTP.")
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            self.entry_url_http.delete(0, "end")
            self.entry_url_http.insert(0, url)
        self.registrar("HTTP: peticion manual a %s" % url, "info")
        cab = self.cabeceras_extra()

        def tarea():
            r = net.peticion_http(url, cabeceras=cab, timeout=15)
            self.bus.http("http", url, r.status, r.peticion_cruda,
                          r.respuesta_cruda, r.tiempo)
            if r.tls:
                self.bus.log("http", "TLS %s / %s" % (r.tls.get("version"),
                                                      r.tls.get("cipher")), "info")
            if r.error:
                self.bus.log("http", "Error: " + r.error, "error")
        threading.Thread(target=tarea, daemon=True).start()

    def repetir_http(self):
        if not self.ultimo_http:
            messagebox.showinfo("HTTP", "Todavia no hay peticiones registradas.")
            return
        self.entry_url_http.delete(0, "end")
        self.entry_url_http.insert(0, self.ultimo_http.get("url", ""))
        self.pedir_http_manual()

    # ------------------------------------------------------------ CVE y IA
    def buscar_nvd(self):
        termino = self.entry_nvd.get().strip()
        if not termino:
            return
        self.registrar("NVD: buscando '%s'..." % termino, "info")

        def tarea():
            res = cve.consultar_nvd(
                termino, limite=10,
                log=lambda t, n="info": self.bus.log("cve", t, n))
            for h in res:
                self.bus.hallazgo("cve", h)
        threading.Thread(target=tarea, daemon=True).start()

    def mapear_tecnologias(self):
        if not self.tecnologias:
            messagebox.showinfo("CVE", "Todavia no hay tecnologias detectadas. "
                                       "Ejecuta primero la evaluacion.")
            return
        self.registrar("CVE: mapeando tecnologias detectadas...", "info")

        def tarea():
            res = cve.buscar_cves_por_tecnologias(
                self.tecnologias,
                log=lambda t, n="info": self.bus.log("cve", t, n))
            if not res:
                self.bus.log("cve", "Sin coincidencias en la base local.", "aviso")
            for h in res:
                self.bus.hallazgo("cve", h)
        threading.Thread(target=tarea, daemon=True).start()

    def analizar_con_ia(self):
        if not self.grafo.nodos:
            messagebox.showinfo("IA", "El grafo esta vacio. Ejecuta una evaluacion "
                                      "para construir la superficie de ataque.")
            return
        resumen = self.grafo.resumen()
        resumen["texto"] = self.grafo.resumen_para_ia()
        modelo = (self.ai_model.get().strip()
                  if self.ai_provider.get() == "ollama" else "")
        self.lbl_motor_ia.configure(text="analizando...")
        self.registrar("IA: iniciando analisis (%d nodos)" % resumen["nodos"], "info")

        def tarea():
            texto, motor = ai.analizar(
                resumen, self.hallazgos, modelo=modelo,
                log=lambda t, n="info": self.bus.log("ia", t, n))
            self.bus.publicar("ia_listo", texto=texto, motor=motor)
        threading.Thread(target=tarea, daemon=True).start()

    def reorganizar_grafo(self):
        if not self.grafo.nodos:
            return
        iters = 200 if len(self.grafo.nodos) < 60 else 120
        self.lienzo.fijar(self.grafo, self.grafo.layout_fuerza(iteraciones=iters))
        self.registrar("Grafo: reorganizado (%d nodos)" % len(self.grafo.nodos),
                       "info")

    def nodo_pulsado(self, nodo):
        if not nodo:
            self.fijar_texto(self.txt_ia, self.analisis_ia or
                             "Analisis de IA aun no ejecutado.\n\n"
                             "Pulsa 'Analizar con IA'.")
            return
        lineas = ["NODO:       " + str(nodo["etiqueta"]),
                  "TIPO:       " + str(nodo["tipo"]),
                  "CONEXIONES: " + str(nodo.get("grado", 0))]
        for k, v in (nodo.get("datos") or {}).items():
            lineas.append("%-11s %s" % (str(k).upper() + ":", str(v)[:300]))
        self.fijar_texto(self.txt_ia, "\n".join(lineas))

    # ------------------------------------------------------------ ventanas
    def abrir_ventana(self, clave, nombre):
        v = self.ventanas.get(clave)
        if v is not None:
            try:
                v.deiconify()
                v.lift()
                return
            except Exception:
                self.ventanas.pop(clave, None)
        v = VentanaModulo(self, nombre, C,
                          on_cerrar=lambda c=clave: self.ventanas.pop(c, None))
        v.aplicar_tema(C)
        aplicar_icono(v, getattr(self, "ruta_ico", None))
        self.ventanas[clave] = v
        for ev in self.bus.historial(events.LOG):
            if ev.get("modulo") == clave:
                v.escribir(ev.get("texto", ""), ev.get("nivel", "info"))
        est = self.modulo_estado.get(clave, {})
        v.estado(est.get("estado", "pendiente"))

    # ------------------------------------------------------------- ejecucion
    def target_actual(self):
        """Host limpio del objetivo: sin esquema, ruta, credenciales ni puerto."""
        t = self.entry_target.get().strip() or "objetivo"
        t = t.replace("https://", "").replace("http://", "").split("/")[0]
        if "@" in t:
            t = t.split("@")[-1]
        if t.startswith("["):            # IPv6 entre corchetes
            t = t[1:].split("]")[0]
        elif t.count(":") == 1:          # host:puerto
            t = t.split(":")[0]
        return t or "objetivo"

    def cabeceras_extra(self):
        crudo = self.entry_cabeceras.get().strip()
        salida = {}
        if not crudo:
            return salida
        for parte in crudo.split(";"):
            if ":" in parte:
                k, v = parte.split(":", 1)
                if k.strip():
                    salida[k.strip()] = v.strip()
        return salida

    def cambiar_perfil(self, perfil):
        self.lbl_status.configure(text="Perfil: " + perfil)

    def cambiar_proveedor(self, proveedor):
        self.lbl_status.configure(text="Proveedor IA: " + proveedor)

    def abrir_buscar_target(self):
        t = simpledialog.askstring("Buscar target", "Dominio o URL objetivo:",
                                   parent=self)
        if t and t.strip():
            self.entry_target.delete(0, "end")
            self.entry_target.insert(0, t.strip())
            self.lbl_status.configure(text="Target: " + t.strip())

    # ------------------------------------------------------------ acerca de
    def acerca_de(self):
        """Ventana de creditos e informacion, con acabado cuidado."""
        existente = getattr(self, "_ventana_acerca", None)
        if existente is not None:
            try:
                existente.deiconify()
                existente.lift()
                existente.focus_force()
                return
            except Exception:
                self._ventana_acerca = None

        import platform

        v = ctk.CTkToplevel(self)
        self._ventana_acerca = v
        v.title("Acerca de HunterBug")
        v.geometry("720x620")
        v.minsize(620, 520)
        v.configure(fg_color=C['bg'])
        try:
            v.transient(self)
        except Exception:
            pass

        def cerrar_acerca():
            self._ventana_acerca = None
            self.widgets_tema = [(w, r) for (w, r) in self.widgets_tema
                                 if getattr(w, "winfo_exists", lambda: 0)() == 1]
            try:
                v.destroy()
            except Exception:
                pass

        v.protocol("WM_DELETE_WINDOW", cerrar_acerca)
        aplicar_icono(v, getattr(self, "ruta_ico", None))

        # ---------------- cabecera ----------------
        cab = self.reg(ctk.CTkFrame(v, corner_radius=0, height=112),
                       fg_color='bar')
        cab.pack(fill="x")
        cab.pack_propagate(False)

        self.reg(ctk.CTkFrame(cab, width=5, corner_radius=0),
                 fg_color='green').place(x=0, y=0, relheight=1)

        logo = self.cargar_logo(64)
        if logo is not None:
            self.reg(ctk.CTkLabel(cab, image=logo, text=""),
                     fg_color='bar').place(x=24, y=24)
            xt = 104
        else:
            xt = 26

        self.reg(ctk.CTkLabel(cab, text="HUNTERBUG",
                              font=ctk.CTkFont(family="Consolas", size=30,
                                               weight="bold")),
                 fg_color='bar', text_color='green').place(x=xt, y=18)
        self.reg(ctk.CTkLabel(cab, text="1.0",
                              font=ctk.CTkFont(family="Consolas", size=15,
                                               weight="bold")),
                 fg_color='bar', text_color='cyan').place(x=xt + 206, y=34)
        self.reg(ctk.CTkLabel(cab,
                              text="Framework de evaluacion de seguridad "
                                   "para bug hunters",
                              font=ctk.CTkFont(family="Consolas", size=10)),
                 fg_color='bar', text_color='text2').place(x=xt + 1, y=62)
        self.reg(ctk.CTkLabel(cab,
                              text="Version mejorada y creada para la comunidad "
                                   "hacking team by Juan Antonio",
                              font=ctk.CTkFont(family="Consolas", size=10,
                                               weight="bold")),
                 fg_color='bar', text_color='cyan').place(x=xt + 1, y=84)

        # ---------------- cuerpo ----------------
        cuerpo = self.reg(ctk.CTkScrollableFrame(v, corner_radius=0),
                          fg_color='bg')
        cuerpo.pack(fill="both", expand=True, padx=20, pady=(14, 6))

        def seccion(titulo):
            self.reg(ctk.CTkLabel(cuerpo, text=titulo,
                                  font=ctk.CTkFont(family="Consolas", size=10,
                                                   weight="bold")),
                     fg_color='bg', text_color='green').pack(anchor="w",
                                                             pady=(14, 4))
            self.reg(ctk.CTkFrame(cuerpo, height=1, corner_radius=0),
                     fg_color='grid').pack(fill="x", pady=(0, 6))

        def fila(etiqueta, valor, color_valor=None):
            f = self.reg(ctk.CTkFrame(cuerpo, corner_radius=0), fg_color='bg')
            f.pack(fill="x", pady=1)
            self.reg(ctk.CTkLabel(f, text=etiqueta, width=150, anchor="w",
                                  font=ctk.CTkFont(family="Consolas", size=10)),
                     fg_color='bg', text_color='text3').pack(side="left",
                                                             padx=(8, 0))
            self.reg(ctk.CTkLabel(f, text=valor, anchor="w", justify="left",
                                  wraplength=480,
                                  font=ctk.CTkFont(family="Consolas", size=10)),
                     fg_color='bg',
                     text_color=color_valor or 'text').pack(side="left")

        def parrafo(texto, color=None):
            self.reg(ctk.CTkLabel(cuerpo, text=texto, anchor="w",
                                  justify="left", wraplength=620,
                                  font=ctk.CTkFont(family="Consolas", size=10)),
                     fg_color='bg',
                     text_color=color or 'text2').pack(anchor="w", padx=8,
                                                       pady=1)

        seccion("CREDITOS")
        fila("Autor", "Juan Antonio")
        fila("Comunidad", "hacking team")
        fila("Version", "1.0", 'cyan')
        fila("Proposito", "Bug bounty y pruebas de seguridad autorizadas")

        seccion("MOTORES INCLUIDOS")
        fila("Reconocimiento", "DNS (A, AAAA, MX, TXT, NS, SOA, CAA), IP y\n"
                               "resolucion inversa, escaneo TCP con banner")
        fila("HTTP / HTTPS", "Peticion y respuesta en bruto tipo proxy, TLS,\n"
                             "auditoria de cabeceras y fingerprint")
        fila("Vulnerabilidades", "SQLi (errores y diferencial booleano), XSS\n"
                                 "reflejado, IDOR y BOLA")
        fila("Inteligencia", "Base local de 34 CVEs reales con comparacion de\n"
                             "versiones + consulta en vivo al NVD")
        fila("Analisis", "Grafo de superficie de ataque con layout por fuerzas\n"
                         "y analisis asistido por IA")
        fila("Salida", "Resultados en tiempo real por categoria, ventanas por\n"
                       "modulo e informe Markdown o JSON")

        seccion("COMO SE USA")
        for paso in (
            "1.  Escribe el objetivo: dominio, URL o URL con parametros.",
            "2.  Marca la casilla de autorizacion para habilitar los modulos activos.",
            "3.  Pulsa EJECUTAR EVALUACION y sigue el progreso modulo a modulo.",
            "4.  Revisa cada pestana; abre ventanas si quieres verlas a la vez.",
            "5.  Pulsa Analizar con IA y exporta el informe en Markdown o JSON.",
        ):
            parrafo(paso)

        seccion("AVISO LEGAL")
        parrafo("Uso exclusivo en pruebas AUTORIZADAS: programas de bug bounty "
                "dentro de alcance, laboratorios propios o encargos con permiso "
                "por escrito.", 'text')
        parrafo("Los modulos activos trabajan con volumen bajo y sin tecnicas "
                "destructivas (nada de denegacion de servicio ni fuerza bruta), "
                "pero probar sistemas sin autorizacion es ilegal. La "
                "responsabilidad del uso recae en quien ejecuta la herramienta.",
                'red')

        # ---------------- pie ----------------
        pie = self.reg(ctk.CTkFrame(v, corner_radius=0, height=54),
                       fg_color='bar')
        pie.pack(fill="x", side="bottom")
        pie.pack_propagate(False)
        self.reg(ctk.CTkLabel(pie,
                              text="Python %s  ·  %s  ·  motores verificados"
                                   % (platform.python_version(),
                                      platform.system()),
                              font=ctk.CTkFont(family="Consolas", size=8)),
                 fg_color='bar', text_color='text3').pack(side="left", padx=20)
        self.reg(ctk.CTkButton(pie, text="Cerrar", width=130, height=32,
                               font=ctk.CTkFont(family="Consolas", size=10,
                                                weight="bold"),
                               command=cerrar_acerca),
                 fg_color='green', hover_color='green_dim',
                 text_color='bg').pack(side="right", padx=20)

        # centrar sobre la ventana principal
        try:
            v.update_idletasks()
            x = self.winfo_rootx() + (self.winfo_width() - 720) // 2
            y = self.winfo_rooty() + (self.winfo_height() - 620) // 2
            v.geometry("+%d+%d" % (max(0, x), max(0, y)))
            v.lift()
            v.focus_force()
        except Exception:
            pass

    def detectar_modelos_locales(self):
        self.registrar("IA: buscando modelos locales en Ollama...", "info")

        def tarea():
            modelos = ai.modelos_ollama()
            if modelos:
                self.bus.publicar("modelos_listos", modelos=modelos)
                self.bus.log("ia", "%d modelo(s) local(es): %s"
                             % (len(modelos), ", ".join(modelos[:6])), "exito")
            else:
                self.bus.log("ia", "No se detectaron modelos locales. El analisis "
                                   "usara el motor de reglas.", "aviso")
        threading.Thread(target=tarea, daemon=True).start()

    def ejecutar_evaluacion(self):
        if self.running:
            return
        objetivo = self.entry_target.get().strip()
        if not objetivo:
            messagebox.showerror("Error", "Indica un objetivo.")
            return
        if not objetivo.startswith(("http://", "https://")):
            objetivo = "https://" + objetivo
            self.entry_target.delete(0, "end")
            self.entry_target.insert(0, objetivo)

        self.running = True
        self.cancel_requested = False
        self.btn_ejecutar.configure(state="disabled")
        self.btn_parar.configure(state="normal")
        self.lbl_status.configure(text="Ejecutando evaluacion...")
        for clave, _, _, _ in MODULOS:
            self.modulo_estado[clave] = {"estado": "pendiente", "progreso": 0,
                                         "inicio": None, "fin": None}
            self.actualizar_modulo(clave, pct=0, estado="pendiente")
        self.fijar_progreso_global()
        autorizado = bool(self.var_autorizado.get())
        # Tk no es thread-safe: se leen TODOS los widgets aqui, en el hilo
        # principal, y el hilo de trabajo solo recibe datos planos.
        cfg = {
            "host": self.target_actual(),
            "cabeceras": self.cabeceras_extra(),
            "perfil": self.perfil.get(),
            "patron_idor": self.entry_patron_idor.get().strip(),
            "id_a": self.entry_id_a.get().strip(),
            "id_b": self.entry_id_b.get().strip(),
            "url_bola": self.entry_url_bola.get().strip(),
            "token_a": self.entry_token_a.get().strip(),
            "token_b": self.entry_token_b.get().strip(),
            "cookie_a": self.entry_cookie_a.get().strip(),
            "cookie_b": self.entry_cookie_b.get().strip(),
            "autorizado": autorizado,
        }
        self.registrar(">>> Evaluacion iniciada sobre %s (perfil %s, autorizacion=%s)"
                       % (objetivo, cfg["perfil"],
                          "si" if autorizado else "NO"),
                       "exito" if autorizado else "aviso")
        if not autorizado:
            self.registrar(">>> Los modulos activos (puertos, SQLi, XSS, IDOR, BOLA) "
                           "se OMITIRAN hasta que marques la casilla de autorizacion.",
                           "aviso")
        threading.Thread(target=self.correr_modulos,
                         args=(objetivo, autorizado, cfg), daemon=True).start()

    def correr_modulos(self, objetivo, autorizado, cfg):
        try:
            for clave, nombre, _, activo in MODULOS:
                if self.cancel_requested or not self._vivo:
                    self.bus.log(clave, "Cancelado", "error")
                    break
                if activo and not autorizado:
                    self.bus.estado(clave, "omitido")
                    self.bus.log(clave, "Omitido: falta confirmar la autorizacion.",
                                 "aviso")
                    self.bus.progreso(clave, 100)
                    self.ui(self.fijar_progreso_global)
                    continue
                self.bus.estado(clave, "ejecutando")
                self.bus.progreso(clave, 5)
                try:
                    self.ejecutar_modulo(clave, objetivo, cfg)
                    self.bus.estado(clave, "completado")
                    self.bus.progreso(clave, 100)
                except Exception as e:
                    self.bus.log(clave, "Fallo: %s" % str(e)[:150], "error")
                    self.bus.estado(clave, "fallido")
                self.ui(self.fijar_progreso_global)
            self.bus.log("nucleo", ">>> Evaluacion finalizada.", "exito")
        except Exception as e:
            self.bus.log("nucleo", ">>> Error general: %s" % e, "error")
        finally:
            self.ui(self.fin_evaluacion)

    def ejecutar_modulo(self, clave, objetivo, cfg):
        def L(t, n="info"):
            self.bus.log(clave, t, n)

        cab = cfg.get("cabeceras") or {}
        host = cfg.get("host") or self.target_actual()

        if clave == "dns":
            L("Consultando registros de %s via DNS-over-HTTPS..." % host)
            self.dns = net.recon_dns(host)
            total = 0
            for tipo, regs in self.dns.items():
                for v in regs:
                    if v:
                        self.bus.publicar("dns_fila", tipo=tipo, valor=v)
                        total += 1
            L("%d registro(s) DNS encontrados." % total,
              "exito" if total else "aviso")

        elif clave == "ip":
            ips = net.resolver_ip(host)
            self.ips = ips
            for ip in ips:
                rev = net.reverse_dns(ip)
                self.bus.publicar("ip_fila", ip=ip, reversa=rev)
                L("%s -> %s" % (ip, rev or "(sin reversa)"), "exito")
            L("%d direccion(es) IP." % len(ips), "info")

        elif clave == "http":
            L("Peticion HTTP/HTTPS a %s..." % objetivo)
            r = net.peticion_http(objetivo, cabeceras=cab, timeout=15, seguir=1)
            self.bus.http(clave, objetivo, r.status, r.peticion_cruda,
                          r.respuesta_cruda, r.tiempo, tls=r.tls)
            if r.error:
                L("Error: " + r.error, "error")
                return
            L("%d %s | %d bytes | %.0f ms | IP %s"
              % (r.status, r.reason, r.cuerpo_bytes, r.tiempo * 1000, r.ip), "exito")
            if r.tls:
                L("TLS %s / %s | certificado valido hasta %s"
                  % (r.tls.get("version"), r.tls.get("cipher"),
                     r.tls.get("valido_hasta", "?")))
            self.tecnologias = net.detectar_tecnologias(r)
            for k, v in self.tecnologias.items():
                self.bus.publicar("tec_fila", producto=k, evidencia=str(v)[:120])
                L("Tecnologia: %s -> %s" % (k, str(v)[:70]))
            hallazgos = net.auditar_cabeceras(r)
            for h in hallazgos:
                self.bus.hallazgo(clave, h)
            L("%d hallazgo(s) en cabeceras." % len(hallazgos),
              "exito" if hallazgos else "info")

        elif clave == "cve":
            if not self.tecnologias:
                L("Sin tecnologias detectadas antes; se omite el mapeo local.",
                  "aviso")
                return
            res = cve.buscar_cves_por_tecnologias(self.tecnologias, log=L)
            for h in res:
                self.bus.hallazgo(clave, h)
            L("%d CVE(s) coincidentes en la base local." % len(res),
              "exito" if res else "info")

        elif clave == "puertos":
            total_p = len(net.PUERTOS_COMUNES)
            L("Escaneo TCP moderado (%d puertos, 40 hilos) sobre %s..."
              % (total_p, host))
            hechos = [0]

            def cb(res):
                hechos[0] += 1
                self.bus.progreso(clave, int(hechos[0] / total_p * 100))
                if res["abierto"]:
                    self.puertos.append(res)
                    self.bus.publicar("puerto_fila", puerto=res["puerto"],
                                      servicio=res["servicio"],
                                      banner=res["banner"])
                    L("abierto %d/%s %s" % (res["puerto"], res["servicio"],
                                            res["banner"][:60]), "exito")

            abiertos = net.escanear_puertos(host, hilos=40, timeout=1.5, callback=cb)
            L("%d puerto(s) abierto(s)." % len(abiertos),
              "exito" if abiertos else "info")

        elif clave == "sqli":
            if not vulns.parametros_de(objetivo):
                L("La URL no tiene parametros; anade ?clave=valor para probar SQLi.",
                  "aviso")
                return
            res = vulns.probar_sqli(objetivo, cabeceras=cab, log=L)
            for h in res:
                self.bus.hallazgo(clave, h)
            L("SQLi: %d hallazgo(s)." % len(res), "exito" if res else "info")

        elif clave == "xss":
            if not vulns.parametros_de(objetivo):
                L("La URL no tiene parametros; anade ?clave=valor para probar XSS.",
                  "aviso")
                return
            res = vulns.probar_xss(objetivo, cabeceras=cab, log=L)
            for h in res:
                self.bus.hallazgo(clave, h)
            L("XSS: %d hallazgo(s)." % len(res), "exito" if res else "info")

        elif clave == "idor":
            patron = cfg.get("patron_idor", "")
            if "{id}" not in patron:
                L("Indica un patron IDOR que contenga {id}.", "aviso")
                return
            try:
                ida = int(cfg.get("id_a") or 1)
                idb = int(cfg.get("id_b") or 2)
            except ValueError:
                ida, idb = 1, 2
            res = vulns.probar_idor(patron, ida, idb, cabeceras=cab, log=L)
            for h in res:
                self.bus.hallazgo(clave, h)
            L("IDOR: %d resultado(s)." % len(res), "exito" if res else "info")

        elif clave == "bola":
            url = cfg.get("url_bola", "")
            if not url:
                L("Indica la URL BOLA a comparar.", "aviso")
                return
            res = vulns.probar_bola(
                url,
                cookies_a=cfg.get("cookie_a") or None,
                cookies_b=cfg.get("cookie_b") or None,
                token_a=cfg.get("token_a") or None,
                token_b=cfg.get("token_b") or None,
                log=L)
            for h in res:
                self.bus.hallazgo(clave, h)
            L("BOLA: %d resultado(s)." % len(res), "exito" if res else "info")

        elif clave == "catalogo":
            self.ejecutar_catalogo_modulo(
                objetivo, cab, bool(cfg.get("autorizado")), L)

    def ejecutar_catalogo_modulo(self, objetivo, cab, autorizado, L):
        """Ejecuta el motor de 203 chequeos y publica cada resultado."""
        total = len(checks.CATALOGO)
        L("Motor de %d chequeos sobre %s (autorizacion=%s)..."
          % (total, objetivo, "si" if autorizado else "NO"), "info")
        if not autorizado:
            L("Sin autorizacion solo se ejecutan los %d chequeos pasivos."
              % (total - sum(1 for c in checks.CATALOGO if c["activo"])),
              "aviso")

        acumulados = {}

        def progreso(hechos, tot, cid):
            self.bus.progreso("catalogo", int(hechos / tot * 100),
                              "%d/%d %s" % (hechos, tot, cid))

        hallazgos, resultados, ctx = checks.ejecutar(
            objetivo, cabeceras_extra=cab, autorizado=autorizado,
            log=lambda t, n="info": L(t, n), pausa=0.05,
            debe_cancelar=lambda: self.cancel_requested, progreso=progreso)

        for r in resultados:
            acumulados[r["id"]] = r
            self.bus.catalogo(id=r["id"], nombre=r["nombre"],
                              estado=r["estado"], categoria=r["categoria"],
                              severidad=r["severidad"], cwe=r["cwe"],
                              hallazgo=r.get("hallazgo"),
                              detalle=r.get("detalle", ""))
            if r["estado"] == "fallo":
                h = r.get("hallazgo") or {}
                h.setdefault("modulo", "catalogo")
                self.bus.hallazgo("catalogo", h)

        self.catalogo_resultados = acumulados
        p, filas = metrics.cuadro(resultados, ctx=ctx)
        self.bus.metricas(p, filas)
        self.puntuacion = p

        fallos = p["por_severidad"]
        L("Catalogo: %d chequeos | puntuacion %s/100 (%s) | "
          "criticos=%d altos=%d medios=%d"
          % (len(resultados), p["puntos"], p["letra"],
             fallos.get("critico", 0), fallos.get("alto", 0),
             fallos.get("medio", 0)),
          "exito" if p["letra"] in ("A", "B") else "aviso")
        self.ui(self.pintar_metricas, p, filas)
        self.ui(self.filtrar_catalogo)
        self.ui(self.fijar_progreso_global)

    def ui(self, fn, *args):
        if not self._vivo:
            return
        try:
            self.after(0, lambda: fn(*args) if self._vivo else None)
        except Exception:
            pass

    def fin_evaluacion(self):
        self.running = False
        self.btn_ejecutar.configure(state="normal")
        self.btn_parar.configure(state="disabled")
        self.lbl_status.configure(text="Estado: completado")
        self.fijar_progreso_global()
        self.actualizar_resumen()
        try:
            self._actualizar_estado_informe()
        except Exception:
            pass
        if self.grafo.nodos:
            self.reorganizar_grafo()

    def parar_evaluacion(self):
        if self.running:
            self.cancel_requested = True
            self.lbl_status.configure(text="Estado: deteniendo...")
            self.registrar(">>> Detencion solicitada", "aviso")

    def reiniciar_motor(self):
        self.cancel_requested = True
        self.running = False
        self.hallazgos = []
        self.puertos = []
        self.dns = {}
        self.ips = []
        self.tecnologias = {}
        self.http_historial = []
        self.ultimo_http = None
        self.analisis_ia = ""
        self.catalogo_resultados = {}
        self.puntuacion = None
        self._catalogo_pendiente = 0
        self.grafo.limpiar()
        self.bus.vaciar()
        for tabla in self.tablas.values():
            tabla.limpiar()
        for clave, _, _, _ in MODULOS:
            self.modulo_estado[clave] = {"estado": "pendiente", "progreso": 0,
                                         "inicio": None, "fin": None}
            self.actualizar_modulo(clave, pct=0, estado="pendiente")
        self.fijar_progreso_global()
        self.actualizar_grafica()
        self.actualizar_resumen()
        self.lienzo.fijar(None, {})
        self.btn_ejecutar.configure(state="normal")
        self.btn_parar.configure(state="disabled")
        self.lbl_status.configure(text="Estado: reiniciado")
        self.registrar(">>> Motor reiniciado.", "info")

    # -------------------------------------------------------------- informe
    def exportar_informe(self):
        if not self.hallazgos and not self.puertos:
            messagebox.showinfo("Informe", "No hay datos que exportar todavia.")
            return
        ruta = filedialog.asksaveasfilename(
            defaultextension=".md",
            initialfile="hunterbug_informe_%s.md"
                        % datetime.now().strftime("%Y%m%d_%H%M"),
            filetypes=[("Markdown", "*.md"), ("JSON", "*.json")],
            title="Guardar informe")
        if not ruta:
            return
        datos = {"objetivo": self.target_actual(),
                 "fecha": datetime.now(timezone.utc).isoformat(),
                 "resumen": self.grafo.resumen(),
                 "puertos": self.puertos, "dns": self.dns,
                 "tecnologias": self.tecnologias,
                 "hallazgos": self.hallazgos, "analisis_ia": self.analisis_ia}
        try:
            if ruta.lower().endswith(".json"):
                with open(ruta, "w", encoding="utf-8") as f:
                    json.dump(datos, f, indent=2, ensure_ascii=False)
            else:
                with open(ruta, "w", encoding="utf-8") as f:
                    f.write(self.informe_markdown(datos))
            self.registrar("Informe exportado a %s" % ruta, "exito")
            messagebox.showinfo("Informe", "Guardado en:\n" + ruta)
        except Exception as e:
            messagebox.showerror("Informe", "No se pudo guardar: %s" % e)

    def informe_markdown(self, d):
        l = ["# Informe de evaluacion - HunterBug 1.0", "",
             "- **Herramienta:** HunterBug 1.0 - version mejorada creada para la "
             "comunidad hacking team by Juan Antonio", "",
             "- **Objetivo:** %s" % d["objetivo"],
             "- **Fecha (UTC):** %s" % d["fecha"],
             "- **Grafo:** %d nodos / %d aristas"
             % (d["resumen"]["nodos"], d["resumen"]["aristas"]), ""]
        conteo = {}
        for h in d["hallazgos"]:
            k = h.get("severidad", "info")
            conteo[k] = conteo.get(k, 0) + 1
        l.append("## Resumen de severidad")
        for k in ("critico", "alto", "medio", "bajo", "info"):
            if conteo.get(k):
                l.append("- **%s:** %d" % (k.upper(), conteo[k]))
        l.append("")
        if d["puertos"]:
            l += ["## Puertos abiertos", "| Puerto | Servicio | Banner |",
                  "|---|---|---|"]
            for p in d["puertos"]:
                l.append("| %s | %s | %s |"
                         % (p.get("puerto"), p.get("servicio"),
                            (p.get("banner") or "").replace("|", "/")))
            l.append("")
        if d["tecnologias"]:
            l.append("## Tecnologias detectadas")
            for k, v in d["tecnologias"].items():
                l.append("- **%s:** %s" % (k, str(v)[:160]))
            l.append("")
        l.append("## Hallazgos")
        orden = {"critico": 0, "alto": 1, "medio": 2, "bajo": 3, "info": 4}
        for i, h in enumerate(sorted(d["hallazgos"],
                                     key=lambda x: orden.get(x.get("severidad",
                                                                   "info"), 5)),
                              start=1):
            l += ["", "### %d. [%s] %s" % (i, str(h.get("severidad", "")).upper(),
                                           h.get("titulo", ""))]
            if h.get("url"):
                l.append("- URL: `%s`" % h["url"])
            if h.get("parametro"):
                l.append("- Parametro: `%s`" % h["parametro"])
            l.append("- Detalle: %s" % h.get("detalle", ""))
            ev = h.get("evidencia") or {}
            if ev:
                l.append("- Evidencia:")
                for k, v in ev.items():
                    l.append("    - `%s`: %s" % (k, str(v)[:300]))
            if h.get("recomendacion"):
                l.append("- Recomendacion: %s" % h["recomendacion"])
        if d["analisis_ia"]:
            l += ["", "## Analisis asistido por IA", "```", d["analisis_ia"], "```"]
        return "\n".join(l)

    # ---------------------------------------------------------------- cierre
    def cerrar(self):
        self._vivo = False
        self.cancel_requested = True
        v_acerca = getattr(self, "_ventana_acerca", None)
        if v_acerca is not None:
            try:
                v_acerca.destroy()
            except Exception:
                pass
            self._ventana_acerca = None
        for v in list(self.ventanas.values()):
            try:
                v.destroy()
            except Exception:
                pass
        self.ventanas.clear()
        try:
            if self._after_fondo:
                self.after_cancel(self._after_fondo)
        except Exception:
            pass
        try:
            self.quit()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass


def main():
    app = HunterBugGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
