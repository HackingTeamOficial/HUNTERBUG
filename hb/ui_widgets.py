"""HunterBug - widgets de interfaz reutilizables.

Tabla, visor de peticion/respuesta tipo proxy, lienzo de grafo con zoom y
ventanas de modulo independientes con salida en vivo.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

from .graph import TIPOS_NODO, SEVERIDAD_COLOR


# --------------------------------------------------------------------------
# Tabla
# --------------------------------------------------------------------------

class Tabla(ctk.CTkFrame):
    """Tabla con estilo propio y soporte de tema."""

    def __init__(self, maestro, columnas, anchos=None, alto=10, **kw):
        super().__init__(maestro, corner_radius=6, **kw)
        self.columnas = list(columnas)
        self.anchos = anchos or [140] * len(columnas)
        self._paleta = None

        self.style = ttk.Style()
        self._nombre_estilo = "HB.Treeview"

        cont = tk.Frame(self, bd=0, highlightthickness=0)
        cont.pack(fill="both", expand=True, padx=6, pady=6)

        self.tree = ttk.Treeview(cont, columns=self.columnas, show="headings",
                                 height=alto, style=self._nombre_estilo)
        for col, anc in zip(self.columnas, self.anchos):
            self.tree.heading(col, text=col,
                              command=lambda c=col: self._ordenar(c))
            self.tree.column(col, width=anc, anchor="w", stretch=True)

        vs = ttk.Scrollbar(cont, orient="vertical", command=self.tree.yview)
        hs = ttk.Scrollbar(cont, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        cont.rowconfigure(0, weight=1)
        cont.columnconfigure(0, weight=1)

        self._datos = []
        self._orden_col = None
        self._orden_desc = False

        self.tree.tag_configure("critico", foreground="#ff5555")
        self.tree.tag_configure("alto", foreground="#ff9944")
        self.tree.tag_configure("medio", foreground="#ffdd55")
        self.tree.tag_configure("bajo", foreground="#88dd88")
        self.tree.tag_configure("info", foreground="#99aabb")
        self.tree.tag_configure("ok", foreground="#66ddaa")

    def aplicar_tema(self, paleta):
        self._paleta = paleta
        self.configure(fg_color=paleta["bg2"])
        self.style.theme_use("clam")
        self.style.configure(self._nombre_estilo,
                             background=paleta["bg2"],
                             fieldbackground=paleta["bg2"],
                             foreground=paleta["text"],
                             bordercolor=paleta["panel"],
                             lightcolor=paleta["panel"],
                             darkcolor=paleta["panel"],
                             rowheight=22,
                             font=("Consolas", 9))
        self.style.configure(self._nombre_estilo + ".Heading",
                             background=paleta["panel"],
                             foreground=paleta["green"],
                             font=("Consolas", 9, "bold"))
        self.style.map(self._nombre_estilo,
                       background=[("selected", paleta["panel2"])],
                       foreground=[("selected", paleta["green"])])

    # ---- datos ----

    def limpiar(self):
        self._datos = []
        for i in self.tree.get_children():
            self.tree.delete(i)

    def agregar(self, valores, etiqueta=None):
        self._datos.append((list(valores), etiqueta))
        self.tree.insert("", "end", values=valores,
                         tags=(etiqueta,) if etiqueta else ())

    def agregar_muchos(self, filas):
        for f in filas:
            if isinstance(f, tuple) and len(f) == 2 and isinstance(f[1], str):
                self.agregar(f[0], f[1])
            else:
                self.agregar(f)

    def filas(self):
        return [d[0] for d in self._datos]

    def seleccion(self):
        sel = self.tree.selection()
        if not sel:
            return None
        return list(self.tree.item(sel[0], "values"))

    def _ordenar(self, col):
        try:
            idx = self.columnas.index(col)
        except ValueError:
            return
        self._orden_desc = not self._orden_desc if self._orden_col == col else False
        self._orden_col = col

        def clave(item):
            v = str(item[0][idx])
            try:
                return (0, float(v.replace("%", "").replace(",", "")))
            except ValueError:
                return (1, v.lower())

        self._datos.sort(key=clave, reverse=self._orden_desc)
        for i in self.tree.get_children():
            self.tree.delete(i)
        for valores, etiqueta in self._datos:
            self.tree.insert("", "end", values=valores,
                             tags=(etiqueta,) if etiqueta else ())

    def al_seleccionar(self, fn):
        self.tree.bind("<<TreeviewSelect>>", lambda e: fn(self.seleccion()))


# --------------------------------------------------------------------------
# Visor de peticion / respuesta
# --------------------------------------------------------------------------

class VisorHTTP(ctk.CTkFrame):
    """Dos paneles con la peticion y la respuesta en bruto, coloreadas."""

    def __init__(self, maestro, alto=16, **kw):
        super().__init__(maestro, corner_radius=8, **kw)
        self._paleta = None

        cab = ctk.CTkFrame(self, corner_radius=0)
        cab.pack(fill="x", padx=8, pady=(8, 0))
        self.lbl_info = ctk.CTkLabel(cab, text="Sin peticiones todavia",
                                     font=ctk.CTkFont(family="Consolas", size=9,
                                                      weight="bold"))
        self.lbl_info.pack(side="left")
        self.lbl_tls = ctk.CTkLabel(cab, text="",
                                    font=ctk.CTkFont(family="Consolas", size=8))
        self.lbl_tls.pack(side="right")

        cuerpo = ctk.CTkFrame(self, corner_radius=0)
        cuerpo.pack(fill="both", expand=True, padx=8, pady=8)

        izq = ctk.CTkFrame(cuerpo, corner_radius=6)
        izq.pack(side="left", fill="both", expand=True, padx=(0, 4))
        self.lbl_pet = ctk.CTkLabel(izq, text="PETICION",
                                    font=ctk.CTkFont(family="Consolas", size=9,
                                                     weight="bold"))
        self.lbl_pet.pack(anchor="w", padx=8, pady=(6, 0))
        self.txt_pet = tk.Text(izq, height=alto, wrap="none", bd=0,
                               font=("Consolas", 9))
        self.txt_pet.pack(fill="both", expand=True, padx=8, pady=(2, 8))

        der = ctk.CTkFrame(cuerpo, corner_radius=6)
        der.pack(side="right", fill="both", expand=True, padx=(4, 0))
        self.lbl_res = ctk.CTkLabel(der, text="RESPUESTA",
                                    font=ctk.CTkFont(family="Consolas", size=9,
                                                     weight="bold"))
        self.lbl_res.pack(anchor="w", padx=8, pady=(6, 0))
        self.txt_res = tk.Text(der, height=alto, wrap="none", bd=0,
                               font=("Consolas", 9))
        self.txt_res.pack(fill="both", expand=True, padx=8, pady=(2, 8))

    def aplicar_tema(self, paleta):
        self._paleta = paleta
        self.configure(fg_color=paleta["panel"])
        for w in (self.lbl_info, self.lbl_tls, self.lbl_pet, self.lbl_res):
            w.configure(fg_color=paleta["panel"], text_color=paleta["text2"])
        self.lbl_info.configure(text_color=paleta["green"])
        for txt in (self.txt_pet, self.txt_res):
            txt.configure(bg=paleta["bg"], fg=paleta["text"],
                          insertbackground=paleta["green"])
        for padre in (self.txt_pet.master, self.txt_res.master):
            padre.configure(fg_color=paleta["bg2"])
        self._recolorear()

    def _recolorear(self):
        if not self._paleta:
            return
        p = self._paleta
        for txt in (self.txt_pet, self.txt_res):
            txt.tag_config("linea_estado", foreground=p["green"])
            txt.tag_config("cabecera", foreground=p["cyan"])
            txt.tag_config("valor", foreground=p["text"])
            txt.tag_config("malo", foreground=p["red"])

    def mostrar(self, peticion, respuesta, url="", status=0, ms=0.0, tls=None):
        p = self._paleta or {}
        self.lbl_info.configure(
            text="%s  ->  %s  |  %d  |  %.0f ms"
                 % ("HTTP", url[:90], status, ms * 1000))
        self.lbl_tls.configure(
            text=("TLS %s / %s" % (tls.get("version", "?"), tls.get("cipher", "?")))
            if tls else "")

        for txt, contenido in ((self.txt_pet, peticion), (self.txt_res, respuesta)):
            txt.configure(state="normal")
            txt.delete("1.0", "end")
            for i, linea in enumerate((contenido or "").splitlines()):
                if i == 0:
                    txt.insert("end", linea + "\n", "linea_estado")
                elif ":" in linea and not linea.startswith(" "):
                    k, _, v = linea.partition(":")
                    txt.insert("end", k + ":", "cabecera")
                    txt.insert("end", v + "\n", "valor")
                else:
                    txt.insert("end", linea + "\n")
            txt.configure(state="disabled")


# --------------------------------------------------------------------------
# Lienzo del grafo
# --------------------------------------------------------------------------

class LienzoGrafo(ctk.CTkFrame):
    """Dibuja el grafo de superficie de ataque con zoom y arrastre."""

    def __init__(self, maestro, **kw):
        super().__init__(maestro, corner_radius=8, **kw)
        self._paleta = None
        self._pos = {}
        self._grafo = None
        self.escala = 1.0
        self.desplazado = [0.0, 0.0]
        self._arrastre = None
        self.al_pulsar_nodo = None
        self._radio_min = 9

        self.canvas = tk.Canvas(self, bd=0, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True, padx=6, pady=6)
        self.canvas.bind("<MouseWheel>", self._zoom)
        self.canvas.bind("<Button-4>", lambda e: self._zoom(e, 1))
        self.canvas.bind("<Button-5>", lambda e: self._zoom(e, -1))
        self.canvas.bind("<ButtonPress-1>", self._iniciar_arrastre)
        self.canvas.bind("<B1-Motion>", self._arrastrar)
        self.canvas.bind("<ButtonRelease-1>", self._fin_arrastre)
        self.canvas.bind("<Button-3>", self.centrar)

    def aplicar_tema(self, paleta):
        self._paleta = paleta
        self.configure(fg_color=paleta["panel"])
        self.canvas.configure(bg=paleta["bg2"])
        self.redibujar()

    def fijar(self, grafo, pos):
        self._grafo = grafo
        self._pos = pos or {}
        self.redibujar()

    def centrar(self, _evt=None):
        self.escala = 1.0
        self.desplazado = [0.0, 0.0]
        self.redibujar()

    def _zoom(self, evt, direccion=None):
        if direccion is None:
            direccion = 1 if getattr(evt, "delta", 0) > 0 else -1
        self.escala = max(0.25, min(3.5, self.escala * (1.12 if direccion > 0 else 0.89)))
        self.redibujar()

    def _iniciar_arrastre(self, evt):
        self._arrastre = (evt.x, evt.y, self.desplazado[0], self.desplazado[1])

    def _arrastrar(self, evt):
        if not self._arrastre:
            return
        x0, y0, dx0, dy0 = self._arrastre
        self.desplazado = [dx0 + (evt.x - x0), dy0 + (evt.y - y0)]
        self.redibujar()

    def _fin_arrastre(self, evt):
        if self._arrastre and abs(evt.x - self._arrastre[0]) < 4 \
                and abs(evt.y - self._arrastre[1]) < 4:
            self._pulsar(evt)
        self._arrastre = None

    def _pulsar(self, evt):
        if not self.al_pulsar_nodo or not self._grafo:
            return
        for nid, (x, y) in self._pos.items():
            sx, sy = self._pantalla(x, y)
            if (sx - evt.x) ** 2 + (sy - evt.y) ** 2 <= (self._radio_min + 8) ** 2:
                self.al_pulsar_nodo(self._grafo.nodos.get(nid))
                return
        self.al_pulsar_nodo(None)

    def _pantalla(self, x, y):
        return (x * self.escala + self.desplazado[0],
                y * self.escala + self.desplazado[1])

    def redibujar(self):
        c = self.canvas
        c.delete("all")
        p = self._paleta or {}
        if not self._grafo or not self._pos:
            c.create_text(20, 20, anchor="nw",
                          text="Sin datos de grafo todavia.\n\n"
                               "Ejecuta una evaluacion para construir la superficie "
                               "de ataque.",
                          fill=p.get("text3", "#888"), font=("Consolas", 10))
            return

        # aristas primero
        for a in self._grafo.aristas:
            if a["origen"] not in self._pos or a["destino"] not in self._pos:
                continue
            x1, y1 = self._pantalla(*self._pos[a["origen"]])
            x2, y2 = self._pantalla(*self._pos[a["destino"]])
            color = p.get("grid", "#334155")
            grosor = 1
            if a["tipo"] == "hallazgo":
                color = SEVERIDAD_COLOR.get("alto", "#ff6600")
                grosor = 2
            elif a["tipo"] == "cve":
                color = SEVERIDAD_COLOR.get("critico", "#ff2222")
                grosor = 2
            c.create_line(x1, y1, x2, y2, fill=color, width=grosor)

        # nodos
        for nid, n in self._grafo.nodos.items():
            if nid not in self._pos:
                continue
            x, y = self._pantalla(*self._pos[nid])
            info = TIPOS_NODO.get(n["tipo"], {"color": "#888", "radio": 14})
            radio = max(self._radio_min, info["radio"] * self.escala)
            color = info["color"]
            if n["tipo"] == "hallazgo":
                color = SEVERIDAD_COLOR.get(n["datos"].get("severidad", "info"), color)
            borde = p.get("bg", "#000")
            c.create_oval(x - radio, y - radio, x + radio, y + radio,
                          fill=color, outline=borde, width=2)
            etiqueta = str(n["etiqueta"])[:22]
            if self.escala >= 0.5:
                c.create_text(x, y + radio + 9, text=etiqueta,
                              fill=p.get("text2", "#aaa"), font=("Consolas", 8))

        # leyenda
        lx, ly = 14, 14
        for i, (tipo, info) in enumerate(TIPOS_NODO.items()):
            yy = ly + i * 17
            c.create_oval(lx, yy, lx + 10, yy + 10, fill=info["color"], outline="")
            c.create_text(lx + 16, yy + 5, anchor="w", text=info["etiqueta"],
                          fill=p.get("text3", "#888"), font=("Consolas", 8))

        resumen = self._grafo.resumen()
        c.create_text(c.winfo_width() - 14, 14, anchor="ne",
                      text="%d nodos / %d aristas  |  zoom %.0f%%"
                           % (resumen["nodos"], resumen["aristas"], self.escala * 100),
                      fill=p.get("text3", "#888"), font=("Consolas", 8))


# --------------------------------------------------------------------------
# Ventana independiente de modulo
# --------------------------------------------------------------------------

class VentanaModulo(ctk.CTkToplevel):
    """Ventana suelta con la salida en vivo de un modulo."""

    def __init__(self, maestro, titulo, paleta, on_cerrar=None):
        super().__init__(maestro)
        self.title("HunterBug - " + titulo)
        self.geometry("760x460")
        self.minsize(520, 300)
        self._paleta = paleta
        self._on_cerrar = on_cerrar
        self.protocol("WM_DELETE_WINDOW", self.cerrar)

        cab = ctk.CTkFrame(self, corner_radius=0, height=34)
        cab.pack(fill="x")
        cab.pack_propagate(False)
        self.lbl = ctk.CTkLabel(cab, text=titulo,
                                font=ctk.CTkFont(family="Consolas", size=11,
                                                 weight="bold"))
        self.lbl.pack(side="left", padx=12)
        self.lbl_estado = ctk.CTkLabel(cab, text="pendiente",
                                       font=ctk.CTkFont(family="Consolas", size=9))
        self.lbl_estado.pack(side="right", padx=12)

        self.txt = tk.Text(self, wrap="word", bd=0, font=("Consolas", 9))
        self.txt.pack(fill="both", expand=True, padx=8, pady=8)
        self.aplicar_tema(paleta)

    def aplicar_tema(self, paleta):
        self._paleta = paleta
        self.configure(fg_color=paleta["bg"])
        self.lbl.configure(fg_color=paleta["bar"], text_color=paleta["green"])
        self.lbl_estado.configure(fg_color=paleta["bar"], text_color=paleta["text2"])
        self.txt.master.configure(fg_color=paleta["bg"])
        self.txt.configure(bg=paleta["bg"], fg=paleta["text"],
                           insertbackground=paleta["green"])
        for etiqueta, color in (("info", paleta["text3"]), ("exito", paleta["green"]),
                                ("error", paleta["red"]), ("aviso", paleta["cyan"])):
            self.txt.tag_config(etiqueta, foreground=color)

    def escribir(self, texto, nivel="info"):
        try:
            self.txt.insert("end", texto + "\n", nivel)
            self.txt.see("end")
        except Exception:
            pass

    def estado(self, texto, color=None):
        try:
            self.lbl_estado.configure(text=texto,
                                      text_color=color or self._paleta["text2"])
        except Exception:
            pass

    def cerrar(self):
        if self._on_cerrar:
            try:
                self._on_cerrar()
            except Exception:
                pass
        try:
            self.destroy()
        except Exception:
            pass
