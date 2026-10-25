"""HunterBug - grafo de superficie de ataque.

Modelo de nodos/aristas que crece en vivo mientras se ejecutan los modulos,
mas un layout dirigido por fuerzas (sin dependencias) para dibujarlo y un
resumen textual que se envia al modelo de IA.
"""

from __future__ import annotations

import math
import random

TIPOS_NODO = {
    "objetivo":   {"color": "#00ff41", "radio": 26, "etiqueta": "Objetivo"},
    "dominio":    {"color": "#00d4ff", "radio": 20, "etiqueta": "Dominio"},
    "subdominio": {"color": "#3399ff", "radio": 17, "etiqueta": "Subdominio"},
    "ip":         {"color": "#a78bfa", "radio": 18, "etiqueta": "IP"},
    "puerto":     {"color": "#fbbf24", "radio": 15, "etiqueta": "Puerto"},
    "servicio":   {"color": "#fb923c", "radio": 15, "etiqueta": "Servicio"},
    "tecnologia": {"color": "#38bdf8", "radio": 15, "etiqueta": "Tecnologia"},
    "endpoint":   {"color": "#94a3b8", "radio": 13, "etiqueta": "Endpoint"},
    "parametro":  {"color": "#cbd5e1", "radio": 11, "etiqueta": "Parametro"},
    "cve":        {"color": "#ff3333", "radio": 17, "etiqueta": "CVE"},
    "hallazgo":   {"color": "#ff9900", "radio": 15, "etiqueta": "Hallazgo"},
}

SEVERIDAD_COLOR = {
    "critico": "#ff2222", "alto": "#ff6600", "medio": "#ffcc00",
    "bajo": "#66cc66", "info": "#8899aa",
}


class Grafo:
    """Grafo dirigido ligero con identificadores estables."""

    def __init__(self):
        self.nodos = {}
        self.aristas = []
        self._claves = set()

    # ---- construccion ----

    def nodo(self, nid, tipo, etiqueta, **datos):
        if nid not in self.nodos:
            self.nodos[nid] = {"id": nid, "tipo": tipo, "etiqueta": etiqueta,
                               "datos": dict(datos), "grado": 0}
        else:
            self.nodos[nid]["datos"].update(datos)
            if etiqueta and not self.nodos[nid]["etiqueta"]:
                self.nodos[nid]["etiqueta"] = etiqueta
        return nid

    def arista(self, origen, destino, tipo="relacion", etiqueta=""):
        if origen not in self.nodos or destino not in self.nodos:
            return
        clave = (origen, destino, tipo)
        if clave in self._claves:
            return
        self._claves.add(clave)
        self.aristas.append({"origen": origen, "destino": destino,
                             "tipo": tipo, "etiqueta": etiqueta})
        self.nodos[origen]["grado"] += 1
        self.nodos[destino]["grado"] += 1

    def id_nodo(self, tipo, valor):
        return "%s:%s" % (tipo, str(valor).strip().lower())

    def limpiar(self):
        self.nodos.clear()
        self.aristas.clear()
        self._claves.clear()

    # ---- consultas ----

    def por_tipo(self, tipo):
        return [n for n in self.nodos.values() if n["tipo"] == tipo]

    def conteo_por_tipo(self):
        c = {}
        for n in self.nodos.values():
            c[n["tipo"]] = c.get(n["tipo"], 0) + 1
        return c

    def hallazgos(self):
        return self.por_tipo("hallazgo")

    def resumen(self):
        c = self.conteo_por_tipo()
        return {"nodos": len(self.nodos), "aristas": len(self.aristas), "por_tipo": c}

    # ---- layout ----

    def layout_fuerza(self, ancho=1200.0, alto=700.0, iteraciones=280, semilla=7):
        """Fruchterman-Reingold simplificado. Devuelve {id: (x, y)}."""
        rnd = random.Random(semilla)
        ids = list(self.nodos.keys())
        if not ids:
            return {}
        n = len(ids)
        pos = {i: [rnd.uniform(0, ancho), rnd.uniform(0, alto)] for i in ids}

        area = ancho * alto
        k = math.sqrt(area / max(1, n)) * 0.75
        temp = ancho * 0.10

        ady = {i: [] for i in ids}
        for a in self.aristas:
            if a["origen"] in ady and a["destino"] in ady:
                ady[a["origen"]].append(a["destino"])
                ady[a["destino"]].append(a["origen"])

        for it in range(iteraciones):
            desp = {i: [0.0, 0.0] for i in ids}

            # repulsion entre todos (O(n^2) acotado por el numero de nodos reales)
            for idx_a in range(n):
                ia = ids[idx_a]
                for idx_b in range(idx_a + 1, n):
                    ib = ids[idx_b]
                    dx = pos[ia][0] - pos[ib][0]
                    dy = pos[ia][1] - pos[ib][1]
                    d2 = dx * dx + dy * dy
                    if d2 < 0.01:
                        dx, dy, d2 = rnd.uniform(-1, 1), rnd.uniform(-1, 1), 0.01
                    d = math.sqrt(d2)
                    f = (k * k) / d
                    ux, uy = dx / d, dy / d
                    desp[ia][0] += ux * f
                    desp[ia][1] += uy * f
                    desp[ib][0] -= ux * f
                    desp[ib][1] -= uy * f

            # atraccion por aristas
            for a in self.aristas:
                ia, ib = a["origen"], a["destino"]
                if ia not in pos or ib not in pos:
                    continue
                dx = pos[ia][0] - pos[ib][0]
                dy = pos[ia][1] - pos[ib][1]
                d = math.sqrt(dx * dx + dy * dy) or 0.01
                f = (d * d) / k
                ux, uy = dx / d, dy / d
                desp[ia][0] -= ux * f
                desp[ia][1] -= uy * f
                desp[ib][0] += ux * f
                desp[ib][1] += uy * f

            # gravedad suave hacia el centro (mantiene el grafo compacto)
            for i in ids:
                desp[i][0] += (ancho / 2 - pos[i][0]) * 0.008
                desp[i][1] += (alto / 2 - pos[i][1]) * 0.008

            for i in ids:
                dx, dy = desp[i]
                d = math.sqrt(dx * dx + dy * dy) or 0.01
                lim = min(d, temp)
                pos[i][0] += (dx / d) * lim
                pos[i][1] += (dy / d) * lim
                pos[i][0] = max(30, min(ancho - 30, pos[i][0]))
                pos[i][1] = max(30, min(alto - 30, pos[i][1]))
            temp *= 0.985

        return {i: (pos[i][0], pos[i][1]) for i in ids}

    # ---- resumen para la IA ----

    def resumen_para_ia(self, max_hallazgos=40):
        lineas = ["SUPERFICIE DE ATAQUE OBSERVADA"]
        c = self.conteo_por_tipo()
        lineas.append("Nodos: %d | Aristas: %d | Detalle: %s"
                      % (len(self.nodos), len(self.aristas),
                         ", ".join("%s=%d" % (k, v) for k, v in sorted(c.items()))))

        for tipo in ("dominio", "subdominio", "ip", "puerto", "servicio", "tecnologia"):
            lista = self.por_tipo(tipo)
            if lista:
                vals = ", ".join(sorted({n["etiqueta"] for n in lista})[:25])
                lineas.append("- %s (%d): %s" % (tipo, len(lista), vals))

        hall = self.hallazgos()
        if hall:
            orden = {"critico": 0, "alto": 1, "medio": 2, "bajo": 3, "info": 4}
            hall = sorted(hall, key=lambda h: orden.get(h["datos"].get("severidad", "info"), 5))
            lineas.append("HALLAZGOS (%d), ordenados por severidad:" % len(hall))
            for h in hall[:max_hallazgos]:
                d = h["datos"]
                lineas.append("  [%s] %s | %s"
                              % (str(d.get("severidad", "")).upper(),
                                 d.get("titulo", h["etiqueta"]),
                                 str(d.get("detalle", ""))[:180]))
        else:
            lineas.append("HALLAZGOS: ninguno todavia")
        return "\n".join(lineas)


def construir_desde_resultados(objetivo, dns=None, ips=None, puertos=None,
                               tecnologias=None, cabeceras=None, hallazgos=None,
                               subdominios=None, endpoints=None):
    """Crea un grafo a partir de los resultados de los modulos."""
    g = Grafo()
    nid_obj = g.nodo(g.id_nodo("objetivo", objetivo), "objetivo", objetivo,
                     valor=objetivo)

    for nombre in (subdominios or []):
        nid = g.nodo(g.id_nodo("subdominio", nombre), "subdominio", nombre)
        g.arista(nid_obj, nid, "contiene")

    nid_dom = g.nodo(g.id_nodo("dominio", objetivo), "dominio", objetivo)
    g.arista(nid_obj, nid_dom, "resuelve")

    for tipo, registros in (dns or {}).items():
        for valor in registros:
            if not valor:
                continue
            if tipo in ("A", "AAAA"):
                nid_ip = g.nodo(g.id_nodo("ip", valor), "ip", valor)
                g.arista(nid_dom, nid_ip, "A" if tipo == "A" else "AAAA")
            else:
                nid = g.nodo(g.id_nodo("registro-" + tipo, valor), "endpoint",
                             "%s %s" % (tipo, valor[:40]))
                g.arista(nid_dom, nid, "registro")

    for ip in (ips or []):
        nid_ip = g.nodo(g.id_nodo("ip", ip), "ip", ip)
        g.arista(nid_dom, nid_ip, "resuelve")

    for p in (puertos or []):
        nid_p = g.nodo(g.id_nodo("puerto", "%s:%s" % (objetivo, p.get("puerto"))),
                       "puerto", "tcp/%s" % p.get("puerto"),
                       abierto=True, banner=p.get("banner", ""))
        g.arista(nid_obj, nid_p, "expone")
        if p.get("servicio"):
            nid_s = g.nodo(g.id_nodo("servicio", p["servicio"]), "servicio", p["servicio"])
            g.arista(nid_p, nid_s, "ejecuta")
        if p.get("banner"):
            g.nodo(g.id_nodo("puerto", "%s:%s" % (objetivo, p.get("puerto"))),
                   "puerto", "tcp/%s" % p.get("puerto"), banner=p["banner"][:80])

    for nombre, valor in (tecnologias or {}).items():
        nid_t = g.nodo(g.id_nodo("tecnologia", nombre), "tecnologia", str(nombre),
                       valor=str(valor)[:80])
        g.arista(nid_obj, nid_t, "usa")

    for h in (cabeceras or []):
        nid_h = g.nodo(g.id_nodo("hallazgo", h.get("titulo")), "hallazgo",
                       str(h.get("titulo"))[:60], severidad=h.get("severidad", "info"),
                       detalle=h.get("detalle", ""), tipo_h=h.get("tipo", ""))
        g.arista(nid_obj, nid_h, "cabecera")

    for h in (hallazgos or []):
        sev = h.get("severidad", "info")
        nid_h = g.nodo(g.id_nodo("hallazgo", h.get("titulo")), "hallazgo",
                       str(h.get("titulo"))[:60], severidad=sev,
                       detalle=h.get("detalle", ""), tipo_h=h.get("tipo", ""),
                       url=h.get("url", ""))
        g.arista(nid_obj, nid_h, "hallazgo")
        cve = (h.get("evidencia") or {}).get("cve")
        if cve:
            nid_c = g.nodo(g.id_nodo("cve", cve), "cve", cve,
                           cvss=(h.get("evidencia") or {}).get("cvss", 0))
            g.arista(nid_h, nid_c, "cve")

    for ep in (endpoints or []):
        nid_e = g.nodo(g.id_nodo("endpoint", ep), "endpoint", str(ep)[:60])
        g.arista(nid_obj, nid_e, "endpoint")

    return g
