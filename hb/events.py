"""HunterBug - bus de eventos para actualizaciones en tiempo real.

Los modulos de escaneo corren en hilos y publican eventos; la interfaz los
consume desde su propio hilo con `drenar()`.
"""

from __future__ import annotations

import queue
import threading
import time

# Tipos de evento
LOG = "log"              # {"modulo", "nivel", "texto"}
HALLAZGO = "hallazgo"    # {"modulo", "hallazgo": {...}}
PROGRESO = "progreso"    # {"modulo", "pct", "texto"}
GRAFO = "grafo"          # {"accion": "reiniciar"|"nodo"|"arista", ...}
HTTP = "http"            # {"modulo", "peticion", "respuesta", "status", "url"}
ESTADO = "estado"        # {"modulo", "estado"}
FIN = "fin"              # {"modulo"}


class Bus:
    def __init__(self):
        self._q = queue.Queue()
        self._historial = []
        self._lock = threading.Lock()
        self._max_historial = 5000
        self.iniciado = time.time()

    def publicar(self, tipo, **datos):
        ev = {"tipo": tipo, "ts": time.time()}
        ev.update(datos)
        with self._lock:
            self._historial.append(ev)
            if len(self._historial) > self._max_historial:
                del self._historial[:1000]
        self._q.put(ev)
        return ev

    def log(self, modulo, texto, nivel="info"):
        return self.publicar(LOG, modulo=modulo, texto=texto, nivel=nivel)

    def hallazgo(self, modulo, hallazgo):
        return self.publicar(HALLAZGO, modulo=modulo, hallazgo=hallazgo)

    def progreso(self, modulo, pct, texto=""):
        return self.publicar(PROGRESO, modulo=modulo, pct=int(pct), texto=texto)

    def estado(self, modulo, estado):
        return self.publicar(ESTADO, modulo=modulo, estado=estado)

    def http(self, modulo, url, status, peticion, respuesta, ms=0.0, tls=None):
        return self.publicar(HTTP, modulo=modulo, url=url, status=status,
                             peticion=peticion, respuesta=respuesta, ms=ms,
                             tls=tls)

    def drenar(self, maximo=400):
        """Saca eventos pendientes sin bloquear. Devuelve una lista."""
        salida = []
        for _ in range(maximo):
            try:
                salida.append(self._q.get_nowait())
            except queue.Empty:
                break
        return salida

    def historial(self, tipo=None):
        with self._lock:
            if tipo is None:
                return list(self._historial)
            return [e for e in self._historial if e.get("tipo") == tipo]

    def vaciar(self):
        self.drenar(100000)
        with self._lock:
            self._historial.clear()
