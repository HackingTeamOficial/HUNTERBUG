"""Banco de pruebas local: servidor deliberadamente vulnerable.

SOLO escucha en 127.0.0.1 y existe unicamente para verificar que los
detectores de HunterBug encuentran fallos reales. No forma parte del producto.
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PAGINA_LARGA = "<html><body>" + ("relleno " * 400) + "</body></html>"
PAGINA_CORTA = "<html><body>no encontrado</body></html>"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # laboratorio: simula un Apache antiguo en TODAS las respuestas
    server_version = "Apache/2.4.49"
    sys_version = "(Unix)"

    def log_message(self, *a):
        pass

    def version_string(self):
        return "Apache/2.4.49 (Unix)"

    def _responder(self, cuerpo, status=200, tipo="text/html; charset=utf-8",
                   extra=None):
        datos = cuerpo.encode("utf-8") if isinstance(cuerpo, str) else cuerpo
        self.send_response(status)
        self.send_header("Content-Type", tipo)
        self.send_header("X-Powered-By", "PHP/8.1.2")
        self.send_header("Content-Length", str(len(datos)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(datos)

    def do_HEAD(self):
        self._responder("", 200)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query, keep_blank_values=True)
        crudo = u.query

        # --- SQLi basado en errores ---
        if u.path == "/buscar":
            valor = (q.get("q", [""])[0])
            if "'" in valor or '"' in valor:
                return self._responder(
                    "<h1>Error</h1>You have an error in your SQL syntax; "
                    "check the manual that corresponds to your MySQL server "
                    "version for the right syntax to use near '%s'" % valor, 500)
            return self._responder("<h1>Resultados para %s</h1>nada</body></html>" % valor)

        # --- SQLi diferencial booleano (mismo codigo, distinto tamano) ---
        if u.path == "/item":
            valor = q.get("id", [""])[0]
            if "1=2" in valor:
                return self._responder(PAGINA_CORTA)
            if "1=1" in valor:
                return self._responder(PAGINA_LARGA)
            return self._responder(PAGINA_CORTA)

        # --- XSS reflejado ---
        if u.path == "/saludo":
            nombre = q.get("name", [""])[0]
            return self._responder("<html><body><h1>Hola %s</h1></body></html>" % nombre)

        # --- IDOR: sin comprobacion de propiedad ---
        m = re.match(r"^/api/usuario/(\d+)$", u.path)
        if m:
            uid = int(m.group(1))
            return self._responder(json.dumps({
                "id": uid, "nombre": "usuario%d" % uid,
                "email": "usuario%d@ejemplo.test" % uid,
                "saldo": 1000 * uid,
                "tarjeta": "4111-1111-1111-%04d" % uid,
            }), 200, "application/json")

        # --- BOLA: autorizacion correcta (debe salir como informativo) ---
        if u.path == "/api/cuenta/1":
            tok = self.headers.get("Authorization", "")
            if "tokenA" in tok:
                return self._responder(json.dumps({"cuenta": 1, "titular": "Ana",
                                                   "saldo": 500}), 200,
                                       "application/json")
            return self._responder(json.dumps({"error": "prohibido"}), 403,
                                   "application/json")

        # --- BOLA: fuga real entre credenciales ---
        if u.path == "/api/fuga/1":
            tok = self.headers.get("Authorization", "")
            if "tokenA" in tok:
                return self._responder(json.dumps({"cuenta": 1, "titular": "Ana",
                                                   "saldo": 500}), 200,
                                       "application/json")
            if "tokenB" in tok:
                return self._responder(json.dumps({"cuenta": 1, "titular": "Ana",
                                                   "saldo": 500, "iban": "ES00",
                                                   "movimientos": [1, 2, 3]}), 200,
                                       "application/json")
            return self._responder("{}", 401, "application/json")

        if u.path == "/":
            return self._responder(
                "<html><head><title>objetivo de prueba</title></head>"
                "<body>servidor de pruebas</body></html>",
                200, extra={"Server": "Apache/2.4.49 (Unix)",
                            "X-Powered-By": "PHP/8.1.2"})
        return self._responder("no encontrado", 404)


class ServidorPrueba:
    """Servidor de laboratorio. Intenta un puerto habitual para que el
    escaner de puertos de HunterBug lo encuentre de verdad."""

    PUERTOS_PREFERIDOS = [8080, 8000, 8888, 3000, 5000]

    def __init__(self, puerto=0):
        self.httpd = None
        if puerto == 0:
            for p in self.PUERTOS_PREFERIDOS:
                try:
                    self.httpd = ThreadingHTTPServer(("127.0.0.1", p), Handler)
                    break
                except OSError:
                    continue
        if self.httpd is None:
            self.httpd = ThreadingHTTPServer(("127.0.0.1", puerto), Handler)
        self.puerto = self.httpd.server_address[1]
        self.hilo = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def base(self):
        return "http://127.0.0.1:%d" % self.puerto

    def __enter__(self):
        self.hilo.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()
