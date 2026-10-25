"""Banco de pruebas local: servidor deliberadamente vulnerable.

SOLO escucha en 127.0.0.1 y existe unicamente para verificar que los
chequeos de HunterBug encuentran fallos reales. No forma parte del producto.

Planta un fallo por cada familia del catalogo, de forma que ninguna prueba
pueda pasar por casualidad.
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PAGINA_LARGA = "<html><body>" + ("relleno " * 400) + "</body></html>"
PAGINA_CORTA = "<html><body>no encontrado</body></html>"

PANEL_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="generator" content="PanelCMS 3.1.4">
  <title>Panel de prueba</title>
  <!-- TODO: quitar el usuario admin / password: Sup3rS3cret0 antes de publicar -->
  <!-- FIXME: la api key de produccion es api_key = "AKIAIOSFODNN7EXAMPLE1" -->
  <script src="https://cdn.ejemplo.invalid/lib.js"></script>
  <script src="/app.js"></script>
  <!--//# sourceMappingURL=/app.js.map-->
  <link rel="stylesheet" href="http://insecure.ejemplo.invalid/estilo.css">
</head>
<body>
  <h1>Panel interno version 3.1.4</h1>
  <p>Contacto: soporte@ejemplo.test y admin@ejemplo.test</p>
  <p>Servidor interno: 10.20.30.40 y 192.168.1.10</p>
  <p>Ruta del despliegue: /var/www/panel/public</p>
  <a href="https://externo.invalid" target="_blank">Documentacion</a>
  <iframe src="https://externo.invalid/widget"></iframe>
  <form action="https://recolector.invalid/recoger" method="post">
    <input type="text" name="usuario">
  </form>
  <form action="/login" method="get">
    <input type="text" name="usuario">
    <input type="password" name="clave">
    <input type="submit">
  </form>
  <form action="/perfil" method="post">
    <input type="text" name="nombre">
    <input type="submit">
  </form>
  <p>Bucket: https://panel-datos.s3.amazonaws.com/export/</p>
  <p>Endpoints: "/api/v1/usuarios" y "/api/v1/facturas"</p>
  <p>Panel de gestion en "/admin/panel"</p>
  <p>&copy; 2019 Panel S.L.</p>
  <div id="app" data-reactroot=""></div>
  <p>wp-content y __next/static en la raiz</p>
  <!--RESULTADO-->
</body>
</html>
"""

PANEL_JS = """var config = { api_key: "sk_live_51H8xQ2eZvKYlo2C9dEfGhIjK",
  token: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdef" };
//# sourceMappingURL=app.js.map
"""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Apache/2.4.49"
    sys_version = "(Unix)"

    def log_message(self, *a):
        pass

    def version_string(self):
        return "Apache/2.4.49 (Unix)"

    # ---------------------------------------------------------------- salida
    def _responder(self, cuerpo, status=200, tipo="text/html; charset=utf-8",
                   extra=None):
        datos = cuerpo.encode("utf-8") if isinstance(cuerpo, str) else cuerpo
        self.send_response(status)
        self.send_header("Content-Type", tipo)
        self.send_header("X-Powered-By", "PHP/8.1.2")
        self.send_header("X-Runtime", "0.0412")
        self.send_header("Via", "1.1 hunterbug-proxy")
        self.send_header("Content-Length", str(len(datos)))
        # cookie de sesion con todos los fallos plantados, en toda respuesta
        self.send_header("Set-Cookie", "PHPSESSID=abc123; Path=/")
        # CORS: refleja el Origin y acepta credenciales
        origen = self.headers.get("Origin")
        if origen:
            self.send_header("Access-Control-Allow-Origin", origen)
            self.send_header("Access-Control-Allow-Credentials", "true")
        else:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Expose-Headers", "Authorization")
        for k, v in (extra or {}).items():
            if k.lower() in ("content-type", "content-length"):
                continue
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(datos)

    def _cookie_sesion(self):
        return {"Set-Cookie": "PHPSESSID=abc123; Path=/"}

    def _cors(self):
        origen = self.headers.get("Origin")
        if origen:
            return {"Access-Control-Allow-Origin": origen,
                    "Access-Control-Allow-Credentials": "true"}
        return {"Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Expose-Headers": "Authorization, X-Token"}

    # ---------------------------------------------------------------- GET
    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query, keep_blank_values=True)
        ruta = u.path

        if ruta == "/hunterbug-opt":
            return self._responder("", 200, extra={
                "Allow": "GET, HEAD, POST, PUT, DELETE, PATCH, PROPFIND, TRACE"})

        if ruta == "/buscar":
            valor = q.get("q", [""])[0]
            if "'" in valor or '"' in valor:
                return self._responder(
                    "<h1>Error</h1>You have an error in your SQL syntax; "
                    "check the manual that corresponds to your MySQL server "
                    "version for the right syntax to use near '%s'" % valor, 500)
            # la pagina objetivo lleva TODOS los fallos de contenido plantados
            # y ademas refleja el parametro sin escapar (XSS)
            return self._responder(
                PANEL_HTML.replace("<!--RESULTADO-->",
                                   "<h2>Resultados para %s</h2>" % valor))

        if ruta == "/item":
            valor = q.get("id", [""])[0]
            if "1=2" in valor:
                return self._responder(PAGINA_CORTA)
            if "1=1" in valor:
                return self._responder(PAGINA_LARGA)
            return self._responder(PAGINA_CORTA)

        if ruta == "/saludo":
            nombre = q.get("name", [""])[0]
            return self._responder(
                "<html><body><h1>Hola %s</h1></body></html>" % nombre)

        if ruta == "/plantilla":
            nombre = q.get("name", [""])[0]
            # simula un motor de plantillas que evalua la expresion recibida
            m = re.fullmatch(r"\{\{([\d\s\+\-\*/]+)\}\}", nombre) or \
                re.fullmatch(r"\$\{([\d\s\+\-\*/]+)\}", nombre)
            if m:
                try:
                    valor = eval(m.group(1), {"__builtins__": {}}, {})
                except Exception:
                    valor = "error"
                return self._responder("<p>Resultado: %s</p>" % valor)
            return self._responder("<p>Resultado: %s</p>" % nombre)

        if ruta == "/crlf":
            destino = q.get("next", [""])[0]
            if "\r\n" in destino:
                extra = {}
                for linea in destino.split("\r\n")[1:]:
                    if ":" in linea:
                        k, v = linea.split(":", 1)
                        extra[k.strip()] = v.strip()
                return self._responder("redirigiendo", 200, extra=extra)
            return self._responder("redirigiendo a %s" % destino)

        if ruta == "/fichero":
            f = q.get("file", [""])[0]
            if ".." in f or "etc/passwd" in f:
                return self._responder(
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
            return self._responder("<p>Fichero: %s</p>" % f)

        if ruta == "/redir":
            destino = q.get("url", ["/"])[0]
            return self._responder("", 302, extra={"Location": destino})

        if ruta == "/hpp":
            valores = q.get("a", [])
            if len(valores) > 1:
                return self._responder("<h1>Error 500</h1>parametro duplicado", 500)
            return self._responder("<p>a=%s</p>" % (valores[0] if valores else ""))

        if ruta == "/precio":
            p = q.get("p", ["0"])[0]
            return self._responder(
                "<html><body>precio calculado para %s: 100</body></html>" % p)

        if ruta == "/" and "usuario" in q:
            usuario = q["usuario"][0]
            if usuario == "admin":
                return self._responder("<p>usuario valido</p>", 200)
            return self._responder("<p>no existe</p>", 404)

        # --- enumeracion de usuarios: 'admin' existe, el resto no ---
        if ruta == "/usuario":
            email = q.get("email", [""])[0]
            if email == "admin@ejemplo.test":
                return self._responder("<p>usuario valido</p>", 200)
            return self._responder("<p>no existe</p>", 404)

        m = re.match(r"^/api/usuario/(\d+)$", ruta)
        if m:
            uid = int(m.group(1))
            return self._responder(json.dumps({
                "id": uid, "nombre": "usuario%d" % uid,
                "email": "usuario%d@ejemplo.test" % uid,
                "saldo": 1000 * uid,
                "tarjeta": "4111-1111-1111-%04d" % uid,
            }), 200, "application/json")

        if ruta == "/api/cuenta/1":
            tok = self.headers.get("Authorization", "")
            if "tokenA" in tok:
                return self._responder(json.dumps({"cuenta": 1, "titular": "Ana",
                                                   "saldo": 500}), 200,
                                       "application/json")
            return self._responder(json.dumps({"error": "prohibido"}), 403,
                                   "application/json")

        if ruta == "/api/fuga/1":
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

        if ruta.startswith("/api/"):
            return self._responder(json.dumps({"ok": True}), 200,
                                   "application/json", extra=self._cors())

        if ruta == "/.git/config":
            return self._responder("[core]\n\trepositoryformatversion = 0\n"
                                   "\tfilemode = true\n[remote \"origin\"]\n"
                                   "\turl = https://git.interno/panel.git")
        if ruta == "/.env":
            return self._responder("APP_ENV=production\n"
                                   "DB_PASSWORD=Sup3rS3cret0\n"
                                   "AWS_SECRET_ACCESS_KEY=abcd1234")
        if ruta == "/.svn/entries":
            return self._responder("12\n\ndir\n/trunk\n")
        if ruta == "/.DS_Store":
            return self._responder("Bud1\x00\x00\x00\x00\x00\x00\x00\x00index.html")
        if ruta == "/server-status":
            return self._responder("<html><title>Apache Server Status</title>"
                                   "<h1>Apache Server Status for 127.0.0.1</h1>"
                                   "Current Time: now\nTotal accesses: 12")
        if ruta == "/phpinfo.php":
            return self._responder("<html><title>phpinfo()</title>"
                                   "<h1>PHP Version 8.1.2</h1>")
        if ruta == "/actuator":
            return self._responder(json.dumps(
                {"_links": {"env": {"href": "/actuator/env"}}}), 200,
                "application/json")
        if ruta == "/actuator/env":
            return self._responder(json.dumps({
                "activeProfiles": ["prod"],
                "propertySources": [{"name": "systemEnvironment",
                                     "properties": {"DB_PASSWORD": {"value": "x"}}}]}),
                200, "application/json")
        if ruta == "/debug":
            return self._responder("<h1>Debug console</h1><p>ejecutar codigo</p>")
        if ruta == "/console":
            return self._responder("<h1>Consola interactiva</h1>")
        if ruta == "/swagger-ui.html":
            return self._responder("<html><title>Swagger UI</title><p>swagger</p>")
        if ruta == "/api-docs":
            return self._responder(json.dumps({"openapi": "3.0.0",
                                               "paths": {"/api/v1/usuarios": {}}}),
                                   200, "application/json")
        if ruta == "/robots.txt":
            return self._responder("User-agent: *\nDisallow: /admin/\n"
                                   "Disallow: /backup/\nDisallow: /config/\n"
                                   "Disallow: /interno/", 200, "text/plain")
        if ruta == "/sitemap.xml":
            return self._responder("<?xml version=\"1.0\"?><urlset>"
                                   "<url><loc>/panel</loc></url></urlset>",
                                   200, "application/xml")
        if ruta == "/admin/":
            filas = "".join(
                "<tr><td>admin</td><td>Administrador</td>"
                "<td>%s</td></tr>" % ("activo" if i % 2 else "baja")
                for i in range(20))
            return self._responder(
                "<html><head><title>Administracion</title></head><body>"
                "<h1>Acceso administradores</h1>"
                "<table><tr><th>usuario</th><th>rol</th><th>estado</th></tr>"
                + filas + "</table></body></html>")
        if ruta == "/backup.zip":
            return self._responder(b"PK\x03\x04" + b"x" * 500, 200,
                                   "application/zip")
        if ruta == "/.env.local":
            return self._responder("SECRET_KEY=otra-clave-larga-aqui")

        if ruta == "/panel":
            return self._responder(PANEL_HTML)
        if ruta == "/app.js":
            return self._responder(PANEL_JS, 200, "application/javascript")

        if ruta == "/error500":
            return self._responder(
                "Traceback (most recent call last):\n"
                "  File \"/var/www/panel/app/main.py\", line 42, in handler\n"
                "    cursor.execute(sql)\n"
                "You have an error in your SQL syntax near 'SELECT * FROM users'\n"
                "sqlite3.OperationalError: near \"SELECT\": syntax error", 500)

        if ruta == "/":
            return self._responder(
                "<html><head><title>objetivo de prueba</title></head>"
                "<body>servidor de pruebas</body></html>",
                200, extra=self._cookie_sesion())

        return self._responder(
            "<html><head><title>404 Not Found</title></head><body>"
            "<h1>Not Found</h1><address>Apache/2.4.49 (Unix) Server at "
            "127.0.0.1 Port 8080</address></body></html>", 404)

    def do_HEAD(self):
        self.do_GET()

    # ---------------------------------------------------------------- otros
    def do_TRACE(self):
        return self._responder("TRACE %s HTTP/1.1\r\nHost: %s\r\n\r\n"
                               % (self.path, self.headers.get("Host", "")),
                               200, "message/http")

    def do_OPTIONS(self):
        return self._responder("", 200, extra={
            "Allow": "GET, HEAD, POST, PUT, DELETE, PATCH, PROPFIND, TRACE"})

    def do_PUT(self):
        largo = int(self.headers.get("Content-Length") or 0)
        if largo:
            self.rfile.read(largo)
        return self._responder("", 201)

    def do_DELETE(self):
        return self._responder("", 204)

    def do_PATCH(self):
        return self._responder("", 200)

    def do_PROPFIND(self):
        return self._responder("", 207)

    def do_HUNTERBUG(self):
        return self._responder("", 200)

    # ---------------------------------------------------------------- POST
    def do_POST(self):
        u = urlparse(self.path)
        largo = int(self.headers.get("Content-Length") or 0)
        cuerpo = self.rfile.read(largo).decode("utf-8", "replace") if largo else ""

        if u.path == "/api/perfil":
            # asignacion masiva: refleja los campos recibidos, incluido role
            return self._responder(cuerpo or "{}", 200, "application/json")

        if u.path == "/graphql":
            if "__schema" in cuerpo:
                return self._responder(json.dumps(
                    {"data": {"__schema": {"types": [{"name": "User"}]}}}), 200,
                    "application/json")
            return self._responder(json.dumps({"data": None}), 200,
                                   "application/json")

        # endpoint generico: acusa el recibo sin devolver el cuerpo
        return self._responder(json.dumps({"ok": True, "recibido": largo}), 200,
                               "application/json")


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
