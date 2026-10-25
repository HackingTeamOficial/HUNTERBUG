"""HunterBug - registro y ejecutor del catalogo de chequeos.

Cada chequeo es una funcion que recibe un `Ctx` (contexto con la respuesta
HTTP, cabeceras, cookies, TLS, metodos permitidos y rutas sondeadas) y
devuelve None si pasa, o un hallazgo con evidencia si falla.

Los chequeos activos (sondeo de rutas, metodos y parametros) solo se ejecutan
si el llamante declara autorizacion. Todos son de volumen bajo y no
destructivos: no hay fuerza bruta, ni denegacion de servicio, ni escritura de
recursos reales.
"""

from __future__ import annotations

import re
import time

from . import net

# --------------------------------------------------------------------------
# Registro
# --------------------------------------------------------------------------

CATALOGO = []

CATEGORIAS = [
    ("cabeceras",  "Cabeceras de seguridad"),
    ("cookies",    "Cookies y sesion"),
    ("cors",       "CORS"),
    ("metodos",    "Metodos HTTP"),
    ("tls",        "TLS y certificado"),
    ("contenido",  "Contenido y HTML"),
    ("fugas",      "Fuga de informacion"),
    ("rutas",      "Rutas y paneles expuestos"),
    ("parametros", "Inyeccion y logica en parametros"),
    ("tecnologia", "Tecnologia y exposicion"),
    ("respuesta",  "Calidad de la respuesta"),
]


def check(cid, nombre, categoria, severidad, activo=False, cwe="", owasp="",
          solo_https=False):
    """Decorador que registra un chequeo en el catalogo."""
    def deco(fn):
        CATALOGO.append({
            "id": cid, "nombre": nombre, "categoria": categoria,
            "severidad": severidad, "activo": activo, "cwe": cwe,
            "owasp": owasp, "solo_https": solo_https, "fn": fn,
        })
        return fn
    return deco


def por_id(cid):
    for c in CATALOGO:
        if c["id"] == cid:
            return c
    return None


def resumen_catalogo():
    """Estadisticas del catalogo: totales por categoria y por severidad."""
    por_cat, por_sev, activos = {}, {}, 0
    for c in CATALOGO:
        por_cat[c["categoria"]] = por_cat.get(c["categoria"], 0) + 1
        por_sev[c["severidad"]] = por_sev.get(c["severidad"], 0) + 1
        if c["activo"]:
            activos += 1
    return {"total": len(CATALOGO), "por_categoria": por_cat,
            "por_severidad": por_sev, "activos": activos,
            "pasivos": len(CATALOGO) - activos}


# --------------------------------------------------------------------------
# Contexto
# --------------------------------------------------------------------------

RUTAS_SONDA = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/.git/config", "/.env", "/.svn/entries", "/.DS_Store",
    "/server-status", "/phpinfo.php", "/actuator", "/actuator/env",
    "/debug", "/console", "/swagger-ui.html", "/api-docs", "/graphql",
    "/backup.zip", "/wp-login.php", "/admin/", "/.well-known/change-password",
]

CABECERAS_SONDA = ["Server", "X-Powered-By", "Via", "X-Backend-Server"]


class Ctx:
    """Todo lo que un chequeo puede necesitar sobre una respuesta."""

    def __init__(self, url, resultado=None, cabeceras_extra=None,
                 autorizado=False, log=None, pausa=0.15):
        self.url = url
        self.autorizado = autorizado
        self.log = log or (lambda t, n="info": None)
        self.pausa = pausa
        self.peticiones = 0
        self.bytes_recibidos = 0
        self.t_inicio = time.time()

        self.r = resultado or net.peticion_http(url, cabeceras=cabeceras_extra,
                                                timeout=15, seguir=1)
        self.peticiones += 1
        self.bytes_recibidos += self.r.cuerpo_bytes

        self.cabeceras = {k.lower(): v for k, v in self.r.cabeceras}
        self.cuerpo = self.r.cuerpo or ""
        self.cuerpo_min = self.cuerpo.lower()
        self.esquema, self.host, self.puerto, self.ruta = net._host_puerto(url)
        self.cookies = self._parsear_cookies()
        self._metodos = None
        self._rutas = {}
        self._tls_extra = None

    # ---- ayudas ----

    def _parsear_cookies(self):
        lista = []
        crudo = self.cabeceras.get("set-cookie")
        valores = [v for k, v in self.r.cabeceras if k.lower() == "set-cookie"]
        for v in valores:
            partes = [p.strip() for p in v.split(";")]
            if not partes:
                continue
            nombre, _, valor = partes[0].partition("=")
            attrs = {}
            for p in partes[1:]:
                k, _, val = p.partition("=")
                attrs[k.strip().lower()] = val.strip()
            lista.append({"nombre": nombre.strip(), "valor": valor.strip(),
                          "atributos": attrs, "crudo": v})
        return lista

    def pedir(self, url, metodo="GET", cabeceras=None, cuerpo=None, timeout=12):
        r = net.peticion_http(url, metodo=metodo, cabeceras=cabeceras,
                              cuerpo=cuerpo, timeout=timeout)
        self.peticiones += 1
        self.bytes_recibidos += r.cuerpo_bytes
        if self.pausa:
            time.sleep(self.pausa)
        return r

    def cabecera(self, nombre, defecto=""):
        return self.cabeceras.get(nombre.lower(), defecto)

    def tiene(self, nombre):
        return nombre.lower() in self.cabeceras

    def metodos(self):
        """Metodos anunciados por el servidor (OPTIONS). Cacheado."""
        if self._metodos is None:
            self._metodos = []
            if self.autorizado:
                base = "%s://%s%s" % (self.esquema, self.host,
                                      "" if self.puerto in (80, 443)
                                      else ":%d" % self.puerto)
                r = self.pedir(base + "/", metodo="OPTIONS")
                allow = r.cabecera("allow")
                self._metodos = [m.strip().upper() for m in allow.split(",") if m.strip()]
            else:
                allow = self.cabecera("allow")
                self._metodos = [m.strip().upper() for m in allow.split(",") if m.strip()]
        return self._metodos

    def rutas(self):
        """Sondea las rutas conocidas una sola vez. Cacheado."""
        if not self._rutas and self.autorizado:
            base = "%s://%s%s" % (self.esquema, self.host,
                                  "" if self.puerto in (80, 443)
                                  else ":%d" % self.puerto)
            for ruta in RUTAS_SONDA:
                try:
                    r = self.pedir(base + ruta, timeout=8)
                    self._rutas[ruta] = {"status": r.status,
                                         "bytes": r.cuerpo_bytes,
                                         "cuerpo": (r.cuerpo or "")[:4000]}
                except Exception:
                    self._rutas[ruta] = {"status": 0, "bytes": 0, "cuerpo": ""}
        return self._rutas

    def ruta(self, ruta):
        return self.rutas().get(ruta, {"status": 0, "bytes": 0, "cuerpo": ""})

    def hallazgo(self, h):
        h.setdefault("url", self.url)
        return h


# --------------------------------------------------------------------------
# Ejecutor
# --------------------------------------------------------------------------

def ejecutar(url, cabeceras_extra=None, autorizado=False, log=None,
             pausa=0.15, solo_ids=None, omitir_ids=None):
    """Ejecuta el catalogo completo sobre una URL.

    Devuelve (hallazgos, resultados) donde `resultados` incluye el estado de
    TODOS los chequeos, pasen o no, para poder mostrar cobertura y metricas.
    """
    ctx = Ctx(url, cabeceras_extra=cabeceras_extra, autorizado=autorizado,
              log=log, pausa=pausa)
    hallazgos, resultados = [], []
    t0 = time.time()

    for c in CATALOGO:
        if solo_ids and c["id"] not in solo_ids:
            continue
        if omitir_ids and c["id"] in omitir_ids:
            continue
        if c["activo"] and not autorizado:
            resultados.append({"id": c["id"], "nombre": c["nombre"],
                               "categoria": c["categoria"],
                               "severidad": c["severidad"], "estado": "omitido",
                               "detalle": "requiere autorizacion", "cwe": c["cwe"],
                               "owasp": c["owasp"], "activo": c["activo"]})
            continue
        if c["solo_https"] and ctx.esquema != "https":
            resultados.append({"id": c["id"], "nombre": c["nombre"],
                               "categoria": c["categoria"],
                               "severidad": c["severidad"], "estado": "omitido",
                               "detalle": "solo aplica sobre HTTPS",
                               "cwe": c["cwe"], "owasp": c["owasp"],
                               "activo": c["activo"]})
            continue
        try:
            salida = c["fn"](ctx)
        except Exception as e:
            salida = None
            resultados.append({"id": c["id"], "nombre": c["nombre"],
                               "categoria": c["categoria"],
                               "severidad": c["severidad"], "estado": "error",
                               "detalle": "%s: %s" % (type(e).__name__, str(e)[:120]),
                               "cwe": c["cwe"], "owasp": c["owasp"],
                               "activo": c["activo"]})
            continue

        if salida:
            h = dict(salida)
            h.setdefault("severidad", c["severidad"])
            h["id_check"] = c["id"]
            h["categoria"] = c["categoria"]
            h["cwe"] = c["cwe"]
            h["owasp"] = c["owasp"]
            h.setdefault("tipo", c["categoria"])
            h.setdefault("url", url)
            h.setdefault("evidencia", {})
            hallazgos.append(h)
            resultados.append({"id": c["id"], "nombre": c["nombre"],
                               "categoria": c["categoria"],
                               "severidad": h["severidad"], "estado": "fallo",
                               "detalle": str(h.get("detalle", ""))[:200],
                               "cwe": c["cwe"], "owasp": c["owasp"],
                               "activo": c["activo"]})
        else:
            resultados.append({"id": c["id"], "nombre": c["nombre"],
                               "categoria": c["categoria"],
                               "severidad": c["severidad"], "estado": "ok",
                               "detalle": "", "cwe": c["cwe"],
                               "owasp": c["owasp"], "activo": c["activo"]})

    ctx.t_total = time.time() - t0
    return hallazgos, resultados, ctx


# --------------------------------------------------------------------------
# Utilidades compartidas por los chequeos
# --------------------------------------------------------------------------

RE_IP_PRIVADA = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")
RE_EMAIL = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
RE_RUTA_ABS = re.compile(r"(?:/var/www|/home/[a-z]+/|C:\\\\inetpub|/usr/local/)")
RE_SECRETO = re.compile(
    r"(?:api[_-]?key|apikey|secret|token|passwd|password|private[_-]?key)"
    r"\s*[:=]\s*[\"']([A-Za-z0-9_\-\.]{16,})[\"']", re.IGNORECASE)
RE_AWS = re.compile(r"AKIA[0-9A-Z]{16}")
RE_JWT = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}")
RE_STACK = re.compile(
    r"(Traceback \(most recent call last\)|at [a-z]+\.[a-z]+\.[A-Za-z]+\.|"
    r"java\.lang\.[A-Za-z]+Exception|Warning: \w+\(\) expects parameter|"
    r"Fatal error:|Stack trace:|Notice: Undefined)", re.IGNORECASE)
RE_BD_ERROR = re.compile(
    r"(you have an error in your sql syntax|unclosed quotation mark|"
    r"ORA-\d{4,5}|pg_query\(\)|sqlite3?\.\w*Error|SQLSTATE\[)", re.IGNORECASE)
RE_COMENTARIO = re.compile(r"<!--(.{0,400}?)-->", re.DOTALL)
RE_MIXED = re.compile(r"(?:src|href)\s*=\s*[\"']http://[^\"']+", re.IGNORECASE)
RE_FORM = re.compile(r"<form\b[^>]*>(.*?)</form>", re.DOTALL | re.IGNORECASE)
RE_INPUT_PWD = re.compile(r"<input[^>]*type\s*=\s*[\"']?password", re.IGNORECASE)
RE_IFRAME = re.compile(r"<iframe\b[^>]*>", re.IGNORECASE)
RE_BLANK = re.compile(r"<a\b[^>]*target\s*=\s*[\"']?_blank[^>]*>", re.IGNORECASE)
RE_SCRIPT_EXT = re.compile(r"<script[^>]*src\s*=\s*[\"'](https?://[^\"']+)[\"']",
                           re.IGNORECASE)
RE_MAP = re.compile(r"sourceMappingURL\s*=\s*([^\s*]+)", re.IGNORECASE)
RE_BUCKET = re.compile(r"https?://([a-z0-9.\-]+\.s3[.\-][a-z0-9.\-]*amazonaws\.com"
                       r"|[a-z0-9.\-]+\.blob\.core\.windows\.net"
                       r"|storage\.googleapis\.com/[a-z0-9.\-_]+)", re.IGNORECASE)

FIRMAS_TECNOLOGIA = [
    ("WordPress", ["wp-content", "wp-includes", "wp-json"]),
    ("Drupal", ["/sites/default/files", "x-drupal", "drupal.js"]),
    ("Joomla", ["/components/com_", "joomla"]),
    ("Shopify", ["cdn.shopify.com", "shopify"]),
    ("Next.js", ["_next/static", "__next"]),
    ("React", ["data-reactroot", "react-dom"]),
    ("Vue.js", ["vue.js", "vue.min.js", "data-v-"]),
    ("Angular", ["ng-version", "angular.min.js"]),
    ("Laravel", ["laravel_session", "csrf-token"]),
    ("Django", ["csrfmiddlewaretoken", "__admin__"]),
    ("Ruby on Rails", ["x-runtime", "rails"]),
    ("Spring", ["x-application-context", "spring"]),
    ("ASP.NET", ["asp.net", "__viewstate", "aspnet"]),
    ("PHP", ["phpsessid", ".php"]),
    ("Apache Tomcat", ["tomcat", "coyote"]),
    ("nginx", ["nginx"]),
    ("Apache", ["apache"]),
    ("IIS", ["microsoft-iis", "iis"]),
    ("Cloudflare", ["cloudflare", "cf-ray"]),
    ("Vercel", ["x-vercel", "vercel"]),
]


def longitud_normalizada(texto):
    return len(re.sub(r"\s+", " ", texto or ""))
