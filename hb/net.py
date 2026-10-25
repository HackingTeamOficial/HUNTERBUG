"""HunterBug - nucleo de red: HTTP en crudo, TLS, DNS y puertos.

Sin dependencias externas: solo stdlib (socket/ssl/urllib).
"""

from __future__ import annotations

import gzip
import json
import re
import socket
import ssl
import time
import urllib.parse
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed

UA = "HunterBug/1.0 (+authorized-security-testing)"

PUERTOS_COMUNES = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 514, 587, 636, 873, 993, 995, 1080, 1433, 1521, 2049, 2375, 3000,
    3306, 3389, 5000, 5432, 5601, 5900, 6379, 7001, 8000, 8080, 8081, 8443,
    8888, 9000, 9090, 9200, 9300, 11211, 27017,
]

SERVICIOS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "smtp-sub", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker",
    3000: "dev-http", 3306: "mysql", 3389: "rdp", 5000: "upnp/http",
    5432: "postgres", 5601: "kibana", 5900: "vnc", 6379: "redis",
    7001: "weblogic", 8000: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9090: "http-alt",
    9200: "elasticsearch", 9300: "es-transport", 11211: "memcached",
    27017: "mongodb",
}


# --------------------------------------------------------------------------
# HTTP en crudo (peticion y respuesta tal cual viajan por el cable)
# --------------------------------------------------------------------------

class ResultadoHTTP:
    def __init__(self):
        self.ok = False
        self.error = ""
        self.url = ""
        self.metodo = "GET"
        self.peticion_cruda = ""
        self.respuesta_cruda = ""
        self.status = 0
        self.reason = ""
        self.version = ""
        self.cabeceras = []          # [(nombre, valor)]
        self.cuerpo = ""
        self.cuerpo_bytes = 0
        self.tiempo = 0.0
        self.tls = {}
        self.ip = ""

    def cabecera(self, nombre, defecto=""):
        n = nombre.lower()
        for k, v in self.cabeceras:
            if k.lower() == n:
                return v
        return defecto

    def cabeceras_dict(self):
        return {k: v for k, v in self.cabeceras}


def _host_puerto(url):
    p = urllib.parse.urlsplit(url)
    if not p.scheme:
        p = urllib.parse.urlsplit("https://" + url)
    host = p.hostname or ""
    https = p.scheme == "https"
    puerto = p.port or (443 if https else 80)
    ruta = p.path or "/"
    if p.query:
        ruta += "?" + p.query
    return p.scheme, host, puerto, ruta


def _decodificar_cuerpo(cabeceras, crudo):
    """Descomprime gzip/deflate y trocea transfer-encoding: chunked."""
    te = ""
    ce = ""
    for k, v in cabeceras:
        kl = k.lower()
        if kl == "transfer-encoding":
            te = v.lower()
        elif kl == "content-encoding":
            ce = v.lower()

    datos = crudo
    if "chunked" in te:
        partes = []
        resto = datos
        while True:
            idx = resto.find(b"\r\n")
            if idx < 0:
                break
            tam_txt = resto[:idx].split(b";")[0].strip()
            try:
                tam = int(tam_txt, 16)
            except ValueError:
                break
            if tam == 0:
                break
            partes.append(resto[idx + 2: idx + 2 + tam])
            resto = resto[idx + 2 + tam + 2:]
        datos = b"".join(partes)

    try:
        if "gzip" in ce:
            datos = gzip.decompress(datos)
        elif "deflate" in ce:
            try:
                datos = zlib.decompress(datos)
            except zlib.error:
                datos = zlib.decompress(datos, -zlib.MAX_WBITS)
    except Exception:
        pass
    return datos


def peticion_http(url, metodo="GET", cabeceras=None, cuerpo=None,
                  timeout=10.0, seguir=0, verificar_tls=False):
    """Envia una peticion HTTP/1.1 por socket crudo y devuelve todo capturado."""
    r = ResultadoHTTP()
    r.url = url
    r.metodo = metodo.upper()
    cabeceras = dict(cabeceras or {})

    try:
        esquema, host, puerto, ruta = _host_puerto(url)
    except Exception as e:
        r.error = "URL invalida: " + str(e)
        return r
    if not host:
        r.error = "URL sin host"
        return r

    cuerpo_b = None
    if cuerpo is not None:
        cuerpo_b = cuerpo.encode("utf-8") if isinstance(cuerpo, str) else cuerpo

    enviadas = {"Host": host if puerto in (80, 443) else "%s:%d" % (host, puerto),
                "User-Agent": UA, "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate", "Connection": "close"}
    enviadas.update(cabeceras)
    if cuerpo_b is not None and not any(k.lower() == "content-length"
                                        for k in enviadas):
        enviadas["Content-Length"] = str(len(cuerpo_b))

    lineas = ["%s %s HTTP/1.1" % (r.metodo, ruta)]
    lineas += ["%s: %s" % (k, v) for k, v in enviadas.items()]
    peticion = ("\r\n".join(lineas) + "\r\n\r\n").encode("utf-8")
    if cuerpo_b:
        peticion += cuerpo_b
    r.peticion_cruda = peticion.decode("utf-8", "replace")

    t0 = time.time()
    try:
        crudo = socket.create_connection((host, puerto), timeout=timeout)
        r.ip = crudo.getpeername()[0]
    except Exception as e:
        r.error = "conexion fallida: %s" % e
        r.tiempo = time.time() - t0
        return r

    try:
        if esquema == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE if not verificar_tls else ssl.CERT_REQUIRED
            if verificar_tls:
                ctx.check_hostname = True
                ctx.load_default_certs()
            tls = ctx.wrap_socket(crudo, server_hostname=host)
            try:
                cert = tls.getpeercert()
                r.tls = {
                    "version": tls.version(),
                    "cipher": (tls.cipher() or ("",))[0],
                    "sujeto": dict(x[0] for x in cert.get("subject", ())) if cert else {},
                    "emisor": dict(x[0] for x in cert.get("issuer", ())) if cert else {},
                    "valido_desde": cert.get("notBefore", "") if cert else "",
                    "valido_hasta": cert.get("notAfter", "") if cert else "",
                }
            except Exception:
                r.tls = {"version": tls.version(), "cipher": (tls.cipher() or ("",))[0]}
            con = tls
        else:
            con = crudo

        con.sendall(peticion)
        trozos = []
        while True:
            d = con.recv(65536)
            if not d:
                break
            trozos.append(d)
            if sum(len(x) for x in trozos) > 8 * 1024 * 1024:
                break
        bruto = b"".join(trozos)
        con.close()
    except Exception as e:
        r.error = "fallo de E/S: %s" % e
        r.tiempo = time.time() - t0
        return r

    r.tiempo = time.time() - t0
    r.respuesta_cruda = bruto.decode("utf-8", "replace")

    if not bruto:
        r.error = "respuesta vacia"
        return r

    corte = bruto.find(b"\r\n\r\n")
    if corte < 0:
        r.error = "respuesta sin cabeceras"
        return r
    cab_txt = bruto[:corte].decode("utf-8", "replace")
    cuerpo_bruto = bruto[corte + 4:]

    lns = cab_txt.split("\r\n")
    estado = lns[0].split(" ", 2)
    r.version = estado[0] if estado else ""
    try:
        r.status = int(estado[1])
    except Exception:
        r.status = 0
    r.reason = estado[2] if len(estado) > 2 else ""
    for ln in lns[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            r.cabeceras.append((k.strip(), v.strip()))

    datos = _decodificar_cuerpo(r.cabeceras, cuerpo_bruto)
    r.cuerpo_bytes = len(datos)
    r.cuerpo = datos.decode("utf-8", "replace")
    r.ok = 200 <= r.status < 400

    if seguir > 0 and r.status in (301, 302, 303, 307, 308):
        destino = r.cabecera("location")
        if destino:
            destino = urllib.parse.urljoin(url, destino)
            return peticion_http(destino, "GET" if r.status == 303 else metodo,
                                 cabeceras, None if r.status == 303 else cuerpo,
                                 timeout, seguir - 1, verificar_tls)
    return r


# --------------------------------------------------------------------------
# DNS (via DNS-over-HTTPS, sin dependencias)
# --------------------------------------------------------------------------

DOH_PROVEEDORES = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
    "https://dns.quad9.net:5053/dns-query",
]
TIPOS_DNS = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"]


def _doh(url, timeout):
    """GET a un resolutor DoH con verificacion TLS y respaldo sin verificar."""
    req = urllib.request.Request(url, headers={"accept": "application/dns-json",
                                               "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace")), ""
    except Exception as e:
        # algunos entornos no tienen la cadena de CA completa
        try:
            ctx = ssl._create_unverified_context()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return json.loads(resp.read().decode("utf-8", "replace")), ""
        except Exception:
            return None, str(e)


def consulta_dns(nombre, tipo="A", timeout=8.0):
    """Consulta DNS por DoH probando varios resolutores. Devuelve (registros, estado)."""
    ultimo = ""
    for base in DOH_PROVEEDORES:
        url = "%s?name=%s&type=%s" % (base, urllib.parse.quote(nombre),
                                      urllib.parse.quote(tipo))
        data, err = _doh(url, timeout)
        if data is None:
            ultimo = err
            continue
        salida = []
        for a in data.get("Answer", []) or []:
            val = str(a.get("data", ""))
            if tipo == "MX" and " " in val:
                val = val.split(" ", 1)[1].rstrip(".")
            salida.append(val.strip('"') if tipo == "TXT" else val)
        return salida, data.get("Status", 0)
    return [], "error DoH: " + ultimo


def recon_dns(dominio, timeout=8.0):
    """Todos los tipos de registro utiles para un dominio."""
    resultado = {}
    for tipo in TIPOS_DNS:
        regs, estado = consulta_dns(dominio, tipo, timeout)
        resultado[tipo] = regs
    return resultado


def resolver_ip(host):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except Exception:
        return []


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# --------------------------------------------------------------------------
# Puertos
# --------------------------------------------------------------------------

def escanear_puerto(host, puerto, timeout=1.2, banner=True):
    """Devuelve dict con estado del puerto y banner si lo hay."""
    res = {"puerto": puerto, "abierto": False, "servicio": SERVICIOS.get(puerto, ""),
           "banner": ""}
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((host, puerto)) == 0:
            res["abierto"] = True
            if banner:
                try:
                    s.settimeout(1.5)
                    if puerto in (80, 8080, 8000, 8888, 3000, 5000, 9090):
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    elif puerto in (443, 8443):
                        res["banner"] = "(tls)"
                        raise socket.timeout()
                    datos = s.recv(256)
                    res["banner"] = datos.decode("utf-8", "replace").split("\r\n")[0][:120]
                except Exception:
                    pass
    except Exception:
        pass
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    return res


def escanear_puertos(host, puertos=None, hilos=40, timeout=1.2, callback=None):
    """Escaneo concurrente y moderado. callback(resultado) por cada puerto."""
    puertos = puertos or PUERTOS_COMUNES
    abiertos = []
    with ThreadPoolExecutor(max_workers=hilos) as ex:
        futuros = {ex.submit(escanear_puerto, host, p, timeout): p for p in puertos}
        for f in as_completed(futuros):
            try:
                r = f.result()
            except Exception:
                continue
            if callback:
                callback(r)
            if r["abierto"]:
                abiertos.append(r)
    return sorted(abiertos, key=lambda x: x["puerto"])


# --------------------------------------------------------------------------
# Auditoria de cabeceras de seguridad
# --------------------------------------------------------------------------

CABECERAS_SEGURIDAD = [
    ("strict-transport-security", "alto",
     "HSTS ausente: permite degradar a HTTP y facilita MITM",
     "max-age=31536000; includeSubDomains"),
    ("content-security-policy", "alto",
     "CSP ausente: sin defensa en profundidad contra XSS",
     "default-src 'self'; object-src 'none'; base-uri 'none'"),
    ("x-content-type-options", "medio",
     "Sin X-Content-Type-Options: riesgo de MIME sniffing",
     "nosniff"),
    ("x-frame-options", "medio",
     "Sin X-Frame-Options ni frame-ancestors: posible clickjacking",
     "DENY"),
    ("referrer-policy", "bajo",
     "Sin Referrer-Policy: se filtran URLs a terceros",
     "strict-origin-when-cross-origin"),
    ("permissions-policy", "bajo",
     "Sin Permissions-Policy: APIs del navegador sin restringir",
     "geolocation=(), microphone=(), camera=()"),
]

CABECERAS_FUGA = ["server", "x-powered-by", "x-aspnet-version",
                  "x-generator", "via", "x-backend-server"]


def auditar_cabeceras(resultado_http):
    """Analiza cabeceras y devuelve hallazgos con severidad."""
    presentes = {k.lower(): v for k, v in resultado_http.cabeceras}
    hallazgos = []

    for nombre, sev, motivo, recomendado in CABECERAS_SEGURIDAD:
        if nombre not in presentes:
            if nombre == "strict-transport-security" and not resultado_http.url.startswith("https"):
                continue
            hallazgos.append({
                "tipo": "cabecera-ausente", "severidad": sev,
                "titulo": "Falta " + nombre,
                "detalle": motivo, "recomendacion": recomendado,
                "evidencia": {"cabecera": nombre},
            })
        else:
            valor = presentes[nombre]
            if nombre == "strict-transport-security":
                m = re.search(r"max-age=(\d+)", valor)
                if m and int(m.group(1)) < 15552000:
                    hallazgos.append({
                        "tipo": "hsts-debil", "severidad": "medio",
                        "titulo": "HSTS con max-age corto (%s)" % m.group(1),
                        "detalle": "max-age menor de 180 dias reduce la proteccion",
                        "recomendacion": "max-age=31536000; includeSubDomains; preload",
                        "evidencia": {"valor": valor},
                    })

    for nombre in CABECERAS_FUGA:
        if nombre in presentes:
            hallazgos.append({
                "tipo": "fuga-tecnologia", "severidad": "bajo",
                "titulo": "Cabecera revela tecnologia: %s" % nombre,
                "detalle": "Facilita al atacante elegir exploits concretos",
                "recomendacion": "Eliminar o minimizar la cabecera",
                "evidencia": {"cabecera": nombre, "valor": presentes[nombre]},
            })

    csp = presentes.get("content-security-policy", "")
    if csp:
        debil = []
        if "'unsafe-inline'" in csp:
            debil.append("'unsafe-inline'")
        if "'unsafe-eval'" in csp:
            debil.append("'unsafe-eval'")
        if re.search(r"(script-src|default-src)[^;]*\*", csp):
            debil.append("comodin *")
        if "http:" in csp:
            debil.append("origen http:")
        if debil:
            hallazgos.append({
                "tipo": "csp-debil", "severidad": "medio",
                "titulo": "CSP con directivas debiles",
                "detalle": "La CSP permite: " + ", ".join(debil),
                "recomendacion": "Quitar unsafe-inline/eval y el comodin",
                "evidencia": {"csp": csp},
            })
    return hallazgos


def detectar_tecnologias(resultado_http):
    """Fingerprint pasivo a partir de cabeceras y cuerpo."""
    tec = {}
    h = {k.lower(): v for k, v in resultado_http.cabeceras}
    cuerpo = (resultado_http.cuerpo or "")[:200000].lower()

    pares = [
        ("server", None), ("x-powered-by", None), ("x-aspnet-version", None),
        ("x-drupal-cache", "Drupal"), ("x-generator", "Generator"),
        ("x-shopify-stage", "Shopify"), ("x-vercel-id", "Vercel"),
        ("cf-ray", "Cloudflare"), ("x-amz-cf-id", "CloudFront"),
        ("x-github-request-id", "GitHub"), ("x-azure-ref", "Azure"),
    ]
    for k, etiqueta in pares:
        if k in h:
            tec[etiqueta or k] = h[k]

    firmas = [
        ("wp-content", "WordPress"), ("wp-includes", "WordPress"),
        ("/sites/default/files", "Drupal"), ("joomla", "Joomla"),
        ("cdn.shopify.com", "Shopify"), ("_next/static", "Next.js"),
        ("__next", "Next.js"), ("ng-version", "Angular"),
        ("data-reactroot", "React"), ("vue.js", "Vue.js"),
        ("laravel_session", "Laravel"), ("csrfmiddlewaretoken", "Django"),
        ("jsessionid", "Java/Tomcat"), ("phpsessid", "PHP"),
        ("asp.net", "ASP.NET"), ("graphql", "GraphQL"),
    ]
    for firma, nombre in firmas:
        if firma in cuerpo:
            tec.setdefault(nombre, "detectado en el cuerpo")
    return tec
