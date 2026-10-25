"""HunterBug - catalogo de chequeos: cabeceras, cookies, CORS, metodos,
TLS y calidad de la respuesta.

Todos los chequeos devuelven None si pasan, o un dict de hallazgo con
evidencia si fallan. Ver `hb/checks.py` para el registro y el ejecutor.
"""

from __future__ import annotations

import socket
import ssl
import time

from . import net, x509lite
from .checks import check, RE_STACK, RE_BD_ERROR

CAB = "cabeceras"
CKI = "cookies"
CRS = "cors"
MTH = "metodos"
TLS = "tls"
RSP = "respuesta"


# ==========================================================================
# Cabeceras de seguridad (40)
# ==========================================================================

def _falta(nombre, sev, motivo, rec, cid, cwe="", owasp="", cat=CAB,
           solo_https=False):
    @check(cid, "Falta la cabecera " + nombre, cat, sev, cwe=cwe, owasp=owasp,
           solo_https=solo_https)
    def _f(ctx):
        if ctx.tiene(nombre):
            return None
        return {"titulo": "Falta la cabecera " + nombre, "detalle": motivo,
                "recomendacion": rec,
                "evidencia": {"cabecera_ausente": nombre}}
    return _f


_falta("strict-transport-security", "alto",
       "Sin HSTS el navegador puede degradar a HTTP y es vulnerable a "
       "interceptacion",
       "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
       "HDR-01", cwe="CWE-319", owasp="A05:2021", solo_https=True)

_falta("content-security-policy", "alto",
       "Sin CSP no hay defensa en profundidad contra XSS ni control de origenes",
       "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'",
       "HDR-02", cwe="CWE-1021", owasp="A05:2021")

_falta("x-content-type-options", "medio",
       "Sin nosniff el navegador puede interpretar un fichero con otro tipo MIME",
       "X-Content-Type-Options: nosniff", "HDR-03", cwe="CWE-436", owasp="A05:2021")

_falta("x-frame-options", "medio",
       "Sin proteccion de framing la pagina es embebible y vulnerable a "
       "clickjacking",
       "X-Frame-Options: DENY (o CSP frame-ancestors 'none')",
       "HDR-04", cwe="CWE-1021", owasp="A05:2021")

_falta("referrer-policy", "bajo",
       "Sin Referrer-Policy se filtran URLs completas a terceros",
       "Referrer-Policy: strict-origin-when-cross-origin",
       "HDR-05", cwe="CWE-200", owasp="A01:2021")

_falta("permissions-policy", "bajo",
       "Sin Permissions-Policy las APIs del navegador quedan sin restringir",
       "Permissions-Policy: geolocation=(), microphone=(), camera=()",
       "HDR-06", cwe="CWE-693", owasp="A05:2021")

_falta("cross-origin-opener-policy", "bajo",
       "Sin COOP la ventana puede ser referenciada desde otro origen",
       "Cross-Origin-Opener-Policy: same-origin",
       "HDR-07", cwe="CWE-346", owasp="A05:2021")

_falta("cross-origin-resource-policy", "bajo",
       "Sin CORP los recursos pueden ser embebidos desde otros origenes",
       "Cross-Origin-Resource-Policy: same-origin",
       "HDR-08", cwe="CWE-346", owasp="A05:2021")

_falta("cross-origin-embedder-policy", "info",
       "Sin COEP no se aisla el contexto de ejecucion",
       "Cross-Origin-Embedder-Policy: require-corp",
       "HDR-09", cwe="CWE-346", owasp="A05:2021")

_falta("x-permitted-cross-domain-policies", "info",
       "Sin esta cabecera los plugins de Adobe pueden cargar contenido cruzado",
       "X-Permitted-Cross-Domain-Policies: none",
       "HDR-10", cwe="CWE-346", owasp="A05:2021")

_falta("x-dns-prefetch-control", "info",
       "Sin control de prefetch DNS se filtran dominios a terceros",
       "X-DNS-Prefetch-Control: off", "HDR-11", cwe="CWE-200", owasp="A01:2021")

_falta("x-download-options", "info",
       "Sin X-Download-Options los ficheros descargados pueden ejecutarse en "
       "contexto del sitio",
       "X-Download-Options: noopen", "HDR-12", cwe="CWE-436", owasp="A05:2021")

_falta("clear-site-data", "info",
       "Sin Clear-Site-Data no se limpian los datos del sitio al cerrar sesion",
       "Clear-Site-Data: \"cache\", \"cookies\"", "HDR-13",
       cwe="CWE-613", owasp="A07:2021")


@check("HDR-14", "HSTS con max-age corto", CAB, "medio",
       cwe="CWE-319", owasp="A05:2021", solo_https=True)
def hsts_corto(ctx):
    v = ctx.cabecera("strict-transport-security")
    if not v:
        return None
    m = __import__("re").search(r"max-age\s*=\s*(\d+)", v)
    if not m:
        return {"titulo": "HSTS sin max-age valido",
                "detalle": "La cabecera HSTS no declara max-age utilizable",
                "recomendacion": "max-age=31536000; includeSubDomains; preload",
                "evidencia": {"valor": v}}
    seg = int(m.group(1))
    if seg < 15552000:
        return {"titulo": "HSTS con max-age corto (%d s)" % seg,
                "detalle": "Menos de 180 dias reduce la proteccion frente a "
                           "degradacion a HTTP",
                "recomendacion": "max-age=31536000",
                "evidencia": {"valor": v, "max_age_segundos": seg,
                              "dias": round(seg / 86400, 1)}}
    return None


@check("HDR-15", "HSTS sin includeSubDomains", CAB, "bajo",
       cwe="CWE-319", owasp="A05:2021", solo_https=True)
def hsts_subdominios(ctx):
    v = ctx.cabecera("strict-transport-security")
    if v and "includesubdomains" not in v.lower():
        return {"titulo": "HSTS sin includeSubDomains",
                "detalle": "Los subdominios no heredan la politica HSTS y "
                           "pueden ser atacados por separado",
                "recomendacion": "max-age=31536000; includeSubDomains",
                "evidencia": {"valor": v}}
    return None


@check("HDR-16", "HSTS sin preload", CAB, "info",
       cwe="CWE-319", owasp="A05:2021", solo_https=True)
def hsts_preload(ctx):
    v = ctx.cabecera("strict-transport-security")
    if v and "preload" not in v.lower():
        return {"titulo": "HSTS sin preload",
                "detalle": "Sin preload la primera visita sigue siendo "
                           "vulnerable a interceptacion",
                "recomendacion": "Anadir preload y enviar el dominio a "
                                 "hstspreload.org",
                "evidencia": {"valor": v}}
    return None


@check("HDR-17", "CSP sin default-src", CAB, "medio",
       cwe="CWE-1021", owasp="A05:2021")
def csp_default(ctx):
    c = ctx.cabecera("content-security-policy").lower()
    if c and "default-src" not in c:
        return {"titulo": "CSP sin directiva default-src",
                "detalle": "Sin default-src las directivas no declaradas "
                           "quedan sin restringir",
                "recomendacion": "default-src 'self'",
                "evidencia": {"csp": c[:400]}}
    return None


@check("HDR-18", "CSP sin object-src", CAB, "bajo",
       cwe="CWE-1021", owasp="A05:2021")
def csp_object(ctx):
    c = ctx.cabecera("content-security-policy").lower()
    if c and "object-src" not in c and "default-src" not in c:
        return {"titulo": "CSP sin object-src",
                "detalle": "Los plugins embebidos (Flash, PDF) quedan permitidos",
                "recomendacion": "object-src 'none'",
                "evidencia": {"csp": c[:400]}}
    return None


@check("HDR-19", "CSP sin base-uri", CAB, "bajo",
       cwe="CWE-1021", owasp="A05:2021")
def csp_base(ctx):
    c = ctx.cabecera("content-security-policy").lower()
    if c and "base-uri" not in c:
        return {"titulo": "CSP sin base-uri",
                "detalle": "Un <base> inyectado puede redirigir todas las "
                           "rutas relativas",
                "recomendacion": "base-uri 'none'",
                "evidencia": {"csp": c[:400]}}
    return None


@check("HDR-20", "CSP sin frame-ancestors", CAB, "medio",
       cwe="CWE-1021", owasp="A05:2021")
def csp_frame(ctx):
    c = ctx.cabecera("content-security-policy").lower()
    if c and "frame-ancestors" not in c and not ctx.tiene("x-frame-options"):
        return {"titulo": "CSP sin frame-ancestors y sin X-Frame-Options",
                "detalle": "La pagina no declara ninguna proteccion contra "
                           "clickjacking",
                "recomendacion": "frame-ancestors 'none'",
                "evidencia": {"csp": c[:400]}}
    return None


@check("HDR-21", "CSP con unsafe-inline", CAB, "medio",
       cwe="CWE-1021", owasp="A05:2021")
def csp_inline(ctx):
    c = ctx.cabecera("content-security-policy").lower()
    if "'unsafe-inline'" in c:
        return {"titulo": "CSP permite 'unsafe-inline'",
                "detalle": "El script y el estilo en linea quedan permitidos, "
                           "lo que anula buena parte de la proteccion XSS",
                "recomendacion": "Usar nonces o hashes en lugar de unsafe-inline",
                "evidencia": {"csp": c[:400]}}
    return None


@check("HDR-22", "CSP con unsafe-eval", CAB, "medio",
       cwe="CWE-1021", owasp="A05:2021")
def csp_eval(ctx):
    c = ctx.cabecera("content-security-policy").lower()
    if "'unsafe-eval'" in c:
        return {"titulo": "CSP permite 'unsafe-eval'",
                "detalle": "eval() y el constructor Function quedan permitidos",
                "recomendacion": "Quitar unsafe-eval y refactorizar el codigo",
                "evidencia": {"csp": c[:400]}}
    return None


@check("HDR-23", "CSP con comodin *", CAB, "medio",
       cwe="CWE-1021", owasp="A05:2021")
def csp_wildcard(ctx):
    c = ctx.cabecera("content-security-policy").lower()
    if __import__("re").search(r"(script-src|default-src)[^;]*\*", c):
        return {"titulo": "CSP permite cualquier origen en script-src/default-src",
                "detalle": "El comodin anula la restriccion de origen",
                "recomendacion": "Listar solo los origenes necesarios",
                "evidencia": {"csp": c[:400]}}
    return None


@check("HDR-24", "CSP permite data: en scripts", CAB, "bajo",
       cwe="CWE-1021", owasp="A05:2021")
def csp_data(ctx):
    c = ctx.cabecera("content-security-policy").lower()
    if __import__("re").search(r"(script-src|default-src)[^;]*data:", c):
        return {"titulo": "CSP permite data: en scripts",
                "detalle": "Los URIs data: pueden alojar script ejecutable",
                "recomendacion": "Quitar data: de script-src",
                "evidencia": {"csp": c[:400]}}
    return None


@check("HDR-25", "CSP sin form-action", CAB, "info",
       cwe="CWE-1021", owasp="A05:2021")
def csp_form(ctx):
    c = ctx.cabecera("content-security-policy").lower()
    if c and "form-action" not in c:
        return {"titulo": "CSP sin form-action",
                "detalle": "Un formulario inyectado puede enviar datos a un "
                           "origen externo",
                "recomendacion": "form-action 'self'",
                "evidencia": {"csp": c[:400]}}
    return None


@check("HDR-26", "CSP sin upgrade-insecure-requests", CAB, "info",
       cwe="CWE-319", owasp="A05:2021")
def csp_upgrade(ctx):
    c = ctx.cabecera("content-security-policy").lower()
    if c and "upgrade-insecure-requests" not in c:
        return {"titulo": "CSP sin upgrade-insecure-requests",
                "detalle": "Los recursos http:// de la pagina no se elevan a "
                           "https:// automaticamente",
                "recomendacion": "upgrade-insecure-requests",
                "evidencia": {"csp": c[:400]}}
    return None


@check("HDR-27", "CSP sin reporte de violaciones", CAB, "info",
       cwe="CWE-693", owasp="A09:2021")
def csp_report(ctx):
    c = ctx.cabecera("content-security-policy").lower()
    if c and "report-uri" not in c and "report-to" not in c:
        return {"titulo": "CSP sin report-uri ni report-to",
                "detalle": "Sin endpoint de reporte no se detectan violaciones "
                           "de politica en produccion",
                "recomendacion": "Anadir report-to con un colector",
                "evidencia": {"csp": c[:400]}}
    return None


@check("HDR-28", "X-Content-Type-Options con valor invalido", CAB, "bajo",
       cwe="CWE-436", owasp="A05:2021")
def xcto_valor(ctx):
    v = ctx.cabecera("x-content-type-options")
    if v and v.strip().lower() != "nosniff":
        return {"titulo": "X-Content-Type-Options con valor inesperado",
                "detalle": "El unico valor util es nosniff; se encontro '%s'" % v,
                "recomendacion": "X-Content-Type-Options: nosniff",
                "evidencia": {"valor": v}}
    return None


@check("HDR-29", "X-Frame-Options con valor invalido", CAB, "bajo",
       cwe="CWE-1021", owasp="A05:2021")
def xfo_valor(ctx):
    v = ctx.cabecera("x-frame-options").strip().upper()
    if v and v not in ("DENY", "SAMEORIGIN"):
        return {"titulo": "X-Frame-Options con valor no reconocido (%s)" % v,
                "detalle": "Solo DENY y SAMEORIGIN son validos en navegadores "
                           "modernos",
                "recomendacion": "X-Frame-Options: DENY",
                "evidencia": {"valor": v}}
    return None


@check("HDR-30", "X-Frame-Options ALLOW-FROM obsoleto", CAB, "info",
       cwe="CWE-1021", owasp="A05:2021")
def xfo_allowfrom(ctx):
    v = ctx.cabecera("x-frame-options")
    if "allow-from" in v.lower():
        return {"titulo": "X-Frame-Options usa ALLOW-FROM",
                "detalle": "ALLOW-FROM esta obsoleto y no lo aplica ningun "
                           "navegador actual",
                "recomendacion": "Usar CSP frame-ancestors",
                "evidencia": {"valor": v}}
    return None


@check("HDR-31", "Referrer-Policy insegura", CAB, "bajo",
       cwe="CWE-200", owasp="A01:2021")
def rp_insegura(ctx):
    v = ctx.cabecera("referrer-policy").lower()
    if v and ("unsafe-url" in v or "no-referrer-when-downgrade" in v):
        return {"titulo": "Referrer-Policy envia la URL completa",
                "detalle": "El valor '%s' filtra la ruta y los parametros a "
                           "sitios externos" % v,
                "recomendacion": "strict-origin-when-cross-origin",
                "evidencia": {"valor": v}}
    return None


@check("HDR-32", "Permissions-Policy ausente con Feature-Policy", CAB, "bajo",
       cwe="CWE-693", owasp="A05:2021")
def pp_obsoleta(ctx):
    if ctx.tiene("feature-policy") and not ctx.tiene("permissions-policy"):
        return {"titulo": "Usa Feature-Policy (obsoleta)",
                "detalle": "Feature-Policy fue sustituida por Permissions-Policy",
                "recomendacion": "Migrar a Permissions-Policy",
                "evidencia": {"feature_policy": ctx.cabecera("feature-policy")}}
    return None


@check("HDR-33", "X-XSS-Protection presente (obsoleta)", CAB, "info",
       cwe="CWE-693", owasp="A05:2021")
def xxp(ctx):
    v = ctx.cabecera("x-xss-protection")
    if v:
        return {"titulo": "Cabecera X-XSS-Protection presente",
                "detalle": "Esta cabecera esta retirada de los navegadores "
                           "modernos y puede introducir fallos propios",
                "recomendacion": "Eliminarla y usar CSP",
                "evidencia": {"valor": v}}
    return None


@check("HDR-34", "Cache-Control sin no-store", CAB, "bajo",
       cwe="CWE-525", owasp="A04:2021")
def cache_nostore(ctx):
    v = ctx.cabecera("cache-control").lower()
    if not v:
        return {"titulo": "Sin cabecera Cache-Control",
                "detalle": "El contenido puede quedar en cache de proxies "
                           "intermedios o del navegador",
                "recomendacion": "Cache-Control: no-store en respuestas "
                                 "autenticadas o sensibles",
                "evidencia": {"cache_control": ""}}
    if "no-store" not in v and "private" not in v:
        return {"titulo": "Cache-Control permite almacenamiento compartido",
                "detalle": "El valor '%s' permite cachear la respuesta en "
                           "proxies" % v,
                "recomendacion": "Cache-Control: no-store",
                "evidencia": {"cache_control": v}}
    return None


@check("HDR-35", "Cabeceras Pragma/Expires obsoletas", CAB, "info",
       cwe="CWE-525", owasp="A04:2021")
def pragma(ctx):
    if ctx.tiene("pragma") or ctx.tiene("expires"):
        return {"titulo": "Usa Pragma/Expires (obsoletas)",
                "detalle": "Son de HTTP/1.0; el control real es Cache-Control",
                "recomendacion": "Sustituir por Cache-Control",
                "evidencia": {"pragma": ctx.cabecera("pragma"),
                              "expires": ctx.cabecera("expires")}}
    return None


@check("HDR-36", "Server revela version", CAB, "bajo",
       cwe="CWE-200", owasp="A05:2021")
def server_version(ctx):
    v = ctx.cabecera("server")
    if v and __import__("re").search(r"\d+\.\d+", v):
        return {"titulo": "La cabecera Server revela version",
                "detalle": "Facilita elegir exploits concretos para esa version",
                "recomendacion": "Ocultar la version (ServerTokens Prod, "
                                 "server_tokens off)",
                "evidencia": {"server": v}}
    return None


@check("HDR-37", "X-Powered-By revela tecnologia", CAB, "bajo",
       cwe="CWE-200", owasp="A05:2021")
def xpb(ctx):
    v = ctx.cabecera("x-powered-by")
    if v:
        return {"titulo": "X-Powered-By revela la tecnologia",
                "detalle": "Expone el lenguaje y a veces la version exacta",
                "recomendacion": "Eliminar la cabecera",
                "evidencia": {"x_powered_by": v}}
    return None


@check("HDR-38", "Otras cabeceras revelan el stack", CAB, "bajo",
       cwe="CWE-200", owasp="A05:2021")
def otras_fugas(ctx):
    encontradas = {h: ctx.cabecera(h) for h in
                   ("x-aspnet-version", "x-aspnetmvc-version", "x-generator",
                    "x-drupal-cache", "x-runtime", "x-backend-server",
                    "x-served-by", "x-cache", "via")
                   if ctx.tiene(h)}
    if encontradas:
        return {"titulo": "Cabeceras que revelan infraestructura (%d)"
                          % len(encontradas),
                "detalle": "Revelan servidores intermedios, frameworks o "
                           "versiones internas",
                "recomendacion": "Eliminar o minimizar estas cabeceras",
                "evidencia": encontradas}
    return None


@check("HDR-39", "Sin cabecera Vary", CAB, "info",
       cwe="CWE-436", owasp="A05:2021")
def sin_vary(ctx):
    if not ctx.tiene("vary") and ctx.tiene("cache-control"):
        return {"titulo": "Respuesta cacheable sin cabecera Vary",
                "detalle": "Un proxy puede servir una respuesta cacheada a "
                           "otro usuario con distinta cabecera",
                "recomendacion": "Declarar Vary con las cabeceras que afectan "
                                 "al contenido",
                "evidencia": {"cache_control": ctx.cabecera("cache-control")}}
    return None


@check("HDR-40", "Sin politica de contenido en el idioma declarado", CAB,
       "info", cwe="CWE-1059", owasp="A05:2021")
def sin_lang(ctx):
    if "<html" in ctx.cuerpo_min and "lang=" not in ctx.cuerpo_min[:2000]:
        return {"titulo": "El documento no declara idioma (lang)",
                "detalle": "Afecta a accesibilidad y a la interpretacion del "
                           "contenido por herramientas automaticas",
                "recomendacion": "Anadir lang al elemento html",
                "evidencia": {"extracto": ctx.cuerpo_min[:120]}}
    return None


# ==========================================================================
# Cookies y sesion (12)
# ==========================================================================

def _cookies_sin(atributo, sev, motivo, rec, cid, cwe="", owasp=""):
    @check(cid, "Cookie sin " + atributo, CKI, sev, cwe=cwe, owasp=owasp)
    def _f(ctx):
        malas = [c for c in ctx.cookies if atributo.lower() not in c["atributos"]]
        if malas:
            return {"titulo": "%d cookie(s) sin %s" % (len(malas), atributo),
                    "detalle": motivo,
                    "recomendacion": rec,
                    "evidencia": {"cookies": [c["crudo"][:160] for c in malas[:6]]}}
        return None
    return _f


_cookies_sin("secure", "alto",
             "La cookie viaja tambien por HTTP sin cifrar y puede ser "
             "interceptada",
             "Anadir el atributo Secure a todas las cookies de sesion",
             "CKI-01", cwe="CWE-614", owasp="A05:2021")

_cookies_sin("httponly", "alto",
             "Sin HttpOnly el JavaScript de la pagina puede leer la cookie, lo "
             "que convierte cualquier XSS en robo de sesion",
             "Anadir HttpOnly a las cookies de sesion",
             "CKI-02", cwe="CWE-1004", owasp="A05:2021")

_cookies_sin("samesite", "medio",
             "Sin SameSite el navegador envia la cookie en peticiones cruzadas, "
             "lo que facilita CSRF",
             "Anadir SameSite=Lax o Strict",
             "CKI-03", cwe="CWE-1275", owasp="A01:2021")


@check("CKI-04", "SameSite=None sin Secure", CKI, "alto",
       cwe="CWE-1275", owasp="A01:2021")
def samesite_none(ctx):
    malas = [c for c in ctx.cookies
             if c["atributos"].get("samesite", "").lower() == "none"
             and "secure" not in c["atributos"]]
    if malas:
        return {"titulo": "SameSite=None sin Secure",
                "detalle": "Los navegadores modernos rechazan esa combinacion y "
                           "la cookie puede no enviarse o quedar expuesta",
                "recomendacion": "Anadir Secure junto a SameSite=None",
                "evidencia": {"cookies": [c["crudo"][:160] for c in malas]}}
    return None


@check("CKI-05", "Prefijo __Host- mal aplicado", CKI, "bajo",
       cwe="CWE-565", owasp="A05:2021")
def prefijo_host(ctx):
    malas = []
    for c in ctx.cookies:
        if c["nombre"].startswith("__Host-"):
            if "secure" not in c["atributos"] or c["atributos"].get("path") != "/" \
                    or "domain" in c["atributos"]:
                malas.append(c["crudo"][:160])
    if malas:
        return {"titulo": "Cookie con prefijo __Host- mal configurada",
                "detalle": "__Host- exige Secure, Path=/ y sin atributo Domain",
                "recomendacion": "Cumplir los requisitos del prefijo o quitarlo",
                "evidencia": {"cookies": malas}}
    return None


@check("CKI-06", "Prefijo __Secure- mal aplicado", CKI, "bajo",
       cwe="CWE-565", owasp="A05:2021")
def prefijo_secure(ctx):
    malas = [c["crudo"][:160] for c in ctx.cookies
             if c["nombre"].startswith("__Secure-") and "secure" not in c["atributos"]]
    if malas:
        return {"titulo": "Cookie con prefijo __Secure- sin Secure",
                "detalle": "El prefijo __Secure- obliga a declarar Secure",
                "recomendacion": "Anadir Secure o quitar el prefijo",
                "evidencia": {"cookies": malas}}
    return None


@check("CKI-07", "Nombre de cookie de sesion por defecto", CKI, "bajo",
       cwe="CWE-200", owasp="A05:2021")
def nombre_defecto(ctx):
    conocidos = {"phpsessid": "PHP", "jsessionid": "Java/Tomcat",
                 "asp.net_sessionid": "ASP.NET", "connect.sid": "Express",
                 "laravel_session": "Laravel", "ci_session": "CodeIgniter"}
    for c in ctx.cookies:
        k = c["nombre"].lower()
        if k in conocidos:
            return {"titulo": "Cookie de sesion con nombre por defecto (%s)"
                              % c["nombre"],
                    "detalle": "Revela el framework (%s) sin necesidad de "
                               "fingerprint" % conocidos[k],
                    "recomendacion": "Renombrar la cookie de sesion",
                    "evidencia": {"cookie": c["crudo"][:160],
                                  "framework": conocidos[k]}}
    return None


@check("CKI-08", "Cookie de sesion con valor corto", CKI, "medio",
       cwe="CWE-330", owasp="A02:2021")
def valor_corto(ctx):
    for c in ctx.cookies:
        v = c["valor"]
        if 0 < len(v) < 16 and any(x in c["nombre"].lower() for x in
                                   ("sess", "sid", "token", "auth", "jwt")):
            return {"titulo": "Identificador de sesion corto (%d caracteres)"
                              % len(v),
                    "detalle": "Un identificador corto es adivinable por fuerza "
                               "bruta",
                    "recomendacion": "Usar al menos 128 bits de entropia",
                    "evidencia": {"cookie": c["nombre"], "longitud": len(v)}}
    return None


@check("CKI-09", "Cookie de sesion persistente", CKI, "bajo",
       cwe="CWE-539", owasp="A07:2021")
def sesion_persistente(ctx):
    for c in ctx.cookies:
        a = c["atributos"]
        if any(x in c["nombre"].lower() for x in ("sess", "sid", "token", "auth")) \
                and ("max-age" in a or "expires" in a):
            return {"titulo": "Cookie de sesion con caducidad larga",
                    "detalle": "Una sesion persistente amplia la ventana de "
                               "robo de cookie",
                    "recomendacion": "Sesion corta y rotacion de identificador",
                    "evidencia": {"cookie": c["crudo"][:160]}}
    return None


@check("CKI-10", "Cookie con Domain demasiado amplio", CKI, "medio",
       cwe="CWE-565", owasp="A05:2021")
def dominio_amplio(ctx):
    for c in ctx.cookies:
        dom = c["atributos"].get("domain", "")
        if dom.startswith(".") and dom.count(".") == 1:
            return {"titulo": "Cookie compartida con todos los subdominios",
                    "detalle": "El atributo Domain='%s' entrega la cookie a "
                               "cualquier subdominio, incluidos los de terceros"
                               % dom,
                    "recomendacion": "Omitir Domain o restringirlo al host exacto",
                    "evidencia": {"cookie": c["crudo"][:160], "domain": dom}}
    return None


@check("CKI-11", "Cookie sin Path", CKI, "info",
       cwe="CWE-565", owasp="A05:2021")
def sin_path(ctx):
    malas = [c["crudo"][:160] for c in ctx.cookies if "path" not in c["atributos"]]
    if malas:
        return {"titulo": "%d cookie(s) sin atributo Path" % len(malas),
                "detalle": "Sin Path la cookie se envia a todo el sitio",
                "recomendacion": "Acotar Path al ambito necesario",
                "evidencia": {"cookies": malas}}
    return None


@check("CKI-12", "Sin cookies de sesion con proteccion completa", CKI, "info",
       cwe="CWE-614", owasp="A05:2021")
def sin_proteccion_completa(ctx):
    if not ctx.cookies:
        return None
    completas = [c for c in ctx.cookies
                 if "secure" in c["atributos"] and "httponly" in c["atributos"]
                 and "samesite" in c["atributos"]]
    if not completas:
        return {"titulo": "Ninguna cookie cumple Secure + HttpOnly + SameSite",
                "detalle": "Se han visto %d cookie(s) y ninguna reune las tres "
                           "protecciones" % len(ctx.cookies),
                "recomendacion": "Aplicar las tres a todas las cookies",
                "evidencia": {"total_cookies": len(ctx.cookies),
                              "cookies": [c["crudo"][:120] for c in ctx.cookies[:5]]}}
    return None


# ==========================================================================
# CORS (7)
# ==========================================================================

@check("CRS-01", "CORS con comodin", CRS, "medio",
       cwe="CWE-942", owasp="A05:2021")
def cors_wildcard(ctx):
    if ctx.cabecera("access-control-allow-origin") == "*":
        return {"titulo": "CORS permite cualquier origen (*)",
                "detalle": "Cualquier web puede leer la respuesta desde el "
                           "navegador de la victima",
                "recomendacion": "Lista blanca de origenes concretos",
                "evidencia": {"acao": "*"}}
    return None


@check("CRS-02", "CORS refleja el origen recibido", CRS, "alto",
       cwe="CWE-942", owasp="A05:2021")
def cors_reflejo(ctx):
    # comprobacion real: pedir con un Origin propio y ver si lo devuelve
    if not ctx.autorizado:
        return None
    origen = "https://hunterbug-prueba.invalid"
    r = ctx.pedir(ctx.url, cabeceras={"Origin": origen})
    devuelto = r.cabecera("access-control-allow-origin")
    if devuelto and devuelto.rstrip("/") == origen:
        return {"titulo": "CORS refleja cualquier Origin enviado",
                "detalle": "El servidor devuelve el origen solicitado sin "
                           "validarlo, lo que permite leer respuestas desde "
                           "cualquier web",
                "recomendacion": "Validar el Origin contra una lista blanca",
                "evidencia": {"origin_enviado": origen, "acao_devuelto": devuelto}}
    return None


@check("CRS-03", "CORS refleja origen con credenciales", CRS, "critico",
       cwe="CWE-942", owasp="A05:2021")
def cors_credenciales(ctx):
    """Prueba activa: con Allow-Credentials el navegador manda cookies, asi que
    reflejar el Origin convierte la API en legible desde cualquier web."""
    if not ctx.autorizado:
        return None
    origen = "https://hunterbug-prueba.invalid"
    r = ctx.pedir(ctx.url, cabeceras={"Origin": origen})
    acao = r.cabecera("access-control-allow-origin")
    acac = r.cabecera("access-control-allow-credentials").lower()
    if acao and acao != "*" and acac == "true" and \
            acao.rstrip("/") == origen:
        return {"titulo": "CORS con credenciales y origen reflejado",
                "detalle": "Con Allow-Credentials true y el Origin reflejado, "
                           "cualquier web puede leer respuestas con la sesion "
                           "del usuario",
                "recomendacion": "Lista blanca estricta de origenes y "
                                 "Vary: Origin",
                "evidencia": {"origin_enviado": origen, "acao": acao,
                              "acac": acac}}
    return None


@check("CRS-04", "CORS acepta origen null", CRS, "alto",
       cwe="CWE-942", owasp="A05:2021")
def cors_null(ctx):
    if not ctx.autorizado:
        return None
    r = ctx.pedir(ctx.url, cabeceras={"Origin": "null"})
    if r.cabecera("access-control-allow-origin").lower() == "null":
        return {"titulo": "CORS acepta el origen null",
                "detalle": "El origen null procede de iframes sandbox o "
                           "ficheros locales y no deberia autorizarse",
                "recomendacion": "Rechazar explicitamente el origen null",
                "evidencia": {"acao": "null"}}
    return None


@check("CRS-05", "CORS con comodin y credenciales", CRS, "alto",
       cwe="CWE-942", owasp="A05:2021")
def cors_wild_cred(ctx):
    if ctx.cabecera("access-control-allow-origin") == "*" and \
            ctx.cabecera("access-control-allow-credentials").lower() == "true":
        return {"titulo": "CORS con comodin y credenciales",
                "detalle": "Combinacion contradictoria que algunos proxies "
                           "resuelven reflejando el origen",
                "recomendacion": "Eliminar el comodin cuando se usan credenciales",
                "evidencia": {"acao": "*", "acac": "true"}}
    return None


@check("CRS-06", "Sin Vary: Origin en respuesta CORS", CRS, "bajo",
       cwe="CWE-436", owasp="A05:2021")
def cors_vary(ctx):
    if ctx.tiene("access-control-allow-origin") and \
            "origin" not in ctx.cabecera("vary").lower():
        return {"titulo": "Respuesta CORS sin Vary: Origin",
                "detalle": "Una cache intermedia puede servir la cabecera CORS "
                           "de un origen a otro",
                "recomendacion": "Anadir Vary: Origin",
                "evidencia": {"vary": ctx.cabecera("vary")}}
    return None


@check("CRS-07", "CORS expone cabeceras sensibles", CRS, "info",
       cwe="CWE-200", owasp="A05:2021")
def cors_expose(ctx):
    v = ctx.cabecera("access-control-expose-headers")
    if v and any(x in v.lower() for x in ("authorization", "set-cookie",
                                          "x-token", "x-auth")):
        return {"titulo": "CORS expone cabeceras sensibles al JavaScript",
                "detalle": "Expose-Headers incluye cabeceras de autenticacion",
                "recomendacion": "Exponer solo las cabeceras necesarias",
                "evidencia": {"expose_headers": v}}
    return None


# ==========================================================================
# Metodos HTTP (8)
# ==========================================================================

@check("MTH-01", "TRACE habilitado", MTH, "medio", activo=True,
       cwe="CWE-693", owasp="A05:2021")
def trace(ctx):
    base = "%s://%s%s" % (ctx.esquema, ctx.host,
                          "" if ctx.puerto in (80, 443) else ":%d" % ctx.puerto)
    r = ctx.pedir(base + "/", metodo="TRACE")
    if r.status == 200 and "TRACE /" in (r.cuerpo or ""):
        return {"titulo": "Metodo TRACE habilitado",
                "detalle": "TRACE devuelve la peticion completa y facilita "
                           "Cross-Site Tracing",
                "recomendacion": "Deshabilitar TRACE (TraceEnable off)",
                "evidencia": {"status": r.status,
                              "cuerpo": (r.cuerpo or "")[:200]}}
    return None


@check("MTH-02", "OPTIONS revela metodos de escritura", MTH, "medio",
       activo=True, cwe="CWE-650", owasp="A05:2021")
def options_metodos(ctx):
    permitidos = ctx.metodos()
    peligrosos = [m for m in permitidos if m in ("PUT", "DELETE", "PATCH")]
    if peligrosos:
        return {"titulo": "OPTIONS anuncia metodos de escritura",
                "detalle": "El servidor declara: %s" % ", ".join(permitidos),
                "recomendacion": "Deshabilitar los metodos no usados",
                "evidencia": {"allow": ", ".join(permitidos),
                              "peligrosos": peligrosos}}
    return None


@check("MTH-03", "PUT no rechazado", MTH, "alto", activo=True,
       cwe="CWE-650", owasp="A05:2021")
def put_habilitado(ctx):
    base = "%s://%s%s" % (ctx.esquema, ctx.host,
                          "" if ctx.puerto in (80, 443) else ":%d" % ctx.puerto)
    # ruta inexistente y sin cuerpo: no crea nada real
    objetivo = base + "/hunterbug-sonda-%d" % int(time.time())
    r = ctx.pedir(objetivo, metodo="PUT", cuerpo="")
    if r.status in (200, 201, 204):
        return {"titulo": "El servidor acepta PUT",
                "detalle": "PUT sobre una ruta inexistente devolvio %d: puede "
                           "permitir subir contenido" % r.status,
                "recomendacion": "Rechazar PUT con 405 salvo donde sea necesario",
                "evidencia": {"status": r.status, "ruta": objetivo}}
    return None


@check("MTH-04", "DELETE no rechazado", MTH, "alto", activo=True,
       cwe="CWE-650", owasp="A05:2021")
def delete_habilitado(ctx):
    base = "%s://%s%s" % (ctx.esquema, ctx.host,
                          "" if ctx.puerto in (80, 443) else ":%d" % ctx.puerto)
    objetivo = base + "/hunterbug-sonda-%d" % int(time.time())
    r = ctx.pedir(objetivo, metodo="DELETE")
    if r.status in (200, 202, 204):
        return {"titulo": "El servidor acepta DELETE",
                "detalle": "DELETE sobre una ruta inexistente devolvio %d"
                           % r.status,
                "recomendacion": "Rechazar DELETE con 405 salvo donde sea necesario",
                "evidencia": {"status": r.status, "ruta": objetivo}}
    return None


@check("MTH-05", "Metodo arbitrario no rechazado", MTH, "bajo", activo=True,
       cwe="CWE-650", owasp="A05:2021")
def metodo_raro(ctx):
    base = "%s://%s%s" % (ctx.esquema, ctx.host,
                          "" if ctx.puerto in (80, 443) else ":%d" % ctx.puerto)
    r = ctx.pedir(base + "/", metodo="HUNTERBUG")
    if r.status not in (400, 405, 501, 0):
        return {"titulo": "Un metodo no estandar no es rechazado",
                "detalle": "El metodo HUNTERBUG devolvio %d en lugar de "
                           "405/501" % r.status,
                "recomendacion": "Rechazar metodos no implementados",
                "evidencia": {"status": r.status}}
    return None


@check("MTH-06", "Sin cabecera Allow en OPTIONS", MTH, "info", activo=True,
       cwe="CWE-1059", owasp="A05:2021")
def sin_allow(ctx):
    if ctx.metodos():
        return None
    base = "%s://%s%s" % (ctx.esquema, ctx.host,
                          "" if ctx.puerto in (80, 443) else ":%d" % ctx.puerto)
    r = ctx.pedir(base + "/", metodo="OPTIONS")
    if r.status and not r.cabecera("allow"):
        return {"titulo": "OPTIONS no devuelve la cabecera Allow",
                "detalle": "Dificulta saber que metodos expone el recurso",
                "recomendacion": "Responder OPTIONS con Allow",
                "evidencia": {"status": r.status}}
    return None


@check("MTH-07", "Metodos de escritura anunciados en Allow", MTH, "info",
       activo=True, cwe="CWE-650", owasp="A05:2021")
def allow_escritura(ctx):
    permitidos = ctx.metodos()
    if permitidos and any(m in permitidos for m in ("PUT", "DELETE", "PATCH")) \
            and not any(m in permitidos for m in ("PUT", "DELETE")):
        return {"titulo": "Allow declara PATCH",
                "detalle": "PATCH puede permitir modificar recursos parciales",
                "recomendacion": "Revisar si PATCH es necesario",
                "evidencia": {"allow": ", ".join(permitidos)}}
    return None


@check("MTH-08", "WebDAV anunciado", MTH, "medio", activo=True,
       cwe="CWE-650", owasp="A05:2021")
def webdav(ctx):
    permitidos = ctx.metodos()
    dav = [m for m in permitidos if m in ("PROPFIND", "MKCOL", "COPY", "MOVE",
                                          "LOCK", "UNLOCK")]
    if dav:
        return {"titulo": "WebDAV habilitado",
                "detalle": "Anuncia: %s" % ", ".join(dav),
                "recomendacion": "Deshabilitar WebDAV si no se usa",
                "evidencia": {"metodos_dav": dav}}
    return None


# ==========================================================================
# TLS y certificado (14)
# ==========================================================================

def _datos_tls(ctx):
    """Handshakes TLS y lectura del certificado. Cacheado en el contexto."""
    if getattr(ctx, "_tls_extra", None) is not None:
        return ctx._tls_extra
    info = {"soporta": {}, "cert": {}, "cifrado": "", "version": "",
            "error": ""}
    host, puerto = ctx.host, ctx.puerto or 443
    if ctx.esquema != "https":
        info["error"] = "el objetivo no usa HTTPS"
        ctx._tls_extra = info
        return info

    for etiqueta, ver in (("tls1.0", ssl.TLSVersion.TLSv1),
                          ("tls1.1", ssl.TLSVersion.TLSv1_1),
                          ("tls1.2", ssl.TLSVersion.TLSv1_2),
                          ("tls1.3", ssl.TLSVersion.TLSv1_3)):
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            c.minimum_version = ver
            c.maximum_version = ver
            with socket.create_connection((host, puerto), timeout=6) as s:
                with c.wrap_socket(s, server_hostname=host) as t:
                    info["soporta"][etiqueta] = True
                    if not info["cifrado"]:
                        info["cifrado"] = (t.cipher() or ("",))[0]
                        info["version"] = t.version()
                        info["cert"] = x509lite.analizar_cert(
                            t.getpeercert(binary_form=True))
        except Exception:
            info["soporta"][etiqueta] = False
    ctx._tls_extra = info
    return info


def _tls_falla(cid, nombre, sev, motivo, rec, condicion, cwe="CWE-326"):
    @check(cid, nombre, TLS, sev, cwe=cwe, owasp="A02:2021", solo_https=True)
    def _f(ctx):
        info = _datos_tls(ctx)
        if info.get("error"):
            return None
        d = condicion(info)
        if d:
            return {"titulo": nombre, "detalle": motivo,
                    "recomendacion": rec, "evidencia": d}
        return None
    return _f


_tls_falla("TLS-01", "TLS 1.0 aceptado", "alto",
           "TLS 1.0 esta obsoleto y tiene fallos conocidos de protocolo",
           "Deshabilitar TLS 1.0 y 1.1; dejar TLS 1.2 y 1.3",
           lambda i: {"soportado": True} if i["soporta"].get("tls1.0") else None)

_tls_falla("TLS-02", "TLS 1.1 aceptado", "medio",
           "TLS 1.1 esta obsoleto y sin soporte de los navegadores actuales",
           "Deshabilitar TLS 1.0 y 1.1; dejar TLS 1.2 y 1.3",
           lambda i: {"soportado": True} if i["soporta"].get("tls1.1") else None)

_tls_falla("TLS-03", "Sin TLS 1.3", "bajo",
           "TLS 1.3 aporta cifrado mas robusto y handshake mas simple",
           "Habilitar TLS 1.3",
           lambda i: {"soportado": False, "version_usada": i["version"]}
           if not i["soporta"].get("tls1.3") else None)

_tls_falla("TLS-04", "Solo TLS 1.2 o inferior", "info",
           "El servidor no ofrece TLS 1.3, lo que deja el cifrado en la "
           "generacion anterior",
           "Habilitar TLS 1.3",
           lambda i: {"tls13": False} if not i["soporta"].get("tls1.3") else None)

_tls_falla("TLS-05", "Certificado caducado", "alto",
           "El certificado ha superado su fecha de validez y los navegadores "
           "mostraran un error al usuario",
           "Renovar el certificado",
           lambda i: {"valido_hasta": i["cert"].get("valido_hasta")}
           if x509lite.caducado(i["cert"].get("valido_hasta", "")) else None,
           cwe="CWE-298")

_tls_falla("TLS-06", "Certificado caduca pronto", "bajo",
           "Quedan menos de 30 dias de validez",
           "Automatizar la renovacion (ACME)",
           lambda i: {"dias": x509lite.dias_para_caducar(i["cert"].get("valido_hasta", ""))}
           if (x509lite.dias_para_caducar(i["cert"].get("valido_hasta", "")) is not None
               and 0 <= x509lite.dias_para_caducar(i["cert"].get("valido_hasta", "")) < 30)
           else None, cwe="CWE-298")

_tls_falla("TLS-07", "Certificado autofirmado", "medio",
           "El certificado no lo firma una autoridad de confianza",
           "Emitir un certificado de una CA reconocida",
           lambda i: {"sujeto": i["cert"].get("sujeto"),
                      "emisor": i["cert"].get("emisor")}
           if i["cert"].get("autofirmado") else None, cwe="CWE-295")

_tls_falla("TLS-08", "Firma del certificado con SHA-1", "alto",
           "SHA-1 esta roto para firmas de certificado",
           "Reemitir el certificado con SHA-256 o superior",
           lambda i: {"firma": i["cert"].get("firma")}
           if i["cert"].get("sha1") else None, cwe="CWE-327")

_tls_falla("TLS-09", "Clave RSA menor de 2048 bits", "alto",
           "Una clave corta es factorizable con recursos asequibles",
           "Usar RSA de 2048 bits o mas, o ECDSA P-256",
           lambda i: {"clave": i["cert"].get("clave"),
                      "bits": i["cert"].get("bits_clave")}
           if (i["cert"].get("clave") == "RSA"
               and 0 < i["cert"].get("bits_clave", 0) < 2048) else None,
           cwe="CWE-326")

_tls_falla("TLS-10", "Cifrado sin forward secrecy", "medio",
           "Sin ECDHE, la clave de sesion puede recuperarse si se filtra la "
           "clave privada del servidor",
           "Preferir suites con ECDHE",
           lambda i: {"cifrado": i["cifrado"]}
           if i["cifrado"] and "ecdhe" not in i["cifrado"].lower()
           and "tls_aes" not in i["cifrado"].lower() else None, cwe="CWE-326")

_tls_falla("TLS-11", "Cifrado debil (RC4/3DES/CBC)", "alto",
           "El cifrado negociado usa primitivas obsoletas",
           "Deshabilitar RC4, 3DES y los modos CBC",
           lambda i: {"cifrado": i["cifrado"]}
           if i["cifrado"] and any(x in i["cifrado"].upper()
                                   for x in ("RC4", "3DES", "_CBC_")) else None,
           cwe="CWE-327")

_tls_falla("TLS-12", "Sin datos del certificado", "info",
           "No se pudo leer el certificado presentado por el servidor",
           "Comprobar que el handshake TLS es correcto",
           lambda i: {"error": "certificado no legible"}
           if not i["cert"].get("valido_hasta") else None, cwe="CWE-295")

_tls_falla("TLS-13", "Emisor desconocido", "info",
           "No se pudo identificar la autoridad emisora del certificado",
           "Revisar la cadena de certificacion",
           lambda i: {"emisor": i["cert"].get("emisor")}
           if not i["cert"].get("emisor") else None, cwe="CWE-295")

_tls_falla("TLS-14", "Sin sujeto legible en el certificado", "info",
           "No se pudo extraer el nombre del titular",
           "Revisar el certificado",
           lambda i: {"sujeto": i["cert"].get("sujeto")}
           if not i["cert"].get("sujeto") else None, cwe="CWE-295")


# ==========================================================================
# Calidad de la respuesta (12)
# ==========================================================================

@check("RSP-01", "Respuesta lenta", RSP, "info",
       cwe="CWE-1059", owasp="A04:2021")
def respuesta_lenta(ctx):
    if ctx.r.tiempo > 3.0:
        return {"titulo": "Tiempo de respuesta alto (%.2f s)" % ctx.r.tiempo,
                "detalle": "Respuestas lentas dificultan la deteccion de "
                           "inyecciones basadas en tiempo",
                "recomendacion": "Revisar el rendimiento del backend",
                "evidencia": {"segundos": round(ctx.r.tiempo, 3)}}
    return None


@check("RSP-02", "Sin compresion", RSP, "info",
       cwe="CWE-1059", owasp="A04:2021")
def sin_compresion(ctx):
    if not ctx.tiene("content-encoding") and ctx.r.cuerpo_bytes > 2048:
        return {"titulo": "Respuesta grande sin comprimir",
                "detalle": "El cuerpo tiene %d bytes y no se comprime"
                           % ctx.r.cuerpo_bytes,
                "recomendacion": "Habilitar gzip o brotli",
                "evidencia": {"bytes": ctx.r.cuerpo_bytes}}
    return None


@check("RSP-03", "Compresion con datos sensibles", RSP, "bajo",
       cwe="CWE-310", owasp="A02:2021")
def compresion_sensible(ctx):
    if ctx.tiene("content-encoding") and \
            any(x in ctx.cuerpo_min for x in ("token", "password", "csrf")):
        return {"titulo": "Compresion activa con contenido sensible",
                "detalle": "La compresion junto a secretos reflejados es la "
                           "base del ataque BREACH",
                "recomendacion": "Desactivar la compresion en respuestas con "
                                 "secretos o usar cabeceras aleatorias",
                "evidencia": {"encoding": ctx.cabecera("content-encoding")}}
    return None


@check("RSP-04", "Sin cabecera Content-Type", RSP, "medio",
       cwe="CWE-436", owasp="A05:2021")
def sin_content_type(ctx):
    if not ctx.tiene("content-type"):
        return {"titulo": "Respuesta sin Content-Type",
                "detalle": "El navegador debe adivinar el tipo del contenido",
                "recomendacion": "Declarar siempre Content-Type",
                "evidencia": {}}
    return None


@check("RSP-05", "Sin charset declarado", RSP, "info",
       cwe="CWE-436", owasp="A05:2021")
def sin_charset(ctx):
    ct = ctx.cabecera("content-type")
    if ct and "text/" in ct and "charset" not in ct.lower():
        return {"titulo": "Content-Type sin charset",
                "detalle": "Sin charset el navegador puede interpretar los "
                           "bytes con otra codificacion",
                "recomendacion": "Anadir charset=utf-8",
                "evidencia": {"content_type": ct}}
    return None


@check("RSP-06", "Sin cabecera Date", RSP, "info",
       cwe="CWE-1059", owasp="A05:2021")
def sin_date(ctx):
    if not ctx.tiene("date"):
        return {"titulo": "Respuesta sin cabecera Date",
                "detalle": "Su ausencia puede indicar un proxy o servidor mal "
                           "configurado",
                "recomendacion": "Emitir la cabecera Date",
                "evidencia": {}}
    return None


@check("RSP-07", "Sin Content-Length ni chunked", RSP, "info",
       cwe="CWE-1059", owasp="A05:2021")
def sin_longitud(ctx):
    if not ctx.tiene("content-length") and \
            "chunked" not in ctx.cabecera("transfer-encoding").lower():
        return {"titulo": "Sin Content-Length ni Transfer-Encoding",
                "detalle": "El cliente debe leer hasta el cierre de conexion",
                "recomendacion": "Declarar la longitud o usar chunked",
                "evidencia": {}}
    return None


@check("RSP-08", "HTTP/1.0 soportado", RSP, "info",
       cwe="CWE-1059", owasp="A05:2021")
def http10(ctx):
    if "HTTP/1.0" in ctx.r.version:
        return {"titulo": "El servidor responde con HTTP/1.0",
                "detalle": "Protocolo antiguo sin keep-alive ni pipelining",
                "recomendacion": "Servir HTTP/1.1 o superior",
                "evidencia": {"version": ctx.r.version}}
    return None


@check("RSP-09", "Cabeceras duplicadas", RSP, "bajo",
       cwe="CWE-436", owasp="A05:2021")
def cabeceras_duplicadas(ctx):
    vistos, dup = set(), []
    for k, v in ctx.r.cabeceras:
        kl = k.lower()
        if kl in vistos and kl not in ("set-cookie", "cache-control"):
            dup.append(k)
        vistos.add(kl)
    if dup:
        return {"titulo": "Cabeceras duplicadas en la respuesta",
                "detalle": "Duplicadas: %s. Pueden provocar comportamiento "
                           "ambiguo en proxies" % ", ".join(sorted(set(dup))),
                "recomendacion": "Unificar cada cabecera en un solo valor",
                "evidencia": {"duplicadas": sorted(set(dup))}}
    return None


@check("RSP-10", "Redireccion a otro dominio", RSP, "bajo",
       cwe="CWE-601", owasp="A01:2021")
def redireccion_externa(ctx):
    if ctx.r.status in (301, 302, 303, 307, 308):
        destino = ctx.cabecera("location")
        if destino and ctx.host not in destino and destino.startswith("http"):
            return {"titulo": "La redireccion apunta a otro dominio",
                    "detalle": "Destino: %s" % destino[:200],
                    "recomendacion": "Revisar si la redireccion externa es "
                                     "intencionada",
                    "evidencia": {"location": destino[:200],
                                  "status": ctx.r.status}}
    return None


@check("RSP-11", "Redireccion en cadena larga", RSP, "info",
       cwe="CWE-601", owasp="A01:2021")
def cadena_redirecciones(ctx):
    n, url = 0, ctx.url
    while n < 6:
        r = net.peticion_http(url, timeout=8)
        if r.status in (301, 302, 303, 307, 308) and r.cabecera("location"):
            import urllib.parse as up
            url = up.urljoin(url, r.cabecera("location"))
            n += 1
        else:
            break
    if n >= 4:
        return {"titulo": "Cadena de %d redirecciones" % n,
                "detalle": "Las cadenas largas retrasan la carga y pueden "
                           "ocultar destinos",
                "recomendacion": "Reducir los saltos a uno",
                "evidencia": {"saltos": n, "destino_final": url[:200]}}
    return None


@check("RSP-12", "Cuerpo de error con detalles internos", RSP, "medio",
       cwe="CWE-209", owasp="A05:2021")
def error_verboso(ctx):
    if ctx.r.status >= 500:
        if RE_STACK.search(ctx.cuerpo) or RE_BD_ERROR.search(ctx.cuerpo):
            return {"titulo": "Error %d con traza o detalle de base de datos"
                              % ctx.r.status,
                    "detalle": "El servidor expone informacion interna en la "
                               "pagina de error",
                    "recomendacion": "Pagina de error generica y registro "
                                     "interno del detalle",
                    "evidencia": {"status": ctx.r.status,
                                  "extracto": ctx.cuerpo[:300]}}
    return None
