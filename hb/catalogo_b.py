"""HunterBug - catalogo de chequeos: contenido, fuga de informacion, rutas
expuestas, tecnologia y pruebas de inyeccion/logica en parametros.

Los chequeos de parametros son de volumen bajo y no destructivos: no hay
ataques basados en tiempo, ni fuerza bruta, ni escritura de recursos reales.
"""

from __future__ import annotations

import random
import re
import string
import time
import urllib.parse

from . import net, vulns
from .checks import (check, RE_IP_PRIVADA, RE_EMAIL, RE_RUTA_ABS, RE_SECRETO,
                     RE_AWS, RE_JWT, RE_STACK, RE_BD_ERROR, RE_COMENTARIO,
                     RE_MIXED, RE_FORM, RE_INPUT_PWD, RE_IFRAME, RE_BLANK,
                     RE_SCRIPT_EXT, RE_MAP, RE_BUCKET, FIRMAS_TECNOLOGIA)

CON = "contenido"
FUG = "fugas"
RUT = "rutas"
TEC = "tecnologia"
PAR = "parametros"


def _marca(n=6):
    return "hb" + "".join(random.choices(string.ascii_lowercase + string.digits,
                                         k=n))


# ==========================================================================
# Contenido y HTML (28)
# ==========================================================================

@check("CON-01", "Comentarios HTML con informacion sensible", CON, "bajo",
       cwe="CWE-615", owasp="A05:2021")
def comentarios(ctx):
    sospechosos = []
    for m in RE_COMENTARIO.finditer(ctx.cuerpo):
        texto = m.group(1)
        if re.search(r"(todo|fixme|hack|password|passwd|api[_ ]?key|secret|"
                     r"token|usuario|admin|debug|borrar)", texto, re.I):
            sospechosos.append(re.sub(r"\s+", " ", texto).strip()[:200])
    if sospechosos:
        return {"titulo": "%d comentario(s) HTML con informacion sensible"
                          % len(sospechosos),
                "detalle": "Los comentarios viajan al cliente y revelan notas "
                           "internas, credenciales o rutas",
                "recomendacion": "Eliminar los comentarios en produccion",
                "evidencia": {"comentarios": sospechosos[:5]}}
    return None


@check("CON-02", "Source maps expuestos", CON, "medio",
       cwe="CWE-540", owasp="A05:2021")
def source_maps(ctx):
    refs = RE_MAP.findall(ctx.cuerpo)
    if refs:
        return {"titulo": "El codigo referencia source maps",
                "detalle": "Los ficheros .map permiten reconstruir el codigo "
                           "fuente original",
                "recomendacion": "No publicar los .map en produccion",
                "evidencia": {"referencias": refs[:5]}}
    return None


@check("CON-03", "Secretos en el codigo del cliente", CON, "alto",
       cwe="CWE-798", owasp="A05:2021")
def secretos(ctx):
    encontrados = []
    for m in RE_SECRETO.finditer(ctx.cuerpo):
        encontrados.append("%s = %s..." % (m.group(0)[:40], m.group(1)[:8]))
    for m in RE_AWS.finditer(ctx.cuerpo):
        encontrados.append("AWS key: " + m.group(0)[:12] + "...")
    for m in RE_JWT.finditer(ctx.cuerpo):
        encontrados.append("JWT: " + m.group(0)[:24] + "...")
    if encontrados:
        return {"titulo": "%d posible(s) secreto(s) en el cliente"
                          % len(encontrados),
                "detalle": "Claves o tokens embebidos en el HTML o el JS son "
                           "visibles para cualquiera",
                "recomendacion": "Mover los secretos al servidor y rotarlos",
                "evidencia": {"hallazgos": encontrados[:5]}}
    return None


@check("CON-04", "Direcciones de correo expuestas", CON, "info",
       cwe="CWE-200", owasp="A01:2021")
def correos(ctx):
    vistos = sorted(set(RE_EMAIL.findall(ctx.cuerpo)))
    if vistos:
        return {"titulo": "%d direccion(es) de correo en el cuerpo" % len(vistos),
                "detalle": "Facilitan campanas de phishing y enumeracion",
                "recomendacion": "Ofuscar o eliminar los correos publicos",
                "evidencia": {"correos": vistos[:6]}}
    return None


@check("CON-05", "Direcciones IP internas expuestas", CON, "medio",
       cwe="CWE-200", owasp="A01:2021")
def ips_internas(ctx):
    vistos = sorted(set(RE_IP_PRIVADA.findall(ctx.cuerpo)))
    if vistos:
        return {"titulo": "%d direccion(es) IP privada(s) en el cuerpo"
                          % len(vistos),
                "detalle": "Revelan la topologia interna de la red",
                "recomendacion": "Eliminar las referencias a la red interna",
                "evidencia": {"ips": vistos[:6]}}
    return None


@check("CON-06", "Rutas absolutas del servidor", CON, "medio",
       cwe="CWE-200", owasp="A05:2021")
def rutas_absolutas(ctx):
    vistos = sorted(set(RE_RUTA_ABS.findall(ctx.cuerpo)))
    if vistos:
        return {"titulo": "Rutas absolutas del sistema en el cuerpo",
                "detalle": "Revelan la estructura de directorios del servidor",
                "recomendacion": "Usar rutas relativas y errores genericos",
                "evidencia": {"rutas": vistos[:5]}}
    return None


@check("CON-07", "Contenido mixto (http:// en https)", CON, "medio",
       cwe="CWE-311", owasp="A02:2021")
def mixto(ctx):
    if ctx.esquema != "https":
        return None
    vistos = RE_MIXED.findall(ctx.cuerpo)
    if vistos:
        return {"titulo": "%d recurso(s) cargado(s) por HTTP en pagina HTTPS"
                          % len(vistos),
                "detalle": "El contenido mixto puede ser interceptado y "
                           "modificado",
                "recomendacion": "Servir todos los recursos por HTTPS",
                "evidencia": {"recursos": vistos[:5]}}
    return None


@check("CON-08", "Scripts externos sin integrity (SRI)", CON, "bajo",
       cwe="CWE-353", owasp="A08:2021")
def sin_sri(ctx):
    externos = []
    for m in re.finditer(r"<script[^>]*>", ctx.cuerpo, re.I):
        etiqueta = m.group(0)
        if "src=" in etiqueta.lower() and "integrity=" not in etiqueta.lower():
            externos.append(etiqueta[:150])
    if externos:
        return {"titulo": "%d script(s) sin Subresource Integrity" % len(externos),
                "detalle": "Si el CDN se compromete, el script se ejecuta sin "
                           "que nadie lo detecte",
                "recomendacion": "Anadir integrity y crossorigin a los scripts "
                                 "de terceros",
                "evidencia": {"scripts": externos[:4]}}
    return None


@check("CON-09", "Formulario envia a un dominio externo", CON, "medio",
       cwe="CWE-346", owasp="A01:2021")
def form_externo(ctx):
    externos = []
    for m in re.finditer(r"<form[^>]*action\s*=\s*[\"']([^\"']+)[\"']",
                         ctx.cuerpo, re.I):
        accion = m.group(1)
        if accion.startswith("http") and ctx.host not in accion:
            externos.append(accion[:150])
    if externos:
        return {"titulo": "Formulario que envia datos a otro dominio",
                "detalle": "Los datos del usuario salen del sitio",
                "recomendacion": "Enviar los formularios al propio dominio",
                "evidencia": {"acciones": externos[:5]}}
    return None


@check("CON-10", "Formulario con contrasena por GET", CON, "alto",
       cwe="CWE-598", owasp="A04:2021")
def pwd_get(ctx):
    for m in RE_FORM.finditer(ctx.cuerpo):
        bloque = m.group(0)
        if RE_INPUT_PWD.search(bloque) and re.search(r"method\s*=\s*[\"']?get",
                                                     bloque, re.I):
            return {"titulo": "Formulario de contrasena con method=GET",
                    "detalle": "La contrasena queda en la URL, en el historial "
                               "y en los registros del servidor",
                    "recomendacion": "Usar POST sobre HTTPS",
                    "evidencia": {"formulario": re.sub(r"\s+", " ", bloque)[:250]}}
    return None


@check("CON-11", "Campo de contrasena sin autocomplete off", CON, "info",
       cwe="CWE-522", owasp="A07:2021")
def pwd_autocomplete(ctx):
    for m in re.finditer(r"<input[^>]*type\s*=\s*[\"']?password[^>]*>",
                         ctx.cuerpo, re.I):
        etiqueta = m.group(0)
        if "autocomplete" not in etiqueta.lower():
            return {"titulo": "Campo de contrasena sin autocomplete",
                    "detalle": "El navegador puede almacenar la contrasena en "
                               "equipos compartidos",
                    "recomendacion": "autocomplete=\"current-password\" o \"off\"",
                    "evidencia": {"input": etiqueta[:200]}}
    return None


@check("CON-12", "Formulario POST sin token CSRF", CON, "medio",
       cwe="CWE-352", owasp="A01:2021")
def sin_csrf(ctx):
    sospechosos = []
    for m in RE_FORM.finditer(ctx.cuerpo):
        bloque = m.group(0)
        if not re.search(r"method\s*=\s*[\"']?post", bloque, re.I):
            continue
        if re.search(r"(csrf|_token|authenticity_token|nonce)", bloque, re.I):
            continue
        sospechosos.append(re.sub(r"\s+", " ", bloque)[:200])
    if sospechosos:
        return {"titulo": "%d formulario(s) POST sin token anti-CSRF"
                          % len(sospechosos),
                "detalle": "Sin token, otra web puede enviar el formulario en "
                           "nombre del usuario",
                "recomendacion": "Token por sesion y validacion SameSite",
                "evidencia": {"formularios": sospechosos[:4]}}
    return None


@check("CON-13", "Enlaces target=_blank sin noopener", CON, "bajo",
       cwe="CWE-1022", owasp="A05:2021")
def sin_noopener(ctx):
    malos = [m.group(0)[:150] for m in RE_BLANK.finditer(ctx.cuerpo)
             if "noopener" not in m.group(0).lower()
             and "noreferrer" not in m.group(0).lower()]
    if malos:
        return {"titulo": "%d enlace(s) _blank sin rel=noopener" % len(malos),
                "detalle": "La pagina destino puede manipular la ventana de "
                           "origen mediante window.opener",
                "recomendacion": "Anadir rel=\"noopener noreferrer\"",
                "evidencia": {"enlaces": malos[:4]}}
    return None


@check("CON-14", "iframe sin sandbox", CON, "info",
       cwe="CWE-1021", owasp="A05:2021")
def iframe_sandbox(ctx):
    malos = [m.group(0)[:150] for m in RE_IFRAME.finditer(ctx.cuerpo)
             if "sandbox" not in m.group(0).lower()]
    if malos:
        return {"titulo": "%d iframe(s) sin atributo sandbox" % len(malos),
                "detalle": "El contenido embebido se ejecuta con los permisos "
                           "de la pagina",
                "recomendacion": "Anadir sandbox a los iframes de terceros",
                "evidencia": {"iframes": malos[:4]}}
    return None


@check("CON-15", "Meta generator con version", CON, "info",
       cwe="CWE-200", owasp="A05:2021")
def meta_generator(ctx):
    m = re.search(r"<meta[^>]*name\s*=\s*[\"']generator[\"'][^>]*>",
                  ctx.cuerpo, re.I)
    if m:
        return {"titulo": "Meta generator revela el CMS y su version",
                "detalle": m.group(0)[:200],
                "recomendacion": "Eliminar la etiqueta generator",
                "evidencia": {"meta": m.group(0)[:200]}}
    return None


@check("CON-16", "Modo depuracion visible", CON, "alto",
       cwe="CWE-489", owasp="A05:2021")
def debug_visible(ctx):
    patrones = [r"debug\s*=\s*true", r"app\.debug", r"DJANGO_SETTINGS_MODULE",
                r"whoops", r"laravel.*debug", r"werkzeug debugger",
                r"traceback \(most recent call last\)"]
    for p in patrones:
        m = re.search(p, ctx.cuerpo, re.I)
        if m:
            return {"titulo": "Indicio de modo depuracion activo",
                    "detalle": "Coincide con '%s': expone informacion interna "
                               "y a veces permite ejecucion" % m.group(0)[:60],
                    "recomendacion": "Desactivar el modo debug en produccion",
                    "evidencia": {"coincidencia": m.group(0)[:120]}}
    return None


@check("CON-17", "Traza de pila en la respuesta", CON, "alto",
       cwe="CWE-209", owasp="A05:2021")
def traza(ctx):
    m = RE_STACK.search(ctx.cuerpo)
    if m:
        return {"titulo": "La respuesta contiene una traza de pila",
                "detalle": "Revela rutas, versiones y estructura interna",
                "recomendacion": "Capturar las excepciones y devolver un error "
                                 "generico",
                "evidencia": {"extracto": ctx.cuerpo[max(0, m.start() - 60):
                                                     m.end() + 120][:300]}}
    return None


@check("CON-18", "Error de base de datos visible", CON, "alto",
       cwe="CWE-209", owasp="A05:2021")
def error_bd(ctx):
    m = RE_BD_ERROR.search(ctx.cuerpo)
    if m:
        return {"titulo": "La respuesta expone un error de base de datos",
                "detalle": "Confirma el motor y a menudo la consulta",
                "recomendacion": "Errores genericos al cliente y registro "
                                 "interno",
                "evidencia": {"extracto": ctx.cuerpo[max(0, m.start() - 60):
                                                     m.end() + 120][:300]}}
    return None


@check("CON-19", "Referencias a almacenamiento en la nube", CON, "info",
       cwe="CWE-200", owasp="A05:2021")
def buckets(ctx):
    vistos = sorted(set(m.group(0) for m in RE_BUCKET.finditer(ctx.cuerpo)))
    if vistos:
        return {"titulo": "%d referencia(s) a almacenamiento externo"
                          % len(vistos),
                "detalle": "Los buckets mal configurados son una fuga de datos "
                           "habitual",
                "recomendacion": "Revisar las politicas del bucket",
                "evidencia": {"buckets": vistos[:5]}}
    return None


@check("CON-20", "Endpoints de API listados en el HTML", CON, "info",
       cwe="CWE-200", owasp="A01:2021")
def endpoints_html(ctx):
    vistos = sorted(set(re.findall(r"[\"'](/api/[A-Za-z0-9_\-/{}\.]+)[\"']",
                                   ctx.cuerpo)))
    if vistos:
        return {"titulo": "%d endpoint(s) de API referenciados" % len(vistos),
                "detalle": "Amplia la superficie de ataque conocida",
                "recomendacion": "Revisar que cada endpoint comprueba "
                                 "autorizacion",
                "evidencia": {"endpoints": vistos[:8]}}
    return None


@check("CON-21", "Rutas de administracion enlazadas", CON, "info",
       cwe="CWE-200", owasp="A01:2021")
def rutas_admin(ctx):
    vistos = sorted(set(re.findall(
        r"[\"'](/[A-Za-z0-9_\-/]*(?:admin|manage|dashboard|panel|backoffice)"
        r"[A-Za-z0-9_\-/]*)[\"']", ctx.cuerpo, re.I)))
    if vistos:
        return {"titulo": "El HTML enlaza paneles de administracion",
                "detalle": "Facilita localizar la zona privilegiada",
                "recomendacion": "Restringir el acceso por red o autenticacion "
                                 "fuerte",
                "evidencia": {"rutas": vistos[:6]}}
    return None


@check("CON-22", "Token o credencial en la URL", CON, "medio",
       cwe="CWE-598", owasp="A04:2021")
def token_en_url(ctx):
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(ctx.url).query)
    sensibles = [k for k in q if re.search(
        r"(token|key|secret|pass|auth|session|jwt|api)", k, re.I)]
    if sensibles:
        return {"titulo": "Parametros sensibles en la URL",
                "detalle": "Claves: %s. Las URLs quedan en historial, "
                           "referrer y registros" % ", ".join(sensibles),
                "recomendacion": "Enviar credenciales en cabeceras o cuerpo",
                "evidencia": {"parametros": sensibles}}
    return None


@check("CON-23", "Version del producto en el cuerpo", CON, "info",
       cwe="CWE-200", owasp="A05:2021")
def version_cuerpo(ctx):
    m = re.search(r"(?:version|v)\s*[:=]?\s*(\d+\.\d+(?:\.\d+)?)",
                  ctx.cuerpo[:8000], re.I)
    if m:
        return {"titulo": "El cuerpo declara un numero de version",
                "detalle": "Version visible: %s" % m.group(1),
                "recomendacion": "Ocultar las versiones de los componentes",
                "evidencia": {"version": m.group(1)}}
    return None


@check("CON-24", "Copyright antiguo", CON, "info",
       cwe="CWE-1059", owasp="A05:2021")
def copyright_antiguo(ctx):
    anios = [int(a) for a in re.findall(r"(?:©|&copy;|copyright)[^0-9]{0,20}"
                                        r"((?:19|20)\d{2})", ctx.cuerpo, re.I)]
    actual = time.localtime().tm_year
    if anios and max(anios) < actual - 2:
        return {"titulo": "Copyright de %d (hace %d anos)"
                          % (max(anios), actual - max(anios)),
                "detalle": "Suele indicar un sitio sin mantenimiento, con "
                           "componentes antiguos",
                "recomendacion": "Actualizar y revisar dependencias",
                "evidencia": {"anios": anios[:5]}}
    return None


@check("CON-25", "Sin declaracion de viewport", CON, "info",
       cwe="CWE-1059", owasp="A05:2021")
def sin_viewport(ctx):
    cabeza = ctx.cuerpo_min[:3000]
    if "<head" in cabeza and "viewport" not in cabeza:
        return {"titulo": "El documento no declara viewport",
                "detalle": "Afecta a la usabilidad movil y suele acompanar a "
                           "sitios antiguos",
                "recomendacion": "Anadir meta viewport",
                "evidencia": {"cabecera_html": cabeza[:300]}}
    return None


@check("CON-26", "Sin meta charset", CON, "info",
       cwe="CWE-436", owasp="A05:2021")
def sin_meta_charset(ctx):
    cabeza = ctx.cuerpo_min[:3000]
    if "<head" in cabeza and not re.search(r"<meta[^>]*charset", cabeza):
        return {"titulo": "El documento no declara charset en el HTML",
                "detalle": "Puede provocar interpretacion incorrecta de los "
                           "bytes recibidos",
                "recomendacion": "Anadir <meta charset=\"utf-8\">",
                "evidencia": {"cabecera_html": cabeza[:300],
                              "content_type": ctx.cabecera("content-type")}}
    return None


@check("CON-27", "Pagina de error por defecto del servidor", CON, "info",
       cwe="CWE-200", owasp="A05:2021")
def error_servidor(ctx):
    firmas = ("apache server at", "nginx", "microsoft-iis", "iis 7",
              "default web site page", "it works!")
    for f in firmas:
        if f in ctx.cuerpo_min and ctx.r.status >= 400:
            return {"titulo": "Pagina de error por defecto del servidor",
                    "detalle": "Revela el producto y a veces la version",
                    "recomendacion": "Paginas de error personalizadas",
                    "evidencia": {"status": ctx.r.status,
                                  "firma": f,
                                  "extracto": ctx.cuerpo[:200]}}
    return None


@check("CON-28", "Tecnologias declaradas en el cuerpo", CON, "info",
       cwe="CWE-200", owasp="A05:2021")
def tecnologias_cuerpo(ctx):
    encontradas = [n for n, firmas in FIRMAS_TECNOLOGIA
                   if any(f in ctx.cuerpo_min for f in firmas)]
    if len(encontradas) >= 3:
        return {"titulo": "%d tecnologias identificadas por el contenido"
                          % len(encontradas),
                "detalle": "Detectadas: %s" % ", ".join(encontradas[:8]),
                "recomendacion": "Minimizar las huellas del stack",
                "evidencia": {"tecnologias": encontradas}}
    return None


# ==========================================================================
# Fuga de informacion y rutas expuestas (22)
# ==========================================================================

def _ruta_expuesta(cid, ruta, nombre, sev, marca, motivo, rec, cwe="CWE-538"):
    @check(cid, nombre, RUT, sev, activo=True, cwe=cwe, owasp="A01:2021")
    def _f(ctx):
        d = ctx.ruta(ruta)
        if d["status"] in (200, 201) and d["bytes"] > 0:
            cuerpo = (d["cuerpo"] or "").lower()
            if marca and marca.lower() not in cuerpo and d["bytes"] < 40:
                return None
            return {"titulo": nombre + " accesible",
                    "detalle": motivo,
                    "recomendacion": rec,
                    "url": ctx.url.split("//")[0] + "//" + ctx.host + ruta,
                    "evidencia": {"ruta": ruta, "status": d["status"],
                                  "bytes": d["bytes"],
                                  "extracto": (d["cuerpo"] or "")[:300]}}
        return None
    return _f


_ruta_expuesta("FUG-01", "/.git/config", "Repositorio Git expuesto", "critico",
               "[core]", "Permite reconstruir el codigo fuente completo",
               "Bloquear el acceso a .git desde el servidor web",
               cwe="CWE-538")

_ruta_expuesta("FUG-02", "/.env", "Fichero .env expuesto", "critico", "",
               "Contiene credenciales, claves y configuracion de la aplicacion",
               "Sacar el .env del directorio publico", cwe="CWE-538")

_ruta_expuesta("FUG-03", "/.svn/entries", "Metadatos SVN expuestos", "alto",
               "", "Revela el historial de versiones y el codigo fuente",
               "Bloquear el acceso a .svn", cwe="CWE-538")

_ruta_expuesta("FUG-04", "/.DS_Store", "Fichero .DS_Store expuesto", "bajo",
               "", "Revela nombres de ficheros y estructura de directorios",
               "Bloquear el acceso a .DS_Store", cwe="CWE-538")

_ruta_expuesta("FUG-05", "/server-status", "Estado del servidor expuesto",
               "medio", "apache server status",
               "Revela peticiones en curso, clientes y carga del servidor",
               "Restringir /server-status a la red local", cwe="CWE-200")

_ruta_expuesta("FUG-06", "/phpinfo.php", "phpinfo() expuesto", "alto",
               "php version", "Expone la configuracion completa de PHP",
               "Eliminar phpinfo() de produccion", cwe="CWE-200")

_ruta_expuesta("FUG-07", "/actuator", "Spring Boot Actuator expuesto", "alto",
               "", "Los endpoints de gestion pueden filtrar configuracion y "
                   "permitir cambios",
               "Proteger /actuator con autenticacion", cwe="CWE-200")

_ruta_expuesta("FUG-08", "/actuator/env", "Actuator /env expuesto", "critico",
               "", "Muestra variables de entorno, incluidas credenciales",
               "Deshabilitar o proteger el endpoint env", cwe="CWE-200")

_ruta_expuesta("FUG-09", "/debug", "Endpoint de depuracion expuesto", "alto",
               "", "Suele permitir ejecutar codigo o volcar el estado interno",
               "Eliminar los endpoints de depuracion", cwe="CWE-489")

_ruta_expuesta("FUG-10", "/console", "Consola expuesta", "critico", "",
               "Una consola interactiva expuesta permite ejecucion de codigo",
               "Eliminar o proteger la consola", cwe="CWE-489")

_ruta_expuesta("FUG-11", "/swagger-ui.html", "Documentacion de API expuesta",
               "medio", "swagger", "Describe todos los endpoints y sus "
                                   "esquemas, incluidos los internos",
               "Proteger la documentacion en produccion", cwe="CWE-200")

_ruta_expuesta("FUG-12", "/api-docs", "Especificacion de API expuesta", "medio",
               "", "Facilita la enumeracion completa de la API",
               "Restringir el acceso a la especificacion", cwe="CWE-200")


@check("FUG-13", "GraphQL con introspeccion habilitada", FUG, "medio",
       activo=True, cwe="CWE-200", owasp="A01:2021")
def graphql_introspection(ctx):
    d = ctx.ruta("/graphql")
    if d["status"] not in (200, 400):
        return None
    base = "%s://%s%s" % (ctx.esquema, ctx.host,
                          "" if ctx.puerto in (80, 443) else ":%d" % ctx.puerto)
    consulta = '{"query":"{__schema{types{name}}}"}'
    r = ctx.pedir(base + "/graphql", metodo="POST",
                  cabeceras={"Content-Type": "application/json"},
                  cuerpo=consulta)
    if r.status == 200 and "__schema" in (r.cuerpo or ""):
        return {"titulo": "GraphQL permite introspeccion",
                "detalle": "El esquema completo queda expuesto, incluidos "
                           "campos internos y mutaciones",
                "recomendacion": "Deshabilitar la introspeccion en produccion",
                "evidencia": {"extracto": (r.cuerpo or "")[:300]}}
    return None


@check("FUG-14", "robots.txt revela rutas sensibles", FUG, "bajo",
       activo=True, cwe="CWE-200", owasp="A01:2021")
def robots(ctx):
    d = ctx.ruta("/robots.txt")
    if d["status"] != 200 or not d["cuerpo"]:
        return None
    rutas = re.findall(r"(?:Disallow|Allow)\s*:\s*(\S+)", d["cuerpo"], re.I)
    sensibles = [r for r in rutas
                 if re.search(r"(admin|backup|config|private|internal|test|"
                              r"staging|dev|db|sql|secret)", r, re.I)]
    if sensibles:
        return {"titulo": "robots.txt expone rutas internas",
                "detalle": "Rutas listadas: %s" % ", ".join(sensibles[:8]),
                "recomendacion": "No listar rutas privadas en robots.txt",
                "evidencia": {"rutas": sensibles[:8]}}
    return None


@check("FUG-15", "Sin security.txt", FUG, "info", activo=True,
       cwe="CWE-1059", owasp="A05:2021")
def sin_security_txt(ctx):
    d = ctx.ruta("/.well-known/security.txt")
    if d["status"] not in (200, 201):
        return {"titulo": "No publica /.well-known/security.txt",
                "detalle": "Sin canal declarado de reporte de vulnerabilidades",
                "recomendacion": "Publicar security.txt con un contacto de "
                                 "seguridad",
                "evidencia": {"status": d["status"]}}
    return None


@check("FUG-16", "sitemap.xml accesible", FUG, "info", activo=True,
       cwe="CWE-200", owasp="A01:2021")
def sitemap(ctx):
    d = ctx.ruta("/sitemap.xml")
    if d["status"] == 200 and d["bytes"] > 0:
        return {"titulo": "sitemap.xml accesible",
                "detalle": "Facilita el inventario de URLs del sitio",
                "recomendacion": "Revisar si el sitemap debe ser publico",
                "evidencia": {"bytes": d["bytes"]}}
    return None


@check("FUG-17", "Backup comprimido accesible", FUG, "critico", activo=True,
       cwe="CWE-530", owasp="A05:2021")
def backup(ctx):
    for ruta in ("/backup.zip", "/backup.tar.gz", "/www.zip", "/site.zip",
                 "/db.sql"):
        d = ctx.ruta(ruta)
        if d["status"] == 200 and d["bytes"] > 100:
            return {"titulo": "Copia de seguridad accesible (%s)" % ruta,
                    "detalle": "Una copia descargable entrega el codigo o la "
                               "base de datos completa",
                    "recomendacion": "Retirar las copias del directorio web",
                    "evidencia": {"ruta": ruta, "bytes": d["bytes"]}}
    return None


@check("FUG-18", "Listado de directorios habilitado", FUG, "medio",
       activo=True, cwe="CWE-548", owasp="A05:2021")
def listado(ctx):
    if re.search(r"<title>\s*index of /", ctx.cuerpo_min) or \
            re.search(r"<h1>\s*index of /", ctx.cuerpo_min):
        return {"titulo": "Listado de directorios habilitado",
                "detalle": "El servidor muestra el contenido de los directorios",
                "recomendacion": "Deshabilitar autoindex / directory browsing",
                "evidencia": {"extracto": ctx.cuerpo[:200]}}
    return None


@check("FUG-19", "Panel de administracion conocido", FUG, "info",
       activo=True, cwe="CWE-200", owasp="A01:2021")
def panel_admin(ctx):
    for ruta in ("/admin/", "/wp-login.php", "/administrator/"):
        d = ctx.ruta(ruta)
        if d["status"] in (200, 302) and d["bytes"] > 200:
            return {"titulo": "Panel de administracion accesible (%s)" % ruta,
                    "detalle": "Expone la interfaz de gestion del CMS",
                    "recomendacion": "Restringir por IP o autenticacion "
                                     "adicional",
                    "evidencia": {"ruta": ruta, "status": d["status"]}}
    return None


@check("FUG-20", "Fichero de entorno alternativo", FUG, "alto", activo=True,
       cwe="CWE-538", owasp="A05:2021")
def env_alternativo(ctx):
    for ruta in ("/.env.local", "/.env.production", "/config.php.bak",
                 "/wp-config.php.bak", "/.htpasswd"):
        d = ctx.ruta(ruta)
        if d["status"] == 200 and d["bytes"] > 10:
            return {"titulo": "Fichero sensible accesible (%s)" % ruta,
                    "detalle": "Suele contener credenciales o hashes",
                    "recomendacion": "Eliminar copias y ficheros de "
                                     "configuracion del directorio publico",
                    "evidencia": {"ruta": ruta, "bytes": d["bytes"]}}
    return None


@check("FUG-21", "Metodos de depuracion de framework", FUG, "info",
       activo=True, cwe="CWE-489", owasp="A05:2021")
def framework_debug(ctx):
    for ruta, firma in (("/_debug_toolbar/", "djdt"),
                        ("/__debug__/", "debug"),
                        ("/telescope", "laravel"),
                        ("/horizon", "laravel")):
        d = ctx.ruta(ruta)
        if d["status"] == 200 and firma.lower() in (d["cuerpo"] or "").lower():
            return {"titulo": "Herramienta de depuracion accesible (%s)" % ruta,
                    "detalle": "Expone consultas, variables y a veces ejecucion",
                    "recomendacion": "Desactivar las barras de depuracion en "
                                     "produccion",
                    "evidencia": {"ruta": ruta}}
    return None


@check("FUG-22", "Version en la ruta de error 404", FUG, "info",
       activo=True, cwe="CWE-200", owasp="A05:2021")
def error_404(ctx):
    base = "%s://%s%s" % (ctx.esquema, ctx.host,
                          "" if ctx.puerto in (80, 443) else ":%d" % ctx.puerto)
    r = ctx.pedir(base + "/hunterbug-%s" % _marca())
    if r.status == 404:
        m = re.search(r"(\b(?:nginx|apache|iis|tomcat|jetty|express|gunicorn|"
                      r"werkzeug|kestrel)[/ ]?[\d\.]*)", r.cuerpo or "", re.I)
        if m:
            return {"titulo": "La pagina 404 revela el servidor y su version",
                    "detalle": "Firma encontrada: %s" % m.group(1),
                    "recomendacion": "Pagina 404 personalizada",
                    "evidencia": {"firma": m.group(1),
                                  "extracto": (r.cuerpo or "")[:200]}}
    return None


# ==========================================================================
# Tecnologia (20)
# ==========================================================================

def _tec(nombre, firmas, cid, sev="info"):
    @check(cid, "Tecnologia detectada: " + nombre, TEC, sev,
           cwe="CWE-200", owasp="A05:2021")
    def _f(ctx):
        blob = (ctx.cuerpo_min + " " + " ".join(
            "%s %s" % (k, v) for k, v in ctx.cabeceras.items()))
        for f in firmas:
            if f in blob:
                return {"titulo": "Tecnologia detectada: " + nombre,
                        "detalle": "Firma encontrada: '%s'" % f,
                        "recomendacion": "Mantener la version al dia y revisar "
                                         "sus CVE conocidos",
                        "evidencia": {"tecnologia": nombre, "firma": f}}
        return None
    return _f


_tec("WordPress", ["wp-content", "wp-includes", "wp-json"], "TEC-01")
_tec("Drupal", ["/sites/default/files", "x-drupal", "drupal.js"], "TEC-02")
_tec("Joomla", ["/components/com_", "joomla"], "TEC-03")
_tec("Shopify", ["cdn.shopify.com", "x-shopify"], "TEC-04")
_tec("Next.js", ["_next/static", "__next"], "TEC-05")
_tec("React", ["data-reactroot", "react-dom"], "TEC-06")
_tec("Vue.js", ["vue.js", "vue.min.js", "data-v-"], "TEC-07")
_tec("Angular", ["ng-version", "angular.min.js"], "TEC-08")
_tec("Laravel", ["laravel_session", "csrf-token"], "TEC-09")
_tec("Django", ["csrfmiddlewaretoken", "__admin__"], "TEC-10")
_tec("Ruby on Rails", ["x-runtime", "rails"], "TEC-11")
_tec("Spring", ["x-application-context", "spring"], "TEC-12")
_tec("ASP.NET", ["asp.net", "__viewstate", "aspnet"], "TEC-13")
_tec("PHP", ["phpsessid", "x-powered-by: php"], "TEC-14")
_tec("Apache Tomcat", ["tomcat", "coyote"], "TEC-15")
_tec("nginx", ["nginx"], "TEC-16")
_tec("Apache", ["apache"], "TEC-17")
_tec("IIS", ["microsoft-iis", "iis/"], "TEC-18")
_tec("Cloudflare", ["cloudflare", "cf-ray"], "TEC-19")
_tec("Vercel", ["x-vercel", "vercel"], "TEC-20")


# ==========================================================================
# Inyeccion y logica en parametros (40)
# ==========================================================================

def _con_parametros(ctx):
    return vulns.parametros_de(ctx.url)


def _base(ctx):
    return "%s://%s%s" % (ctx.esquema, ctx.host,
                          "" if ctx.puerto in (80, 443) else ":%d" % ctx.puerto)


@check("PAR-01", "SQLi basada en errores", PAR, "critico", activo=True,
       cwe="CWE-89", owasp="A03:2021")
def par_sqli_error(ctx):
    if not _con_parametros(ctx):
        return None
    res = vulns.probar_sqli(ctx.url, cabeceras=None, pausa=ctx.pausa,
                            log=ctx.log)
    for h in res:
        if "error" in h["titulo"].lower():
            return {"titulo": h["titulo"], "detalle": h["detalle"],
                    "recomendacion": h["recomendacion"],
                    "parametro": h.get("parametro", ""),
                    "evidencia": h.get("evidencia", {})}
    return None


@check("PAR-02", "SQLi por diferencial booleano", PAR, "alto", activo=True,
       cwe="CWE-89", owasp="A03:2021")
def par_sqli_bool(ctx):
    if not _con_parametros(ctx):
        return None
    res = vulns.probar_sqli(ctx.url, cabeceras=None, pausa=ctx.pausa,
                            log=ctx.log)
    for h in res:
        if "booleano" in h["titulo"].lower() or "condicion" in h["titulo"].lower():
            return {"titulo": h["titulo"], "detalle": h["detalle"],
                    "recomendacion": h["recomendacion"],
                    "parametro": h.get("parametro", ""),
                    "evidencia": h.get("evidencia", {})}
    return None


@check("PAR-03", "SQLi en cabecera User-Agent", PAR, "alto", activo=True,
       cwe="CWE-89", owasp="A03:2021")
def par_sqli_ua(ctx):
    for pay in ("'", "\"", "')"):
        r = ctx.pedir(ctx.url, cabeceras={"User-Agent": "HunterBug" + pay})
        m = RE_BD_ERROR.search(r.cuerpo or "")
        if m:
            return {"titulo": "SQLi reflejada desde la cabecera User-Agent",
                    "detalle": "La cabecera se usa en una consulta sin sanear",
                    "recomendacion": "Parametrizar tambien las cabeceras usadas "
                                     "en consultas",
                    "evidencia": {"payload": pay, "extracto": m.group(0)[:120]}}
    return None


@check("PAR-04", "SQLi en cabecera Referer", PAR, "alto", activo=True,
       cwe="CWE-89", owasp="A03:2021")
def par_sqli_referer(ctx):
    for pay in ("'", "\"", "')"):
        r = ctx.pedir(ctx.url, cabeceras={"Referer": _base(ctx) + "/" + pay})
        m = RE_BD_ERROR.search(r.cuerpo or "")
        if m:
            return {"titulo": "SQLi reflejada desde la cabecera Referer",
                    "detalle": "El Referer se usa en una consulta sin sanear",
                    "recomendacion": "Parametrizar las consultas",
                    "evidencia": {"payload": pay, "extracto": m.group(0)[:120]}}
    return None


@check("PAR-05", "SQLi en cookie", PAR, "alto", activo=True,
       cwe="CWE-89", owasp="A03:2021")
def par_sqli_cookie(ctx):
    if not ctx.cookies:
        return None
    nombre = ctx.cookies[0]["nombre"]
    for pay in ("'", "\""):
        r = ctx.pedir(ctx.url, cabeceras={"Cookie": "%s=%s" % (nombre, pay)})
        m = RE_BD_ERROR.search(r.cuerpo or "")
        if m:
            return {"titulo": "SQLi reflejada desde una cookie",
                    "detalle": "La cookie '%s' llega a una consulta sin sanear"
                               % nombre,
                    "recomendacion": "Parametrizar las consultas",
                    "evidencia": {"cookie": nombre, "payload": pay,
                                  "extracto": m.group(0)[:120]}}
    return None


@check("PAR-06", "XSS reflejado en el cuerpo", PAR, "alto", activo=True,
       cwe="CWE-79", owasp="A03:2021")
def par_xss(ctx):
    if not _con_parametros(ctx):
        return None
    res = vulns.probar_xss(ctx.url, cabeceras=None, pausa=ctx.pausa, log=ctx.log)
    for h in res:
        if h["severidad"] == "alto":
            return {"titulo": h["titulo"], "detalle": h["detalle"],
                    "recomendacion": h["recomendacion"],
                    "parametro": h.get("parametro", ""),
                    "evidencia": h.get("evidencia", {})}
    return None


@check("PAR-07", "XSS reflejado (posible, escapado)", PAR, "bajo", activo=True,
       cwe="CWE-79", owasp="A03:2021")
def par_xss_debil(ctx):
    if not _con_parametros(ctx):
        return None
    res = vulns.probar_xss(ctx.url, cabeceras=None, pausa=ctx.pausa, log=ctx.log)
    for h in res:
        if h["severidad"] == "bajo":
            return {"titulo": h["titulo"], "detalle": h["detalle"],
                    "recomendacion": h["recomendacion"],
                    "parametro": h.get("parametro", ""),
                    "evidencia": h.get("evidencia", {})}
    return None


@check("PAR-08", "XSS en cabecera reflejada", PAR, "medio", activo=True,
       cwe="CWE-79", owasp="A03:2021")
def par_xss_header(ctx):
    marca = _marca()
    pay = "<%s>" % marca
    for cab in ("User-Agent", "Referer"):
        r = ctx.pedir(ctx.url, cabeceras={cab: pay})
        if marca in (r.cuerpo or "") and pay in (r.cuerpo or ""):
            return {"titulo": "XSS reflejado desde la cabecera %s" % cab,
                    "detalle": "El valor de la cabecera vuelve al HTML sin "
                               "escapar",
                    "recomendacion": "Escapar toda salida, incluidas las "
                                     "cabeceras registradas o mostradas",
                    "evidencia": {"cabecera": cab, "payload": pay}}
    return None
@check("PAR-09", "Inyeccion HTML (sin script)", PAR, "medio", activo=True,
       cwe="CWE-79", owasp="A03:2021")
def par_html_injection(ctx):
    if not _con_parametros(ctx):
        return None
    marca = _marca()
    pay = "<hbmk-%s>x</hbmk-%s>" % (marca, marca)
    for nombre, _ in _con_parametros(ctx)[:4]:
        u = vulns._sustituir_param(ctx.url, nombre, pay)
        r = ctx.pedir(u)
        if pay in (r.cuerpo or ""):
            return {"titulo": "Inyeccion HTML en '%s'" % nombre,
                    "detalle": "Se pueden inyectar etiquetas HTML arbitrarias; "
                               "con un navegador puede escalarse a XSS",
                    "recomendacion": "Escapar la salida segun contexto",
                    "parametro": nombre,
                    "evidencia": {"payload": pay}}
    return None
def _ssti_evaluado(ctx, nombre, envoltura):
    """Comprueba SSTI con DOS expresiones distintas. Con una sola basta
    una coincidencia casual en el HTML (p. ej. una version "2.4.49")
    para dar un falso positivo."""
    for expresion, esperado in (("7*7", "49"), ("123*456", "56088")):
        pay = envoltura(expresion)
        u = vulns._sustituir_param(ctx.url, nombre, pay)
        r = ctx.pedir(u)
        cuerpo = r.cuerpo or ""
        if esperado not in cuerpo or pay in cuerpo:
            return None
    return pay


@check("PAR-10", "SSTI con {{7*7}}", PAR, "critico", activo=True,
       cwe="CWE-1336", owasp="A03:2021")
def par_ssti_doble(ctx):
    if not _con_parametros(ctx):
        return None
    for nombre, _ in _con_parametros(ctx)[:4]:
        ultimo = _ssti_evaluado(ctx, nombre,
                               lambda e: "{{%s}}" % e)
        if ultimo:
            return {"titulo": "SSTI evaluado en '%s'" % nombre,
                    "detalle": "Las expresiones enviadas por el usuario se "
                               "evaluan en el servidor",
                    "recomendacion": "No construir plantillas con entrada "
                                     "del usuario; usar plantillas estaticas",
                    "parametro": nombre,
                    "evidencia": {"payload": ultimo,
                                  "respuestas": ["49", "56088"]}}
    return None


@check("PAR-11", "SSTI con ${7*7}", PAR, "critico", activo=True,
       cwe="CWE-1336", owasp="A03:2021")
def par_ssti_dolar(ctx):
    if not _con_parametros(ctx):
        return None
    for nombre, _ in _con_parametros(ctx)[:4]:
        ultimo = _ssti_evaluado(ctx, nombre,
                               lambda e: "${%s}" % e)
        if ultimo:
            return {"titulo": "SSTI con sintaxis ${} en '%s'" % nombre,
                    "detalle": "El motor de plantillas evalua las expresiones "
                               "recibidas del cliente",
                    "recomendacion": "Plantillas estaticas y escape de la "
                                     "entrada",
                    "parametro": nombre,
                    "evidencia": {"payload": ultimo,
                                  "respuestas": ["49", "56088"]}}
    return None
@check("PAR-12", "Inyeccion CRLF", PAR, "alto", activo=True,
       cwe="CWE-93", owasp="A03:2021")
def par_crlf(ctx):
    if not _con_parametros(ctx):
        return None
    marca = _marca()
    pay = "\r\n" + "HunterBug-%s: inyectado" % marca
    for nombre, _ in _con_parametros(ctx)[:4]:
        u = vulns._sustituir_param(ctx.url, nombre, pay)
        r = ctx.pedir(u)
        if any(k.lower() == "hunterbug-" + marca for k, _ in r.cabeceras):
            return {"titulo": "Inyeccion CRLF en '%s'" % nombre,
                    "detalle": "Se inyectan cabeceras nuevas en la respuesta a "
                               "partir de un salto de linea en el parametro",
                    "recomendacion": "Eliminar CR y LF de los valores que acaban "
                                     "en cabeceras",
                    "parametro": nombre,
                    "evidencia": {"parametro": nombre,
                                  "cabecera_inyectada": "HunterBug-" + marca,
                                  "cabeceras": [k for k, _ in r.cabeceras]}}
    return None
@check("PAR-13", "Path traversal", PAR, "alto", activo=True,
       cwe="CWE-22", owasp="A01:2021")
def par_traversal(ctx):
    if not _con_parametros(ctx):
        return None
    for nombre, _ in _con_parametros(ctx)[:4]:
        for pay in ("../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"):
            u = vulns._sustituir_param(ctx.url, nombre, pay)
            r = ctx.pedir(u)
            if re.search(r"root:.*:0:0:", r.cuerpo or ""):
                return {"titulo": "Path traversal en '%s'" % nombre,
                        "detalle": "Se lee /etc/passwd a traves del parametro",
                        "recomendacion": "Normalizar y validar rutas; usar "
                                         "listas blancas de ficheros",
                        "parametro": nombre,
                        "evidencia": {"payload": pay,
                                      "extracto": (r.cuerpo or "")[:200]}}
    return None


@check("PAR-14", "Inclusion local de ficheros", PAR, "alto", activo=True,
       cwe="CWE-98", owasp="A03:2021")
def par_lfi(ctx):
    if not _con_parametros(ctx):
        return None
    pay = "php://filter/convert.base64-encode/resource=index.php"
    for nombre, _ in _con_parametros(ctx)[:4]:
        u = vulns._sustituir_param(ctx.url, nombre, pay)
        r = ctx.pedir(u)
        if re.search(r"[A-Za-z0-9+/]{60,}={0,2}", r.cuerpo or ""):
            return {"titulo": "Posible LFI con wrapper php:// en '%s'" % nombre,
                    "detalle": "La respuesta contiene datos en base64 "
                               "compatibles con un fichero leido",
                    "recomendacion": "Validar el parametro contra una lista "
                                     "blanca de ficheros",
                    "parametro": nombre,
                    "evidencia": {"payload": pay}}
    return None
@check("PAR-15", "Redireccion abierta", PAR, "medio", activo=True,
       cwe="CWE-601", owasp="A01:2021")
def par_open_redirect(ctx):
    params = [n for n, _ in _con_parametros(ctx)]
    interesantes = [p for p in params
                    if re.search(r"(url|redir|next|dest|goto|return|continue|"
                                 r"target|to|out|link)", p, re.I)]
    for nombre in (interesantes or params)[:4]:
        pay = "https://hunterbug-prueba.invalid/"
        u = vulns._sustituir_param(ctx.url, nombre, pay)
        r = ctx.pedir(u, seguir=0)
        destino = r.cabecera("location")
        if r.status in (301, 302, 303, 307, 308) and "hunterbug-prueba.invalid" in destino:
            return {"titulo": "Redireccion abierta en '%s'" % nombre,
                    "detalle": "El parametro controla el destino de la "
                               "redireccion, util para phishing y para robar "
                               "tokens OAuth",
                    "recomendacion": "Lista blanca de destinos o redireccion "
                                     "por identificador interno",
                    "parametro": nombre,
                    "evidencia": {"payload": pay, "location": destino[:200]}}
    return None


@check("PAR-16", "SSRF en parametro de URL", PAR, "alto", activo=True,
       cwe="CWE-918", owasp="A10:2021")
def par_ssrf(ctx):
    """Solo se reporta si la respuesta delata un fallo de conexion del servidor
    hacia un destino interno, que es el indicador fiable de SSRF."""
    params = [n for n, _ in _con_parametros(ctx)]
    interesantes = [p for p in params
                    if re.search(r"(url|uri|src|dest|redirect|proxy|fetch|"
                                 r"callback|webhook|feed|host)", p, re.I)]
    firmas = ("connection refused", "failed to connect", "no route to host",
              "couldn't connect", "getaddrinfo", "name or service not known",
              "connection timed out", "econnrefused", "socket error",
              "failed to open stream")
    for nombre in (interesantes or params)[:3]:
        u = vulns._sustituir_param(ctx.url, nombre, "http://127.0.0.1:1/")
        r = ctx.pedir(u, timeout=8)
        cuerpo = (r.cuerpo or "").lower()
        for f in firmas:
            if f in cuerpo:
                return {"titulo": "SSRF en '%s' (el servidor intento conectar)"
                                  % nombre,
                        "detalle": "El parametro hace que el servidor realice "
                                   "la peticion: la respuesta contiene '%s'" % f,
                        "recomendacion": "Validar destinos contra lista blanca y "
                                         "bloquear rangos internos",
                        "parametro": nombre,
                        "evidencia": {"payload": "http://127.0.0.1:1/",
                                      "firma": f,
                                      "extracto": (r.cuerpo or "")[:250]}}
    return None


RE_PARAM_RUTA = re.compile(
    r"(url|uri|src|dest|redirect|redir|next|goto|target|to|out|link|path|file|page|view|callback|return|continue|route|endpoint)", re.I)


def _param_no_ruta(ctx):
    """Primer parametro del objetivo que no controle una ruta o destino.
    Inyectar operadores NoSQL en esos parametros no es evidencia."""
    for nombre, _ in _con_parametros(ctx):
        if not RE_PARAM_RUTA.search(nombre):
            return nombre
    return None

@check("PAR-17", "Inyeccion de comandos (indicador)", PAR, "critico",
       activo=True, cwe="CWE-78", owasp="A03:2021")
def par_cmd(ctx):
    if not _con_parametros(ctx):
        return None
    for nombre, _ in _con_parametros(ctx)[:4]:
        u = vulns._sustituir_param(ctx.url, nombre, ";echo hunterbug_probe")
        r = ctx.pedir(u)
        if "hunterbug_probe" in (r.cuerpo or ""):
            return {"titulo": "Inyeccion de comandos en '%s'" % nombre,
                    "detalle": "El comando enviado aparece en la salida",
                    "recomendacion": "No construir comandos con entrada del "
                                     "usuario; usar APIs del sistema",
                    "parametro": nombre,
                    "evidencia": {"payload": ";echo hunterbug_probe"}}
    return None


@check("PAR-18", "Inyeccion LDAP", PAR, "alto", activo=True,
       cwe="CWE-90", owasp="A03:2021")
def par_ldap(ctx):
    if not _con_parametros(ctx):
        return None
    firmas = ("javax.naming", "ldap_search", "invalid dn syntax",
              "ldapexception", "supplied argument is not a valid ldap")
    for nombre, _ in _con_parametros(ctx)[:4]:
        u = vulns._sustituir_param(ctx.url, nombre, "*)(uid=*))(|(uid=*")
        r = ctx.pedir(u)
        cuerpo = (r.cuerpo or "").lower()
        for f in firmas:
            if f in cuerpo:
                return {"titulo": "Posible inyeccion LDAP en '%s'" % nombre,
                        "detalle": "La respuesta contiene un error de LDAP",
                        "recomendacion": "Escapar los caracteres especiales de "
                                         "filtros LDAP",
                        "parametro": nombre,
                        "evidencia": {"payload": "*)(uid=*))(|(uid=*",
                                      "firma": f}}
    return None


@check("PAR-19", "Inyeccion XPath", PAR, "medio", activo=True,
       cwe="CWE-643", owasp="A03:2021")
def par_xpath(ctx):
    if not _con_parametros(ctx):
        return None
    firmas = ("xpathexception", "invalid xpath", "xmlxpath", "xpath syntax error")
    for nombre, _ in _con_parametros(ctx)[:4]:
        u = vulns._sustituir_param(ctx.url, nombre, "' or '1'='1")
        r = ctx.pedir(u)
        cuerpo = (r.cuerpo or "").lower()
        for f in firmas:
            if f in cuerpo:
                return {"titulo": "Posible inyeccion XPath en '%s'" % nombre,
                        "detalle": "Error de XPath en la respuesta",
                        "recomendacion": "Usar consultas parametrizadas de XPath",
                        "parametro": nombre,
                        "evidencia": {"payload": "' or '1'='1", "firma": f}}
    return None


@check("PAR-20", "Inyeccion NoSQL ($ne)", PAR, "alto", activo=True,
       cwe="CWE-943", owasp="A03:2021")
def par_nosql_ne(ctx):
    nombre = _param_no_ruta(ctx)
    if not nombre:
        return None
    r = ctx.pedir(vulns._sustituir_param(ctx.url, nombre, "x[$ne]=x"))
    base = ctx.control()
    if r.status and base.status and r.status != base.status:
        return {"titulo": "Posible inyeccion NoSQL en '%s'" % nombre,
                "detalle": "El operador $ne altero la respuesta (%d frente "
                           "a %d en el control)" % (r.status, base.status),
                "recomendacion": "Convertir los tipos y rechazar objetos en "
                                 "la entrada",
                "parametro": nombre,
                "evidencia": {"payload": "x[$ne]=x", "status": r.status,
                              "status_control": base.status}}
    return None


@check("PAR-21", "Inyeccion NoSQL ($gt)", PAR, "alto", activo=True,
       cwe="CWE-943", owasp="A03:2021")
def par_nosql_gt(ctx):
    nombre = _param_no_ruta(ctx)
    if not nombre:
        return None
    r = ctx.pedir(vulns._sustituir_param(ctx.url, nombre, "x[$gt]="))
    base = ctx.control()
    if r.status and base.status and r.status != base.status:
        return {"titulo": "Posible inyeccion NoSQL con $gt en '%s'" % nombre,
                "detalle": "El operador $gt altero la respuesta (%d frente "
                           "a %d en el control)" % (r.status, base.status),
                "recomendacion": "Validar el tipo de los parametros",
                "parametro": nombre,
                "evidencia": {"payload": "x[$gt]=", "status": r.status,
                              "status_control": base.status}}
    return None
@check("PAR-22", "XML externo (XXE)", PAR, "critico", activo=True,
       cwe="CWE-611", owasp="A05:2021")
def par_xxe(ctx):
    base = _base(ctx)
    carga = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
             '"file:///etc/passwd">]><r>&x;</r>')
    for ruta in ("/", ctx.ruta_base):
        r = ctx.pedir(base + ruta, metodo="POST",
                      cabeceras={"Content-Type": "application/xml"}, cuerpo=carga)
        if re.search(r"root:.*:0:0:", r.cuerpo or ""):
            return {"titulo": "XXE: el servidor resuelve entidades externas",
                    "detalle": "Un documento XML con entidad externa devuelve "
                               "el contenido del fichero",
                    "recomendacion": "Deshabilitar entidades externas y DTD en "
                                     "el parser XML",
                    "evidencia": {"ruta": ruta, "status": r.status,
                                  "extracto": (r.cuerpo or "")[:200]}}
    return None


@check("PAR-23", "Contaminacion de parametros HTTP (HPP)", PAR, "medio",
       activo=True, cwe="CWE-235", owasp="A03:2021")
def par_hpp(ctx):
    params = _con_parametros(ctx)
    if not params:
        return None
    nombre, valor = params[0]
    sep = "&" if "?" in ctx.url else "?"
    u = "%s%s%s=%s&%s=%s" % (ctx.url, sep, nombre, valor, nombre, valor + "x")
    r = ctx.pedir(u)
    base = ctx.control()
    if r.status and base.status and r.status != base.status:
        return {"titulo": "El parametro duplicado cambia la respuesta",
                "detalle": "Enviar '%s' dos veces altera el comportamiento "
                           "(%d frente a %d en el control), lo que puede "
                           "saltarse validaciones"
                           % (nombre, r.status, base.status),
                "recomendacion": "Rechazar parametros duplicados o normalizar "
                                 "antes de validar",
                "parametro": nombre,
                "evidencia": {"status_duplicado": r.status,
                              "status_control": base.status}}
    return None


@check("PAR-24", "Asignacion masiva (mass assignment)", PAR, "alto",
       activo=True, cwe="CWE-915", owasp="A01:2021")
def par_mass_assignment(ctx):
    base = _base(ctx)
    campos = '{"role":"admin","is_admin":true,"admin":true}'
    rutas = (ctx.ruta_base, "/api/perfil", "/api/usuario/1", "/api/me",
             "/api/usuario")
    for ruta in rutas:
        r = ctx.pedir(base + ruta, metodo="POST",
                      cabeceras={"Content-Type": "application/json"},
                      cuerpo=campos)
        if r.status in (200, 201) and re.search(
                r'"(role|is_admin|admin)"\s*:\s*(?:"admin"|true)',
                r.cuerpo or "", re.I):
            return {"titulo": "Posible asignacion masiva en %s" % ruta,
                    "detalle": "El servidor acepto campos de privilegio "
                               "enviados por el cliente",
                    "recomendacion": "Lista blanca de campos asignables",
                    "evidencia": {"ruta": ruta, "status": r.status,
                                  "extracto": (r.cuerpo or "")[:250]}}
    return None


@check("PAR-25", "IDOR", PAR, "alto", activo=True,
       cwe="CWE-639", owasp="A01:2021")
def par_idor(ctx):
    return None    # se ejecuta desde el modulo IDOR con patron explicito


@check("PAR-26", "BOLA", PAR, "alto", activo=True,
       cwe="CWE-639", owasp="A01:2021")
def par_bola(ctx):
    return None    # se ejecuta desde el modulo BOLA con dos credenciales


@check("PAR-27", "Sin limite de peticiones", PAR, "medio", activo=True,
       cwe="CWE-770", owasp="A04:2021")
def par_rate_limit(ctx):
    codigos = []
    for _ in range(12):
        r = ctx.pedir(ctx.url, timeout=8)
        codigos.append(r.status)
    if codigos and all(c == codigos[0] for c in codigos) and codigos[0] not in (0, 429):
        return {"titulo": "No se observa limite de peticiones",
                "detalle": "12 peticiones seguidas devolvieron siempre %d, sin "
                           "429 ni bloqueo" % codigos[0],
                "recomendacion": "Aplicar limite por IP y por cuenta en "
                                 "endpoints sensibles",
                "evidencia": {"peticiones": len(codigos),
                              "codigos": sorted(set(codigos))}}
    return None


@check("PAR-28", "Enumeracion de usuarios", PAR, "medio", activo=True,
       cwe="CWE-204", owasp="A07:2021")
def par_enumeracion(ctx):
    """Prueba valores habituales frente a uno inventado: si la respuesta cambia,
    el endpoint delata cuales existen."""
    params = _con_parametros(ctx)
    if not params:
        return None
    nombre, _ = params[0]
    candidatos = ("admin", "admin@ejemplo.test", "test", "1", "root")
    malo = _marca(12)
    r_malo = ctx.pedir(vulns._sustituir_param(ctx.url, nombre, malo))
    for valor in candidatos:
        r = ctx.pedir(vulns._sustituir_param(ctx.url, nombre, valor))
        if r.status and r_malo.status and r.status != r_malo.status:
            return {"titulo": "Enumeracion de usuarios en '%s'" % nombre,
                    "detalle": "El valor '%s' devuelve %d y uno inexistente %d, "
                               "lo que permite descubrir cuentas validas"
                               % (valor, r.status, r_malo.status),
                    "recomendacion": "Respuesta generica identica en ambos "
                                     "casos",
                    "parametro": nombre,
                    "evidencia": {"parametro": nombre, "valor_existente": valor,
                                  "status_existente": r.status,
                                  "status_inexistente": r_malo.status}}
    return None


@check("PAR-29", "Identificadores secuenciales predecibles", PAR, "info",
       activo=True, cwe="CWE-340", owasp="A01:2021")
def par_secuencial(ctx):
    m = re.search(r"/(\d{1,6})(?:/|$|\?)", ctx.url)
    if not m:
        return None
    n = int(m.group(1))
    return {"titulo": "Identificador numerico secuencial en la ruta",
            "detalle": "El valor %d invita a enumerar vecinos; comprobar "
                       "autorizacion por objeto" % n,
            "recomendacion": "Usar identificadores opacos y validar propiedad",
            "evidencia": {"identificador": n}}


@check("PAR-30", "Valor negativo aceptado", PAR, "info", activo=True,
       cwe="CWE-20", owasp="A03:2021")
def par_negativo(ctx):
    """Solo se reporta si -1 se trata como un valor valido: misma respuesta que
    el valor legitimo, no una pagina de error o de vacio."""
    params = _con_parametros(ctx)
    base_bytes = ctx.r.cuerpo_bytes
    for nombre, valor in params[:4]:
        if not re.fullmatch(r"\d+", valor or ""):
            continue
        u = vulns._sustituir_param(ctx.url, nombre, "-1")
        r = ctx.pedir(u)
        base = ctx.control()
        base_bytes = base.cuerpo_bytes
        if r.status == base.status and base_bytes > 0 and \
                abs(r.cuerpo_bytes - base_bytes) <= max(64, base_bytes * 0.2):
            return {"titulo": "El parametro '%s' trata -1 como valor valido"
                              % nombre,
                    "detalle": "La respuesta a -1 es practicamente identica a la "
                               "del valor legitimo (%d frente a %d bytes), senal "
                               "de que no se valida el rango"
                               % (r.cuerpo_bytes, base_bytes),
                    "recomendacion": "Validar tipo y rango en el servidor",
                    "parametro": nombre,
                    "evidencia": {"valor_probado": -1, "status": r.status,
                                  "bytes": r.cuerpo_bytes,
                                  "bytes_base": base_bytes}}
    return None


@check("PAR-31", "Desbordamiento de entero aceptado", PAR, "info", activo=True,
       cwe="CWE-190", owasp="A03:2021")
def par_overflow(ctx):
    params = _con_parametros(ctx)
    for nombre, valor in params[:4]:
        if not re.fullmatch(r"\d+", valor or ""):
            continue
        u = vulns._sustituir_param(ctx.url, nombre, "99999999999999999999")
        r = ctx.pedir(u)
        if r.status >= 500:
            return {"titulo": "Un entero enorme provoca error %d" % r.status
                              + " en '%s'" % nombre,
                    "detalle": "No se comprueba el rango del valor",
                    "recomendacion": "Validar limites numericos",
                    "parametro": nombre,
                    "evidencia": {"status": r.status}}
    return None


@check("PAR-32", "Inyeccion de plantilla en JSON", PAR, "medio", activo=True,
       cwe="CWE-1336", owasp="A03:2021")
def par_json_injection(ctx):
    base = _base(ctx)
    r = ctx.pedir(base + ctx.ruta_base, metodo="POST",
                  cabeceras={"Content-Type": "application/json"},
                  cuerpo='{"name":"{{7*7}}","x":"${7*7}"}')
    cuerpo = r.cuerpo or ""
    if "49" in cuerpo and "{{7*7}}" not in cuerpo:
        return {"titulo": "El JSON se evalua como plantilla",
                "detalle": "La expresion {{7*7}} devolvio 49 en la respuesta",
                "recomendacion": "No renderizar los valores recibidos como "
                                 "plantilla",
                "evidencia": {"status": r.status,
                              "extracto": cuerpo[:200]}}
    return None


@check("PAR-33", "Prototype pollution (__proto__)", PAR, "medio", activo=True,
       cwe="CWE-1321", owasp="A03:2021")
def par_proto(ctx):
    base = _base(ctx)
    r = ctx.pedir(base + ctx.ruta_base, metodo="POST",
                  cabeceras={"Content-Type": "application/json"},
                  cuerpo='{"__proto__":{"hunterbug":1},"constructor":{"prototype":{"hb":1}}}')
    if r.status in (200, 201) and "hunterbug" in (r.cuerpo or ""):
        return {"titulo": "El objeto __proto__ llega al servidor",
                "detalle": "La respuesta refleja la clave inyectada; puede "
                           "permitir contaminar el prototipo",
                "recomendacion": "Filtrar __proto__/constructor en la entrada",
                "evidencia": {"status": r.status}}
    return None


@check("PAR-34", "Content-Type no validado", PAR, "info", activo=True,
       cwe="CWE-436", owasp="A03:2021")
def par_content_type(ctx):
    base = _base(ctx)
    r = ctx.pedir(base + ctx.ruta_base, metodo="POST",
                  cabeceras={"Content-Type": "text/plain"},
                  cuerpo='{"x":1}')
    if r.status in (200, 201, 202):
        return {"titulo": "El endpoint acepta text/plain en un cuerpo JSON",
                "detalle": "No se valida el tipo de contenido declarado",
                "recomendacion": "Rechazar tipos no esperados con 415",
                "evidencia": {"status": r.status}}
    return None


@check("PAR-35", "Cabecera de suplantacion aceptada", PAR, "alto", activo=True,
       cwe="CWE-290", owasp="A01:2021")
def par_suplantacion(ctx):
    for cab, valor in (("X-Forwarded-For", "127.0.0.1"),
                       ("X-Original-URL", "/admin"),
                       ("X-Rewrite-URL", "/admin"),
                       ("X-Forwarded-Host", "hunterbug.invalid")):
        r = ctx.pedir(ctx.url, cabeceras={cab: valor})
        base = ctx.control()
        if r.status and base.status and r.status != base.status and \
                r.status in (200, 302):
            return {"titulo": "La cabecera %s altera la respuesta" % cab,
                    "detalle": "Respondio %d frente a %d en el control; "
                               "puede permitir saltarse controles de acceso" %
                               (r.status, base.status),
                    "recomendacion": "No confiar en cabeceras de proxy sin "
                                     "validar el origen",
                    "evidencia": {"cabecera": cab, "valor": valor,
                                  "status": r.status,
                                  "status_control": base.status}}
    return None


@check("PAR-36", "Inyeccion de plantilla en cabecera", PAR, "medio",
       activo=True, cwe="CWE-1336", owasp="A03:2021")
def par_ssti_header(ctx):
    r = ctx.pedir(ctx.url, cabeceras={"User-Agent": "{{7*7}}"})
    if "49" in (r.cuerpo or "") and "{{7*7}}" not in (r.cuerpo or ""):
        return {"titulo": "La cabecera User-Agent se evalua como plantilla",
                "detalle": "{{7*7}} devolvio 49",
                "recomendacion": "No renderizar cabeceras como plantilla",
                "evidencia": {"status": r.status}}
    return None


@check("PAR-37", "Respuesta refleja entrada sin escapar (contexto JS)", PAR,
       "medio", activo=True, cwe="CWE-79", owasp="A03:2021")
def par_js_context(ctx):
    if not _con_parametros(ctx):
        return None
    marca = _marca()
    pay = "'+" + "%s+" % marca + "'"
    for nombre, _ in _con_parametros(ctx)[:4]:
        u = vulns._sustituir_param(ctx.url, nombre, pay)
        r = ctx.pedir(u)
        if pay in (r.cuerpo or ""):
            return {"titulo": "Entrada reflejada dentro de JavaScript (%s)"
                              % nombre,
                    "detalle": "El valor vuelve sin escapar en un contexto de "
                               "script, lo que permite romper la cadena",
                    "recomendacion": "Escapar segun contexto JS y usar "
                                     "JSON.stringify",
                    "parametro": nombre,
                    "evidencia": {"payload": pay}}
    return None
@check("PAR-38", "Redireccion a esquema peligroso", PAR, "medio", activo=True,
       cwe="CWE-601", owasp="A01:2021")
def par_esquema_peligroso(ctx):
    params = [n for n, _ in _con_parametros(ctx)]
    for nombre in params[:4]:
        u = vulns._sustituir_param(ctx.url, nombre, "javascript:alert(1)")
        r = ctx.pedir(u, seguir=0)
        if "javascript:alert(1)" in (r.cabecera("location") or ""):
            return {"titulo": "El parametro acepta esquemas peligrosos (%s)"
                              % nombre,
                    "detalle": "Se permite javascript: en el destino de la "
                               "redireccion",
                    "recomendacion": "Permitir solo http y https",
                    "parametro": nombre,
                    "evidencia": {"payload": "javascript:alert(1)"}}
    return None


@check("PAR-39", "Parametro de fichero sin validar", PAR, "medio", activo=True,
       cwe="CWE-73", owasp="A01:2021")
def par_fichero(ctx):
    params = [n for n, _ in _con_parametros(ctx)]
    interesantes = [p for p in params
                    if re.search(r"(file|path|page|include|doc|template|view)",
                                 p, re.I)]
    for nombre in interesantes[:3]:
        u = vulns._sustituir_param(ctx.url, nombre, "/etc/hostname")
        r = ctx.pedir(u)
        base = ctx.control()
        if r.status == 200 and r.cuerpo_bytes > 0 and \
                base.status and r.status != base.status:
            return {"titulo": "Parametro de fichero sin validar (%s)" % nombre,
                    "detalle": "Acepta una ruta absoluta del sistema",
                    "recomendacion": "Lista blanca de ficheros permitidos",
                    "parametro": nombre,
                    "evidencia": {"status": r.status}}
    return None


@check("PAR-40", "Sin cabecera de seguridad en la respuesta dinamica", PAR,
       "info", activo=True, cwe="CWE-693", owasp="A05:2021")
def par_sin_cabeceras(ctx):
    if not _con_parametros(ctx):
        return None
    r = ctx.pedir(ctx.url)
    faltan = [h for h in ("content-security-policy", "x-content-type-options")
              if not r.cabecera(h)]
    if len(faltan) == 2:
        return {"titulo": "La respuesta con parametros no aplica CSP ni "
                          "nosniff",
                "detalle": "Una respuesta dinamica sin estas cabeceras es el "
                           "escenario ideal para XSS",
                "recomendacion": "Aplicar las cabeceras de seguridad a todas "
                                 "las respuestas, no solo a la portada",
                "evidencia": {"faltan": faltan}}
    return None