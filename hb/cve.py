"""HunterBug - inteligencia de vulnerabilidades conocidas (CVE).

Dos fuentes:
  1. Base local curada con CVEs reales y muy conocidos, mapeados a producto
     y rango de versiones (funciona sin conexion).
  2. Consulta en vivo a la API publica del NVD (sin clave).

Los rangos de version se comparan de verdad, no por texto literal.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request

UA = "HunterBug/1.0 (+authorized-security-testing)"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# --------------------------------------------------------------------------
# Comparacion de versiones
# --------------------------------------------------------------------------

def partes_version(v):
    v = str(v or "").strip().lstrip("vV")
    nums = re.findall(r"\d+", v)
    letras = re.findall(r"[a-zA-Z]+", v)
    partes = [int(n) for n in nums[:4]]
    while len(partes) < 4:
        partes.append(0)
    return tuple(partes), (letras[0].lower() if letras else "")


def comparar_version(a, b):
    pa, la = partes_version(a)
    pb, lb = partes_version(b)
    if pa != pb:
        return -1 if pa < pb else 1
    if la == lb:
        return 0
    if not la:
        return -1
    if not lb:
        return 1
    return -1 if la < lb else 1


def version_en_rango(version, minimo=None, maximo=None, maximo_incl=False):
    """True si `version` cae en [minimo, maximo)."""
    if not version:
        return False
    if minimo and comparar_version(version, minimo) < 0:
        return False
    if maximo:
        c = comparar_version(version, maximo)
        if c > 0 or (c == 0 and not maximo_incl):
            return False
    return True


# --------------------------------------------------------------------------
# Base local de CVEs reales
# --------------------------------------------------------------------------

# Cada entrada: producto -> lista de reglas
#   min/max: rango de version afectada (max exclusivo salvo max_incl)
#   detectar: subcadenas (minusculas) que delatan el producto en banner/HTML
BASE_CVE = [
    {"cve": "CVE-2021-44228", "cvss": 10.0, "tipo": "rce",
     "producto": "Apache Log4j", "min": "2.0", "max": "2.15.0",
     "detectar": ["log4j", "log4shell"],
     "titulo": "Log4Shell: ejecucion remota de codigo via JNDI lookup",
     "detalle": "Un atacante que controle un valor registrado puede forzar la carga "
                "de codigo desde LDAP/RMI y ejecutar codigo arbitrario.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]},

    {"cve": "CVE-2017-5638", "cvss": 10.0, "tipo": "rce",
     "producto": "Apache Struts 2", "min": "2.3.5", "max": "2.5.11",
     "detectar": ["struts"],
     "titulo": "Struts 2: RCE via cabecera Content-Type malformada",
     "detalle": "El parser Jakarta Multipart permite ejecucion de comandos del sistema.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2017-5638"]},

    {"cve": "CVE-2022-22965", "cvss": 9.8, "tipo": "rce",
     "producto": "Spring Framework", "min": "5.3.0", "max": "5.3.18",
     "detectar": ["spring", "springboot"],
     "titulo": "Spring4Shell: RCE via data binding en Spring MVC",
     "detalle": "Permite modificar el classloader de Tomcat y escribir un JSP.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"]},

    {"cve": "CVE-2014-0160", "cvss": 7.5, "tipo": "fuga",
     "producto": "OpenSSL", "min": "1.0.1", "max": "1.0.1g",
     "detectar": ["openssl/1.0.1", "openssl 1.0.1"],
     "titulo": "Heartbleed: lectura de memoria del proceso TLS",
     "detalle": "La extension heartbeat devuelve hasta 64 KB de memoria, incluidas "
                "claves privadas y credenciales.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"]},

    {"cve": "CVE-2022-3602", "cvss": 7.5, "tipo": "desbordamiento",
     "producto": "OpenSSL 3.x", "min": "3.0.0", "max": "3.0.7",
     "detectar": ["openssl/3.0", "openssl 3.0"],
     "titulo": "OpenSSL 3.x: desbordamiento de pila al validar certificados X.509",
     "detalle": "Un certificado con nombre punycode manipulado puede provocar "
                "desbordamiento (potencial RCE).",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2022-3602"]},

    {"cve": "CVE-2021-41773", "cvss": 9.8, "tipo": "traversal",
     "producto": "Apache HTTP Server", "min": "2.4.49", "max": "2.4.50",
     "detectar": ["apache/2.4.49", "apache/2.4.50"],
     "titulo": "Apache 2.4.49: path traversal y posible RCE",
     "detalle": "La normalizacion de rutas permite salir del directorio raiz y "
                "leer ficheros, o ejecutar CGI si esta habilitado.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"]},

    {"cve": "CVE-2021-40438", "cvss": 9.0, "tipo": "ssrf",
     "producto": "Apache HTTP Server", "min": "2.4.0", "max": "2.4.49",
     "detectar": ["apache/2.4"],
     "titulo": "Apache httpd: SSRF con mod_proxy",
     "detalle": "Un `?unix:` manipulado permite redirigir la peticion a un servidor "
                "controlado por el atacante.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-40438"]},

    {"cve": "CVE-2021-23017", "cvss": 7.7, "tipo": "desbordamiento",
     "producto": "nginx", "min": "0.6.18", "max": "1.21.0",
     "detectar": ["nginx/1.2", "nginx/1.1", "nginx/1.0"],
     "titulo": "nginx: error off-by-one en el resolver DNS",
     "detalle": "Una respuesta DNS manipulada puede provocar desbordamiento de un byte.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"]},

    {"cve": "CVE-2018-15473", "cvss": 5.3, "tipo": "enumeracion",
     "producto": "OpenSSH", "min": "0", "max": "7.7",
     "detectar": ["openssh_6", "openssh_7.0", "openssh_7.1", "openssh_7.2",
                  "openssh_7.3", "openssh_7.4", "openssh_7.5", "openssh_7.6"],
     "titulo": "OpenSSH < 7.7: enumeracion de usuarios por canal temporal",
     "detalle": "La diferencia de tiempo al autenticar revela que usuarios existen.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2018-15473"]},

    {"cve": "CVE-2020-1938", "cvss": 9.8, "tipo": "traversal",
     "producto": "Apache Tomcat", "min": "7.0.0", "max": "9.0.31",
     "detectar": ["tomcat", "coyote"],
     "titulo": "Ghostcat: lectura de ficheros via conector AJP",
     "detalle": "El conector AJP expuesto permite leer ficheros de la aplicacion "
                "e incluir JSP si hay permisos de escritura.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2020-1938"]},

    {"cve": "CVE-2020-14882", "cvss": 9.8, "tipo": "rce",
     "producto": "Oracle WebLogic", "min": "10.3.6", "max": "12.2.1.5",
     "detectar": ["weblogic"],
     "titulo": "WebLogic: bypass de autenticacion en la consola",
     "detalle": "Permite alcanzar rutas administrativas sin credenciales y ejecutar codigo.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2020-14882"]},

    {"cve": "CVE-2018-7600", "cvss": 9.8, "tipo": "rce",
     "producto": "Drupal", "min": "7.0", "max": "7.58",
     "detectar": ["drupal 7", "x-drupal"],
     "titulo": "Drupalgeddon2: RCE sin autenticar",
     "detalle": "El renderizado de formularios permite ejecutar codigo remoto.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2018-7600"]},

    {"cve": "CVE-2022-21661", "cvss": 8.8, "tipo": "sqli",
     "producto": "WordPress", "min": "3.7", "max": "5.8.3",
     "detectar": ["wp-content", "wp-includes", "wordpress"],
     "titulo": "WordPress < 5.8.3: inyeccion SQL en WP_Query",
     "detalle": "Parametros concretos llegan a la consulta sin sanear correctamente.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2022-21661"]},

    {"cve": "CVE-2019-8331", "cvss": 6.1, "tipo": "xss",
     "producto": "Bootstrap", "min": "3.0.0", "max": "3.4.1",
     "detectar": ["bootstrap/3", "bootstrap.min.js"],
     "titulo": "Bootstrap 3.x: XSS en el atributo data-target",
     "detalle": "El saneado del selector permite inyectar HTML/JS.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2019-8331"]},

    {"cve": "CVE-2020-11022", "cvss": 6.1, "tipo": "xss",
     "producto": "jQuery", "min": "1.2", "max": "3.5.0",
     "detectar": ["jquery-1", "jquery-2", "jquery-3.4", "jquery.min.js"],
     "titulo": "jQuery < 3.5.0: XSS al pasar HTML a los metodos DOM",
     "detalle": "Incluso con htmlPrefilter, ciertos patrones ejecutan script.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2020-11022"]},

    {"cve": "CVE-2021-3129", "cvss": 9.8, "tipo": "rce",
     "producto": "Laravel Ignition", "min": "0", "max": "2.5.2",
     "detectar": ["ignition", "laravel"],
     "titulo": "Laravel Ignition: RCE por deserializacion en el modo debug",
     "detalle": "El endpoint de soluciones (_ignition/execute-solution) permite RCE.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-3129"]},

    {"cve": "CVE-2022-28346", "cvss": 9.8, "tipo": "sqli",
     "producto": "Django", "min": "2.2", "max": "4.0.4",
     "detectar": ["django", "csrfmiddlewaretoken"],
     "titulo": "Django: SQLi en QuerySet.annotate/aggregate",
     "detalle": "Los alias controlados por el usuario llegan al SQL generado.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2022-28346"]},

    {"cve": "CVE-2021-43798", "cvss": 7.5, "tipo": "traversal",
     "producto": "Grafana", "min": "8.0.0", "max": "8.3.1",
     "detectar": ["grafana"],
     "titulo": "Grafana 8.x: lectura de ficheros via path traversal en plugins",
     "detalle": "La ruta de plugins permite salir del directorio y leer /etc/passwd.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-43798"]},

    {"cve": "CVE-2020-5902", "cvss": 9.8, "tipo": "rce",
     "producto": "F5 BIG-IP", "min": "11.6.0", "max": "15.1.0",
     "detectar": ["big-ip", "bigip", "f5 networks"],
     "titulo": "F5 BIG-IP: RCE en la interfaz de gestion TMUI",
     "detalle": "Path traversal en /tmui/ permite ejecutar comandos como root.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2020-5902"]},

    {"cve": "CVE-2018-13379", "cvss": 9.8, "tipo": "traversal",
     "producto": "Fortinet FortiOS", "min": "5.4.0", "max": "6.4.2",
     "detectar": ["fortigate", "fortios"],
     "titulo": "FortiOS: lectura del fichero de sesiones SSL-VPN",
     "detalle": "Path traversal en el portal SSL-VPN expone credenciales en claro.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2018-13379"]},

    {"cve": "CVE-2019-19781", "cvss": 9.8, "tipo": "traversal",
     "producto": "Citrix ADC", "min": "10.5", "max": "13.0.47",
     "detectar": ["citrix", "netscaler"],
     "titulo": "Citrix ADC: path traversal y ejecucion de codigo",
     "detalle": "VPNSvc/ permite escribir plantillas y ejecutar comandos.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2019-19781"]},

    {"cve": "CVE-2021-26855", "cvss": 9.8, "tipo": "ssrf",
     "producto": "Microsoft Exchange", "min": "15.0", "max": "15.2.792",
     "detectar": ["exchange", "outlook web"],
     "titulo": "ProxyLogon: SSRF que encadena a RCE en Exchange",
     "detalle": "Permite autenticarse como administrador y escribir webshells.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-26855"]},

    {"cve": "CVE-2022-26134", "cvss": 9.8, "tipo": "rce",
     "producto": "Atlassian Confluence", "min": "1.3", "max": "7.18.1",
     "detectar": ["confluence"],
     "titulo": "Confluence: inyeccion OGNL sin autenticar",
     "detalle": "Un URI manipulado ejecuta expresiones OGNL en el servidor.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2022-26134"]},

    {"cve": "CVE-2019-11581", "cvss": 9.8, "tipo": "ssti",
     "producto": "Atlassian Jira", "min": "4.4", "max": "8.5.2",
     "detectar": ["jira", "atlassian"],
     "titulo": "Jira Server: inyeccion de plantillas en el formulario de contacto",
     "detalle": "La plantilla de email permite ejecutar codigo del servidor.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2019-11581"]},

    {"cve": "CVE-2021-22205", "cvss": 10.0, "tipo": "rce",
     "producto": "GitLab", "min": "10.0", "max": "13.10.3",
     "detectar": ["gitlab"],
     "titulo": "GitLab CE/EE: RCE al subir una imagen manipulada",
     "detalle": "ExifTool procesa el fichero y ejecuta codigo sin autenticar.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-22205"]},

    {"cve": "CVE-2021-21972", "cvss": 9.8, "tipo": "rce",
     "producto": "VMware vCenter", "min": "6.5", "max": "7.0.2",
     "detectar": ["vcenter", "vmware"],
     "titulo": "vCenter: RCE en el plugin de cliente vRealize Operations",
     "detalle": "Subida de fichero sin validar en /ui/vropspluginui/.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-21972"]},

    {"cve": "CVE-2022-23131", "cvss": 9.8, "tipo": "authz",
     "producto": "Zabbix", "min": "5.0.0", "max": "6.0.0",
     "detectar": ["zabbix"],
     "titulo": "Zabbix: suplantacion de sesion SAML",
     "detalle": "La cookie zbx_session manipulada permite entrar como admin.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2022-23131"]},

    {"cve": "CVE-2021-31166", "cvss": 9.8, "tipo": "rce",
     "producto": "Microsoft IIS / HTTP.sys", "min": "10.0", "max": "10.0.19042",
     "detectar": ["microsoft-iis", "iis/10"],
     "titulo": "HTTP.sys: uso despues de liberar en el analizador de peticiones",
     "detalle": "Un Accept-Encoding manipulado provoca RCE en el kernel.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-31166"]},

    {"cve": "CVE-2020-8163", "cvss": 8.8, "tipo": "rce",
     "producto": "Ruby on Rails", "min": "5.0.0", "max": "5.2.4",
     "detectar": ["rails", "x-runtime"],
     "titulo": "Rails: RCE via render parcial con parametros controlados",
     "detalle": "El parametro `render` permite ejecutar codigo Ruby.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2020-8163"]},

    {"cve": "CVE-2017-0144", "cvss": 8.1, "tipo": "rce",
     "producto": "SMBv1 (Windows)", "min": "0", "max": "1",
     "detectar": ["microsoft-ds", "netbios-ssn", "smb"],
     "titulo": "EternalBlue: RCE en SMBv1",
     "detalle": "El fallo en el tratamiento de paquetes SMB1 permite ejecucion remota.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2017-0144"]},

    {"cve": "CVE-2015-1427", "cvss": 9.3, "tipo": "rce",
     "producto": "Elasticsearch", "min": "1.3.0", "max": "1.4.3",
     "detectar": ["elasticsearch", "you know, for search"],
     "titulo": "Elasticsearch: RCE via scripting dinamico en Groovy",
     "detalle": "La busqueda permite ejecutar codigo sin autenticar.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2015-1427"]},

    {"cve": "CVE-2021-27905", "cvss": 9.8, "tipo": "ssrf",
     "producto": "Apache Solr", "min": "7.0.0", "max": "8.8.2",
     "detectar": ["solr"],
     "titulo": "Solr: SSRF en el manejador ReplicationHandler",
     "detalle": "El parametro `masterUrl` permite peticiones a destinos internos.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2021-27905"]},

    {"cve": "CVE-2018-1000861", "cvss": 9.8, "tipo": "rce",
     "producto": "Jenkins", "min": "2.0", "max": "2.138.4",
     "detectar": ["jenkins", "x-jenkins"],
     "titulo": "Jenkins: RCE por deserializacion en Stapler",
     "detalle": "El enrutado dinamico permite invocar metodos arbitrarios.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2018-1000861"]},

    {"cve": "CVE-2022-24086", "cvss": 9.8, "tipo": "rce",
     "producto": "Adobe Commerce / Magento", "min": "2.3.0", "max": "2.4.4",
     "detectar": ["magento", "adobe commerce"],
     "titulo": "Magento: RCE por inyeccion de plantilla en el checkout",
     "detalle": "El email de confirmacion permite inyectar plantillas.",
     "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2022-24086"]},
]

POR_CVE = {e["cve"]: e for e in BASE_CVE}


def _normalizar(texto):
    return str(texto or "").lower()


def buscar_cves_por_tecnologias(tecnologias, log=None):
    """tecnologias: dict {producto: valor_banner}. Devuelve lista de coincidencias."""
    encontrados = []
    if not tecnologias:
        return encontrados
    blob = " ".join("%s %s" % (k, v) for k, v in tecnologias.items())
    blob_n = _normalizar(blob)

    for entrada in BASE_CVE:
        pistas = entrada.get("detectar") or [_normalizar(entrada["producto"])]
        pista_ok = None
        for p in pistas:
            if _normalizar(p) in blob_n:
                pista_ok = p
                break
        if not pista_ok:
            continue

        version = _version_de_tecnologia(tecnologias, entrada)
        if version and not version_en_rango(version, entrada.get("min"), entrada.get("max")):
            if log:
                log("CVE: %s detectado pero version %s fuera del rango afectado"
                    % (entrada["producto"], version), "info")
            continue

        encontrados.append({
            "tipo": "cve", "severidad": _severidad(entrada["cvss"]),
            "titulo": "%s - %s" % (entrada["cve"], entrada["titulo"]),
            "detalle": entrada["detalle"],
            "url": (entrada.get("refs") or [""])[0],
            "evidencia": {"cve": entrada["cve"], "cvss": entrada["cvss"],
                          "producto": entrada["producto"],
                          "version_detectada": version or "no determinada",
                          "pista": pista_ok,
                          "referencias": entrada.get("refs", [])},
            "recomendacion": "Actualizar %s a una version no afectada y aplicar los "
                             "parches del proveedor." % entrada["producto"],
        })
        if log:
            log("CVE: %s (CVSS %.1f) coincide con %s"
                % (entrada["cve"], entrada["cvss"], entrada["producto"]), "exito")
    return encontrados


def _version_de_tecnologia(tecnologias, entrada):
    """Intenta extraer una version del banner que case con el producto."""
    claves = [_normalizar(entrada["producto"])] + [_normalizar(x) for x in entrada.get("detectar", [])]
    for nombre, valor in tecnologias.items():
        texto = _normalizar("%s %s" % (nombre, valor))
        if not any(c.split()[0] in texto for c in claves if c):
            continue
        m = re.search(r"(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)", texto)
        if m:
            return m.group(1)
    return None


def _severidad(cvss):
    if cvss >= 9.0:
        return "critico"
    if cvss >= 7.0:
        return "alto"
    if cvss >= 4.0:
        return "medio"
    if cvss > 0:
        return "bajo"
    return "info"


def consultar_nvd(termino, limite=8, timeout=12.0, log=None):
    """Consulta la API publica del NVD por palabra clave o CVE-XXXX-YYYY."""
    termino = (termino or "").strip()
    if not termino:
        return []
    if re.fullmatch(r"CVE-\d{4}-\d+", termino, re.IGNORECASE):
        url = "%s?cveId=%s" % (NVD, urllib.parse.quote(termino.upper()))
    else:
        url = "%s?keywordSearch=%s&resultsPerPage=%d" % (
            NVD, urllib.parse.quote(termino), max(1, min(limite, 20)))
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as e:
        if log:
            log("NVD: fallo la consulta (%s)" % e, "error")
        return []

    salida = []
    for item in data.get("vulnerabilities", [])[:limite]:
        cve = item.get("cve", {})
        cid = cve.get("id", "")
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        cvss = 0.0
        for clave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            lista = cve.get("metrics", {}).get(clave) or []
            if lista:
                cvss = float(lista[0].get("cvssData", {}).get("baseScore", 0.0) or 0.0)
                break
        salida.append({
            "tipo": "cve", "severidad": _severidad(cvss),
            "titulo": "%s (CVSS %.1f)" % (cid, cvss),
            "detalle": desc[:600],
            "url": "https://nvd.nist.gov/vuln/detail/" + cid,
            "evidencia": {"cve": cid, "cvss": cvss, "publicado": cve.get("published", "")},
            "recomendacion": "Revisar el aviso del proveedor y actualizar.",
        })
    if log:
        log("NVD: %d resultado(s) para '%s'" % (len(salida), termino),
            "exito" if salida else "aviso")
    return salida


def estadisticas_base():
    tipos = {}
    for e in BASE_CVE:
        tipos[e["tipo"]] = tipos.get(e["tipo"], 0) + 1
    return {"total": len(BASE_CVE), "por_tipo": tipos,
            "criticos": sum(1 for e in BASE_CVE if e["cvss"] >= 9.0)}
