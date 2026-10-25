"""Verificacion de la generacion de informes de HunterBug 1.0.

Ejecuta el catalogo real contra el laboratorio, construye el informe y
comprueba CADA formato: que se genere, que sea valido segun su especificacion
y que lleve dentro los datos y la evidencia.
"""

from __future__ import annotations

import csv
import html as html_mod
import io
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, ".")

from hb import checks, informe, informe_intercambio, metrics, net, pdfmin
from banco_pruebas import ServidorPrueba

fallos = []
ok = 0
SALIDA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_informes")


def check(nombre, cond, extra=""):
    global ok
    if cond:
        ok += 1
        print("  [OK]    %s %s" % (nombre, extra))
    else:
        fallos.append(nombre)
        print("  [FALLO] %s %s" % (nombre, extra))


def seccion(t):
    print("\n=== %s ===" % t)
    sys.stdout.flush()


if not os.path.isdir(SALIDA):
    os.makedirs(SALIDA)

with ServidorPrueba() as srv:
    objetivo = srv.base + "/buscar?q=test"

    seccion("Datos reales de la evaluacion")
    hallazgos, resultados, ctx = checks.ejecutar(objetivo, autorizado=True,
                                                 pausa=0.0)
    puntuacion, filas = metrics.cuadro(resultados, ctx=ctx)
    print("      %d hallazgos | puntuacion %s (%s) | %d peticiones"
          % (len(hallazgos), puntuacion["puntos"], puntuacion["letra"],
             ctx.peticiones))

    # trafico real, en bruto, como evidencia
    r = net.peticion_http(objetivo, timeout=10, seguir=1)
    trafico = [{"url": objetivo, "metodo": "GET", "status": r.status,
                "peticion": r.peticion_cruda, "respuesta": r.respuesta_cruda,
                "ms": r.tiempo * 1000, "ip": r.ip}]

    datos = informe.construir_datos(
        objetivo, hallazgos=hallazgos, resultados=resultados,
        puntuacion=puntuacion, filas_metricas=filas, ctx=ctx,
        dns={"A": [r.ip]}, ips=[r.ip],
        puertos=[{"puerto": srv.puerto, "servicio": "http",
                  "banner": "Apache/2.4.49"}],
        tecnologias={"Apache": "cabecera Server", "PHP": "X-Powered-By"},
        http_historial=trafico, autorizado=True, perfil="completo",
        duracion=1.23)

    check("Los datos reúnen los hallazgos",
          len(datos["hallazgos"]) == len(hallazgos),
          "-> %d" % len(datos["hallazgos"]))
    check("Los hallazgos van ordenados por severidad",
          [h["severidad"] for h in datos["hallazgos"]] ==
          sorted([h["severidad"] for h in datos["hallazgos"]],
                 key=lambda s: informe.SEVERIDADES.index(s)))
    check("El conteo por severidad cuadra",
          sum(datos["conteo"].values()) == len(datos["hallazgos"]),
          "-> %s" % datos["conteo"])
    check("Hay tráfico capturado como evidencia", len(datos["trafico"]) == 1)

    titular, parrafos = informe.resumen_ejecutivo(datos)
    check("El resumen ejecutivo tiene titular y párrafos",
          len(titular) > 20 and len(parrafos) >= 2)

    # ---------------------------------------------------------------- HTML
    seccion("Informe HTML")
    ruta_html = os.path.join(SALIDA, "informe.html")
    informe.escribir_html(datos, ruta_html)
    html = io.open(ruta_html, encoding="utf-8").read()
    check("Se genera el HTML", os.path.getsize(ruta_html) > 20000,
          "-> %.0f KB" % (os.path.getsize(ruta_html) / 1024))
    check("Es un documento HTML completo",
          html.startswith("<!DOCTYPE html>") and html.rstrip().endswith("</html>"))
    check("Declara el idioma español", 'lang="es"' in html)
    check("Es autocontenido (sin recursos externos)",
          not re.search(r'(src|href)="https?://(?!owasp\.org)', html),
          "-> sin <script>/<link> remotos")
    check("Incluye los gráficos SVG", html.count("<svg") >= 2,
          "-> %d svg" % html.count("<svg"))
    check("Incluye la puntuación", "%s / 100" % puntuacion["puntos"] in html)
    faltan = [h["id"] for h in datos["hallazgos"]
              if ('id="%s"' % h["id"]) not in html]
    check("Aparecen todos los hallazgos", not faltan, "-> faltan %s" % faltan[:5])

    def _como_html(v):
        if isinstance(v, (list, tuple)):
            return "\n".join(str(x) for x in v)
        if isinstance(v, dict):
            return json.dumps(v, ensure_ascii=False, indent=1)
        return str(v)

    sin_ev = []
    for h in datos["hallazgos"]:
        ev = h.get("evidencia") or {}
        if not ev:
            continue
        esperado = html_mod.escape(_como_html(list(ev.values())[0])[:60],
                                   quote=True)
        if esperado not in html:
            sin_ev.append(h["id"])
    check("Aparece la evidencia de cada hallazgo", not sin_ev,
          "-> faltan %s" % sin_ev[:5])
    check("Incluye el catálogo completo",
          all(('>' + r_["id"] + '<') in html or r_["id"] in html
              for r_ in resultados[:20]))
    check("Incluye el tráfico HTTP en bruto", "Petición" in html and
          "Respuesta" in html)
    check("Lleva el aviso de uso autorizado", "pruebas autorizadas" in html)
    check("Tiene estilos para impresión", "@media print" in html)

    # ---------------------------------------------------------------- PDF
    seccion("Informe PDF (generador propio, sin navegador)")
    ruta_pdf = os.path.join(SALIDA, "informe_propio.pdf")
    r, metodo = informe.a_pdf(datos, ruta_pdf, preferir_navegador=False)
    check("Se genera el PDF con el generador propio", metodo == "propio")
    check("El PDF es válido", pdfmin.es_pdf_valido(ruta_pdf))
    paginas = pdfmin.paginas_pdf(ruta_pdf)
    check("El PDF tiene varias páginas", paginas >= 3, "-> %d páginas" % paginas)
    print("      %.0f KB, %d páginas" % (os.path.getsize(ruta_pdf) / 1024,
                                         paginas))
    bruto = open(ruta_pdf, "rb").read()
    check("El PDF incrusta el objetivo",
          datos["meta"]["objetivo"].encode("latin-1", "replace")[:30] in bruto)
    ids_en_pdf = [h["id"] for h in datos["hallazgos"][:6]
                  if h["id"].encode("latin-1") in bruto]
    check("El PDF incluye los identificadores de los hallazgos",
          len(ids_en_pdf) >= 4, "-> %s" % ids_en_pdf)
    check("El PDF lleva el nombre de la herramienta",
          b"HunterBug" in bruto)

    seccion("Informe PDF (navegador headless)")
    ruta_pdf2 = os.path.join(SALIDA, "informe_navegador.pdf")
    r2, metodo2 = informe.a_pdf(datos, ruta_pdf2, preferir_navegador=True)
    nav = pdfmin.buscar_navegador()
    if nav:
        check("Con navegador disponible, el PDF se genera", os.path.exists(r2),
              "-> método %s" % metodo2)
        check("El PDF del navegador es válido", pdfmin.es_pdf_valido(r2),
              "-> %.0f KB" % (os.path.getsize(r2) / 1024))
        if metodo2 == "navegador":
            check("El PDF del navegador tiene varias páginas",
                  pdfmin.paginas_pdf(r2) >= 2,
                  "-> %d" % pdfmin.paginas_pdf(r2))
    else:
        check("Sin navegador se usa el generador propio", metodo2 == "propio")

    # ---------------------------------------------------------------- JSON
    seccion("Informe JSON")
    ruta_json = os.path.join(SALIDA, "informe.json")
    informe.a_json(datos, ruta_json)
    j = json.load(io.open(ruta_json, encoding="utf-8"))
    check("El JSON parsea", isinstance(j, dict))
    check("Lleva metadatos, puntuación y hallazgos",
          {"meta", "puntuacion", "hallazgos", "metricas"} <= set(j))
    check("Conserva todos los hallazgos",
          len(j["hallazgos"]) == len(datos["hallazgos"]))
    check("Conserva la evidencia",
          any(h.get("evidencia") for h in j["hallazgos"]))

    # ---------------------------------------------------------------- Markdown
    seccion("Informe Markdown")
    ruta_md = os.path.join(SALIDA, "informe.md")
    informe.escribir_markdown(datos, ruta_md)
    md = io.open(ruta_md, encoding="utf-8").read()
    check("El Markdown se genera", len(md) > 5000, "-> %.0f KB" % (len(md) / 1024))
    check("Tiene títulos y tablas",
          md.startswith("# ") and "|---|" in md)
    check("Incluye todos los hallazgos",
          all(("#### %s" % h["id"]) in md for h in datos["hallazgos"]))

    # ---------------------------------------------------------------- CSV
    seccion("Informe CSV")
    ruta_csv = os.path.join(SALIDA, "informe.csv")
    informe.a_csv(datos, ruta_csv)
    with io.open(ruta_csv, encoding="utf-8", newline="") as f:
        filas_csv = list(csv.reader(f))
    check("El CSV tiene cabecera y una fila por hallazgo",
          len(filas_csv) == len(datos["hallazgos"]) + 1,
          "-> %d filas" % len(filas_csv))
    check("Las columnas son las esperadas",
          filas_csv[0][:5] == ["n", "id", "severidad", "categoria", "titulo"])
    check("La evidencia viaja aplanada en una columna",
          any("=" in fila[-1] for fila in filas_csv[1:]))

    # ---------------------------------------------------------------- HAR
    seccion("HAR 1.2 (para importar en OWASP ZAP)")
    ruta_har = os.path.join(SALIDA, "trafico.har")
    informe_intercambio.escribir_har(datos, ruta_har)
    har = json.load(io.open(ruta_har, encoding="utf-8"))
    log = har.get("log", {})
    check("El HAR parsea y declara la versión 1.2", log.get("version") == "1.2")
    check("Declara el creador", log.get("creator", {}).get("name", "")
          .startswith("HunterBug"))
    entradas = log.get("entries", [])
    check("Tiene una entrada por petición capturada",
          len(entradas) == len(datos["trafico"]), "-> %d" % len(entradas))
    if entradas:
        e = entradas[0]
        check("La entrada tiene los campos obligatorios del HAR",
              {"startedDateTime", "time", "request", "response", "cache",
               "timings"} <= set(e))
        req, res = e["request"], e["response"]
        check("La petición tiene método, URL y cabeceras",
              req.get("method") and req.get("url") and req.get("headers"))
        check("La URL de la petición es la del objetivo",
              req["url"] == objetivo, "-> %s" % req["url"])
        check("La respuesta tiene status y contenido",
              isinstance(res.get("status"), int) and "content" in res,
              "-> status %s" % res.get("status"))
        check("El contenido de la respuesta lleva el cuerpo",
              len(res["content"].get("text", "")) > 100,
              "-> %d bytes" % len(res["content"].get("text", "")))
        check("Las cabeceras son listas de name/value",
              all({"name", "value"} <= set(h) for h in req["headers"]))
        check("Los tiempos son numéricos",
              isinstance(e["time"], (int, float)) and
              isinstance(e["timings"]["wait"], (int, float)))

    # ---------------------------------------------------------------- Burp
    seccion("Burp Suite XML")
    ruta_burp = os.path.join(SALIDA, "hallazgos_burp.xml")
    informe_intercambio.escribir_burp_xml(datos, ruta_burp)
    texto_burp = io.open(ruta_burp, encoding="utf-8").read()
    raiz = ET.fromstring(texto_burp)
    check("El XML de Burp parsea", raiz.tag == "issues", "-> <%s>" % raiz.tag)
    check("Declara burpVersion (lo que usan los importadores)",
          "burpVersion" in raiz.attrib)
    check("El DTD lleva el marcador que detectan los importadores",
          "<!ATTLIST issues burpVersion" in texto_burp)
    issues = raiz.findall("issue")
    check("Hay un <issue> por hallazgo", len(issues) == len(datos["hallazgos"]),
          "-> %d" % len(issues))
    if issues:
        it = issues[0]
        for etiqueta in ("serialNumber", "type", "name", "host", "path",
                         "location", "severity", "confidence", "issueDetail"):
            check("El issue lleva <%s>" % etiqueta, it.find(etiqueta) is not None)
        sev = it.find("severity").text
        check("La severidad es una de las de Burp",
              sev in ("High", "Medium", "Low", "Information"), "-> %s" % sev)
        conf = it.find("confidence").text
        check("La confianza es una de las de Burp",
              conf in ("Certain", "Firm", "Tentative"), "-> %s" % conf)
        rr = it.find("requestresponse")
        check("El issue adjunta la petición y la respuesta en bruto",
              rr is not None and rr.find("request") is not None and
              rr.find("response") is not None)
        check("La petición adjunta lleva HTTP real",
              "HTTP/" in (rr.find("request").text or ""))
    # el CDATA no debe haberse roto
    check("No hay CDATA mal cerrado",
          texto_burp.count("<![CDATA[") == texto_burp.count("]]>"))
    check("El XML de Burp no lleva caracteres de control prohibidos",
          not informe_intercambio._RE_CONTROL.search(texto_burp),
          "-> regresión de bytes NUL del cuerpo HTTP")

    # ---------------------------------------------------------------- ZAP
    seccion("OWASP ZAP XML")
    ruta_zap = os.path.join(SALIDA, "hallazgos_zap.xml")
    informe_intercambio.escribir_zap_xml(datos, ruta_zap)
    texto_zap = io.open(ruta_zap, encoding="utf-8").read()
    raiz_zap = ET.fromstring(texto_zap)
    check("El XML de ZAP parsea", raiz_zap.tag == "OWASPZAPReport",
          "-> <%s>" % raiz_zap.tag)
    check("Declara versión y fecha",
          "version" in raiz_zap.attrib and "generated" in raiz_zap.attrib)
    sitios = raiz_zap.findall("site")
    check("Tiene un <site>", len(sitios) == 1)
    alertas = sitios[0].findall("alerts/alertitem") if sitios else []
    check("Hay un <alertitem> por hallazgo",
          len(alertas) == len(datos["hallazgos"]), "-> %d" % len(alertas))
    if alertas:
        a = alertas[0]
        for etiqueta in ("pluginid", "alert", "name", "riskcode", "confidence",
                         "riskdesc", "desc", "solution", "cweid", "instances"):
            check("La alerta lleva <%s>" % etiqueta, a.find(etiqueta) is not None)
        check("riskcode está en el rango de ZAP",
              a.find("riskcode").text in ("0", "1", "2", "3"),
              "-> %s" % a.find("riskcode").text)
        check("cweid es numérico", a.find("cweid").text.isdigit(),
              "-> %s" % a.find("cweid").text)
        check("La alerta incluye la instancia con la URL",
              a.find("instances/instance/uri") is not None)

    # ---------------------------------------------------------------- SARIF
    seccion("SARIF 2.1.0 (GitHub, GitLab, Azure, add-on de ZAP)")
    ruta_sarif = os.path.join(SALIDA, "hallazgos.sarif")
    informe_intercambio.escribir_sarif(datos, ruta_sarif)
    sarif = json.load(io.open(ruta_sarif, encoding="utf-8"))
    check("El SARIF parsea", isinstance(sarif, dict))
    check("Declara la versión 2.1.0", sarif.get("version") == "2.1.0")
    check("Apunta al esquema oficial",
          sarif.get("$schema", "").endswith("sarif-2.1.0.json"),
          "-> %s" % sarif.get("$schema"))
    corridas = sarif.get("runs", [])
    check("Tiene una corrida", len(corridas) == 1)
    if corridas:
        run = corridas[0]
        drv = run["tool"]["driver"]
        check("El driver declara nombre y versión",
              drv.get("name") == "HunterBug" and drv.get("version"))
        reglas = drv.get("rules", [])
        check("Declara las reglas del catálogo", len(reglas) >= 20,
              "-> %d reglas" % len(reglas))
        check("Cada regla tiene id y descripción",
              all(r.get("id") and r.get("shortDescription") for r in reglas))
        check("Las reglas mapean CWE",
              any("cwe" in r.get("properties", {}) for r in reglas))
        res = run.get("results", [])
        check("Hay un resultado por hallazgo", len(res) == len(datos["hallazgos"]),
              "-> %d" % len(res))
        check("Los niveles son válidos para SARIF",
              all(r.get("level") in ("none", "note", "warning", "error")
                  for r in res))
        check("Cada resultado apunta a una regla",
              all(r.get("ruleId") for r in res))
        check("Cada resultado tiene ubicación",
              all(r.get("locations") for r in res))
        check("El resultado lleva la URL del objetivo",
              any(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                  == objetivo for r in res))
        check("Los resultados adjuntan petición y respuesta web",
              any("webRequest" in r and "webResponse" in r for r in res))
        check("La evidencia viaja en las propiedades",
              any("evidencia" in r.get("properties", {}) for r in res))

    # ---------------------------------------------------------------- nombres
    seccion("Nombres de fichero")
    n1 = informe.nombre_por_defecto(objetivo, "html", SALIDA)
    check("El nombre se deriva del objetivo de forma legible",
          "127.0.0.1" in os.path.basename(n1) and n1.endswith(".html"),
          "-> %s" % os.path.basename(n1))
    n2 = informe.nombre_por_defecto("https://a.test/x/y?z=1", "pdf", SALIDA)
    check("Limpia caracteres no válidos en el nombre",
          re.fullmatch(r"[A-Za-z0-9_\-\.]+", os.path.basename(n2)) is not None,
          "-> %s" % os.path.basename(n2))

    # ---------------------------------------------------------------- vacio
    seccion("Informe sin hallazgos")
    vacio = informe.construir_datos(objetivo, hallazgos=[], resultados=[],
                                    puntuacion={"puntos": 100.0, "letra": "A",
                                                "descripcion": "excelente",
                                                "cobertura": 100.0,
                                                "ejecutados": 203,
                                                "estados": {}, "categorias": []},
                                    autorizado=False)
    h_vacio = informe.a_html(vacio)
    check("El HTML sin hallazgos se genera igual",
          "No se registraron hallazgos" in h_vacio)
    check("Avisa de que fue pasivo", "pasiva" in h_vacio.lower())
    ruta_v = os.path.join(SALIDA, "vacio.pdf")
    informe.a_pdf(vacio, ruta_v, preferir_navegador=False)
    check("El PDF sin hallazgos es válido", pdfmin.es_pdf_valido(ruta_v))
    check("El HAR vacío es válido",
          informe_intercambio.a_har(vacio)["log"]["version"] == "1.2")
    ET.fromstring(informe_intercambio.a_burp_xml(vacio))
    ET.fromstring(informe_intercambio.a_zap_xml(vacio))
    check("Los XML vacíos parsean sin hallazgos", True)

print("\n" + "=" * 64)
print("PRUEBAS OK: %d | FALLOS: %d" % (ok, len(fallos)))
print("Informes de muestra en:", SALIDA)
if fallos:
    for f in fallos[:30]:
        print("   - " + str(f))
    sys.exit(1)
print("GENERACION DE INFORMES VERIFICADA")
