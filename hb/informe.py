"""HunterBug - generación del informe de la evaluación.

Convierte el resultado de una evaluación en un informe detallado con toda la
evidencia, en varios formatos:

  * HTML — informe completo, autocontenido y listo para abrir o imprimir.
  * PDF  — el mismo informe en PDF (navegador headless, o el generador propio
           de `hb.pdfmin` si no hay navegador).
  * JSON — los datos crudos, para automatizar.
  * Markdown — para pegar en un reporte o en una wiki.
  * CSV — una fila por hallazgo, para hoja de cálculo.

Los formatos pensados para intercambio con otras herramientas (HAR, Burp, ZAP,
SARIF) viven en `hb.informe_intercambio`.
"""

from __future__ import annotations

import csv
import html
import io
import json
import os
import time
import urllib.parse

from . import pdfmin
from .informe_intercambio import limpiar_control, limpiar_profundo

VERSION = "1.0"
SEVERIDADES = ["critico", "alto", "medio", "bajo", "info"]

COLOR_SEV = {
    "critico": "#b91c1c", "alto": "#ea580c", "medio": "#ca8a04",
    "bajo": "#15803d", "info": "#475569",
}
FONDO_SEV = {
    "critico": "#fef2f2", "alto": "#fff7ed", "medio": "#fefce8",
    "bajo": "#f0fdf4", "info": "#f8fafc",
}
ETIQUETA_SEV = {
    "critico": "Crítico", "alto": "Alto", "medio": "Medio", "bajo": "Bajo",
    "info": "Informativo",
}
ETIQUETA_ESTADO = {
    "fallo": "FALLO", "ok": "OK", "omitido": "OMITIDO", "error": "ERROR",
    "cancelado": "CANCELADO",
}


# ===========================================================================
# Datos normalizados
# ===========================================================================

def _norm_hallazgo(h, indice=0):
    """Normaliza un hallazgo venga de donde venga."""
    sev = str(h.get("severidad", h.get("severity", "info"))).lower()
    if sev not in SEVERIDADES:
        sev = "info"
    return {
        "n": indice,
        "id": limpiar_control(h.get("id_check") or h.get("id")
                              or h.get("tipo") or "HB-?"),
        "titulo": limpiar_control(h.get("titulo") or h.get("title")
                                  or "Hallazgo sin título"),
        "severidad": sev,
        "confianza": limpiar_control(h.get("confianza", "")),
        "categoria": limpiar_control(h.get("categoria") or h.get("tipo")
                                     or "otros"),
        "modulo": limpiar_control(h.get("modulo", "")),
        "cwe": limpiar_control(h.get("cwe", "")),
        "owasp": limpiar_control(h.get("owasp", "")),
        "url": limpiar_control(h.get("url", "")),
        "parametro": limpiar_control(h.get("parametro", "")),
        "detalle": limpiar_control(h.get("detalle") or h.get("descripcion")
                                   or ""),
        "recomendacion": limpiar_control(h.get("recomendacion", "")),
        "evidencia": limpiar_profundo(h.get("evidencia") or {}),
    }


def construir_datos(objetivo, hallazgos=None, resultados=None, puntuacion=None,
                    filas_metricas=None, ctx=None, dns=None, ips=None,
                    puertos=None, tecnologias=None, http_historial=None,
                    cves=None, grafo=None, autorizado=False, perfil="",
                    duracion=0.0, metadatos=None):
    """Reúne todo lo que ha producido la evaluación en una estructura única."""
    hallazgos = list(hallazgos or [])
    norm = []
    for i, h in enumerate(hallazgos, start=1):
        norm.append(_norm_hallazgo(h, i))
    norm.sort(key=lambda x: (SEVERIDADES.index(x["severidad"]), x["id"]))

    conteo = {s: 0 for s in SEVERIDADES}
    for h in norm:
        conteo[h["severidad"]] += 1

    # métricas de red: del cuadro si está, si no del contexto
    metricas = list(filas_metricas or [])
    if not metricas and ctx is not None:
        try:
            from . import metrics as _m
            _, metricas = _m.cuadro(resultados or [], ctx=ctx)
        except Exception:
            metricas = []

    trafico = []
    for t in (http_historial or []):
        pet = limpiar_control(t.get("peticion", "") or "")
        metodo = t.get("metodo") or ""
        if not metodo and pet:
            primera = pet.split("\n", 1)[0].split()
            if primera:
                metodo = primera[0]
        trafico.append({
            "url": limpiar_control(t.get("url", "")),
            "metodo": limpiar_control(metodo or "GET"),
            "status": t.get("status", 0),
            "peticion": pet,
            "respuesta": limpiar_control(t.get("respuesta", "") or ""),
            "ms": t.get("ms", 0.0),
            "ip": limpiar_control(t.get("ip", "")),
        })

    meta = {
        "herramienta": "HunterBug %s" % VERSION,
        "objetivo": objetivo,
        "fecha": time.strftime("%Y-%m-%d %H:%M:%S"),
        "fecha_larga": time.strftime("%d/%m/%Y a las %H:%M"),
        "autorizado": bool(autorizado),
        "perfil": perfil or "estándar",
        "duracion_s": round(float(duracion or 0.0), 2),
    }
    if metadatos:
        meta.update(metadatos)

    return {
        "meta": meta,
        "puntuacion": puntuacion or {},
        "metricas": metricas,
        "hallazgos": norm,
        "conteo": conteo,
        "resultados": list(resultados or []),
        "superficie": {
            "dns": dns or {},
            "ips": list(ips or []),
            "puertos": list(puertos or []),
            "tecnologias": tecnologias or {},
            "cves": list(cves or []),
        },
        "trafico": trafico,
        "grafo": grafo,
    }


def resumen_ejecutivo(datos):
    """Devuelve (titular, parrafos) con la lectura del resultado."""
    p = datos.get("puntuacion") or {}
    c = datos.get("conteo") or {}
    n = len(datos.get("hallazgos") or [])
    obj = datos["meta"]["objetivo"]

    if p:
        titular = ("El objetivo obtiene %s sobre 100 (calificación %s, %s)."
                   % (p.get("puntos", "?"), p.get("letra", "?"),
                      p.get("descripcion", "")))
    else:
        titular = "Se han registrado %d hallazgos sobre %s." % (n, obj)

    parrafos = []
    if n == 0:
        parrafos.append(
            "No se han registrado hallazgos. Conviene recordar que la ausencia "
            "de hallazgos no equivale a ausencia de vulnerabilidades: "
            "significa que las comprobaciones automáticas de esta pasada no "
            "encontraron nada con la evidencia recogida.")
    else:
        partes = []
        for s in SEVERIDADES:
            if c.get(s):
                partes.append("%d %s" % (c[s], ETIQUETA_SEV[s].lower()))
        parrafos.append("Se han registrado %d hallazgos: %s."
                        % (n, ", ".join(partes) if partes else "sin clasificar"))

    if p:
        cats = p.get("categorias") or []
        peores = [x for x in cats if x.get("fallos")][:3]
        if peores:
            parrafos.append(
                "Las áreas con peor resultado son %s."
                % ", ".join("%s (%s puntos, %d fallo(s))"
                            % (x["categoria"], x["puntos"], x["fallos"])
                            for x in peores))
        parrafos.append(
            "Se ejecutaron %d de los %d chequeos del catálogo (cobertura "
            "%.1f%%). Los chequeos omitidos requieren confirmar la "
            "autorización o solo aplican sobre HTTPS."
            % (p.get("ejecutados", 0),
               p.get("ejecutados", 0) + p.get("estados", {}).get("omitido", 0)
               + p.get("estados", {}).get("error", 0)
               + p.get("estados", {}).get("cancelado", 0),
               p.get("cobertura", 0.0)))

    if not datos["meta"].get("autorizado"):
        parrafos.append(
            "La evaluación se ejecutó SIN confirmar autorización, por lo que "
            "solo se realizaron comprobaciones pasivas (no se envió ninguna "
            "petición de ataque).")
    return titular, parrafos


# ===========================================================================
# Gráficos SVG (sin dependencias, se imprimen bien en PDF)
# ===========================================================================

def _svg_barras_h(pares, ancho=520, alto_fila=22, color_fn=None,
                  etiqueta_ancho=120):
    if not pares:
        return ""
    alto = len(pares) * alto_fila + 22
    util = ancho - etiqueta_ancho - 46
    base_y = alto - 16
    t = []
    t.append('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
             'viewBox="0 0 %d %d" role="img">' % (ancho, alto, ancho, alto))
    # rejilla vertical con etiquetas, para poder leer valores intermedios
    for frac in (0, 0.25, 0.5, 0.75, 1.0):
        x = etiqueta_ancho + util * frac
        t.append('<line x1="%.1f" y1="2" x2="%.1f" y2="%d" stroke="#e5e7eb" '
                 'stroke-width="1"/>' % (x, x, base_y))
        t.append('<text x="%.1f" y="%d" font-size="9" fill="#94a3b8" '
                 'text-anchor="middle" '
                 'font-family="Helvetica,Arial,sans-serif">%d</text>'
                 % (x, alto - 4, round(100 * frac)))
    for i, (nombre, valor) in enumerate(pares):
        y = i * alto_fila + 3
        color = color_fn(valor) if color_fn else "#0b3d2c"
        t.append('<text x="0" y="%d" font-size="11" fill="#334155" '
                 'font-family="Helvetica,Arial,sans-serif">%s</text>'
                 % (y + 12, html.escape(str(nombre)[:18])))
        t.append('<rect x="%d" y="%d" width="%d" height="13" fill="#e5e7eb" '
                 'rx="2"/>' % (etiqueta_ancho, y, util))
        w = max(0.0, min(1.0, (valor or 0) / 100.0)) * util
        if w >= 1.5:
            t.append('<rect x="%d" y="%d" width="%.1f" height="13" fill="%s" '
                     'rx="2"/>' % (etiqueta_ancho, y, w, color))
        else:
            # valor cero: una marca fina para que no parezca un dato que falta
            t.append('<rect x="%d" y="%d" width="1.5" height="13" fill="%s" '
                     'rx="1"/>' % (etiqueta_ancho, y, color))
        t.append('<text x="%d" y="%d" font-size="11" fill="#111" '
                 'font-weight="bold" font-family="Helvetica,Arial,sans-serif">'
                 '%.1f</text>' % (etiqueta_ancho + util + 8, y + 12, valor or 0))
    t.append("</svg>")
    return "".join(t)


def _svg_columnas(conteo, ancho=520, alto=170):
    """Columnas por severidad."""
    if not conteo:
        return ""
    valores = [(s, conteo.get(s, 0)) for s in SEVERIDADES]
    maximo = max([v for _, v in valores] + [1])
    n = len(valores)
    margen_izq = 34
    util = ancho - margen_izq - 14
    ancho_col = util / n
    base = alto - 28
    t = ['<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
         'viewBox="0 0 %d %d" role="img">' % (ancho, alto, ancho, alto)]
    # rejilla
    for frac in (0, 0.25, 0.5, 0.75, 1.0):
        y = base - frac * (base - 18)
        t.append('<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="#e5e7eb" '
                 'stroke-width="1"/>' % (margen_izq, y, ancho - 14, y))
        t.append('<text x="%d" y="%.1f" font-size="9" fill="#94a3b8" '
                 'text-anchor="end" font-family="Helvetica,Arial,sans-serif">'
                 '%d</text>' % (margen_izq - 6, y + 3, round(maximo * frac)))
    for i, (sev, valor) in enumerate(valores):
        h = (valor / maximo) * (base - 18) if maximo else 0
        x = margen_izq + i * ancho_col + ancho_col * 0.18
        w = ancho_col * 0.64
        t.append('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" '
                 'fill="%s" rx="2"/>'
                 % (x, base - h, w, max(h, 0.5), COLOR_SEV[sev]))
        t.append('<text x="%.1f" y="%.1f" font-size="11" font-weight="bold" '
                 'fill="#111" text-anchor="middle" '
                 'font-family="Helvetica,Arial,sans-serif">%d</text>'
                 % (x + w / 2, base - h - 5, valor))
        t.append('<text x="%.1f" y="%d" font-size="9" fill="#475569" '
                 'text-anchor="middle" '
                 'font-family="Helvetica,Arial,sans-serif">%s</text>'
                 % (x + w / 2, base + 14, ETIQUETA_SEV[sev][:9]))
    t.append("</svg>")
    return "".join(t)


def _color_categoria(v):
    return "#b91c1c" if v < 40 else ("#ea580c" if v < 70 else "#15803d")


# ===========================================================================
# HTML
# ===========================================================================

CSS = """
:root{--tinta:#111827;--suave:#6b7280;--borde:#e5e7eb;--fondo:#ffffff;
      --papel:#f9fafb;--acento:#0b3d2c}
*{box-sizing:border-box}
body{margin:0;background:var(--papel);color:var(--tinta);
     font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,
     Helvetica,Arial,sans-serif;font-size:14px;line-height:1.55}
.hoja{max-width:960px;margin:0 auto;background:var(--fondo);padding:44px 52px;
      box-shadow:0 1px 4px rgba(0,0,0,.08)}
h1{font-size:27px;margin:0 0 6px;letter-spacing:-.4px}
h2{font-size:19px;margin:38px 0 12px;padding-bottom:7px;
   border-bottom:2px solid var(--acento);color:var(--acento)}
h3{font-size:15px;margin:24px 0 8px}
h4{font-size:13px;margin:16px 0 6px;color:#374151}
p{margin:8px 0}
small,.suave{color:var(--suave)}
code,kbd{font-family:ui-monospace,Consolas,monospace;font-size:12.5px;
     background:#f1f5f9;padding:1px 5px;border-radius:3px}
pre{background:#0f172a;color:#e2e8f0;padding:12px 14px;border-radius:6px;
    overflow-x:auto;font-size:12px;line-height:1.45;margin:8px 0}
pre code{background:none;color:inherit;padding:0}
.cabecera{border-bottom:3px solid var(--acento);padding-bottom:18px;
          margin-bottom:26px}
.cabecera .sub{color:var(--suave);font-size:13px}
.rejilla{display:flex;gap:22px;flex-wrap:wrap;margin:20px 0}
.tarjeta{flex:1 1 210px;border:1px solid var(--borde);border-radius:8px;
         padding:14px 16px;background:var(--papel)}
.tarjeta .etq{font-size:11px;text-transform:uppercase;letter-spacing:.6px;
              color:var(--suave);font-weight:600}
.tarjeta .val{font-size:23px;font-weight:700;margin-top:3px}
.nota{font-size:22px;font-weight:700}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;
       font-size:11px;font-weight:700;letter-spacing:.4px;color:#fff}
.chip{display:inline-block;padding:1px 7px;border-radius:4px;font-size:11px;
      background:#f1f5f9;color:#334155;margin-right:5px}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px}
th{background:var(--acento);color:#fff;text-align:left;padding:8px 9px;
   font-size:12px;font-weight:600}
td{border-bottom:1px solid var(--borde);padding:7px 9px;vertical-align:top}
tr:nth-child(even) td{background:#fbfcfd}
.hallazgo{border:1px solid var(--borde);border-left-width:5px;border-radius:6px;
          padding:14px 16px;margin:14px 0;background:#fff}
.hallazgo .tit{font-size:15px;font-weight:700;margin:0 0 4px}
.hallazgo .meta{font-size:12px;color:var(--suave);margin-bottom:8px}
.evidencia{background:#f8fafc;border:1px solid var(--borde);border-radius:5px;
           padding:9px 11px;margin-top:9px;font-size:12.5px}
.evidencia dl{margin:0;display:grid;grid-template-columns:auto 1fr;
              gap:2px 12px}
.evidencia dt{font-weight:600;color:#374151;white-space:nowrap}
.evidencia dd{margin:0;word-break:break-word;
              font-family:ui-monospace,Consolas,monospace}
.rec{background:#f0fdf4;border-left:3px solid #15803d;padding:8px 11px;
     margin-top:9px;font-size:13px}
.indice{columns:2;column-gap:30px;font-size:13px}
.indice a{color:var(--acento);text-decoration:none}
.indice a:hover{text-decoration:underline}
.pie{margin-top:44px;padding-top:16px;border-top:1px solid var(--borde);
     font-size:12px;color:var(--suave)}
.aviso{background:#fffbeb;border:1px solid #fde68a;border-radius:6px;
       padding:11px 14px;font-size:13px;margin:16px 0}
@media print{
  body{background:#fff;font-size:11.5px}
  .hoja{box-shadow:none;padding:0;max-width:none}
  h2{page-break-after:avoid}
  .hallazgo,table,pre,.tarjeta{page-break-inside:avoid}
  a{color:inherit;text-decoration:none}
}
"""


def _esc(v):
    return html.escape(str(v), quote=True)


def _tabla_metricas(datos):
    filas = datos.get("metricas") or []
    if not filas:
        return ""
    t = ['<table><thead><tr><th style="width:58%">Métrica</th>'
         '<th>Valor</th></tr></thead><tbody>']
    for k, v in filas:
        t.append("<tr><td>%s</td><td><strong>%s</strong></td></tr>"
                 % (_esc(k), _esc(v)))
    t.append("</tbody></table>")
    return "".join(t)


def _tabla_superficie(datos):
    s = datos.get("superficie") or {}
    partes = []
    dns = s.get("dns") or {}
    if any(dns.values()):
        filas = []
        for tipo in sorted(dns):
            for v in dns[tipo]:
                filas.append([tipo, v])
        partes.append("<h3>Registros DNS</h3>")
        partes.append('<table><thead><tr><th style="width:90px">Tipo</th>'
                      "<th>Valor</th></tr></thead><tbody>")
        for tipo, v in filas:
            partes.append("<tr><td><code>%s</code></td><td>%s</td></tr>"
                          % (_esc(tipo), _esc(v)))
        partes.append("</tbody></table>")
    if s.get("ips"):
        partes.append("<h3>Direcciones IP</h3><p>%s</p>"
                      % " ".join('<span class="chip">%s</span>' % _esc(i)
                                 for i in s["ips"]))
    if s.get("puertos"):
        partes.append("<h3>Puertos y servicios</h3>")
        partes.append('<table><thead><tr><th style="width:80px">Puerto</th>'
                      '<th style="width:150px">Servicio</th><th>Banner</th>'
                      "</tr></thead><tbody>")
        for p in s["puertos"]:
            partes.append("<tr><td><code>%s</code></td><td>%s</td>"
                          "<td>%s</td></tr>"
                          % (_esc(p.get("puerto", "")),
                             _esc(p.get("servicio", "")),
                             _esc(str(p.get("banner", ""))[:300])))
        partes.append("</tbody></table>")
    tec = s.get("tecnologias") or {}
    if tec:
        partes.append("<h3>Tecnologías detectadas</h3>")
        partes.append('<table><thead><tr><th style="width:220px">Producto</th>'
                      "<th>Evidencia</th></tr></thead><tbody>")
        for k in sorted(tec):
            partes.append("<tr><td><strong>%s</strong></td><td>%s</td></tr>"
                          % (_esc(k), _esc(str(tec[k])[:300])))
        partes.append("</tbody></table>")
    if s.get("cves"):
        partes.append("<h3>Vulnerabilidades conocidas (CVE)</h3>")
        partes.append('<table><thead><tr><th style="width:130px">CVE</th>'
                      '<th style="width:80px">Severidad</th><th>Título</th>'
                      "</tr></thead><tbody>")
        for c in s["cves"]:
            sev = str(c.get("severidad", "info")).lower()
            partes.append(
                "<tr><td><code>%s</code></td><td>"
                '<span class="badge" style="background:%s">%s</span></td>'
                "<td>%s</td></tr>"
                % (_esc(c.get("cve", c.get("id", ""))),
                   COLOR_SEV.get(sev, COLOR_SEV["info"]),
                   _esc(ETIQUETA_SEV.get(sev, sev)),
                   _esc(c.get("titulo", c.get("descripcion", "")))))
        partes.append("</tbody></table>")
    return "".join(partes)


def _bloque_hallazgo(h, con_ancla=True):
    color = COLOR_SEV[h["severidad"]]
    t = ['<div class="hallazgo" id="%s" style="border-left-color:%s;'
         'background:%s">' % (_esc(h["id"]), color,
                              FONDO_SEV[h["severidad"]])]
    t.append('<p class="tit">%s</p>' % _esc(h["titulo"]))
    meta = ['<span class="badge" style="background:%s">%s</span>'
            % (color, _esc(ETIQUETA_SEV[h["severidad"]]))]
    if h.get("id"):
        meta.append('<span class="chip">%s</span>' % _esc(h["id"]))
    if h.get("categoria"):
        meta.append('<span class="chip">%s</span>' % _esc(h["categoria"]))
    if h.get("cwe"):
        meta.append('<span class="chip">%s</span>' % _esc(h["cwe"]))
    if h.get("owasp"):
        meta.append('<span class="chip">%s</span>' % _esc(h["owasp"]))
    if h.get("parametro"):
        meta.append('<span class="chip">parámetro: %s</span>'
                    % _esc(h["parametro"]))
    if h.get("confianza"):
        meta.append('<span class="chip">confianza: %s</span>'
                    % _esc(h["confianza"]))
    t.append('<div class="meta">%s</div>' % " ".join(meta))
    if h.get("url"):
        t.append("<p><small>URL: <code>%s</code></small></p>" % _esc(h["url"]))
    if h.get("detalle"):
        t.append("<p>%s</p>" % _esc(h["detalle"]))
    ev = h.get("evidencia") or {}
    if ev:
        t.append('<div class="evidencia"><strong>Evidencia</strong><dl>')
        for k, v in ev.items():
            if isinstance(v, (list, tuple)):
                v = "\n".join(str(x) for x in v)
            elif isinstance(v, dict):
                v = json.dumps(v, ensure_ascii=False, indent=1)
            t.append("<dt>%s</dt><dd>%s</dd>" % (_esc(k), _esc(str(v)[:2000])))
        t.append("</dl></div>")
    if h.get("recomendacion"):
        t.append('<div class="rec"><strong>Recomendación:</strong> %s</div>'
                 % _esc(h["recomendacion"]))
    t.append("</div>")
    return "".join(t)


def a_html(datos, titulo_extra=""):
    """Devuelve el informe completo en HTML, autocontenido."""
    meta = datos["meta"]
    p = datos.get("puntuacion") or {}
    titular, parrafos = resumen_ejecutivo(datos)

    h = []
    h.append("<!DOCTYPE html><html lang=\"es\"><head><meta charset=\"utf-8\">")
    h.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
    h.append("<title>Informe HunterBug — %s</title>" % _esc(meta["objetivo"]))
    h.append("<style>%s</style></head><body><div class=\"hoja\">" % CSS)

    # --- portada
    h.append('<div class="cabecera">')
    h.append("<h1>Informe de evaluación de seguridad</h1>")
    h.append('<div class="sub"><strong>Objetivo:</strong> %s<br>'
             "<strong>Herramienta:</strong> %s &nbsp;·&nbsp; "
             "<strong>Fecha:</strong> %s &nbsp;·&nbsp; "
             "<strong>Perfil:</strong> %s%s</div>"
             % (_esc(meta["objetivo"]), _esc(meta["herramienta"]),
                _esc(meta["fecha_larga"]), _esc(meta["perfil"]),
                " &nbsp;·&nbsp; <strong>Duración:</strong> %.1f s"
                % meta["duracion_s"] if meta.get("duracion_s") else ""))
    if titulo_extra:
        h.append('<p class="suave">%s</p>' % _esc(titulo_extra))
    h.append("</div>")

    if not meta.get("autorizado"):
        h.append('<div class="aviso"><strong>Evaluación pasiva.</strong> No se '
                 "confirmó la autorización, así que no se envió ninguna "
                 "petición de ataque: los chequeos activos aparecen como "
                 "omitidos.</div>")

    # --- tarjetas de resumen
    h.append('<div class="rejilla">')
    if p:
        color = {"A": "#15803d", "B": "#15803d", "C": "#ca8a04",
                 "D": "#ea580c", "E": "#ea580c", "F": "#b91c1c"}.get(
                     p.get("letra"), "#475569")
        h.append('<div class="tarjeta"><div class="etq">Puntuación</div>'
                 '<div class="val" style="color:%s">%s / 100</div>'
                 '<div class="suave">Calificación %s — %s</div></div>'
                 % (color, _esc(p.get("puntos")), _esc(p.get("letra")),
                    _esc(p.get("descripcion"))))
        h.append('<div class="tarjeta"><div class="etq">Cobertura</div>'
                 '<div class="val">%.1f%%</div><div class="suave">%s de %s '
                 "chequeos ejecutados</div></div>"
                 % (p.get("cobertura", 0.0), _esc(p.get("ejecutados")),
                    _esc(p.get("ejecutados", 0)
                         + (p.get("estados") or {}).get("omitido", 0)
                         + (p.get("estados") or {}).get("error", 0)
                         + (p.get("estados") or {}).get("cancelado", 0))))
    c = datos["conteo"]
    h.append('<div class="tarjeta"><div class="etq">Hallazgos</div>'
             '<div class="val">%d</div><div class="suave">%d críticos · '
             "%d altos · %d medios</div></div>"
             % (len(datos["hallazgos"]), c.get("critico", 0), c.get("alto", 0),
                c.get("medio", 0)))
    h.append("</div>")

    # --- resumen ejecutivo
    h.append("<h2>1. Resumen ejecutivo</h2>")
    h.append("<p><strong>%s</strong></p>" % _esc(titular))
    for par in parrafos:
        h.append("<p>%s</p>" % _esc(par))

    if p:
        h.append("<h3>Puntuación por categoría</h3>")
        h.append(_svg_barras_h([(x["categoria"], x["puntos"])
                                for x in (p.get("categorias") or [])],
                               color_fn=_color_categoria))
        h.append("<h3>Hallazgos por severidad</h3>")
        h.append(_svg_columnas(c))

    # --- índice
    if datos["hallazgos"]:
        h.append("<h2>2. Índice de hallazgos</h2>")
        h.append('<div class="indice"><ol>')
        for x in datos["hallazgos"]:
            h.append('<li><a href="#%s">%s</a> '
                     '<span class="suave">(%s)</span></li>'
                     % (_esc(x["id"]), _esc(x["titulo"]),
                        _esc(ETIQUETA_SEV[x["severidad"]])))
        h.append("</ol></div>")

    # --- hallazgos detallados
    h.append("<h2>3. Hallazgos detallados</h2>")
    if not datos["hallazgos"]:
        h.append("<p>No se registraron hallazgos.</p>")
    else:
        for sev in SEVERIDADES:
            grupo = [x for x in datos["hallazgos"] if x["severidad"] == sev]
            if not grupo:
                continue
            h.append("<h3>%s (%d)</h3>" % (ETIQUETA_SEV[sev], len(grupo)))
            for x in grupo:
                h.append(_bloque_hallazgo(x))

    # --- superficie
    sup = _tabla_superficie(datos)
    if sup:
        h.append("<h2>4. Superficie de ataque</h2>")
        h.append(sup)

    # --- métricas
    if datos.get("metricas"):
        h.append("<h2>5. Métricas de la evaluación</h2>")
        h.append(_tabla_metricas(datos))

    # --- catálogo
    resultados = datos.get("resultados") or []
    if resultados:
        h.append("<h2>6. Catálogo de chequeos</h2>")
        h.append("<p>Estado de las %d comprobaciones ejecutadas.</p>"
                 % len(resultados))
        h.append('<table><thead><tr><th style="width:66px">ID</th>'
                 "<th>Chequeo</th><th style=\"width:92px\">Categoría</th>"
                 "<th style=\"width:74px\">Severidad</th>"
                 "<th style=\"width:78px\">Estado</th></tr></thead><tbody>")
        for r in sorted(resultados, key=lambda x: (x.get("estado") != "fallo",
                                                   x.get("id", ""))):
            color = COLOR_SEV.get(r.get("severidad", "info"), "#475569")
            estado = ETIQUETA_ESTADO.get(r.get("estado", ""), r.get("estado", ""))
            negrita = "font-weight:700" if r.get("estado") == "fallo" else ""
            h.append("<tr><td><code>%s</code></td><td style=\"%s\">%s</td>"
                     "<td>%s</td><td>%s</td><td>%s</td></tr>"
                     % (_esc(r.get("id", "")), negrita,
                        _esc(r.get("nombre", "")),
                        _esc(r.get("categoria", "")),
                        _esc(ETIQUETA_SEV.get(r.get("severidad", ""), "")),
                        _esc(estado)))
        h.append("</tbody></table>")

    # --- tráfico HTTP (evidencia en bruto)
    if datos.get("trafico"):
        h.append("<h2>7. Tráfico HTTP capturado</h2>")
        h.append("<p>Peticiones y respuestas en bruto, como evidencia "
                 "reproducible.</p>")
        for i, t in enumerate(datos["trafico"][:40], start=1):
            h.append("<h3>%d. %s %s — %s</h3>"
                     % (i, _esc(t.get("metodo", "GET")), _esc(t["url"]),
                        _esc(t.get("status", ""))))
            if t.get("peticion"):
                h.append("<h4>Petición</h4><pre><code>%s</code></pre>"
                         % _esc(t["peticion"][:4000]))
            if t.get("respuesta"):
                h.append("<h4>Respuesta</h4><pre><code>%s</code></pre>"
                         % _esc(t["respuesta"][:6000]))

    # --- pie
    h.append('<div class="pie">')
    h.append("<p><strong>%s</strong> — informe generado automáticamente el %s. "
             "Documento de uso exclusivo en pruebas autorizadas.</p>"
             % (_esc(meta["herramienta"]), _esc(meta["fecha"])))
    h.append("<p>La ausencia de hallazgos no demuestra la ausencia de "
             "vulnerabilidades. Los resultados deben revisarse y confirmarse "
             "manualmente antes de darlos por válidos.</p>")
    h.append("</div>")
    h.append("</div></body></html>")
    return "".join(h)


def escribir_html(datos, ruta, titulo_extra=""):
    html_txt = a_html(datos, titulo_extra)
    with io.open(ruta, "w", encoding="utf-8") as f:
        f.write(html_txt)
    return ruta


# ===========================================================================
# PDF
# ===========================================================================

def _pdf_con_pdfmin(datos, ruta):
    """Genera el PDF con el escritor propio (siempre funciona)."""
    meta = datos["meta"]
    p = datos.get("puntuacion") or {}
    titular, parrafos = resumen_ejecutivo(datos)
    c = datos["conteo"]

    doc = pdfmin.PDF("Informe HunterBug — %s" % meta["objetivo"],
                     meta["herramienta"], "Evaluación de seguridad",
                     "hunterbug, seguridad, informe")
    doc.titulo_documento("Informe de evaluación de seguridad",
                         "Objetivo: %s\n%s  ·  Fecha: %s  ·  Perfil: %s"
                         % (meta["objetivo"], meta["herramienta"],
                            meta["fecha_larga"], meta["perfil"]))

    if not meta.get("autorizado"):
        doc.caja([("Evaluación pasiva: no se confirmó la autorización, así que "
                   "no se envió ninguna petición de ataque.", True)],
                 color="#fffbeb", borde="#fde68a")

    doc.titulo("1. Resumen ejecutivo")
    doc.parrafo(titular, negrita=True)
    for par in parrafos:
        doc.parrafo(par)

    if p:
        doc.subtitulo("Puntuación por categoría")
        for x in (p.get("categorias") or []):
            doc.barra(x["categoria"], x["puntos"],
                      color=_color_categoria(x["puntos"]))
        doc.subtitulo("Hallazgos por severidad")
        doc.tabla(["Severidad", "Nº"],
                  [[ETIQUETA_SEV[s], c.get(s, 0)] for s in SEVERIDADES],
                  [200, 60], tam=9)

    doc.titulo("2. Hallazgos")
    if not datos["hallazgos"]:
        doc.parrafo("No se registraron hallazgos.")
    else:
        doc.tabla(["ID", "Título", "Severidad", "CWE"],
                  [[x["id"], x["titulo"], ETIQUETA_SEV[x["severidad"]],
                    x["cwe"]] for x in datos["hallazgos"]],
                  [58, 300, 74, 74])

        for i, x in enumerate(datos["hallazgos"], start=1):
            doc.subtitulo("2.%d  %s — %s" % (i, x["id"], x["titulo"]))
            lineas = [("%s  ·  %s%s%s"
                       % (ETIQUETA_SEV[x["severidad"]], x["categoria"],
                          ("  ·  " + x["cwe"]) if x["cwe"] else "",
                          ("  ·  " + x["owasp"]) if x["owasp"] else ""), True)]
            if x["url"]:
                lineas.append(("URL: " + x["url"], False))
            if x["parametro"]:
                lineas.append(("Parámetro: " + x["parametro"], False))
            if x["detalle"]:
                lineas.append((x["detalle"], False))
            doc.caja(lineas, color=FONDO_SEV[x["severidad"]],
                     borde=COLOR_SEV[x["severidad"]])
            ev = x.get("evidencia") or {}
            if ev:
                doc.parrafo("Evidencia:", negrita=True, tam=9)
                pares = []
                for k, v in ev.items():
                    if isinstance(v, (list, tuple)):
                        v = "\n".join(str(z) for z in v)
                    elif isinstance(v, dict):
                        v = json.dumps(v, ensure_ascii=False)
                    pares.append((str(k), str(v)[:1500]))
                doc.clave_valor(pares, tam=8.4, ancho_clave=110)
            if x["recomendacion"]:
                doc.parrafo("Recomendación: " + x["recomendacion"], tam=9,
                            color="#14532d")

    # superficie
    s = datos.get("superficie") or {}
    if s.get("dns") or s.get("ips") or s.get("puertos") or s.get("tecnologias"):
        doc.titulo("3. Superficie de ataque")
        dns = s.get("dns") or {}
        if any(dns.values()):
            doc.subtitulo("Registros DNS")
            doc.tabla(["Tipo", "Valor"],
                      [[t, v] for t in sorted(dns) for v in dns[t]],
                      [70, 400], tam=8.4)
        if s.get("ips"):
            doc.subtitulo("Direcciones IP")
            doc.parrafo(", ".join(s["ips"]))
        if s.get("puertos"):
            doc.subtitulo("Puertos y servicios")
            doc.tabla(["Puerto", "Servicio", "Banner"],
                      [[p.get("puerto", ""), p.get("servicio", ""),
                        str(p.get("banner", ""))[:160]] for p in s["puertos"]],
                      [60, 110, 300], tam=8.4)
        tec = s.get("tecnologias") or {}
        if tec:
            doc.subtitulo("Tecnologías detectadas")
            doc.tabla(["Producto", "Evidencia"],
                      [[k, str(tec[k])[:160]] for k in sorted(tec)],
                      [150, 320], tam=8.4)

    # métricas
    if datos.get("metricas"):
        doc.titulo("4. Métricas de la evaluación")
        doc.tabla(["Métrica", "Valor"],
                  [[k, v] for k, v in datos["metricas"]], [300, 170], tam=8.4)

    # catálogo
    resultados = datos.get("resultados") or []
    if resultados:
        doc.titulo("5. Catálogo de chequeos")
        doc.parrafo("Estado de las %d comprobaciones ejecutadas."
                    % len(resultados))
        doc.tabla(["ID", "Chequeo", "Severidad", "Estado"],
                  [[r.get("id", ""), r.get("nombre", ""),
                    ETIQUETA_SEV.get(r.get("severidad", ""), ""),
                    ETIQUETA_ESTADO.get(r.get("estado", ""), "")]
                   for r in sorted(resultados,
                                   key=lambda x: (x.get("estado") != "fallo",
                                                  x.get("id", "")))],
                  [58, 300, 74, 74], tam=7.6)

    # tráfico
    if datos.get("trafico"):
        doc.titulo("6. Tráfico HTTP capturado")
        for i, t in enumerate(datos["trafico"][:25], start=1):
            doc.subtitulo("%d. %s %s — %s"
                          % (i, t.get("metodo", "GET"), t["url"],
                             t.get("status", "")))
            if t.get("peticion"):
                doc.parrafo("Petición:", negrita=True, tam=8.4)
                doc.parrafo(t["peticion"][:1500], tam=7.4, color="#334155")
            if t.get("respuesta"):
                doc.parrafo("Respuesta:", negrita=True, tam=8.4)
                doc.parrafo(t["respuesta"][:2000], tam=7.4, color="#334155")

    doc.espacio(10)
    doc.parrafo("%s — informe generado automáticamente el %s. Documento de uso "
                "exclusivo en pruebas autorizadas." % (meta["herramienta"],
                                                       meta["fecha"]),
                tam=8, color="#6b7280")
    doc.parrafo("La ausencia de hallazgos no demuestra la ausencia de "
                "vulnerabilidades.", tam=8, color="#6b7280")
    return doc.guardar(ruta)


def a_pdf(datos, ruta, preferir_navegador=True):
    """Genera el PDF del informe.

    Primero intenta el navegador headless (fidelidad perfecta con el HTML);
    si no hay navegador o falla, usa el generador propio.
    Devuelve (ruta, metodo).
    """
    if preferir_navegador:
        try:
            html_txt = a_html(datos)
            r = pdfmin.html_a_pdf(html_txt, ruta)
            if r and pdfmin.es_pdf_valido(r):
                return r, "navegador"
        except Exception:
            pass
    return _pdf_con_pdfmin(datos, ruta), "propio"


# ===========================================================================
# JSON, Markdown y CSV
# ===========================================================================

def _json_serializable(datos):
    d = dict(datos)
    d.pop("grafo", None)  # el grafo es un objeto vivo, no serializable
    return d


def a_json(datos, ruta):
    with io.open(ruta, "w", encoding="utf-8") as f:
        json.dump(_json_serializable(datos), f, ensure_ascii=False, indent=2)
    return ruta


def a_markdown(datos):
    meta = datos["meta"]
    p = datos.get("puntuacion") or {}
    c = datos["conteo"]
    titular, parrafos = resumen_ejecutivo(datos)
    L = []
    L.append("# Informe de evaluación de seguridad")
    L.append("")
    L.append("**Objetivo:** `%s`  " % meta["objetivo"])
    L.append("**Herramienta:** %s · **Fecha:** %s · **Perfil:** %s"
             % (meta["herramienta"], meta["fecha_larga"], meta["perfil"]))
    L.append("")
    if not meta.get("autorizado"):
        L.append("> Evaluación **pasiva**: no se confirmó la autorización, así "
                 "que no se envió ninguna petición de ataque.")
        L.append("")
    L.append("| Métrica | Valor |")
    L.append("|---|---|")
    if p:
        L.append("| Puntuación | **%s / 100** (%s — %s) |"
                 % (p.get("puntos"), p.get("letra"), p.get("descripcion")))
        L.append("| Cobertura | %.1f%% |" % p.get("cobertura", 0.0))
    L.append("| Hallazgos | %d |" % len(datos["hallazgos"]))
    for s in SEVERIDADES:
        L.append("| %s | %d |" % (ETIQUETA_SEV[s], c.get(s, 0)))
    L.append("")
    L.append("## 1. Resumen ejecutivo")
    L.append("")
    L.append("**%s**" % titular)
    L.append("")
    for par in parrafos:
        L.append(par)
        L.append("")
    if p and p.get("categorias"):
        L.append("### Puntuación por categoría")
        L.append("")
        L.append("| Categoría | Puntos | Fallos |")
        L.append("|---|---|---|")
        for x in p["categorias"]:
            L.append("| %s | %.1f | %d |"
                     % (x["categoria"], x["puntos"], x["fallos"]))
        L.append("")
    L.append("## 2. Hallazgos detallados")
    L.append("")
    for sev in SEVERIDADES:
        grupo = [x for x in datos["hallazgos"] if x["severidad"] == sev]
        if not grupo:
            continue
        L.append("### %s (%d)" % (ETIQUETA_SEV[sev], len(grupo)))
        L.append("")
        for x in grupo:
            L.append("#### %s — %s" % (x["id"], x["titulo"]))
            L.append("")
            chips = [ETIQUETA_SEV[sev], x["categoria"]]
            if x["cwe"]:
                chips.append(x["cwe"])
            if x["owasp"]:
                chips.append(x["owasp"])
            L.append("*%s*" % " · ".join(chips))
            L.append("")
            if x["url"]:
                L.append("- **URL:** `%s`" % x["url"])
            if x["parametro"]:
                L.append("- **Parámetro:** `%s`" % x["parametro"])
            L.append("")
            if x["detalle"]:
                L.append(x["detalle"])
                L.append("")
            ev = x.get("evidencia") or {}
            if ev:
                L.append("**Evidencia**")
                L.append("")
                for k, v in ev.items():
                    if isinstance(v, (list, tuple)):
                        v = ", ".join(str(z) for z in v)
                    elif isinstance(v, dict):
                        v = json.dumps(v, ensure_ascii=False)
                    L.append("- `%s`: %s" % (k, str(v)[:600]))
                L.append("")
            if x["recomendacion"]:
                L.append("> **Recomendación:** %s" % x["recomendacion"])
                L.append("")
    s = datos.get("superficie") or {}
    if any((s.get("dns"), s.get("ips"), s.get("puertos"), s.get("tecnologias"))):
        L.append("## 3. Superficie de ataque")
        L.append("")
        dns = s.get("dns") or {}
        for t in sorted(dns):
            for v in dns[t]:
                L.append("- **%s** `%s`" % (t, v))
        if s.get("ips"):
            L.append("- **IPs:** %s" % ", ".join(s["ips"]))
        for pu in s.get("puertos") or []:
            L.append("- **tcp/%s** %s — %s"
                     % (pu.get("puerto"), pu.get("servicio"),
                        str(pu.get("banner", ""))[:80]))
        for k in sorted(s.get("tecnologias") or {}):
            L.append("- **Tecnología:** %s — %s"
                     % (k, str(s["tecnologias"][k])[:120]))
        L.append("")
    if datos.get("metricas"):
        L.append("## 4. Métricas")
        L.append("")
        L.append("| Métrica | Valor |")
        L.append("|---|---|")
        for k, v in datos["metricas"]:
            L.append("| %s | %s |" % (k, v))
        L.append("")
    resultados = datos.get("resultados") or []
    if resultados:
        L.append("## 5. Catálogo de chequeos")
        L.append("")
        L.append("| ID | Chequeo | Categoría | Severidad | Estado |")
        L.append("|---|---|---|---|---|")
        for r in sorted(resultados, key=lambda x: (x.get("estado") != "fallo",
                                                   x.get("id", ""))):
            L.append("| %s | %s | %s | %s | %s |"
                     % (r.get("id", ""), r.get("nombre", ""),
                        r.get("categoria", ""),
                        ETIQUETA_SEV.get(r.get("severidad", ""), ""),
                        ETIQUETA_ESTADO.get(r.get("estado", ""), "")))
        L.append("")
    L.append("---")
    L.append("")
    L.append("*Informe generado por %s el %s. Documento de uso exclusivo en "
             "pruebas autorizadas. La ausencia de hallazgos no demuestra la "
             "ausencia de vulnerabilidades.*"
             % (meta["herramienta"], meta["fecha"]))
    return "\n".join(L)


def escribir_markdown(datos, ruta):
    with io.open(ruta, "w", encoding="utf-8") as f:
        f.write(a_markdown(datos))
    return ruta


def a_csv(datos, ruta):
    """Una fila por hallazgo, con la evidencia aplanada."""
    with io.open(ruta, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["n", "id", "severidad", "categoria", "titulo", "cwe",
                    "owasp", "url", "parametro", "detalle", "recomendacion",
                    "evidencia"])
        for x in datos["hallazgos"]:
            ev = x.get("evidencia") or {}
            plano = " | ".join("%s=%s" % (k, v) for k, v in ev.items())
            w.writerow([x["n"], x["id"], x["severidad"], x["categoria"],
                        x["titulo"], x["cwe"], x["owasp"], x["url"],
                        x["parametro"], x["detalle"], x["recomendacion"],
                        plano])
    return ruta


def nombre_por_defecto(objetivo, extension, carpeta, etiqueta=""):
    """Nombre de fichero estable y legible a partir del objetivo.

    `etiqueta` distingue formatos que comparten extension (p. ej. el XML de
    Burp y el de ZAP son ambos .xml).
    """
    try:
        u = urllib.parse.urlsplit(objetivo if "//" in objetivo
                                  else "//" + objetivo)
        base = (u.hostname or objetivo).replace(":", "_")
        if u.path and u.path != "/":
            base += "_" + u.path.strip("/").replace("/", "-")
    except Exception:
        base = "objetivo"
    base = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in base)
    sello = time.strftime("%Y%m%d-%H%M%S")
    partes = ["hunterbug", base[:60]]
    if etiqueta:
        partes.append("".join(c for c in etiqueta if c.isalnum()))
    partes.append(sello)
    return os.path.join(carpeta, "_".join(partes) + "." + extension)
