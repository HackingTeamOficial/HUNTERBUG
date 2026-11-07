"""HunterBug 1.1 — Reconocimiento dinámico del árbol de direcciones vía AJAX.

Escanea el DOM de una página busca enlaces, formularios, iframes y
endpoints de API descubiertos en JavaScript sin necesidad de hacer
requests de scraping. Muy útil para descubrir rutas ocultas y endpoints
antes de lanzar el scanner de vulnerabilidades.
"""

from __future__ import annotations

import re
import json
import time
from urllib.parse import urljoin, urlparse

from . import net

TIMEOUT = 12

# Patrones comunes de endpoints en JS
API_PATTERNS = [
    r"['\"](/[^'\"]+)['\"]",                                    # URLs en comillas
    r"['\"](/api/[a-z0-9_]+/)['\"]",                            # Rutas /api/...
    r"['\"](/rest/[a-z0-9_]+/)['\"]",
    r"['\"]?(/graphql)['\"]?",
    r"['\"]?(/v\d+[a-z]+)['\"]?",
    r"new\s+XMLHttpRequest\(['\"]([^'\"]+)['\"]\)",
    r"fetch\s*\(\s*['\"]([^'\"]+)['\"]",
]


def _extract_from_html(html, base_url):
    """Extrae URLs, formularios e iframes de HTML estático."""
    urls = set()
    forms = []
    iframes = []

    # Enlaces
    for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\']', html, re.I):
        url = m.group(1)
        if url.startswith(('http://', 'https://', '//')):
            urls.add(url)
        else:
            urls.add(urljoin(base_url, url))

    # Formularios
    for m in re.finditer(r'<form[^>]*>', html, re.I):
        form_match = m.group(0)
        action = None
        method = "get"

        for a in re.finditer(r'(action|method)=["\']([^"\']+)["\']', form_match, re.I):
            if a.group(1).lower() == "action":
                action = a.group(2)
            elif a.group(1).lower() == "method":
                method = a.group(2).lower()

        form_url = urljoin(base_url, action) if action else base_url
        forms.append({"url": form_url, "method": method})

    # Iframes
    for m in re.finditer(r'<iframe[^>]+src=["\']([^"\']+)["\']', html, re.I):
        src = m.group(1)
        iframes.append(urljoin(base_url, src))

    return urls, forms, iframes


def _extract_from_js(js, base_url):
    """Extrae endpoints, URLs y parámetros de JavaScript."""
    urls = set()

    # URLs en rutas
    for pattern in API_PATTERNS:
        for m in re.finditer(pattern, js, re.I):
            url_path = m.group(1) if m.lastindex == 1 else m.group(2) if m.lastindex == 2 else None
            if url_path:
                full_url = urljoin(base_url, url_path)
                urls.add(full_url)

    # Parámetros de funciones sospechosas
    param_patterns = [
        r"['\"]([a-z_]{3,})['\"]\s*[,=]",
    ]
    for pattern in param_patterns:
        for m in re.finditer(pattern, js, re.I):
            param = m.group(1)
            if param not in ("type", "name", "value", "id", "class", "src", "href"):
                # Buscar usos con fetch/ajax con este parámetro
                pass

    # Endpoints de AJAX
    for m in re.finditer(r"[\"'](/[a-z0-9_\\-]+)['\"].*?(?:fetch|axios|XMLHttpRequest)", js, re.I):
        urls.add(urljoin(base_url, m.group(1)))

    return urls


def _extract_from_json(data, base_url, depth=0):
    """Recursivamente extrae URLs de estructuras JSON."""
    urls = set()

    if depth > 5:
        return urls

    if isinstance(data, dict):
        for key, val in data.items():
            if key.lower() in ("url", "link", "href", "src", "redirect", "callback"):
                if isinstance(val, str) and val.startswith("/"):
                    urls.add(urljoin(base_url, val))
                elif isinstance(val, str) and val.startswith(("http://", "https://")):
                    urls.add(val)
            urls.update(_extract_from_json(val, base_url, depth + 1))
    elif isinstance(data, list):
        for item in data:
            urls.update(_extract_from_json(item, base_url, depth + 1))

    return urls


def escanear_ajax(url_objetivo, cabeceras=None, profundidad=2):
    """
    Reconocimiento dinámico del árbol de direcciones.
    
    Descarga la página y busca enlaces, formularios, iframes, JavaScript
    y JSON en busca de endpoints ocultos.
    """
    cabeceras = cabeceras or {}
    
    # Descargar página principal
    r = net.peticion_http(url_objetivo, cabeceras=cabeceras, timeout=TIMEOUT)
    if r.status != 200:
        return {"url": url_objetivo, "error": "sin respuesta", "direcciones": []}

    base_url = url_objetivo
    urls = set()
    forms = []
    iframes = []
    js_files = []
    endpoints_api = []

    html = r.cuerpo or ""

    # Extraer de HTML
    html_urls, forms, iframes = _extract_from_html(html, base_url)
    urls.update(html_urls)

    # Extraer scripts
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
    for src in script_srcs:
        js_url = urljoin(base_url, src)
        js_files.append(js_url)

    # Buscar enlaces dentro de <script> inline
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.I | re.S)
    for script in inline_scripts:
        script_urls = _extract_from_js(script, base_url)
        urls.update(script_urls)

    # Descargar y analizar archivos JS
    for js_url in js_files:
        jr = net.peticion_http(js_url, cabeceras=cabeceras, timeout=TIMEOUT)
        if jr.status == 200:
            js_urls = _extract_from_js(jr.cuerpo or "", js_url)
            urls.update(js_urls)

    # Procesar iframes (hasta profundidad)
    if profundidad > 0:
        for iframe_url in list(iframes):
            ir = net.peticion_http(iframe_url, cabeceras=cabeceras, timeout=TIMEOUT)
            if ir.status == 200:
                iframe_urls, _, _ = _extract_from_html(ir.cuerpo or "", iframe_url)
                urls.update(iframe_urls)

    # Filtrar: solo URLs bajo el mismo dominio
    parsed = urlparse(base_url)
    domain = parsed.netloc
    filtered_urls = {u for u in urls if urlparse(u).netloc == domain or u.startswith("/")}

    # Clasificar endpoints API
    for u in filtered_urls:
        if any(p in u.lower() for p in ("/api/", "/rest/", "/graphql", "/v1/", "/v2/")):
            endpoints_api.append(u)

    return {
        "url": url_objetivo,
        "dominio": domain,
        "direcciones": sorted(filtered_urls),
        "endpoints_api": endpoints_api,
        "formularios": forms,
        "iframes": iframes,
        "archivos_js": js_files,
        "total": len(filtered_urls)
    }


def generar_mapa_sitemap(url_objetivo, cabeceras=None):
    """Genera un sitemap XML a partir del reconocimiento AJAX."""
    datos = escanear_ajax(url_objetivo, cabeceras)
    
    xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    xml_lines.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')
    
    for url in datos.get("direcciones", []):
        xml_lines.append('  <url>')
        xml_lines.append(f'    <loc>{url}</loc>')
        xml_lines.append('  </url>')
    
    xml_lines.append('</urlset>')
    
    return "\n".join(xml_lines), datos


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = escanear_ajax(target)
    print(f"Encontradas {result['total']} direcciones")
    for url in result.get("direcciones", [])[:20]:
        print(f"  - {url}")