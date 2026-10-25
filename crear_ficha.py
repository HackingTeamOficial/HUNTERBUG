"""Genera ficha_hunterbug.html: hoja de presentacion de una pagina,
autocontenida (logotipo incrustado en base64) y con la estetica de la app.
"""

from __future__ import annotations

import base64
import os

RAIZ = os.path.dirname(os.path.abspath(__file__))
LOGO = os.path.join(RAIZ, "assets", "hunterbug_logo.png")
SALIDA = os.path.join(RAIZ, "ficha_hunterbug.html")

VERDE = "#00ff41"
CYAN = "#00d4ff"


def logo_b64():
    if not os.path.exists(LOGO):
        return ""
    with open(LOGO, "rb") as f:
        return "data:image/png;base64," + base64.b64encode(f.read()).decode()


MODULOS = [
    ("DNS", "pasivo", "8 tipos de registro vía DNS-over-HTTPS, con 3 resolutores de respaldo"),
    ("IP / Reversa", "pasivo", "Resolución directa e inversa de direcciones"),
    ("HTTP / Cabeceras", "pasivo", "Petición y respuesta en bruto, TLS y auditoría de seguridad"),
    ("CVE", "pasivo", "34 CVEs reales con comparación de versiones + NVD en vivo"),
    ("Puertos", "activo", "47 puertos TCP en paralelo, con banner y servicio"),
    ("SQLi", "activo", "Inyección SQL por errores y por diferencial booleano"),
    ("XSS", "activo", "Cross-site scripting reflejado con marcador único"),
    ("IDOR", "activo", "Acceso a objetos ajenos comparando identificadores"),
    ("BOLA", "activo", "Autorización por objeto en API con dos credenciales"),
]

AREAS = [
    ("Reconocimiento", [
        "DNS completo con respaldo entre 3 resolutores DoH",
        "Escaneo TCP con captura de banner real",
        "Fingerprint pasivo de 15+ tecnologías",
        "Resolución inversa e identificación de servicio",
    ]),
    ("HTTP y TLS", [
        "Petición y respuesta en bruto, como en un proxy",
        "Historial con método, código y latencia",
        "Versión, cifrado y caducidad del certificado",
        "6 cabeceras de seguridad + 6 de fuga de tecnología",
    ]),
    ("Vulnerabilidades", [
        "SQLi: 15 firmas de error y diferencial booleano",
        "XSS reflejado con marcador aleatorio por petición",
        "IDOR y BOLA con similitud Jaccard sobre tokens",
        "Severidad según confianza, no por suposición",
    ]),
    ("Grafo e IA", [
        "Superficie de ataque en vivo, 11 tipos de nodo",
        "Layout por fuerzas, zoom, arrastre y detalle por nodo",
        "Análisis con Ollama o motor de reglas local",
        "Salida en 4 bloques: grafo, cadena, prioridad, pruebas",
    ]),
]

PERFILES = [
    ("Bug hunter", "Pasada inicial sobre un alcance recién aceptado y informe listo para pegar."),
    ("Pentester autorizado", "Reconocimiento y low-hanging fruit con evidencia reproducible."),
    ("AppSec / DevSecOps", "Comprobación periódica de cabeceras, TLS y puertos propios."),
    ("Estudiante / CTF", "Laboratorio vulnerable incluido para ver cada detector en acción."),
]

METRICAS = [
    ("9", "módulos de evaluación"),
    ("7", "pestañas por categoría"),
    ("34", "CVEs reales en local"),
    ("47", "puertos TCP"),
    ("0", "dependencias de red"),
    ("131", "pruebas superadas"),
]


def html():
    b64 = logo_b64()
    mods = "".join(
        f'<div class="card"><div class="card-h"><span class="name">{n}</span>'
        f'<span class="tag {"on" if t == "activo" else "off"}">{t}</span></div>'
        f'<p>{d}</p></div>' for n, t, d in MODULOS)

    areas = "".join(
        f'<div class="area"><h3>{t}</h3><ul>' +
        "".join(f"<li>{x}</li>" for x in items) + "</ul></div>"
        for t, items in AREAS)

    perfiles = "".join(
        f'<div class="perfil"><strong>{n}</strong><span>{d}</span></div>'
        for n, d in PERFILES)

    metricas = "".join(
        f'<div class="metrica"><span class="num">{v}</span><span class="lbl">{l}</span></div>'
        for v, l in METRICAS)

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>HunterBug 1.0 - Ficha de la herramienta</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 0;
    background: #060807;
    color: #e2e8f0;
    font-family: Consolas, "Cascadia Mono", Menlo, monospace;
    font-size: 14px; line-height: 1.6;
  }}
  .wrap {{ max-width: 1180px; margin: 0 auto; padding: 0 26px 60px; }}

  header {{
    border-bottom: 1px solid #1c2a20;
    background: linear-gradient(180deg, #0a0f0b 0%, #060807 100%);
    padding: 34px 0 30px;
  }}
  .head {{ display: flex; align-items: center; gap: 22px; }}
  .head img {{ width: 96px; height: 96px; flex: 0 0 auto; }}
  .title h1 {{
    margin: 0; font-size: 42px; letter-spacing: 2px; color: {VERDE};
    text-shadow: 0 0 18px rgba(0,255,65,.28);
  }}
  .title .v {{ color: {CYAN}; font-size: 20px; margin-left: 10px; }}
  .title p {{ margin: 6px 0 0; color: #8fa3b0; font-size: 14px; }}
  .credito {{
    margin-top: 12px; display: inline-block;
    border: 1px solid #1f6b39; background: rgba(0,255,65,.06);
    color: {CYAN}; padding: 7px 14px; border-radius: 6px; font-size: 13px;
  }}

  h2 {{
    color: {VERDE}; font-size: 15px; letter-spacing: 1.4px;
    margin: 40px 0 14px; text-transform: uppercase;
    border-left: 3px solid {VERDE}; padding-left: 10px;
  }}

  .lead {{ color: #c8d4dc; font-size: 15px; line-height: 1.75; }}
  .lead b {{ color: #fff; }}

  .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }}
  .card {{
    border: 1px solid #1c2a20; background: #0b120d;
    border-radius: 8px; padding: 13px 15px;
  }}
  .card-h {{ display: flex; justify-content: space-between; align-items: center; gap: 8px; }}
  .name {{ color: {VERDE}; font-weight: 700; font-size: 14px; }}
  .tag {{ font-size: 10px; padding: 2px 7px; border-radius: 10px; letter-spacing: .5px; }}
  .tag.on {{ background: rgba(0,212,255,.13); color: {CYAN}; border: 1px solid #17505f; }}
  .tag.off {{ background: rgba(255,255,255,.05); color: #7d8f9b; border: 1px solid #24313a; }}
  .card p {{ margin: 8px 0 0; color: #a9bac4; font-size: 13px; line-height: 1.55; }}

  .areas {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }}
  .area {{ border: 1px solid #1c2a20; background: #0b120d; border-radius: 8px; padding: 15px 18px; }}
  .area h3 {{ margin: 0 0 8px; color: {CYAN}; font-size: 13.5px; letter-spacing: .6px; }}
  .area ul {{ margin: 0; padding-left: 18px; }}
  .area li {{ color: #b0c0ca; font-size: 13px; margin: 4px 0; }}

  .metricas {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; }}
  .metrica {{
    border: 1px solid #1c2a20; background: #0b120d; border-radius: 8px;
    padding: 16px 8px; text-align: center;
  }}
  .metrica .num {{ display: block; color: {VERDE}; font-size: 28px; font-weight: 700; }}
  .metrica .lbl {{ display: block; color: #93a7b4; font-size: 11.5px; margin-top: 5px; }}

  .perfiles {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }}
  .perfil {{ border: 1px solid #1c2a20; background: #0b120d; border-radius: 8px; padding: 13px 15px; }}
  .perfil strong {{ color: {VERDE}; display: block; font-size: 13.5px; margin-bottom: 4px; }}
  .perfil span {{ color: #a9bac4; font-size: 13px; }}

  .flujo {{ counter-reset: paso; padding: 0; margin: 0; list-style: none; }}
  .flujo li {{
    counter-increment: paso; position: relative; padding: 9px 0 9px 44px;
    color: #b6c4cd; font-size: 13px; border-bottom: 1px dashed #16211a;
  }}
  .flujo li:last-child {{ border-bottom: 0; }}
  .flujo li::before {{
    content: counter(paso); position: absolute; left: 0; top: 9px;
    width: 26px; height: 26px; line-height: 26px; text-align: center;
    border-radius: 50%; border: 1px solid {VERDE}; color: {VERDE}; font-size: 12px;
  }}

  .aviso {{
    margin-top: 40px; border: 1px solid #6b1f1f; background: rgba(255,60,60,.05);
    border-radius: 8px; padding: 16px 18px;
  }}
  .aviso h3 {{ margin: 0 0 8px; color: #ff6b6b; font-size: 13px; letter-spacing: 1px; }}
  .aviso p {{ margin: 0; color: #c9b4b4; font-size: 12.5px; }}

  footer {{
    margin-top: 34px; padding-top: 20px; border-top: 1px solid #1c2a20;
    color: #6f8290; font-size: 12px; text-align: center;
  }}
  footer b {{ color: {VERDE}; }}
  footer .sub {{ color: {CYAN}; }}

  @media (max-width: 900px) {{
    .grid, .areas, .perfiles {{ grid-template-columns: 1fr; }}
    .metricas {{ grid-template-columns: repeat(3, 1fr); }}
    .title h1 {{ font-size: 32px; }}
  }}
</style>
</head>
<body>
<header>
  <div class="wrap head">
    {f'<img src="{b64}" alt="HunterBug">' if b64 else ''}
    <div class="title">
      <h1>HUNTERBUG<span class="v">1.0</span></h1>
      <p>Framework de evaluación de seguridad para bug hunters</p>
      <div class="credito">Versión mejorada y creada para la comunidad
        hacking team · by Juan Antonio</div>
    </div>
  </div>
</header>

<div class="wrap">

  <h2>Qué es</h2>
  <p class="lead">Una herramienta de escritorio para <b>reconocimiento y detección
  de vulnerabilidades web</b> en pruebas autorizadas. Reúne en una sola ventana lo
  que normalmente obliga a saltar entre cinco o seis utilidades: DNS, puertos con
  banner, tráfico HTTP en bruto, auditoría de cabeceras, mapeo a CVE y pruebas de
  SQLi, XSS, IDOR y BOLA.</p>
  <p class="lead">Todo el resultado se construye <b>en vivo</b>: cada módulo reporta
  estado, porcentaje y duración; los hallazgos aparecen en su categoría al instante;
  y los activos descubiertos se dibujan en un <b>grafo de superficie de ataque</b>
  que después se entrega a un modelo de IA para que proponga la cadena de ataque y
  los siguientes pasos. No es un lanzador de exploits: <b>detecta, documenta y
  prioriza</b>.</p>

  <h2>Módulos de evaluación</h2>
  <div class="grid">{mods}</div>

  <h2>Capacidades</h2>
  <div class="areas">{areas}</div>

  <h2>Para quién está pensada</h2>
  <div class="perfiles">{perfiles}</div>

  <h2>En números</h2>
  <div class="metricas">{metricas}</div>

  <h2>Flujo de trabajo</h2>
  <ol class="flujo">
    <li>Escribe el objetivo: dominio, URL o URL con parámetros.</li>
    <li>Marca la casilla de autorización para habilitar los módulos activos.</li>
    <li>Pulsa EJECUTAR EVALUACIÓN y sigue el progreso módulo a módulo.</li>
    <li>Revisa cada pestaña y abre ventanas por módulo si quieres verlas a la vez.</li>
    <li>Pulsa Analizar con IA y exporta el informe en Markdown o JSON.</li>
  </ol>

  <div class="aviso">
    <h3>ALCANCE Y ÉTICA</h3>
    <p>Uso exclusivo en pruebas <b>autorizadas</b>: bug bounty dentro del alcance
    publicado, laboratorios propios o encargos con permiso por escrito. Los módulos
    activos trabajan con volumen bajo y sin técnicas destructivas —nada de
    denegación de servicio, fuerza bruta ni enumeración masiva—, pero probar
    sistemas sin autorización es ilegal. La responsabilidad del uso recae en quien
    ejecuta la herramienta.</p>
  </div>

  <footer>
    <b>HunterBug 1.0</b> · <span class="sub">versión mejorada y creada para la
    comunidad hacking team · by Juan Antonio</span><br>
    Sin dependencias externas de red · Python 3 · Windows
  </footer>

</div>
</body>
</html>
"""


def main():
    with open(SALIDA, "w", encoding="utf-8") as f:
        f.write(html())
    print("ficha generada:", SALIDA, os.path.getsize(SALIDA), "bytes")
    print("logotipo incrustado:", "si" if logo_b64() else "no")


if __name__ == "__main__":
    main()
