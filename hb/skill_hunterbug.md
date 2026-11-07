---
name: hunterbug
description: Use when working on the HunterBug desktop GUI.
---

# HunterBug

Desktop security-evaluation GUI for authorized testing (bug bounty, pentest,
CTF). Python + CustomTkinter + matplotlib, standard-library HTTP/DNS engine,
set for Spanish; user communicates in Spanish.

## Layout (on Desktop, versioned side by side)

```
Desktop/
  HunterBug 1.0/     <- STABLE. Never edit unless asked.
  HunterBug 1.1/     <- STABLE. Never edit unless asked.
  HunterBug 1.2/     <- working version (Bug Hunter Edition)
  HunterBug 1.0.exe  <- the built 1.0 exe lives at Desktop level, NOT in 1.0/dist
  HunterBug 1.1.exe  <- the built 1.1 exe lives at Desktop level
  HunterBug 1.2/dist/HunterBug 1.2.exe
```

Each version folder is self-contained: `HunterBugGUI.py`, `hb/`, `assets/`,
`plugins/`, `templates/`, `banco_pruebas.py` (vulnerable lab), `compilar.bat`,
`README.md`.

**Rule:** copy the whole folder for a new version and never touch the old one.
Verify with `verificar_paquete_12.py`, which md5-compares the shared base
modules (`hb/net.py`, `hb/vulns.py`, `checks.py`) against 1.0 and asserts the
intentionally-changed files (`HunterBugGUI.py`, `hb/__init__.py`, `hb/informe.py`
y `hb/catalogo_a.py`) actually differ.

## Motores (hb/)

| Motor | Líneas | Qué detecta |
|---|---|---|
| `sqli.py` | 525+ | SQLi con confirmation por tiempo, WAF evasion, una payload por vector |
| `xss.py` | 390+ | XSS reflejado con detección de contexto, CSP, DOM XSS (fuente/sumidero) y evasión escapada |
| `authz.py` | 388 | IDOR/BOLA: descubre objetos en URL, evalúa predicibilidad (UUID v1), enumera vecinos acotados |
| `open_redirect.py` | 200 | Open Redirect: detección de redirecciones a hosts externos (header Location, JS, meta refresh) |
| `traversal.py` | 180 | Path Traversal/LFI: prueba payloads contra archivos sensibles del sistema |
| `validacion.py` | 345 | Confianza 0-100, CVSS 3.1, prioridad P1-P4, deduplicación, revisión de falsos positivos |
| `recon11.py` | 249 | Reconocimiento pasivo: subdominios (CT), cert SAN, robots/sitemap, parámetros JS, formularios |
| `bounty.py` | 340 | Comprobador de alcance y generador de reportes (HackerOne, Bugcrowd) |

## The lab

`banco_pruebas.py` starts an HTTP lab on `127.0.0.1:8080` (`ServidorPrueba`,
context manager). Every detector test runs against it. Add endpoints there when
you add a detector — including the **negative cases** (correct authz, escaped
reflections, nonexistent objects). Negative cases are what keep false positives
out.

## Tests (run them, do not describe them)

Every `verificar_*.py` y `prueba_*.py` es un suite ejecutable. Corran todos:

```bash
for t in verificar_sqli verificar_xss verificar_authz verificar_validacion \
         verificar_bounty verificar_gui_12 verificar_catalogo verificar_informes \
         verificar_motores prueba_gui prueba_catalogo_gui prueba_informe_gui \
         prueba_pdf; do
  python3 -u "$t.py" > /tmp/F_$t.out 2>&1
  echo "$t $? $(grep -iE 'PRUEBAS OK|VERIFICAD' /tmp/F_$t.out | tail -1)"
done
```

## Build

`compilar.bat` es el punto de entrada (doble clic o ejecutar). Limpia archivos
anteriores y usa PyInstaller:

```bash
python -m PyInstaller --noconfirm --clean --onefile --noconsole \
  --name "HunterBug 1.2" --icon assets\hunterbug.ico \
  --add-data "assets;assets" --collect-all hb --collect-all customtkinter \
  --hidden-import matplotlib.backends.backend_tkagg \
  --hidden-import PIL._tkinter_finder HunterBugGUI.py
```

Resultado: `dist/HunterBug 1.2.exe` (~42 MB, un solo archivo, sin consola).

## Pitfalls (cada uno rompía la GUI en silencio)

1. `ejecutar_modulo` traga excepciones → solo loguea "Fallo:..." → marca el módulo `fallido`.
2. Las claves de `resumen` varían por motor → usar `.get()` con default.
3. `parametro` es clave top-level, no está en `evidencia`.
4. Nuevo parámetro `analizar()` debe usarse vía `_TIMEOUT` global.
5. Nuevos campos deben agregarse a `_norm_hallazgo()` en `hb/informe.py`.
6. Hallazgos del bus son dicts → usar `bus.hallazgos_de()` y `bus.hallazgos_todos()`.