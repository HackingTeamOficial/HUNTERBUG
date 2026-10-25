# HunterBug 1.0

**Framework de evaluación de seguridad para bug hunters**

creada para la comunidad **hacking team** · by **Juan Antonio**

<img width="1920" height="1031" alt="Screenshot 2026-10-25 033454" src="https://github.com/user-attachments/assets/647a4a5e-3209-44e7-beba-4e8ed6d3ce68" />
<img width="1920" height="1027" alt="12" src="https://github.com/user-attachments/assets/ffd18b72-92ff-405c-a244-3760c155996f" />
<img width="1920" height="1028" alt="11" src="https://github.com/user-attachments/assets/af847931-9698-4607-9aae-484a2ef20502" />
<img width="1912" height="878" alt="10" src="https://github.com/user-attachments/assets/a542728f-3ecc-4ca9-b555-17ae66c7d92f" />
<img width="1920" height="1028" alt="9" src="https://github.com/user-attachments/assets/c7bb83ba-440e-4898-8919-f1ce9261d53f" />
<img width="1920" height="1028" alt="8" src="https://github.com/user-attachments/assets/5fa50aca-883e-45f0-8d9d-91dec19a5b69" />
<img width="1920" height="1028" alt="7" src="https://github.com/user-attachments/assets/141c0508-a188-4c91-9a75-978f8497bccc" />
<img width="1920" height="1031" alt="6" src="https://github.com/user-attachments/assets/fc72a407-ee58-48c4-bc96-1b72a7e88061" />
<img width="1920" height="1030" alt="5" src="https://github.com/user-attachments/assets/70429b90-3846-47eb-b943-ed676e2e3ed6" />
<img width="1920" height="1027" alt="4" src="https://github.com/user-attachments/assets/688a05f3-9e10-4bc0-94a5-a1ab35b96c4e" />
<img width="1920" height="1030" alt="3" src="https://github.com/user-attachments/assets/3c5a1e97-748e-495d-b3cd-318da6f10f2b" />
<img width="1920" height="1030" alt="2" src="https://github.com/user-attachments/assets/442329d0-f735-4970-82c2-ce88631a4a9a" />


## Qué es

HunterBug es una herramienta de escritorio para **reconocimiento y detección de
vulnerabilidades web** en pruebas autorizadas. Reúne en una sola ventana lo que
normalmente obliga a saltar entre cinco o seis utilidades: reconocimiento DNS,
escaneo de puertos con banner, captura de tráfico HTTP en bruto, auditoría de
cabeceras, mapeo a CVE y pruebas de SQLi, XSS, IDOR y BOLA.

Su rasgo distintivo es que **todo el resultado se va construyendo en vivo**: cada
módulo reporta estado, porcentaje y duración; los hallazgos aparecen en su
categoría al instante; y a medida que se descubren activos, se dibuja un **grafo
de superficie de ataque** que después se entrega a un modelo de IA para que
proponga la cadena de ataque y los siguientes pasos.

No es un lanzador de exploits. Es una herramienta de **análisis y evidencia**:
detecta, documenta y prioriza, y deja el trabajo fino en tus manos.

---

## Para quién está pensada

| Perfil | Para qué le sirve |
|---|---|
| **Bug hunter** (HackerOne, Bugcrowd, Intigriti) | Pasada inicial rápida sobre un alcance recién aceptado: qué hay, qué tecnologías, qué CVEs aplican y dónde probar primero. Genera el informe en Markdown para pegar en el reporte. |
| **Pentester en encargo con autorización** | Fase de reconocimiento y *low-hanging fruit* documentada con evidencia reproducible, antes de la explotación manual. |
| **Equipo de AppSec / DevSecOps** | Comprobación periódica de cabeceras de seguridad, TLS y exposición de puertos sobre tus propios servicios. |
| **Estudiante / jugador de CTF** | Trae un **laboratorio vulnerable incluido** (`banco_pruebas.py`) para ver cómo se comporta cada detector contra fallos reales, sin tocar nada ajeno. |

---

## Qué contiene

### Módulos de evaluación (9)

| Módulo | Tipo | Qué hace |
|---|---|---|
| **DNS** | Pasivo | 8 tipos de registro (A, AAAA, MX, TXT, NS, CNAME, SOA, CAA) vía DNS-over-HTTPS, con 3 resolutores de respaldo |
| **IP / Reversa** | Pasivo | Resolución directa e inversa de direcciones |
| **HTTP / Cabeceras** | Pasivo | Petición y respuesta **en bruto**, información TLS y auditoría de seguridad |
| **CVE** | Pasivo | Mapeo de tecnología a vulnerabilidades conocidas + consulta en vivo al NVD |
| **Puertos** | Activo | 47 puertos TCP habituales, en paralelo, con banner y servicio |
| **SQLi** | Activo | Inyección SQL por errores y por diferencial booleano |
| **XSS** | Activo | Cross-site scripting reflejado |
| **IDOR** | Activo | Acceso a objetos ajenos comparando dos identificadores |
| **BOLA** | Activo | Autorización por objeto en API comparando dos credenciales |

> Los módulos **activos** requieren marcar la casilla de autorización. Sin ella se
> omiten y la herramienta sigue funcionando en modo pasivo.

### Reconocimiento

- **DNS completo** con respaldo entre tres resolutores DoH (Cloudflare, Google,
  Quad9): si uno falla o no valida el certificado, prueba el siguiente.
- **Escaneo TCP moderado**: 47 puertos, 40 hilos, 1,5 s de espera, con captura de
  banner real (`SSH-2.0-OpenSSH_6.6.1p1`, `HTTP/1.1 200 OK`, …).
- **Identificación de servicio** por puerto y **resolución inversa**.
- **Fingerprint pasivo** de tecnología por cabeceras y cuerpo: WordPress, Drupal,
  Joomla, Next.js, React, Vue, Laravel, Django, ASP.NET, GraphQL, Shopify y más.

### HTTP y TLS

- **Petición y respuesta en bruto**, capturadas por socket: ves exactamente lo que
  viaja por el cable, igual que en el visor de un proxy.
- **Historial de peticiones** con método, URL, código y latencia, y botón para
  repetir la última.
- **Información TLS**: versión, cifrado, sujeto, emisor y fecha de caducidad del
  certificado.
- **Auditoría de 6 cabeceras de seguridad** (HSTS, CSP, X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy, Permissions-Policy) con severidad y
  recomendación concreta, más detección de **6 cabeceras que filtran tecnología**.
- **Análisis de CSP**: avisa si permite `unsafe-inline`, `unsafe-eval`, comodín
  `*` u orígenes en `http:`.

### Vulnerabilidades

- **SQLi**: 15 firmas de error para MySQL, MSSQL, PostgreSQL, Oracle, SQLite,
  JDBC y Hibernate; 8 payloads de error y 3 pares de condiciones booleanas. Marca
  la severidad según la confianza (confirmado por error → crítico; diferencial →
  alto o medio).
- **XSS reflejado**: 6 payloads con marcador único y aleatorio por petición, para
  no dar falsos positivos por caché ni por reflejo de contenido previo.
- **IDOR / BOLA**: comparación de respuestas con **similitud Jaccard** sobre
  tokens, no solo por tamaño. Distingue tres casos: control de autorización
  correcto (informativo), acceso a objeto ajeno (alto) y respuestas casi idénticas
  (medio, a confirmar).

### CVE

- **Base local de 34 CVEs reales**, 24 de ellos críticos, con comparación **real
  de rangos de versión** (no texto literal): si el producto está parcheado, no lo
  marca. Cubre RCE, path traversal, SSRF, SQLi, XSS, SSTI, desbordamientos,
  enumeración y fallos de autorización, en Log4j, Struts, Spring, OpenSSL,
  Apache, nginx, OpenSSH, Tomcat, WebLogic, Drupal, WordPress, Bootstrap, jQuery,
  Laravel, Django, Grafana, F5, Fortinet, Citrix, Exchange, Confluence, Jira,
  GitLab, vCenter, Zabbix, IIS, Rails, SMBv1, Elasticsearch, Solr, Jenkins,
  Magento y más.
- **Consulta en vivo al NVD** por palabra clave o por identificador `CVE-XXXX-YYYY`,
  sin clave de API.

### Grafo e IA

- **Grafo de superficie de ataque en vivo** con 11 tipos de nodo (objetivo,
  dominio, subdominio, IP, puerto, servicio, tecnología, endpoint, parámetro, CVE
  y hallazgo) y aristas de relación.
- **Layout dirigido por fuerzas** implementado desde cero: zoom con la rueda,
  arrastre con el ratón, clic en un nodo para ver su detalle.
- **Análisis asistido por IA** con dos motores:
  - **Ollama** (modelo local, el que elijas) si está disponible.
  - **Motor de reglas determinista** como respaldo: nunca te quedas sin
    conclusiones.
- La salida se estructura siempre en cuatro bloques: **lectura del grafo**,
  **cadena de ataque**, **prioridad** y **siguientes pruebas**.

### Interfaz y resultados

- **7 pestañas por categoría**: Panel, Reconocimiento, HTTP, Vulnerabilidades,
  CVE, Grafo/IA y Registro.
- **Ventanas independientes por módulo**: abre la de SQLi y la de Puertos a la vez
  y sigue las dos en directo.
- **Progreso individual** de cada módulo con estado, porcentaje y duración, más
  barra de progreso global.
- **Tema oscuro y claro** conmutable en caliente y recordado entre sesiones.
- **Consola de registro** con marcas de tiempo, niveles de color y autoscroll.
- **Informe exportable** en **Markdown** (listo para pegar en un reporte) o
  **JSON** (para automatizar), con resumen de severidad, puertos, tecnologías,
  cada hallazgo con su evidencia y recomendación, y el análisis de IA.

---

## Arquitectura

**Sin dependencias externas de red.** Todo el motor está construido sobre la
biblioteca estándar de Python: `socket` y `ssl` para el HTTP en bruto, `urllib`
para DNS-over-HTTPS y el NVD, `concurrent.futures` para el escaneo en paralelo.
No necesita `requests`, `dnspython`, `networkx` ni `beautifulsoup`.

Eso significa: **se instala solo, arranca rápido y no rompe por una actualización
de una librería ajena.**

```
HunterBugGUI.py     interfaz, temas, pestañas, orquestación y flujo de eventos
hb/
  net.py            HTTP en bruto, TLS, DNS-over-HTTPS, puertos, cabeceras
  vulns.py          detectores SQLi, XSS, IDOR y BOLA
  cve.py            base local de CVEs + consulta al NVD
  graph.py          grafo de superficie de ataque y layout por fuerzas
  ai.py             cliente de Ollama y motor de reglas
  events.py         bus de eventos para el tiempo real
  ui_widgets.py     tabla, visor HTTP, lienzo de grafo y ventanas de módulo
```

El bus de eventos desacopla el trabajo del dibujo: los módulos corren en hilos y
publican eventos; la interfaz los consume en su propio hilo. Por eso todo se ve
en vivo y nada se congela.

---

## Flujo de trabajo

1. **Escribe el objetivo** — dominio, URL o URL con parámetros
   (`https://sitio.com/buscar?q=test`). Los módulos SQLi y XSS necesitan
   parámetros para trabajar.
2. **Marca la casilla de autorización** para habilitar los módulos activos.
3. **Pulsa EJECUTAR EVALUACIÓN** y sigue el progreso módulo a módulo.
4. **Revisa cada pestaña**; abre ventanas por módulo si quieres verlas a la vez.
   Para IDOR y BOLA, rellena el patrón de URL (`.../usuario/{id}`) y las dos
   credenciales.
5. **Pulsa Analizar con IA** y **exporta el informe**.

---

## Calidad

La herramienta se entrega con su propia batería de pruebas, y las pruebas se
ejecutan contra objetivos reales, no contra simulaciones vacías:

| Suite | Qué cubre | Resultado |
|---|---|---|
| `verificar_motores.py` | Detectores contra un **laboratorio vulnerable local** + red real (example.com) | **41 / 41** |
| `prueba_gui.py` | Interfaz completa de extremo a extremo: pestañas, tema, ventanas, evaluación real, grafo, IA, informe, reinicio y cierre | **90 / 90** |
| `smoke_test.py` | Regresión de las funciones base (tema, fondo, persistencia, cierre limpio) | OK |

Los detectores no se dan por buenos "porque compilan": SQLi, XSS, IDOR y BOLA se
verifican contra un servidor deliberadamente vulnerable que levanta el propio
proyecto (`banco_pruebas.py`), y se comprueba que **encuentran el fallo** y que
**no lo inventan** cuando la versión está parcheada.

---

## Alcance y ética

Esta herramienta está pensada **exclusivamente para pruebas autorizadas**:

- Programas de bug bounty **dentro del alcance publicado**.
- Laboratorios propios y entornos de práctica.
- Encargos de cliente con **permiso por escrito**.

Los módulos activos trabajan con **volumen bajo y sin técnicas destructivas**: no
hay denegación de servicio, ni fuerza bruta, ni enumeración masiva de usuarios.
Aun así, **probar sistemas sin autorización es ilegal**, y la responsabilidad del
uso recae en quien ejecuta la herramienta.

---

## Requisitos y puesta en marcha

**Opción 1 — ejecutable (recomendado)**

```
HunterBug 1.0.exe        Doble clic. No requiere instalar nada.
```

**Opción 2 — desde el código**

```
Python 3.10 o superior  (probado en 3.14)
pip install customtkinter pillow matplotlib
python HunterBugGUI.py
```

**Verificar que todo funciona**

```
python verificar_motores.py     # 41 pruebas de los motores
python prueba_gui.py            # 90 pruebas de la interfaz
```

---

## Créditos

**HunterBug 1.0** — versión mejorada y creada para la comunidad **hacking team**
by **Juan Antonio**.

Herramienta de bug bounty y pruebas de seguridad autorizadas.
