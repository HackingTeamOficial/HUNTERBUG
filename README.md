# HunterBug 1.0

**Framework de evaluación de seguridad para bug hunters**

> Versión mejorada y creada para la comunidad **hacking team** · by **Juan Antonio**

---

## Qué es

HunterBug es una herramienta de escritorio para **reconocimiento y detección de
vulnerabilidades web** en pruebas autorizadas. Reúne en una sola ventana lo que
normalmente obliga a saltar entre cinco o seis utilidades: reconocimiento DNS,
escaneo de puertos con banner, captura de tráfico HTTP en bruto, auditoría de
cabeceras, mapeo a CVE y pruebas de SQLi, XSS, IDOR y BOLA.

En la versión 1.0 el análisis se apoya en un **catálogo de 203 chequeos** que
mide el objetivo en once categorías —cabeceras, cookies, CORS, métodos, TLS,
respuesta, contenido, rutas expuestas, tecnología, fugas de información y
pruebas de inyección y lógica sobre parámetros— y devuelve un **índice de
seguridad de 0 a 100** con su desglose.

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

### Módulos de evaluación (10)

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
| **Catálogo** | Mixto | **Motor de 203 chequeos** agrupados en 11 categorías, con puntuación de seguridad |

> Los módulos **activos** requieren marcar la casilla de autorización. Sin ella se
> omiten y la herramienta sigue funcionando en modo pasivo.

### El catálogo de 203 chequeos

El módulo **Catálogo** es el corazón del análisis. Ejecuta 203 verificaciones
organizadas en once categorías, y cada una devuelve título, detalle, evidencia,
CWE y recomendación. Es lo que permite pasar de "mirar una web" a **medirla**.

| Categoría | Chequeos | Qué cubre |
|---|---|---|
| **Cabeceras** | 40 | HSTS, CSP, nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, CORP, exposición del *stack*, caché, compresión, CSP en políticas de *sandbox*… |
| **Cookies** | 12 | Secure, HttpOnly, SameSite, Domain, Path, Prefijo `__Host-`/`__Secure-`, caducidad, longitud y nombres por defecto |
| **CORS** | 7 | Reflexión de `Origin`, credenciales con origen abierto, origen `null`, cabeceras expuestas, `Vary` |
| **Métodos** | 8 | TRACE, verbos de escritura (PUT, DELETE, PATCH), WebDAV, métodos no estándar, negación de verbos inocuos |
| **TLS** | 14 | Versiones negociadas, TLS 1.0/1.1, ciphers débiles, caducidad y emisor del certificado, Autoridad, *pinning* |
| **Respuesta** | 12 | Compresión, caché, duplicados de cabecera, errores del servidor, redirecciones, *MIME sniffing* |
| **Contenido** | 28 | Comentarios con credenciales, *source maps*, secretos en el cliente, correos, IPs internas, rutas absolutas, contenido mixto, SRI, formularios, CSRF, `target=_blank`, `iframes`, errores verbosos |
| **Rutas** | 12 | `.git`, `.env`, `.svn`, `.DS_Store`, `server-status`, `phpinfo()`, Actuator, *debug*, consola, Swagger, *backups*, listado de directorios |
| **Tecnología** | 20 | WordPress, Drupal, Joomla, Shopify, Next.js, React, Vue, Angular, Laravel, Django, Rails, Spring, ASP.NET, PHP, Tomcat, nginx, Apache, IIS, Cloudflare, Vercel |
| **Parámetros** | 40 | SQLi (errores, booleana, cabeceras, cookies), XSS, SSTI, CRLF, *path traversal*, LFI, redirección abierta, SSRF, LDAP, XPath, NoSQL, XXE, HPP, asignación masiva, enumeración de usuarios, HPP, *prototype pollution*, suplantación de cabeceras, límites de peticiones… |
| **Fugas** | 10 | Introspección de GraphQL, `robots.txt`, `security.txt`, `sitemap.xml`, copias de seguridad, paneles de administración |

Cada chequeo se muestra en la pestaña **Catálogo** con su identificador, su
estado (`FALLO`, `OK`, `OMITIDO`, `ERROR`), su CWE y su evidencia, y se puede
filtrar por categoría o por severidad.

### Puntuación y métricas

Al terminar, el catálogo produce un **índice de seguridad de 0 a 100** con letra
(A–F), calculado con decaimiento exponencial sobre la penalización acumulada
por severidad: diferencia objetivos muy cargados de fallos de los simplemente
descuidados sin saturarse en cero. Además entrega:

- Desglose de la puntuación **por categoría** (con gráfico).
- Fallos por severidad: críticos, altos, medios, bajos e informativos.
- **Cobertura**: cuántos chequeos se ejecutaron frente a los omitidos.
- Métricas de red: peticiones, bytes, tiempo total, tiempo medio por petición
  y ritmo (peticiones/segundo).
- Métricas de la respuesta: *status*, versión HTTP, IP, compresión, servidor.
- Métricas de TLS: versión, cifrado, emisor, validez y clave.

El resultado se puede **exportar a CSV** desde la propia pestaña.

### Informes y compatibilidad con otras herramientas

La pestaña **Informe** genera el informe completo de la evaluación en nueve
formatos, con toda la evidencia recogida. Hay un botón por formato y otro para
generarlos todos de una vez en `informes/`.

| Formato | Qué es | Quién lo lee |
|---|---|---|
| **HTML** | Informe completo, autocontenido (sin recursos externos), con portada, resumen ejecutivo, gráficos SVG, todos los hallazgos con su evidencia, la superficie de ataque, las métricas, el catálogo de 203 chequeos y el tráfico HTTP en bruto | Cualquier navegador |
| **PDF** | El mismo informe en PDF. Se genera con el navegador del sistema en modo *headless* (fidelidad idéntica al HTML) y, si no hay navegador, con un **generador de PDF propio sin dependencias** | Adobe, navegador, Word |
| **JSON** | Todos los datos de la evaluación en crudo | Scripts, automatización |
| **Markdown** | Texto plano con tablas, para pegar en el reporte o en una wiki | HackerOne, Bugcrowd, Obsidian |
| **CSV** | Una fila por hallazgo, con la evidencia aplanada | Excel, Google Sheets |
| **HAR 1.2** | El tráfico HTTP capturado, con peticiones y respuestas en bruto | **OWASP ZAP** (Importar → *Import HAR*), Chrome DevTools, Burp con extensión |
| **SARIF 2.1.0** | Formato estándar de resultados de análisis, con reglas, niveles, mapeo a CWE y las peticiones/respuestas (`webRequest`/`webResponse`) | GitHub / GitLab / Azure *code scanning*, add-on SARIF de ZAP |
| **Burp XML** | El mismo XML que exporta Burp Suite con sus *issues* (incluye el DTD con `<!ATTLIST issues burpVersion>`, que es lo que detectan los importadores) | Invicti, Metasploit, Dradis, Burp Pro |
| **ZAP XML** | El informe XML clásico de OWASP ZAP (`<OWASPZAPReport>` con `<alertitem>`, `riskcode` y `cweid`) | Lectores de informes de ZAP |

El tráfico HTTP capturado se adjunta como evidencia reproducible: el HAR, el
SARIF y el XML de Burp incluyen la petición y la respuesta en bruto de cada
hallazgo.

Los nueve formatos están verificados contra su especificación: el HAR declara
la versión 1.2 y sus entradas llevan los campos obligatorios; el SARIF declara
2.1.0 y sus niveles son válidos; los XML parsean y llevan los elementos que
esperan sus lectores.

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

El catálogo de 203 chequeos incluye, además de los módulos independientes:

- **Inyección SQL**: firmas de error para MySQL, MSSQL, PostgreSQL, Oracle,
  SQLite, JDBC y Hibernate; diferencial booleano; inyección desde cabeceras
  (`User-Agent`, `Referer`) y desde cookies.
- **XSS e inyección HTML**: payloads con marcador único y aleatorio por
  petición, en contexto de parámetro, de cabecera y de JavaScript.
- **SSTI**: detección con **dos expresiones distintas** evaluadas, para que una
  coincidencia casual en el HTML no dé un falso positivo.
- **CRLF, path traversal, LFI, redirección abierta, SSRF, LDAP, XPath, NoSQL
  (`$ne`, `$gt`), XXE y contaminación de prototipos**.
- **Lógica**: asignación masiva, contaminación de parámetros (HPP),
  enumeración de usuarios, validación de rangos y tipos, suplantación de
  cabeceras de proxy y ausencia de límite de peticiones.

Los módulos independientes aportan además:

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
| `verificar_catalogo.py` | Los **203 chequeos** contra 11 objetivos del laboratorio vulnerable + objetivo real: que disparen donde deben, que **no den falsos positivos**, métricas y puntuación | **78 / 78** |
| `prueba_catalogo_gui.py` | La pestaña del catálogo de extremo a extremo: construcción, 203 filas, ejecución real, puntuación, filtros, detalle, modo sin autorización y cambio de tema | **23 / 23** |
| `verificar_informes.py` | Los **9 formatos de informe** con datos reales: HTML autocontenido con toda la evidencia, PDF válido, y el HAR, SARIF, Burp XML y ZAP XML contra su especificación | **104 / 104** |
| `prueba_informe_gui.py` | La pestaña de informes: botones por formato, generación de cada uno desde la interfaz, «generar todos», nombres y extensiones, y el registro de resultados | **41 / 41** |
| `prueba_pdf.py` | El generador de PDF propio: validez, tabla `xref` con offsets correctos, troceado de texto, acentos y escapes peligrosos | **17 / 17** |
| `verificar_motores.py` | Detectores clásicos contra el laboratorio + red real (example.com) | **41 / 41** |
| `prueba_gui.py` | Interfaz completa de extremo a extremo: pestañas, tema, ventanas, evaluación real, grafo, IA, informe, reinicio y cierre | **92 / 92** |
| `probar_exe.py` | Que el `.exe` empaquetado **arranca y crea su ventana** | OK |
| `smoke_test.py` | Regresión de las funciones base (tema, fondo, persistencia, cierre limpio) | OK |

Los detectores no se dan por buenos "porque compilan": se verifican contra un
servidor deliberadamente vulnerable que levanta el propio proyecto
(`banco_pruebas.py`), y se comprueba que **encuentran el fallo** y que
**no lo inventan** donde no lo hay. Cada objetivo del laboratorio lleva un
fallo plantado de una familia distinta, y la batería exige además que los
chequeos que no corresponden **no se disparen** en ese objetivo: así se cazan
los falsos positivos, no solo las detecciones.

Durante el desarrollo de esta versión, esa disciplina corrigió diez chequeos
reales: un `self.ruta` que tapaba al método `ruta()`, un `%0d` interpretado
como formato, CRLF escrito como caracteres reales en vez de su escape, un
*regex* de asignación masiva cuya alternancia quedaba fuera del grupo, una
comparación entre respuestas crudas y respuestas con redirecciones seguidas, y
una detección de SSTI que daba positivo con cualquier versión que contuviera
"49".

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
dist\HunterBug 1.0.exe        Doble clic. No requiere instalar nada.
```

Para recompilarlo después de tocar el código:

```
compilar.bat                    (doble clic, o desde la carpeta)
python probar_exe.py            # comprueba que el .exe arranca
```

**Opción 2 — desde el código**

```
Python 3.10 o superior  (probado en 3.14)
pip install customtkinter pillow matplotlib
python HunterBugGUI.py
```

**Verificar que todo funciona**

```
python verificar_catalogo.py    # 78 pruebas: los 203 chequeos
python prueba_catalogo_gui.py   # 23 pruebas: la pestana del catalogo
python verificar_informes.py    # 104 pruebas: los 9 formatos de informe
python prueba_informe_gui.py    # 41 pruebas: la pestana de informes
python prueba_pdf.py            # 17 pruebas: el generador de PDF propio
python verificar_motores.py     # 41 pruebas de los motores
python prueba_gui.py            # 92 pruebas de la interfaz
python probar_exe.py            # el .exe empaquetado arranca
```

---

## Créditos

**HunterBug 1.0** — versión mejorada y creada para la comunidad **hacking team**
by **Juan Antonio**.

Herramienta de bug bounty y pruebas de seguridad autorizadas.
