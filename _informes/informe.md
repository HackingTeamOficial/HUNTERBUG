# Informe de evaluación de seguridad

**Objetivo:** `http://127.0.0.1:8080/buscar?q=test`  
**Herramienta:** HunterBug 1.1 · **Fecha:** 25/10/2026 a las 21:57 · **Perfil:** completo

| Métrica | Valor |
|---|---|
| Puntuación | **1.8 / 100** (F — critico) |
| Cobertura | 91.1% |
| Hallazgos | 88 |
| Crítico | 8 |
| Alto | 17 |
| Medio | 19 |
| Bajo | 16 |
| Informativo | 28 |

## 1. Resumen ejecutivo

**El objetivo obtiene 1.8 sobre 100 (calificación F, critico).**

Se han registrado 88 hallazgos: 8 crítico, 17 alto, 19 medio, 16 bajo, 28 informativo.

Las áreas con peor resultado son cors (0.0 puntos, 7 fallo(s)), metodos (0.0 puntos, 6 fallo(s)), rutas (0.0 puntos, 12 fallo(s)).

Se ejecutaron 185 de los 203 chequeos del catálogo (cobertura 91.1%). Los chequeos omitidos requieren confirmar la autorización o solo aplican sobre HTTPS.

### Puntuación por categoría

| Categoría | Puntos | Fallos |
|---|---|---|
| cors | 0.0 | 7 |
| metodos | 0.0 | 6 |
| rutas | 0.0 | 12 |
| fugas | 0.6 | 7 |
| cookies | 1.0 | 6 |
| contenido | 3.8 | 20 |
| parametros | 5.2 | 9 |
| cabeceras | 22.0 | 17 |
| tecnologia | 89.2 | 4 |
| respuesta | 100.0 | 0 |
| tls | 100.0 | 0 |

## 2. Hallazgos detallados

### Crítico (8)

#### CRS-03 — CORS con credenciales y origen reflejado

*Crítico · cors · CWE-942 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Con Allow-Credentials true y el Origin reflejado, cualquier web puede leer respuestas con la sesion del usuario

**Evidencia**

- `origin_enviado`: https://hunterbug-prueba.invalid
- `acao`: https://hunterbug-prueba.invalid
- `acac`: true

> **Recomendación:** Lista blanca estricta de origenes y Vary: Origin

#### FUG-01 — Repositorio Git expuesto accesible

*Crítico · rutas · CWE-538 · A01:2021*

- **URL:** `http://127.0.0.1/.git/config`

Permite reconstruir el codigo fuente completo

**Evidencia**

- `ruta`: /.git/config
- `status`: 200
- `bytes`: 107
- `extracto`: [core]
	repositoryformatversion = 0
	filemode = true
[remote "origin"]
	url = https://git.interno/panel.git

> **Recomendación:** Bloquear el acceso a .git desde el servidor web

#### FUG-02 — Fichero .env expuesto accesible

*Crítico · rutas · CWE-538 · A01:2021*

- **URL:** `http://127.0.0.1/.env`

Contiene credenciales, claves y configuracion de la aplicacion

**Evidencia**

- `ruta`: /.env
- `status`: 200
- `bytes`: 74
- `extracto`: APP_ENV=production
DB_PASSWORD=Sup3rS3cret0
AWS_SECRET_ACCESS_KEY=abcd1234

> **Recomendación:** Sacar el .env del directorio publico

#### FUG-08 — Actuator /env expuesto accesible

*Crítico · rutas · CWE-200 · A01:2021*

- **URL:** `http://127.0.0.1/actuator/env`

Muestra variables de entorno, incluidas credenciales

**Evidencia**

- `ruta`: /actuator/env
- `status`: 200
- `bytes`: 127
- `extracto`: {"activeProfiles": ["prod"], "propertySources": [{"name": "systemEnvironment", "properties": {"DB_PASSWORD": {"value": "x"}}}]}

> **Recomendación:** Deshabilitar o proteger el endpoint env

#### FUG-10 — Consola expuesta accesible

*Crítico · rutas · CWE-489 · A01:2021*

- **URL:** `http://127.0.0.1/console`

Una consola interactiva expuesta permite ejecucion de codigo

**Evidencia**

- `ruta`: /console
- `status`: 200
- `bytes`: 28
- `extracto`: <h1>Consola interactiva</h1>

> **Recomendación:** Eliminar o proteger la consola

#### FUG-17 — Copia de seguridad accesible (/backup.zip)

*Crítico · fugas · CWE-530 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Una copia descargable entrega el codigo o la base de datos completa

**Evidencia**

- `ruta`: /backup.zip
- `bytes`: 504

> **Recomendación:** Retirar las copias del directorio web

#### PAR-01 — Inyeccion SQL (basada en errores) en 'q'

*Crítico · parametros · CWE-89 · A03:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`
- **Parámetro:** `q`

El parametro 'q' refleja un error de MySQL al inyectar "'"

**Evidencia**

- `payload`: '
- `motor`: MySQL
- `fragmento`: <h1>Error</h1>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to u

> **Recomendación:** Usar consultas parametrizadas (prepared statements) y validacion estricta de entrada.

#### PAR-17 — Inyeccion de comandos en 'q'

*Crítico · parametros · CWE-78 · A03:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`
- **Parámetro:** `q`

El comando enviado aparece en la salida

**Evidencia**

- `payload`: ;echo hunterbug_probe

> **Recomendación:** No construir comandos con entrada del usuario; usar APIs del sistema

### Alto (17)

#### CKI-01 — 1 cookie(s) sin secure

*Alto · cookies · CWE-614 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

La cookie viaja tambien por HTTP sin cifrar y puede ser interceptada

**Evidencia**

- `cookies`: PHPSESSID=abc123; Path=/

> **Recomendación:** Anadir el atributo Secure a todas las cookies de sesion

#### CKI-02 — 1 cookie(s) sin httponly

*Alto · cookies · CWE-1004 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Sin HttpOnly el JavaScript de la pagina puede leer la cookie, lo que convierte cualquier XSS en robo de sesion

**Evidencia**

- `cookies`: PHPSESSID=abc123; Path=/

> **Recomendación:** Anadir HttpOnly a las cookies de sesion

#### CON-03 — 2 posible(s) secreto(s) en el cliente

*Alto · contenido · CWE-798 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Claves o tokens embebidos en el HTML o el JS son visibles para cualquiera

**Evidencia**

- `hallazgos`: api_key = "AKIAIOSFODNN7EXAMPLE1" = AKIAIOSF..., AWS key: AKIAIOSFODNN...

> **Recomendación:** Mover los secretos al servidor y rotarlos

#### CON-10 — Formulario de contrasena con method=GET

*Alto · contenido · CWE-598 · A04:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

La contrasena queda en la URL, en el historial y en los registros del servidor

**Evidencia**

- `formulario`: <form action="/login" method="get"> <input type="text" name="usuario"> <input type="password" name="clave"> <input type="submit"> </form>

> **Recomendación:** Usar POST sobre HTTPS

#### CRS-02 — CORS refleja cualquier Origin enviado

*Alto · cors · CWE-942 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

El servidor devuelve el origen solicitado sin validarlo, lo que permite leer respuestas desde cualquier web

**Evidencia**

- `origin_enviado`: https://hunterbug-prueba.invalid
- `acao_devuelto`: https://hunterbug-prueba.invalid

> **Recomendación:** Validar el Origin contra una lista blanca

#### CRS-04 — CORS acepta el origen null

*Alto · cors · CWE-942 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

El origen null procede de iframes sandbox o ficheros locales y no deberia autorizarse

**Evidencia**

- `acao`: null

> **Recomendación:** Rechazar explicitamente el origen null

#### CRS-05 — CORS con comodin y credenciales

*Alto · cors · CWE-942 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Combinacion contradictoria que algunos proxies resuelven reflejando el origen

**Evidencia**

- `acao`: *
- `acac`: true

> **Recomendación:** Eliminar el comodin cuando se usan credenciales

#### FUG-03 — Metadatos SVN expuestos accesible

*Alto · rutas · CWE-538 · A01:2021*

- **URL:** `http://127.0.0.1/.svn/entries`

Revela el historial de versiones y el codigo fuente

**Evidencia**

- `ruta`: /.svn/entries
- `status`: 200
- `bytes`: 15
- `extracto`: 12

dir
/trunk


> **Recomendación:** Bloquear el acceso a .svn

#### FUG-06 — phpinfo() expuesto accesible

*Alto · rutas · CWE-200 · A01:2021*

- **URL:** `http://127.0.0.1/phpinfo.php`

Expone la configuracion completa de PHP

**Evidencia**

- `ruta`: /phpinfo.php
- `status`: 200
- `bytes`: 56
- `extracto`: <html><title>phpinfo()</title><h1>PHP Version 8.1.2</h1>

> **Recomendación:** Eliminar phpinfo() de produccion

#### FUG-07 — Spring Boot Actuator expuesto accesible

*Alto · rutas · CWE-200 · A01:2021*

- **URL:** `http://127.0.0.1/actuator`

Los endpoints de gestion pueden filtrar configuracion y permitir cambios

**Evidencia**

- `ruta`: /actuator
- `status`: 200
- `bytes`: 46
- `extracto`: {"_links": {"env": {"href": "/actuator/env"}}}

> **Recomendación:** Proteger /actuator con autenticacion

#### FUG-09 — Endpoint de depuracion expuesto accesible

*Alto · rutas · CWE-489 · A01:2021*

- **URL:** `http://127.0.0.1/debug`

Suele permitir ejecutar codigo o volcar el estado interno

**Evidencia**

- `ruta`: /debug
- `status`: 200
- `bytes`: 44
- `extracto`: <h1>Debug console</h1><p>ejecutar codigo</p>

> **Recomendación:** Eliminar los endpoints de depuracion

#### FUG-20 — Fichero sensible accesible (/.env.local)

*Alto · fugas · CWE-538 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Suele contener credenciales o hashes

**Evidencia**

- `ruta`: /.env.local
- `bytes`: 32

> **Recomendación:** Eliminar copias y ficheros de configuracion del directorio publico

#### HDR-02 — Falta la cabecera content-security-policy

*Alto · cabeceras · CWE-1021 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Sin CSP no hay defensa en profundidad contra XSS ni control de origenes

**Evidencia**

- `cabecera_ausente`: content-security-policy

> **Recomendación:** default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'

#### MTH-03 — El servidor acepta PUT

*Alto · metodos · CWE-650 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

PUT sobre una ruta inexistente devolvio 201: puede permitir subir contenido

**Evidencia**

- `status`: 201
- `ruta`: http://127.0.0.1:8080/hunterbug-sonda-1792961860

> **Recomendación:** Rechazar PUT con 405 salvo donde sea necesario

#### MTH-04 — El servidor acepta DELETE

*Alto · metodos · CWE-650 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

DELETE sobre una ruta inexistente devolvio 204

**Evidencia**

- `status`: 204
- `ruta`: http://127.0.0.1:8080/hunterbug-sonda-1792961860

> **Recomendación:** Rechazar DELETE con 405 salvo donde sea necesario

#### PAR-06 — XSS reflejado en 'q'

*Alto · parametros · CWE-79 · A03:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`
- **Parámetro:** `q`

El payload vuelve sin escapar en el cuerpo de la respuesta del parametro 'q'

**Evidencia**

- `payload`: <hbmkhbiotuty>
- `fragmento`: ic en la raiz</p> <h2>Resultados para <hbmkhbiotuty></h2> </body> </html>

> **Recomendación:** Escapar la salida segun contexto, aplicar CSP estricta y validar la entrada.

#### PAR-24 — Posible asignacion masiva en /api/perfil

*Alto · parametros · CWE-915 · A01:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

El servidor acepto campos de privilegio enviados por el cliente

**Evidencia**

- `ruta`: /api/perfil
- `status`: 200
- `extracto`: {"role":"admin","is_admin":true,"admin":true}

> **Recomendación:** Lista blanca de campos asignables

### Medio (19)

#### CKI-03 — 1 cookie(s) sin samesite

*Medio · cookies · CWE-1275 · A01:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Sin SameSite el navegador envia la cookie en peticiones cruzadas, lo que facilita CSRF

**Evidencia**

- `cookies`: PHPSESSID=abc123; Path=/

> **Recomendación:** Anadir SameSite=Lax o Strict

#### CKI-08 — Identificador de sesion corto (6 caracteres)

*Medio · cookies · CWE-330 · A02:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Un identificador corto es adivinable por fuerza bruta

**Evidencia**

- `cookie`: PHPSESSID
- `longitud`: 6

> **Recomendación:** Usar al menos 128 bits de entropia

#### CON-02 — El codigo referencia source maps

*Medio · contenido · CWE-540 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Los ficheros .map permiten reconstruir el codigo fuente original

**Evidencia**

- `referencias`: /app.js.map-->

> **Recomendación:** No publicar los .map en produccion

#### CON-05 — 2 direccion(es) IP privada(s) en el cuerpo

*Medio · contenido · CWE-200 · A01:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Revelan la topologia interna de la red

**Evidencia**

- `ips`: 10.20.30.40, 192.168.1.10

> **Recomendación:** Eliminar las referencias a la red interna

#### CON-06 — Rutas absolutas del sistema en el cuerpo

*Medio · contenido · CWE-200 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Revelan la estructura de directorios del servidor

**Evidencia**

- `rutas`: /var/www

> **Recomendación:** Usar rutas relativas y errores genericos

#### CON-09 — Formulario que envia datos a otro dominio

*Medio · contenido · CWE-346 · A01:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Los datos del usuario salen del sitio

**Evidencia**

- `acciones`: https://recolector.invalid/recoger

> **Recomendación:** Enviar los formularios al propio dominio

#### CON-12 — 2 formulario(s) POST sin token anti-CSRF

*Medio · contenido · CWE-352 · A01:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Sin token, otra web puede enviar el formulario en nombre del usuario

**Evidencia**

- `formularios`: <form action="https://recolector.invalid/recoger" method="post"> <input type="text" name="usuario"> </form>, <form action="/perfil" method="post"> <input type="text" name="nombre"> <input type="submit"> </form>

> **Recomendación:** Token por sesion y validacion SameSite

#### CRS-01 — CORS permite cualquier origen (*)

*Medio · cors · CWE-942 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Cualquier web puede leer la respuesta desde el navegador de la victima

**Evidencia**

- `acao`: *

> **Recomendación:** Lista blanca de origenes concretos

#### FUG-05 — Estado del servidor expuesto accesible

*Medio · rutas · CWE-200 · A01:2021*

- **URL:** `http://127.0.0.1/server-status`

Revela peticiones en curso, clientes y carga del servidor

**Evidencia**

- `ruta`: /server-status
- `status`: 200
- `bytes`: 120
- `extracto`: <html><title>Apache Server Status</title><h1>Apache Server Status for 127.0.0.1</h1>Current Time: now
Total accesses: 12

> **Recomendación:** Restringir /server-status a la red local

#### FUG-11 — Documentacion de API expuesta accesible

*Medio · rutas · CWE-200 · A01:2021*

- **URL:** `http://127.0.0.1/swagger-ui.html`

Describe todos los endpoints y sus esquemas, incluidos los internos

**Evidencia**

- `ruta`: /swagger-ui.html
- `status`: 200
- `bytes`: 45
- `extracto`: <html><title>Swagger UI</title><p>swagger</p>

> **Recomendación:** Proteger la documentacion en produccion

#### FUG-12 — Especificacion de API expuesta accesible

*Medio · rutas · CWE-200 · A01:2021*

- **URL:** `http://127.0.0.1/api-docs`

Facilita la enumeracion completa de la API

**Evidencia**

- `ruta`: /api-docs
- `status`: 200
- `bytes`: 55
- `extracto`: {"openapi": "3.0.0", "paths": {"/api/v1/usuarios": {}}}

> **Recomendación:** Restringir el acceso a la especificacion

#### HDR-03 — Falta la cabecera x-content-type-options

*Medio · cabeceras · CWE-436 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Sin nosniff el navegador puede interpretar un fichero con otro tipo MIME

**Evidencia**

- `cabecera_ausente`: x-content-type-options

> **Recomendación:** X-Content-Type-Options: nosniff

#### HDR-04 — Falta la cabecera x-frame-options

*Medio · cabeceras · CWE-1021 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Sin proteccion de framing la pagina es embebible y vulnerable a clickjacking

**Evidencia**

- `cabecera_ausente`: x-frame-options

> **Recomendación:** X-Frame-Options: DENY (o CSP frame-ancestors 'none')

#### MTH-01 — Metodo TRACE habilitado

*Medio · metodos · CWE-693 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

TRACE devuelve la peticion completa y facilita Cross-Site Tracing

**Evidencia**

- `status`: 200
- `cuerpo`: TRACE / HTTP/1.1
Host: 127.0.0.1:8080



> **Recomendación:** Deshabilitar TRACE (TraceEnable off)

#### MTH-02 — OPTIONS anuncia metodos de escritura

*Medio · metodos · CWE-650 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

El servidor declara: GET, HEAD, POST, PUT, DELETE, PATCH, PROPFIND, TRACE

**Evidencia**

- `allow`: GET, HEAD, POST, PUT, DELETE, PATCH, PROPFIND, TRACE
- `peligrosos`: PUT, DELETE, PATCH

> **Recomendación:** Deshabilitar los metodos no usados

#### MTH-08 — WebDAV habilitado

*Medio · metodos · CWE-650 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Anuncia: PROPFIND

**Evidencia**

- `metodos_dav`: PROPFIND

> **Recomendación:** Deshabilitar WebDAV si no se usa

#### PAR-09 — Inyeccion HTML en 'q'

*Medio · parametros · CWE-79 · A03:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`
- **Parámetro:** `q`

Se pueden inyectar etiquetas HTML arbitrarias; con un navegador puede escalarse a XSS

**Evidencia**

- `payload`: <hbmk-hbfs3u5q>x</hbmk-hbfs3u5q>

> **Recomendación:** Escapar la salida segun contexto

#### PAR-27 — No se observa limite de peticiones

*Medio · parametros · CWE-770 · A04:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

12 peticiones seguidas devolvieron siempre 200, sin 429 ni bloqueo

**Evidencia**

- `peticiones`: 12
- `codigos`: 200

> **Recomendación:** Aplicar limite por IP y por cuenta en endpoints sensibles

#### PAR-37 — Entrada reflejada dentro de JavaScript (q)

*Medio · parametros · CWE-79 · A03:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`
- **Parámetro:** `q`

El valor vuelve sin escapar en un contexto de script, lo que permite romper la cadena

**Evidencia**

- `payload`: '+hbx6644j+'

> **Recomendación:** Escapar segun contexto JS y usar JSON.stringify

### Bajo (16)

#### CKI-07 — Cookie de sesion con nombre por defecto (PHPSESSID)

*Bajo · cookies · CWE-200 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Revela el framework (PHP) sin necesidad de fingerprint

**Evidencia**

- `cookie`: PHPSESSID=abc123; Path=/
- `framework`: PHP

> **Recomendación:** Renombrar la cookie de sesion

#### CON-01 — 2 comentario(s) HTML con informacion sensible

*Bajo · contenido · CWE-615 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Los comentarios viajan al cliente y revelan notas internas, credenciales o rutas

**Evidencia**

- `comentarios`: TODO: quitar el usuario admin / password: Sup3rS3cret0 antes de publicar, FIXME: la api key de produccion es api_key = "AKIAIOSFODNN7EXAMPLE1"

> **Recomendación:** Eliminar los comentarios en produccion

#### CON-08 — 2 script(s) sin Subresource Integrity

*Bajo · contenido · CWE-353 · A08:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Si el CDN se compromete, el script se ejecuta sin que nadie lo detecte

**Evidencia**

- `scripts`: <script src="https://cdn.ejemplo.invalid/lib.js">, <script src="/app.js">

> **Recomendación:** Anadir integrity y crossorigin a los scripts de terceros

#### CON-13 — 1 enlace(s) _blank sin rel=noopener

*Bajo · contenido · CWE-1022 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

La pagina destino puede manipular la ventana de origen mediante window.opener

**Evidencia**

- `enlaces`: <a href="https://externo.invalid" target="_blank">

> **Recomendación:** Anadir rel="noopener noreferrer"

#### CRS-06 — Respuesta CORS sin Vary: Origin

*Bajo · cors · CWE-436 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Una cache intermedia puede servir la cabecera CORS de un origen a otro

**Evidencia**

- `vary`: 

> **Recomendación:** Anadir Vary: Origin

#### FUG-04 — Fichero .DS_Store expuesto accesible

*Bajo · rutas · CWE-538 · A01:2021*

- **URL:** `http://127.0.0.1/.DS_Store`

Revela nombres de ficheros y estructura de directorios

**Evidencia**

- `ruta`: /.DS_Store
- `status`: 200
- `bytes`: 22
- `extracto`: Bud1index.html

> **Recomendación:** Bloquear el acceso a .DS_Store

#### FUG-14 — robots.txt expone rutas internas

*Bajo · fugas · CWE-200 · A01:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Rutas listadas: /admin/, /backup/, /config/

**Evidencia**

- `rutas`: /admin/, /backup/, /config/

> **Recomendación:** No listar rutas privadas en robots.txt

#### HDR-05 — Falta la cabecera referrer-policy

*Bajo · cabeceras · CWE-200 · A01:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Sin Referrer-Policy se filtran URLs completas a terceros

**Evidencia**

- `cabecera_ausente`: referrer-policy

> **Recomendación:** Referrer-Policy: strict-origin-when-cross-origin

#### HDR-06 — Falta la cabecera permissions-policy

*Bajo · cabeceras · CWE-693 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Sin Permissions-Policy las APIs del navegador quedan sin restringir

**Evidencia**

- `cabecera_ausente`: permissions-policy

> **Recomendación:** Permissions-Policy: geolocation=(), microphone=(), camera=()

#### HDR-07 — Falta la cabecera cross-origin-opener-policy

*Bajo · cabeceras · CWE-346 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Sin COOP la ventana puede ser referenciada desde otro origen

**Evidencia**

- `cabecera_ausente`: cross-origin-opener-policy

> **Recomendación:** Cross-Origin-Opener-Policy: same-origin

#### HDR-08 — Falta la cabecera cross-origin-resource-policy

*Bajo · cabeceras · CWE-346 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Sin CORP los recursos pueden ser embebidos desde otros origenes

**Evidencia**

- `cabecera_ausente`: cross-origin-resource-policy

> **Recomendación:** Cross-Origin-Resource-Policy: same-origin

#### HDR-34 — Sin cabecera Cache-Control

*Bajo · cabeceras · CWE-525 · A04:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

El contenido puede quedar en cache de proxies intermedios o del navegador

**Evidencia**

- `cache_control`: 

> **Recomendación:** Cache-Control: no-store en respuestas autenticadas o sensibles

#### HDR-36 — La cabecera Server revela version

*Bajo · cabeceras · CWE-200 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Facilita elegir exploits concretos para esa version

**Evidencia**

- `server`: Apache/2.4.49 (Unix)

> **Recomendación:** Ocultar la version (ServerTokens Prod, server_tokens off)

#### HDR-37 — X-Powered-By revela la tecnologia

*Bajo · cabeceras · CWE-200 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Expone el lenguaje y a veces la version exacta

**Evidencia**

- `x_powered_by`: PHP/8.1.2

> **Recomendación:** Eliminar la cabecera

#### HDR-38 — Cabeceras que revelan infraestructura (2)

*Bajo · cabeceras · CWE-200 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Revelan servidores intermedios, frameworks o versiones internas

**Evidencia**

- `x-runtime`: 0.0412
- `via`: 1.1 hunterbug-proxy

> **Recomendación:** Eliminar o minimizar estas cabeceras

#### MTH-05 — Un metodo no estandar no es rechazado

*Bajo · metodos · CWE-650 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

El metodo HUNTERBUG devolvio 200 en lugar de 405/501

**Evidencia**

- `status`: 200

> **Recomendación:** Rechazar metodos no implementados

### Informativo (28)

#### CKI-12 — Ninguna cookie cumple Secure + HttpOnly + SameSite

*Informativo · cookies · CWE-614 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Se han visto 1 cookie(s) y ninguna reune las tres protecciones

**Evidencia**

- `total_cookies`: 1
- `cookies`: PHPSESSID=abc123; Path=/

> **Recomendación:** Aplicar las tres a todas las cookies

#### CON-04 — 2 direccion(es) de correo en el cuerpo

*Informativo · contenido · CWE-200 · A01:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Facilitan campanas de phishing y enumeracion

**Evidencia**

- `correos`: admin@ejemplo.test, soporte@ejemplo.test

> **Recomendación:** Ofuscar o eliminar los correos publicos

#### CON-11 — Campo de contrasena sin autocomplete

*Informativo · contenido · CWE-522 · A07:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

El navegador puede almacenar la contrasena en equipos compartidos

**Evidencia**

- `input`: <input type="password" name="clave">

> **Recomendación:** autocomplete="current-password" o "off"

#### CON-14 — 1 iframe(s) sin atributo sandbox

*Informativo · contenido · CWE-1021 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

El contenido embebido se ejecuta con los permisos de la pagina

**Evidencia**

- `iframes`: <iframe src="https://externo.invalid/widget">

> **Recomendación:** Anadir sandbox a los iframes de terceros

#### CON-15 — Meta generator revela el CMS y su version

*Informativo · contenido · CWE-200 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

<meta name="generator" content="PanelCMS 3.1.4">

**Evidencia**

- `meta`: <meta name="generator" content="PanelCMS 3.1.4">

> **Recomendación:** Eliminar la etiqueta generator

#### CON-19 — 1 referencia(s) a almacenamiento externo

*Informativo · contenido · CWE-200 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Los buckets mal configurados son una fuga de datos habitual

**Evidencia**

- `buckets`: https://panel-datos.s3.amazonaws.com

> **Recomendación:** Revisar las politicas del bucket

#### CON-20 — 2 endpoint(s) de API referenciados

*Informativo · contenido · CWE-200 · A01:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Amplia la superficie de ataque conocida

**Evidencia**

- `endpoints`: /api/v1/facturas, /api/v1/usuarios

> **Recomendación:** Revisar que cada endpoint comprueba autorizacion

#### CON-21 — El HTML enlaza paneles de administracion

*Informativo · contenido · CWE-200 · A01:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Facilita localizar la zona privilegiada

**Evidencia**

- `rutas`: /admin/panel

> **Recomendación:** Restringir el acceso por red o autenticacion fuerte

#### CON-23 — El cuerpo declara un numero de version

*Informativo · contenido · CWE-200 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Version visible: 3.1.4

**Evidencia**

- `version`: 3.1.4

> **Recomendación:** Ocultar las versiones de los componentes

#### CON-24 — Copyright de 2019 (hace 7 anos)

*Informativo · contenido · CWE-1059 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Suele indicar un sitio sin mantenimiento, con componentes antiguos

**Evidencia**

- `anios`: 2019

> **Recomendación:** Actualizar y revisar dependencias

#### CON-28 — 3 tecnologias identificadas por el contenido

*Informativo · contenido · CWE-200 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Detectadas: WordPress, Next.js, React

**Evidencia**

- `tecnologias`: WordPress, Next.js, React

> **Recomendación:** Minimizar las huellas del stack

#### CRS-07 — CORS expone cabeceras sensibles al JavaScript

*Informativo · cors · CWE-200 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Expose-Headers incluye cabeceras de autenticacion

**Evidencia**

- `expose_headers`: Authorization

> **Recomendación:** Exponer solo las cabeceras necesarias

#### FUG-15 — No publica /.well-known/security.txt

*Informativo · fugas · CWE-1059 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Sin canal declarado de reporte de vulnerabilidades

**Evidencia**

- `status`: 404

> **Recomendación:** Publicar security.txt con un contacto de seguridad

#### FUG-16 — sitemap.xml accesible

*Informativo · fugas · CWE-200 · A01:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Facilita el inventario de URLs del sitio

**Evidencia**

- `bytes`: 66

> **Recomendación:** Revisar si el sitemap debe ser publico

#### FUG-19 — Panel de administracion accesible (/admin/)

*Informativo · fugas · CWE-200 · A01:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Expone la interfaz de gestion del CMS

**Evidencia**

- `ruta`: /admin/
- `status`: 200

> **Recomendación:** Restringir por IP o autenticacion adicional

#### FUG-22 — La pagina 404 revela el servidor y su version

*Informativo · fugas · CWE-200 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Firma encontrada: Apache/2.4.49

**Evidencia**

- `firma`: Apache/2.4.49
- `extracto`: <html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><address>Apache/2.4.49 (Unix) Server at 127.0.0.1 Port 8080</address></body></html>

> **Recomendación:** Pagina 404 personalizada

#### HDR-09 — Falta la cabecera cross-origin-embedder-policy

*Informativo · cabeceras · CWE-346 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Sin COEP no se aisla el contexto de ejecucion

**Evidencia**

- `cabecera_ausente`: cross-origin-embedder-policy

> **Recomendación:** Cross-Origin-Embedder-Policy: require-corp

#### HDR-10 — Falta la cabecera x-permitted-cross-domain-policies

*Informativo · cabeceras · CWE-346 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Sin esta cabecera los plugins de Adobe pueden cargar contenido cruzado

**Evidencia**

- `cabecera_ausente`: x-permitted-cross-domain-policies

> **Recomendación:** X-Permitted-Cross-Domain-Policies: none

#### HDR-11 — Falta la cabecera x-dns-prefetch-control

*Informativo · cabeceras · CWE-200 · A01:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Sin control de prefetch DNS se filtran dominios a terceros

**Evidencia**

- `cabecera_ausente`: x-dns-prefetch-control

> **Recomendación:** X-DNS-Prefetch-Control: off

#### HDR-12 — Falta la cabecera x-download-options

*Informativo · cabeceras · CWE-436 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Sin X-Download-Options los ficheros descargados pueden ejecutarse en contexto del sitio

**Evidencia**

- `cabecera_ausente`: x-download-options

> **Recomendación:** X-Download-Options: noopen

#### HDR-13 — Falta la cabecera clear-site-data

*Informativo · cabeceras · CWE-613 · A07:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Sin Clear-Site-Data no se limpian los datos del sitio al cerrar sesion

**Evidencia**

- `cabecera_ausente`: clear-site-data

> **Recomendación:** Clear-Site-Data: "cache", "cookies"

#### HDR-40 — El documento no declara idioma (lang)

*Informativo · cabeceras · CWE-1059 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Afecta a accesibilidad y a la interpretacion del contenido por herramientas automaticas

**Evidencia**

- `extracto`: <!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scal

> **Recomendación:** Anadir lang al elemento html

#### PAR-34 — El endpoint acepta text/plain en un cuerpo JSON

*Informativo · parametros · CWE-436 · A03:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

No se valida el tipo de contenido declarado

**Evidencia**

- `status`: 200

> **Recomendación:** Rechazar tipos no esperados con 415

#### PAR-40 — La respuesta con parametros no aplica CSP ni nosniff

*Informativo · parametros · CWE-693 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Una respuesta dinamica sin estas cabeceras es el escenario ideal para XSS

**Evidencia**

- `faltan`: content-security-policy, x-content-type-options

> **Recomendación:** Aplicar las cabeceras de seguridad a todas las respuestas, no solo a la portada

#### TEC-01 — Tecnologia detectada: WordPress

*Informativo · tecnologia · CWE-200 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Firma encontrada: 'wp-content'

**Evidencia**

- `tecnologia`: WordPress
- `firma`: wp-content

> **Recomendación:** Mantener la version al dia y revisar sus CVE conocidos

#### TEC-05 — Tecnologia detectada: Next.js

*Informativo · tecnologia · CWE-200 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Firma encontrada: '_next/static'

**Evidencia**

- `tecnologia`: Next.js
- `firma`: _next/static

> **Recomendación:** Mantener la version al dia y revisar sus CVE conocidos

#### TEC-06 — Tecnologia detectada: React

*Informativo · tecnologia · CWE-200 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Firma encontrada: 'data-reactroot'

**Evidencia**

- `tecnologia`: React
- `firma`: data-reactroot

> **Recomendación:** Mantener la version al dia y revisar sus CVE conocidos

#### TEC-11 — Tecnologia detectada: Ruby on Rails

*Informativo · tecnologia · CWE-200 · A05:2021*

- **URL:** `http://127.0.0.1:8080/buscar?q=test`

Firma encontrada: 'x-runtime'

**Evidencia**

- `tecnologia`: Ruby on Rails
- `firma`: x-runtime

> **Recomendación:** Mantener la version al dia y revisar sus CVE conocidos

## 3. Superficie de ataque

- **A** `127.0.0.1`
- **IPs:** 127.0.0.1
- **tcp/8080** http — Apache/2.4.49
- **Tecnología:** Apache — cabecera Server
- **Tecnología:** PHP — X-Powered-By

## 4. Métricas

| Métrica | Valor |
|---|---|
| Puntuacion de seguridad | 1.8 / 100 |
| Calificacion | F (critico) |
| Penalizacion acumulada | 260.6 puntos |
| Chequeos en el catalogo | 203 |
| Chequeos ejecutados | 185 (cobertura 91.1%) |
| Chequeos superados | 97 |
| Chequeos fallidos | 88 |
| Omitidos (sin autorizacion o no aplicables) | 18 |
| Errores de ejecucion | 0 |
| Criticos | 8 |
| Altos | 17 |
| Medios | 19 |
| Bajos | 16 |
| Informativos | 28 |
| Peticiones realizadas | 100 |
| Bytes recibidos | 104.188 |
| Tiempo total | 1.64 s |
| Tiempo medio por peticion | 16.4 ms |
| Ritmo | 61.08 peticiones/s |
| Cookies recibidas | 1 |
| Cabeceras recibidas | 11 |
| Respuesta · url | http://127.0.0.1:8080/buscar?q=test |
| Respuesta · status | 200 |
| Respuesta · motivo | OK |
| Respuesta · version_http | HTTP/1.1 |
| Respuesta · ip | 127.0.0.1 |
| Respuesta · bytes_cuerpo | 1653 |
| Respuesta · tiempo_ms | 1.4 |
| Respuesta · compresion | ninguna |
| Respuesta · content_type | text/html; charset=utf-8 |
| Respuesta · redirecciones | 0 |
| Respuesta · servidor | Apache/2.4.49 (Unix) |

## 5. Catálogo de chequeos

| ID | Chequeo | Categoría | Severidad | Estado |
|---|---|---|---|---|
| CKI-01 | Cookie sin secure | cookies | Alto | FALLO |
| CKI-02 | Cookie sin httponly | cookies | Alto | FALLO |
| CKI-03 | Cookie sin samesite | cookies | Medio | FALLO |
| CKI-07 | Nombre de cookie de sesion por defecto | cookies | Bajo | FALLO |
| CKI-08 | Cookie de sesion con valor corto | cookies | Medio | FALLO |
| CKI-12 | Sin cookies de sesion con proteccion completa | cookies | Informativo | FALLO |
| CON-01 | Comentarios HTML con informacion sensible | contenido | Bajo | FALLO |
| CON-02 | Source maps expuestos | contenido | Medio | FALLO |
| CON-03 | Secretos en el codigo del cliente | contenido | Alto | FALLO |
| CON-04 | Direcciones de correo expuestas | contenido | Informativo | FALLO |
| CON-05 | Direcciones IP internas expuestas | contenido | Medio | FALLO |
| CON-06 | Rutas absolutas del servidor | contenido | Medio | FALLO |
| CON-08 | Scripts externos sin integrity (SRI) | contenido | Bajo | FALLO |
| CON-09 | Formulario envia a un dominio externo | contenido | Medio | FALLO |
| CON-10 | Formulario con contrasena por GET | contenido | Alto | FALLO |
| CON-11 | Campo de contrasena sin autocomplete off | contenido | Informativo | FALLO |
| CON-12 | Formulario POST sin token CSRF | contenido | Medio | FALLO |
| CON-13 | Enlaces target=_blank sin noopener | contenido | Bajo | FALLO |
| CON-14 | iframe sin sandbox | contenido | Informativo | FALLO |
| CON-15 | Meta generator con version | contenido | Informativo | FALLO |
| CON-19 | Referencias a almacenamiento en la nube | contenido | Informativo | FALLO |
| CON-20 | Endpoints de API listados en el HTML | contenido | Informativo | FALLO |
| CON-21 | Rutas de administracion enlazadas | contenido | Informativo | FALLO |
| CON-23 | Version del producto en el cuerpo | contenido | Informativo | FALLO |
| CON-24 | Copyright antiguo | contenido | Informativo | FALLO |
| CON-28 | Tecnologias declaradas en el cuerpo | contenido | Informativo | FALLO |
| CRS-01 | CORS con comodin | cors | Medio | FALLO |
| CRS-02 | CORS refleja el origen recibido | cors | Alto | FALLO |
| CRS-03 | CORS refleja origen con credenciales | cors | Crítico | FALLO |
| CRS-04 | CORS acepta origen null | cors | Alto | FALLO |
| CRS-05 | CORS con comodin y credenciales | cors | Alto | FALLO |
| CRS-06 | Sin Vary: Origin en respuesta CORS | cors | Bajo | FALLO |
| CRS-07 | CORS expone cabeceras sensibles | cors | Informativo | FALLO |
| FUG-01 | Repositorio Git expuesto | rutas | Crítico | FALLO |
| FUG-02 | Fichero .env expuesto | rutas | Crítico | FALLO |
| FUG-03 | Metadatos SVN expuestos | rutas | Alto | FALLO |
| FUG-04 | Fichero .DS_Store expuesto | rutas | Bajo | FALLO |
| FUG-05 | Estado del servidor expuesto | rutas | Medio | FALLO |
| FUG-06 | phpinfo() expuesto | rutas | Alto | FALLO |
| FUG-07 | Spring Boot Actuator expuesto | rutas | Alto | FALLO |
| FUG-08 | Actuator /env expuesto | rutas | Crítico | FALLO |
| FUG-09 | Endpoint de depuracion expuesto | rutas | Alto | FALLO |
| FUG-10 | Consola expuesta | rutas | Crítico | FALLO |
| FUG-11 | Documentacion de API expuesta | rutas | Medio | FALLO |
| FUG-12 | Especificacion de API expuesta | rutas | Medio | FALLO |
| FUG-14 | robots.txt revela rutas sensibles | fugas | Bajo | FALLO |
| FUG-15 | Sin security.txt | fugas | Informativo | FALLO |
| FUG-16 | sitemap.xml accesible | fugas | Informativo | FALLO |
| FUG-17 | Backup comprimido accesible | fugas | Crítico | FALLO |
| FUG-19 | Panel de administracion conocido | fugas | Informativo | FALLO |
| FUG-20 | Fichero de entorno alternativo | fugas | Alto | FALLO |
| FUG-22 | Version en la ruta de error 404 | fugas | Informativo | FALLO |
| HDR-02 | Falta la cabecera content-security-policy | cabeceras | Alto | FALLO |
| HDR-03 | Falta la cabecera x-content-type-options | cabeceras | Medio | FALLO |
| HDR-04 | Falta la cabecera x-frame-options | cabeceras | Medio | FALLO |
| HDR-05 | Falta la cabecera referrer-policy | cabeceras | Bajo | FALLO |
| HDR-06 | Falta la cabecera permissions-policy | cabeceras | Bajo | FALLO |
| HDR-07 | Falta la cabecera cross-origin-opener-policy | cabeceras | Bajo | FALLO |
| HDR-08 | Falta la cabecera cross-origin-resource-policy | cabeceras | Bajo | FALLO |
| HDR-09 | Falta la cabecera cross-origin-embedder-policy | cabeceras | Informativo | FALLO |
| HDR-10 | Falta la cabecera x-permitted-cross-domain-policies | cabeceras | Informativo | FALLO |
| HDR-11 | Falta la cabecera x-dns-prefetch-control | cabeceras | Informativo | FALLO |
| HDR-12 | Falta la cabecera x-download-options | cabeceras | Informativo | FALLO |
| HDR-13 | Falta la cabecera clear-site-data | cabeceras | Informativo | FALLO |
| HDR-34 | Cache-Control sin no-store | cabeceras | Bajo | FALLO |
| HDR-36 | Server revela version | cabeceras | Bajo | FALLO |
| HDR-37 | X-Powered-By revela tecnologia | cabeceras | Bajo | FALLO |
| HDR-38 | Otras cabeceras revelan el stack | cabeceras | Bajo | FALLO |
| HDR-40 | Sin politica de contenido en el idioma declarado | cabeceras | Informativo | FALLO |
| MTH-01 | TRACE habilitado | metodos | Medio | FALLO |
| MTH-02 | OPTIONS revela metodos de escritura | metodos | Medio | FALLO |
| MTH-03 | PUT no rechazado | metodos | Alto | FALLO |
| MTH-04 | DELETE no rechazado | metodos | Alto | FALLO |
| MTH-05 | Metodo arbitrario no rechazado | metodos | Bajo | FALLO |
| MTH-08 | WebDAV anunciado | metodos | Medio | FALLO |
| PAR-01 | SQLi basada en errores | parametros | Crítico | FALLO |
| PAR-06 | XSS reflejado en el cuerpo | parametros | Alto | FALLO |
| PAR-09 | Inyeccion HTML (sin script) | parametros | Medio | FALLO |
| PAR-17 | Inyeccion de comandos (indicador) | parametros | Crítico | FALLO |
| PAR-24 | Asignacion masiva (mass assignment) | parametros | Alto | FALLO |
| PAR-27 | Sin limite de peticiones | parametros | Medio | FALLO |
| PAR-34 | Content-Type no validado | parametros | Informativo | FALLO |
| PAR-37 | Respuesta refleja entrada sin escapar (contexto JS) | parametros | Medio | FALLO |
| PAR-40 | Sin cabecera de seguridad en la respuesta dinamica | parametros | Informativo | FALLO |
| TEC-01 | Tecnologia detectada: WordPress | tecnologia | Informativo | FALLO |
| TEC-05 | Tecnologia detectada: Next.js | tecnologia | Informativo | FALLO |
| TEC-06 | Tecnologia detectada: React | tecnologia | Informativo | FALLO |
| TEC-11 | Tecnologia detectada: Ruby on Rails | tecnologia | Informativo | FALLO |
| CKI-04 | SameSite=None sin Secure | cookies | Alto | OK |
| CKI-05 | Prefijo __Host- mal aplicado | cookies | Bajo | OK |
| CKI-06 | Prefijo __Secure- mal aplicado | cookies | Bajo | OK |
| CKI-09 | Cookie de sesion persistente | cookies | Bajo | OK |
| CKI-10 | Cookie con Domain demasiado amplio | cookies | Medio | OK |
| CKI-11 | Cookie sin Path | cookies | Informativo | OK |
| CON-07 | Contenido mixto (http:// en https) | contenido | Medio | OK |
| CON-16 | Modo depuracion visible | contenido | Alto | OK |
| CON-17 | Traza de pila en la respuesta | contenido | Alto | OK |
| CON-18 | Error de base de datos visible | contenido | Alto | OK |
| CON-22 | Token o credencial en la URL | contenido | Medio | OK |
| CON-25 | Sin declaracion de viewport | contenido | Informativo | OK |
| CON-26 | Sin meta charset | contenido | Informativo | OK |
| CON-27 | Pagina de error por defecto del servidor | contenido | Informativo | OK |
| FUG-13 | GraphQL con introspeccion habilitada | fugas | Medio | OK |
| FUG-18 | Listado de directorios habilitado | fugas | Medio | OK |
| FUG-21 | Metodos de depuracion de framework | fugas | Informativo | OK |
| HDR-01 | Falta la cabecera strict-transport-security | cabeceras | Alto | OMITIDO |
| HDR-14 | HSTS con max-age corto | cabeceras | Medio | OMITIDO |
| HDR-15 | HSTS sin includeSubDomains | cabeceras | Bajo | OMITIDO |
| HDR-16 | HSTS sin preload | cabeceras | Informativo | OMITIDO |
| HDR-17 | CSP sin default-src | cabeceras | Medio | OK |
| HDR-18 | CSP sin object-src | cabeceras | Bajo | OK |
| HDR-19 | CSP sin base-uri | cabeceras | Bajo | OK |
| HDR-20 | CSP sin frame-ancestors | cabeceras | Medio | OK |
| HDR-21 | CSP con unsafe-inline | cabeceras | Medio | OK |
| HDR-22 | CSP con unsafe-eval | cabeceras | Medio | OK |
| HDR-23 | CSP con comodin * | cabeceras | Medio | OK |
| HDR-24 | CSP permite data: en scripts | cabeceras | Bajo | OK |
| HDR-25 | CSP sin form-action | cabeceras | Informativo | OK |
| HDR-26 | CSP sin upgrade-insecure-requests | cabeceras | Informativo | OK |
| HDR-27 | CSP sin reporte de violaciones | cabeceras | Informativo | OK |
| HDR-28 | X-Content-Type-Options con valor invalido | cabeceras | Bajo | OK |
| HDR-29 | X-Frame-Options con valor invalido | cabeceras | Bajo | OK |
| HDR-30 | X-Frame-Options ALLOW-FROM obsoleto | cabeceras | Informativo | OK |
| HDR-31 | Referrer-Policy insegura | cabeceras | Bajo | OK |
| HDR-32 | Permissions-Policy ausente con Feature-Policy | cabeceras | Bajo | OK |
| HDR-33 | X-XSS-Protection presente (obsoleta) | cabeceras | Informativo | OK |
| HDR-35 | Cabeceras Pragma/Expires obsoletas | cabeceras | Informativo | OK |
| HDR-39 | Sin cabecera Vary | cabeceras | Informativo | OK |
| MTH-06 | Sin cabecera Allow en OPTIONS | metodos | Informativo | OK |
| MTH-07 | Metodos de escritura anunciados en Allow | metodos | Informativo | OK |
| PAR-02 | SQLi por diferencial booleano | parametros | Alto | OK |
| PAR-03 | SQLi en cabecera User-Agent | parametros | Alto | OK |
| PAR-04 | SQLi en cabecera Referer | parametros | Alto | OK |
| PAR-05 | SQLi en cookie | parametros | Alto | OK |
| PAR-07 | XSS reflejado (posible, escapado) | parametros | Bajo | OK |
| PAR-08 | XSS en cabecera reflejada | parametros | Medio | OK |
| PAR-10 | SSTI con {{7*7}} | parametros | Crítico | OK |
| PAR-11 | SSTI con ${7*7} | parametros | Crítico | OK |
| PAR-12 | Inyeccion CRLF | parametros | Alto | OK |
| PAR-13 | Path traversal | parametros | Alto | OK |
| PAR-14 | Inclusion local de ficheros | parametros | Alto | OK |
| PAR-15 | Redireccion abierta | parametros | Medio | OK |
| PAR-16 | SSRF en parametro de URL | parametros | Alto | OK |
| PAR-18 | Inyeccion LDAP | parametros | Alto | OK |
| PAR-19 | Inyeccion XPath | parametros | Medio | OK |
| PAR-20 | Inyeccion NoSQL ($ne) | parametros | Alto | OK |
| PAR-21 | Inyeccion NoSQL ($gt) | parametros | Alto | OK |
| PAR-22 | XML externo (XXE) | parametros | Crítico | OK |
| PAR-23 | Contaminacion de parametros HTTP (HPP) | parametros | Medio | OK |
| PAR-25 | IDOR | parametros | Alto | OK |
| PAR-26 | BOLA | parametros | Alto | OK |
| PAR-28 | Enumeracion de usuarios | parametros | Medio | OK |
| PAR-29 | Identificadores secuenciales predecibles | parametros | Informativo | OK |
| PAR-30 | Valor negativo aceptado | parametros | Informativo | OK |
| PAR-31 | Desbordamiento de entero aceptado | parametros | Informativo | OK |
| PAR-32 | Inyeccion de plantilla en JSON | parametros | Medio | OK |
| PAR-33 | Prototype pollution (__proto__) | parametros | Medio | OK |
| PAR-35 | Cabecera de suplantacion aceptada | parametros | Alto | OK |
| PAR-36 | Inyeccion de plantilla en cabecera | parametros | Medio | OK |
| PAR-38 | Redireccion a esquema peligroso | parametros | Medio | OK |
| PAR-39 | Parametro de fichero sin validar | parametros | Medio | OK |
| RSP-01 | Respuesta lenta | respuesta | Informativo | OK |
| RSP-02 | Sin compresion | respuesta | Informativo | OK |
| RSP-03 | Compresion con datos sensibles | respuesta | Bajo | OK |
| RSP-04 | Sin cabecera Content-Type | respuesta | Medio | OK |
| RSP-05 | Sin charset declarado | respuesta | Informativo | OK |
| RSP-06 | Sin cabecera Date | respuesta | Informativo | OK |
| RSP-07 | Sin Content-Length ni chunked | respuesta | Informativo | OK |
| RSP-08 | HTTP/1.0 soportado | respuesta | Informativo | OK |
| RSP-09 | Cabeceras duplicadas | respuesta | Bajo | OK |
| RSP-10 | Redireccion a otro dominio | respuesta | Bajo | OK |
| RSP-11 | Redireccion en cadena larga | respuesta | Informativo | OK |
| RSP-12 | Cuerpo de error con detalles internos | respuesta | Medio | OK |
| TEC-02 | Tecnologia detectada: Drupal | tecnologia | Informativo | OK |
| TEC-03 | Tecnologia detectada: Joomla | tecnologia | Informativo | OK |
| TEC-04 | Tecnologia detectada: Shopify | tecnologia | Informativo | OK |
| TEC-07 | Tecnologia detectada: Vue.js | tecnologia | Informativo | OK |
| TEC-08 | Tecnologia detectada: Angular | tecnologia | Informativo | OK |
| TEC-09 | Tecnologia detectada: Laravel | tecnologia | Informativo | OK |
| TEC-10 | Tecnologia detectada: Django | tecnologia | Informativo | OK |
| TEC-12 | Tecnologia detectada: Spring | tecnologia | Informativo | OK |
| TEC-13 | Tecnologia detectada: ASP.NET | tecnologia | Informativo | OK |
| TEC-14 | Tecnologia detectada: PHP | tecnologia | Informativo | OK |
| TEC-15 | Tecnologia detectada: Apache Tomcat | tecnologia | Informativo | OK |
| TEC-16 | Tecnologia detectada: nginx | tecnologia | Informativo | OK |
| TEC-17 | Tecnologia detectada: Apache | tecnologia | Informativo | OK |
| TEC-18 | Tecnologia detectada: IIS | tecnologia | Informativo | OK |
| TEC-19 | Tecnologia detectada: Cloudflare | tecnologia | Informativo | OK |
| TEC-20 | Tecnologia detectada: Vercel | tecnologia | Informativo | OK |
| TLS-01 | TLS 1.0 aceptado | tls | Alto | OMITIDO |
| TLS-02 | TLS 1.1 aceptado | tls | Medio | OMITIDO |
| TLS-03 | Sin TLS 1.3 | tls | Bajo | OMITIDO |
| TLS-04 | Solo TLS 1.2 o inferior | tls | Informativo | OMITIDO |
| TLS-05 | Certificado caducado | tls | Alto | OMITIDO |
| TLS-06 | Certificado caduca pronto | tls | Bajo | OMITIDO |
| TLS-07 | Certificado autofirmado | tls | Medio | OMITIDO |
| TLS-08 | Firma del certificado con SHA-1 | tls | Alto | OMITIDO |
| TLS-09 | Clave RSA menor de 2048 bits | tls | Alto | OMITIDO |
| TLS-10 | Cifrado sin forward secrecy | tls | Medio | OMITIDO |
| TLS-11 | Cifrado debil (RC4/3DES/CBC) | tls | Alto | OMITIDO |
| TLS-12 | Sin datos del certificado | tls | Informativo | OMITIDO |
| TLS-13 | Emisor desconocido | tls | Informativo | OMITIDO |
| TLS-14 | Sin sujeto legible en el certificado | tls | Informativo | OMITIDO |

---

*Informe generado por HunterBug 1.1 el 2026-10-25 21:57:42. Documento de uso exclusivo en pruebas autorizadas. La ausencia de hallazgos no demuestra la ausencia de vulnerabilidades.*