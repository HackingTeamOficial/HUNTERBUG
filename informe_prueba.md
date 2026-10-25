# Informe de evaluacion - HunterBug 1.0

- **Herramienta:** HunterBug 1.0 - version mejorada creada para la comunidad hacking team by Juan Antonio

- **Objetivo:** 127.0.0.1
- **Fecha (UTC):** 2026-01-01T00:00:00Z
- **Grafo:** 115 nodos / 114 aristas

## Resumen de severidad
- **CRITICO:** 10
- **ALTO:** 22
- **MEDIO:** 21
- **BAJO:** 21
- **INFO:** 28

## Puertos abiertos
| Puerto | Servicio | Banner |
|---|---|---|
| 8080 | http-proxy | HTTP/1.1 200 OK |
| 135 | msrpc |  |
| 445 | smb |  |

## Tecnologias detectadas
- **server:** Apache/2.4.49 (Unix)
- **x-powered-by:** PHP/8.1.2
- **WordPress:** detectado en el cuerpo
- **Next.js:** detectado en el cuerpo
- **React:** detectado en el cuerpo

## Hallazgos

### 1. [CRITICO] CVE-2021-41773 - Apache 2.4.49: path traversal y posible RCE
- URL: `https://nvd.nist.gov/vuln/detail/CVE-2021-41773`
- Detalle: La normalizacion de rutas permite salir del directorio raiz y leer ficheros, o ejecutar CGI si esta habilitado.
- Evidencia:
    - `cve`: CVE-2021-41773
    - `cvss`: 9.8
    - `producto`: Apache HTTP Server
    - `version_detectada`: 2.4.49
    - `pista`: apache/2.4.49
    - `referencias`: ['https://nvd.nist.gov/vuln/detail/CVE-2021-41773']
- Recomendacion: Actualizar Apache HTTP Server a una version no afectada y aplicar los parches del proveedor.

### 2. [CRITICO] Inyeccion SQL (basada en errores) en 'q'
- URL: `http://127.0.0.1:8080/buscar?q=test%27`
- Parametro: `q`
- Detalle: El parametro 'q' refleja un error de MySQL al inyectar "'"
- Evidencia:
    - `payload`: '
    - `motor`: MySQL
    - `fragmento`: <h1>Error</h1>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to u
- Recomendacion: Usar consultas parametrizadas (prepared statements) y validacion estricta de entrada.

### 3. [CRITICO] CORS con credenciales y origen reflejado
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Con Allow-Credentials true y el Origin reflejado, cualquier web puede leer respuestas con la sesion del usuario
- Evidencia:
    - `origin_enviado`: https://hunterbug-prueba.invalid
    - `acao`: https://hunterbug-prueba.invalid
    - `acac`: true
- Recomendacion: Lista blanca estricta de origenes y Vary: Origin

### 4. [CRITICO] Repositorio Git expuesto accesible
- URL: `http://127.0.0.1/.git/config`
- Detalle: Permite reconstruir el codigo fuente completo
- Evidencia:
    - `ruta`: /.git/config
    - `status`: 200
    - `bytes`: 107
    - `extracto`: [core]
	repositoryformatversion = 0
	filemode = true
[remote "origin"]
	url = https://git.interno/panel.git
- Recomendacion: Bloquear el acceso a .git desde el servidor web

### 5. [CRITICO] Fichero .env expuesto accesible
- URL: `http://127.0.0.1/.env`
- Detalle: Contiene credenciales, claves y configuracion de la aplicacion
- Evidencia:
    - `ruta`: /.env
    - `status`: 200
    - `bytes`: 74
    - `extracto`: APP_ENV=production
DB_PASSWORD=Sup3rS3cret0
AWS_SECRET_ACCESS_KEY=abcd1234
- Recomendacion: Sacar el .env del directorio publico

### 6. [CRITICO] Actuator /env expuesto accesible
- URL: `http://127.0.0.1/actuator/env`
- Detalle: Muestra variables de entorno, incluidas credenciales
- Evidencia:
    - `ruta`: /actuator/env
    - `status`: 200
    - `bytes`: 127
    - `extracto`: {"activeProfiles": ["prod"], "propertySources": [{"name": "systemEnvironment", "properties": {"DB_PASSWORD": {"value": "x"}}}]}
- Recomendacion: Deshabilitar o proteger el endpoint env

### 7. [CRITICO] Consola expuesta accesible
- URL: `http://127.0.0.1/console`
- Detalle: Una consola interactiva expuesta permite ejecucion de codigo
- Evidencia:
    - `ruta`: /console
    - `status`: 200
    - `bytes`: 28
    - `extracto`: <h1>Consola interactiva</h1>
- Recomendacion: Eliminar o proteger la consola

### 8. [CRITICO] Copia de seguridad accesible (/backup.zip)
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Una copia descargable entrega el codigo o la base de datos completa
- Evidencia:
    - `ruta`: /backup.zip
    - `bytes`: 504
- Recomendacion: Retirar las copias del directorio web

### 9. [CRITICO] Inyeccion SQL (basada en errores) en 'q'
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Parametro: `q`
- Detalle: El parametro 'q' refleja un error de MySQL al inyectar "'"
- Evidencia:
    - `payload`: '
    - `motor`: MySQL
    - `fragmento`: <h1>Error</h1>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to u
- Recomendacion: Usar consultas parametrizadas (prepared statements) y validacion estricta de entrada.

### 10. [CRITICO] Inyeccion de comandos en 'q'
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Parametro: `q`
- Detalle: El comando enviado aparece en la salida
- Evidencia:
    - `payload`: ;echo hunterbug_probe
- Recomendacion: No construir comandos con entrada del usuario; usar APIs del sistema

### 11. [ALTO] Falta content-security-policy
- Detalle: CSP ausente: sin defensa en profundidad contra XSS
- Evidencia:
    - `cabecera`: content-security-policy
- Recomendacion: default-src 'self'; object-src 'none'; base-uri 'none'

### 12. [ALTO] CVE-2022-21661 - WordPress < 5.8.3: inyeccion SQL en WP_Query
- URL: `https://nvd.nist.gov/vuln/detail/CVE-2022-21661`
- Detalle: Parametros concretos llegan a la consulta sin sanear correctamente.
- Evidencia:
    - `cve`: CVE-2022-21661
    - `cvss`: 8.8
    - `producto`: WordPress
    - `version_detectada`: no determinada
    - `pista`: wordpress
    - `referencias`: ['https://nvd.nist.gov/vuln/detail/CVE-2022-21661']
- Recomendacion: Actualizar WordPress a una version no afectada y aplicar los parches del proveedor.

### 13. [ALTO] XSS reflejado en 'q'
- URL: `http://127.0.0.1:8080/buscar?q=%3Chbmkhbjlb753%3E`
- Parametro: `q`
- Detalle: El payload vuelve sin escapar en el cuerpo de la respuesta del parametro 'q'
- Evidencia:
    - `payload`: <hbmkhbjlb753>
    - `fragmento`: ic en la raiz</p> <h2>Resultados para <hbmkhbjlb753></h2> </body> </html>
- Recomendacion: Escapar la salida segun contexto, aplicar CSP estricta y validar la entrada.

### 14. [ALTO] Acceso a objeto ajeno (IDOR)
- URL: `http://127.0.0.1:8080/api/usuario/1`
- Detalle: Las dos peticiones devuelven 2xx con contenido claramente distinto (similitud 33%): se alcanza un objeto que no corresponde al solicitante.
- Evidencia:
    - `id=1`: {'url': 'http://127.0.0.1:8080/api/usuario/1', 'status': 200, 'bytes': 114}
    - `id=2`: {'url': 'http://127.0.0.1:8080/api/usuario/2', 'status': 200, 'bytes': 114}
    - `similitud`: 0.333
    - `extracto_a`: {"id": 1, "nombre": "usuario1", "email": "usuario1@ejemplo.test", "saldo": 1000, "tarjeta": "4111-1111-1111-0001"}
    - `extracto_b`: {"id": 2, "nombre": "usuario2", "email": "usuario2@ejemplo.test", "saldo": 2000, "tarjeta": "4111-1111-1111-0002"}
- Recomendacion: Comprobar la propiedad del objeto en el servidor en cada peticion (no confiar en el identificador del cliente).

### 15. [ALTO] Fuga de datos entre credenciales (BOLA)
- URL: `http://127.0.0.1:8080/api/fuga/1`
- Detalle: Las dos peticiones devuelven 2xx con contenido claramente distinto (similitud 62%): se alcanza un objeto que no corresponde al solicitante.
- Evidencia:
    - `cuenta-A`: {'url': 'http://127.0.0.1:8080/api/fuga/1', 'status': 200, 'bytes': 45}
    - `cuenta-B`: {'url': 'http://127.0.0.1:8080/api/fuga/1', 'status': 200, 'bytes': 87}
    - `similitud`: 0.625
    - `extracto_a`: {"cuenta": 1, "titular": "Ana", "saldo": 500}
    - `extracto_b`: {"cuenta": 1, "titular": "Ana", "saldo": 500, "iban": "ES00", "movimientos": [1, 2, 3]}
- Recomendacion: Comprobar la propiedad del objeto en el servidor en cada peticion (no confiar en el identificador del cliente).

### 16. [ALTO] Falta la cabecera content-security-policy
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Sin CSP no hay defensa en profundidad contra XSS ni control de origenes
- Evidencia:
    - `cabecera_ausente`: content-security-policy
- Recomendacion: default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'

### 17. [ALTO] 1 cookie(s) sin secure
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: La cookie viaja tambien por HTTP sin cifrar y puede ser interceptada
- Evidencia:
    - `cookies`: ['PHPSESSID=abc123; Path=/']
- Recomendacion: Anadir el atributo Secure a todas las cookies de sesion

### 18. [ALTO] 1 cookie(s) sin httponly
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Sin HttpOnly el JavaScript de la pagina puede leer la cookie, lo que convierte cualquier XSS en robo de sesion
- Evidencia:
    - `cookies`: ['PHPSESSID=abc123; Path=/']
- Recomendacion: Anadir HttpOnly a las cookies de sesion

### 19. [ALTO] CORS refleja cualquier Origin enviado
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: El servidor devuelve el origen solicitado sin validarlo, lo que permite leer respuestas desde cualquier web
- Evidencia:
    - `origin_enviado`: https://hunterbug-prueba.invalid
    - `acao_devuelto`: https://hunterbug-prueba.invalid
- Recomendacion: Validar el Origin contra una lista blanca

### 20. [ALTO] CORS acepta el origen null
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: El origen null procede de iframes sandbox o ficheros locales y no deberia autorizarse
- Evidencia:
    - `acao`: null
- Recomendacion: Rechazar explicitamente el origen null

### 21. [ALTO] CORS con comodin y credenciales
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Combinacion contradictoria que algunos proxies resuelven reflejando el origen
- Evidencia:
    - `acao`: *
    - `acac`: true
- Recomendacion: Eliminar el comodin cuando se usan credenciales

### 22. [ALTO] El servidor acepta PUT
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: PUT sobre una ruta inexistente devolvio 201: puede permitir subir contenido
- Evidencia:
    - `status`: 201
    - `ruta`: http://127.0.0.1:8080/hunterbug-sonda-1792930861
- Recomendacion: Rechazar PUT con 405 salvo donde sea necesario

### 23. [ALTO] El servidor acepta DELETE
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: DELETE sobre una ruta inexistente devolvio 204
- Evidencia:
    - `status`: 204
    - `ruta`: http://127.0.0.1:8080/hunterbug-sonda-1792930861
- Recomendacion: Rechazar DELETE con 405 salvo donde sea necesario

### 24. [ALTO] 2 posible(s) secreto(s) en el cliente
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Claves o tokens embebidos en el HTML o el JS son visibles para cualquiera
- Evidencia:
    - `hallazgos`: ['api_key = "AKIAIOSFODNN7EXAMPLE1" = AKIAIOSF...', 'AWS key: AKIAIOSFODNN...']
- Recomendacion: Mover los secretos al servidor y rotarlos

### 25. [ALTO] Formulario de contrasena con method=GET
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: La contrasena queda en la URL, en el historial y en los registros del servidor
- Evidencia:
    - `formulario`: <form action="/login" method="get"> <input type="text" name="usuario"> <input type="password" name="clave"> <input type="submit"> </form>
- Recomendacion: Usar POST sobre HTTPS

### 26. [ALTO] Metadatos SVN expuestos accesible
- URL: `http://127.0.0.1/.svn/entries`
- Detalle: Revela el historial de versiones y el codigo fuente
- Evidencia:
    - `ruta`: /.svn/entries
    - `status`: 200
    - `bytes`: 15
    - `extracto`: 12

dir
/trunk

- Recomendacion: Bloquear el acceso a .svn

### 27. [ALTO] phpinfo() expuesto accesible
- URL: `http://127.0.0.1/phpinfo.php`
- Detalle: Expone la configuracion completa de PHP
- Evidencia:
    - `ruta`: /phpinfo.php
    - `status`: 200
    - `bytes`: 56
    - `extracto`: <html><title>phpinfo()</title><h1>PHP Version 8.1.2</h1>
- Recomendacion: Eliminar phpinfo() de produccion

### 28. [ALTO] Spring Boot Actuator expuesto accesible
- URL: `http://127.0.0.1/actuator`
- Detalle: Los endpoints de gestion pueden filtrar configuracion y permitir cambios
- Evidencia:
    - `ruta`: /actuator
    - `status`: 200
    - `bytes`: 46
    - `extracto`: {"_links": {"env": {"href": "/actuator/env"}}}
- Recomendacion: Proteger /actuator con autenticacion

### 29. [ALTO] Endpoint de depuracion expuesto accesible
- URL: `http://127.0.0.1/debug`
- Detalle: Suele permitir ejecutar codigo o volcar el estado interno
- Evidencia:
    - `ruta`: /debug
    - `status`: 200
    - `bytes`: 44
    - `extracto`: <h1>Debug console</h1><p>ejecutar codigo</p>
- Recomendacion: Eliminar los endpoints de depuracion

### 30. [ALTO] Fichero sensible accesible (/.env.local)
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Suele contener credenciales o hashes
- Evidencia:
    - `ruta`: /.env.local
    - `bytes`: 32
- Recomendacion: Eliminar copias y ficheros de configuracion del directorio publico

### 31. [ALTO] XSS reflejado en 'q'
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Parametro: `q`
- Detalle: El payload vuelve sin escapar en el cuerpo de la respuesta del parametro 'q'
- Evidencia:
    - `payload`: <hbmkhbajtb2h>
    - `fragmento`: ic en la raiz</p> <h2>Resultados para <hbmkhbajtb2h></h2> </body> </html>
- Recomendacion: Escapar la salida segun contexto, aplicar CSP estricta y validar la entrada.

### 32. [ALTO] Posible asignacion masiva en /api/perfil
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: El servidor acepto campos de privilegio enviados por el cliente
- Evidencia:
    - `ruta`: /api/perfil
    - `status`: 200
    - `extracto`: {"role":"admin","is_admin":true,"admin":true}
- Recomendacion: Lista blanca de campos asignables

### 33. [MEDIO] Falta x-content-type-options
- Detalle: Sin X-Content-Type-Options: riesgo de MIME sniffing
- Evidencia:
    - `cabecera`: x-content-type-options
- Recomendacion: nosniff

### 34. [MEDIO] Falta x-frame-options
- Detalle: Sin X-Frame-Options ni frame-ancestors: posible clickjacking
- Evidencia:
    - `cabecera`: x-frame-options
- Recomendacion: DENY

### 35. [MEDIO] Falta la cabecera x-content-type-options
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Sin nosniff el navegador puede interpretar un fichero con otro tipo MIME
- Evidencia:
    - `cabecera_ausente`: x-content-type-options
- Recomendacion: X-Content-Type-Options: nosniff

### 36. [MEDIO] Falta la cabecera x-frame-options
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Sin proteccion de framing la pagina es embebible y vulnerable a clickjacking
- Evidencia:
    - `cabecera_ausente`: x-frame-options
- Recomendacion: X-Frame-Options: DENY (o CSP frame-ancestors 'none')

### 37. [MEDIO] 1 cookie(s) sin samesite
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Sin SameSite el navegador envia la cookie en peticiones cruzadas, lo que facilita CSRF
- Evidencia:
    - `cookies`: ['PHPSESSID=abc123; Path=/']
- Recomendacion: Anadir SameSite=Lax o Strict

### 38. [MEDIO] Identificador de sesion corto (6 caracteres)
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Un identificador corto es adivinable por fuerza bruta
- Evidencia:
    - `cookie`: PHPSESSID
    - `longitud`: 6
- Recomendacion: Usar al menos 128 bits de entropia

### 39. [MEDIO] CORS permite cualquier origen (*)
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Cualquier web puede leer la respuesta desde el navegador de la victima
- Evidencia:
    - `acao`: *
- Recomendacion: Lista blanca de origenes concretos

### 40. [MEDIO] Metodo TRACE habilitado
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: TRACE devuelve la peticion completa y facilita Cross-Site Tracing
- Evidencia:
    - `status`: 200
    - `cuerpo`: TRACE / HTTP/1.1
Host: 127.0.0.1:8080


- Recomendacion: Deshabilitar TRACE (TraceEnable off)

### 41. [MEDIO] OPTIONS anuncia metodos de escritura
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: El servidor declara: GET, HEAD, POST, PUT, DELETE, PATCH, PROPFIND, TRACE
- Evidencia:
    - `allow`: GET, HEAD, POST, PUT, DELETE, PATCH, PROPFIND, TRACE
    - `peligrosos`: ['PUT', 'DELETE', 'PATCH']
- Recomendacion: Deshabilitar los metodos no usados

### 42. [MEDIO] WebDAV habilitado
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Anuncia: PROPFIND
- Evidencia:
    - `metodos_dav`: ['PROPFIND']
- Recomendacion: Deshabilitar WebDAV si no se usa

### 43. [MEDIO] El codigo referencia source maps
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Los ficheros .map permiten reconstruir el codigo fuente original
- Evidencia:
    - `referencias`: ['/app.js.map-->']
- Recomendacion: No publicar los .map en produccion

### 44. [MEDIO] 2 direccion(es) IP privada(s) en el cuerpo
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Revelan la topologia interna de la red
- Evidencia:
    - `ips`: ['10.20.30.40', '192.168.1.10']
- Recomendacion: Eliminar las referencias a la red interna

### 45. [MEDIO] Rutas absolutas del sistema en el cuerpo
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Revelan la estructura de directorios del servidor
- Evidencia:
    - `rutas`: ['/var/www']
- Recomendacion: Usar rutas relativas y errores genericos

### 46. [MEDIO] Formulario que envia datos a otro dominio
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Los datos del usuario salen del sitio
- Evidencia:
    - `acciones`: ['https://recolector.invalid/recoger']
- Recomendacion: Enviar los formularios al propio dominio

### 47. [MEDIO] 2 formulario(s) POST sin token anti-CSRF
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Sin token, otra web puede enviar el formulario en nombre del usuario
- Evidencia:
    - `formularios`: ['<form action="https://recolector.invalid/recoger" method="post"> <input type="text" name="usuario"> </form>', '<form action="/perfil" method="post"> <input type="text" name="nombre"> <input type="submit"> </form>']
- Recomendacion: Token por sesion y validacion SameSite

### 48. [MEDIO] Estado del servidor expuesto accesible
- URL: `http://127.0.0.1/server-status`
- Detalle: Revela peticiones en curso, clientes y carga del servidor
- Evidencia:
    - `ruta`: /server-status
    - `status`: 200
    - `bytes`: 120
    - `extracto`: <html><title>Apache Server Status</title><h1>Apache Server Status for 127.0.0.1</h1>Current Time: now
Total accesses: 12
- Recomendacion: Restringir /server-status a la red local

### 49. [MEDIO] Documentacion de API expuesta accesible
- URL: `http://127.0.0.1/swagger-ui.html`
- Detalle: Describe todos los endpoints y sus esquemas, incluidos los internos
- Evidencia:
    - `ruta`: /swagger-ui.html
    - `status`: 200
    - `bytes`: 45
    - `extracto`: <html><title>Swagger UI</title><p>swagger</p>
- Recomendacion: Proteger la documentacion en produccion

### 50. [MEDIO] Especificacion de API expuesta accesible
- URL: `http://127.0.0.1/api-docs`
- Detalle: Facilita la enumeracion completa de la API
- Evidencia:
    - `ruta`: /api-docs
    - `status`: 200
    - `bytes`: 55
    - `extracto`: {"openapi": "3.0.0", "paths": {"/api/v1/usuarios": {}}}
- Recomendacion: Restringir el acceso a la especificacion

### 51. [MEDIO] Inyeccion HTML en 'q'
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Parametro: `q`
- Detalle: Se pueden inyectar etiquetas HTML arbitrarias; con un navegador puede escalarse a XSS
- Evidencia:
    - `payload`: <hbmk-hbseod36>x</hbmk-hbseod36>
- Recomendacion: Escapar la salida segun contexto

### 52. [MEDIO] No se observa limite de peticiones
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: 12 peticiones seguidas devolvieron siempre 200, sin 429 ni bloqueo
- Evidencia:
    - `peticiones`: 12
    - `codigos`: [200]
- Recomendacion: Aplicar limite por IP y por cuenta en endpoints sensibles

### 53. [MEDIO] Entrada reflejada dentro de JavaScript (q)
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Parametro: `q`
- Detalle: El valor vuelve sin escapar en un contexto de script, lo que permite romper la cadena
- Evidencia:
    - `payload`: '+hbkdgdqq+'
- Recomendacion: Escapar segun contexto JS y usar JSON.stringify

### 54. [BAJO] Falta referrer-policy
- Detalle: Sin Referrer-Policy: se filtran URLs a terceros
- Evidencia:
    - `cabecera`: referrer-policy
- Recomendacion: strict-origin-when-cross-origin

### 55. [BAJO] Falta permissions-policy
- Detalle: Sin Permissions-Policy: APIs del navegador sin restringir
- Evidencia:
    - `cabecera`: permissions-policy
- Recomendacion: geolocation=(), microphone=(), camera=()

### 56. [BAJO] Cabecera revela tecnologia: server
- Detalle: Facilita al atacante elegir exploits concretos
- Evidencia:
    - `cabecera`: server
    - `valor`: Apache/2.4.49 (Unix)
- Recomendacion: Eliminar o minimizar la cabecera

### 57. [BAJO] Cabecera revela tecnologia: x-powered-by
- Detalle: Facilita al atacante elegir exploits concretos
- Evidencia:
    - `cabecera`: x-powered-by
    - `valor`: PHP/8.1.2
- Recomendacion: Eliminar o minimizar la cabecera

### 58. [BAJO] Cabecera revela tecnologia: via
- Detalle: Facilita al atacante elegir exploits concretos
- Evidencia:
    - `cabecera`: via
    - `valor`: 1.1 hunterbug-proxy
- Recomendacion: Eliminar o minimizar la cabecera

### 59. [BAJO] Falta la cabecera referrer-policy
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Sin Referrer-Policy se filtran URLs completas a terceros
- Evidencia:
    - `cabecera_ausente`: referrer-policy
- Recomendacion: Referrer-Policy: strict-origin-when-cross-origin

### 60. [BAJO] Falta la cabecera permissions-policy
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Sin Permissions-Policy las APIs del navegador quedan sin restringir
- Evidencia:
    - `cabecera_ausente`: permissions-policy
- Recomendacion: Permissions-Policy: geolocation=(), microphone=(), camera=()

### 61. [BAJO] Falta la cabecera cross-origin-opener-policy
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Sin COOP la ventana puede ser referenciada desde otro origen
- Evidencia:
    - `cabecera_ausente`: cross-origin-opener-policy
- Recomendacion: Cross-Origin-Opener-Policy: same-origin

### 62. [BAJO] Falta la cabecera cross-origin-resource-policy
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Sin CORP los recursos pueden ser embebidos desde otros origenes
- Evidencia:
    - `cabecera_ausente`: cross-origin-resource-policy
- Recomendacion: Cross-Origin-Resource-Policy: same-origin

### 63. [BAJO] Sin cabecera Cache-Control
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: El contenido puede quedar en cache de proxies intermedios o del navegador
- Evidencia:
    - `cache_control`: 
- Recomendacion: Cache-Control: no-store en respuestas autenticadas o sensibles

### 64. [BAJO] La cabecera Server revela version
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Facilita elegir exploits concretos para esa version
- Evidencia:
    - `server`: Apache/2.4.49 (Unix)
- Recomendacion: Ocultar la version (ServerTokens Prod, server_tokens off)

### 65. [BAJO] X-Powered-By revela la tecnologia
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Expone el lenguaje y a veces la version exacta
- Evidencia:
    - `x_powered_by`: PHP/8.1.2
- Recomendacion: Eliminar la cabecera

### 66. [BAJO] Cabeceras que revelan infraestructura (2)
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Revelan servidores intermedios, frameworks o versiones internas
- Evidencia:
    - `x-runtime`: 0.0412
    - `via`: 1.1 hunterbug-proxy
- Recomendacion: Eliminar o minimizar estas cabeceras

### 67. [BAJO] Cookie de sesion con nombre por defecto (PHPSESSID)
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Revela el framework (PHP) sin necesidad de fingerprint
- Evidencia:
    - `cookie`: PHPSESSID=abc123; Path=/
    - `framework`: PHP
- Recomendacion: Renombrar la cookie de sesion

### 68. [BAJO] Respuesta CORS sin Vary: Origin
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Una cache intermedia puede servir la cabecera CORS de un origen a otro
- Evidencia:
    - `vary`: 
- Recomendacion: Anadir Vary: Origin

### 69. [BAJO] Un metodo no estandar no es rechazado
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: El metodo HUNTERBUG devolvio 200 en lugar de 405/501
- Evidencia:
    - `status`: 200
- Recomendacion: Rechazar metodos no implementados

### 70. [BAJO] 2 comentario(s) HTML con informacion sensible
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Los comentarios viajan al cliente y revelan notas internas, credenciales o rutas
- Evidencia:
    - `comentarios`: ['TODO: quitar el usuario admin / password: Sup3rS3cret0 antes de publicar', 'FIXME: la api key de produccion es api_key = "AKIAIOSFODNN7EXAMPLE1"']
- Recomendacion: Eliminar los comentarios en produccion

### 71. [BAJO] 2 script(s) sin Subresource Integrity
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Si el CDN se compromete, el script se ejecuta sin que nadie lo detecte
- Evidencia:
    - `scripts`: ['<script src="https://cdn.ejemplo.invalid/lib.js">', '<script src="/app.js">']
- Recomendacion: Anadir integrity y crossorigin a los scripts de terceros

### 72. [BAJO] 1 enlace(s) _blank sin rel=noopener
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: La pagina destino puede manipular la ventana de origen mediante window.opener
- Evidencia:
    - `enlaces`: ['<a href="https://externo.invalid" target="_blank">']
- Recomendacion: Anadir rel="noopener noreferrer"

### 73. [BAJO] Fichero .DS_Store expuesto accesible
- URL: `http://127.0.0.1/.DS_Store`
- Detalle: Revela nombres de ficheros y estructura de directorios
- Evidencia:
    - `ruta`: /.DS_Store
    - `status`: 200
    - `bytes`: 22
    - `extracto`: Bud1        index.html
- Recomendacion: Bloquear el acceso a .DS_Store

### 74. [BAJO] robots.txt expone rutas internas
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Rutas listadas: /admin/, /backup/, /config/
- Evidencia:
    - `rutas`: ['/admin/', '/backup/', '/config/']
- Recomendacion: No listar rutas privadas en robots.txt

### 75. [INFO] Falta la cabecera cross-origin-embedder-policy
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Sin COEP no se aisla el contexto de ejecucion
- Evidencia:
    - `cabecera_ausente`: cross-origin-embedder-policy
- Recomendacion: Cross-Origin-Embedder-Policy: require-corp

### 76. [INFO] Falta la cabecera x-permitted-cross-domain-policies
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Sin esta cabecera los plugins de Adobe pueden cargar contenido cruzado
- Evidencia:
    - `cabecera_ausente`: x-permitted-cross-domain-policies
- Recomendacion: X-Permitted-Cross-Domain-Policies: none

### 77. [INFO] Falta la cabecera x-dns-prefetch-control
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Sin control de prefetch DNS se filtran dominios a terceros
- Evidencia:
    - `cabecera_ausente`: x-dns-prefetch-control
- Recomendacion: X-DNS-Prefetch-Control: off

### 78. [INFO] Falta la cabecera x-download-options
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Sin X-Download-Options los ficheros descargados pueden ejecutarse en contexto del sitio
- Evidencia:
    - `cabecera_ausente`: x-download-options
- Recomendacion: X-Download-Options: noopen

### 79. [INFO] Falta la cabecera clear-site-data
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Sin Clear-Site-Data no se limpian los datos del sitio al cerrar sesion
- Evidencia:
    - `cabecera_ausente`: clear-site-data
- Recomendacion: Clear-Site-Data: "cache", "cookies"

### 80. [INFO] El documento no declara idioma (lang)
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Afecta a accesibilidad y a la interpretacion del contenido por herramientas automaticas
- Evidencia:
    - `extracto`: <!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scal
- Recomendacion: Anadir lang al elemento html

### 81. [INFO] Ninguna cookie cumple Secure + HttpOnly + SameSite
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Se han visto 1 cookie(s) y ninguna reune las tres protecciones
- Evidencia:
    - `total_cookies`: 1
    - `cookies`: ['PHPSESSID=abc123; Path=/']
- Recomendacion: Aplicar las tres a todas las cookies

### 82. [INFO] CORS expone cabeceras sensibles al JavaScript
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Expose-Headers incluye cabeceras de autenticacion
- Evidencia:
    - `expose_headers`: Authorization
- Recomendacion: Exponer solo las cabeceras necesarias

### 83. [INFO] 2 direccion(es) de correo en el cuerpo
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Facilitan campanas de phishing y enumeracion
- Evidencia:
    - `correos`: ['admin@ejemplo.test', 'soporte@ejemplo.test']
- Recomendacion: Ofuscar o eliminar los correos publicos

### 84. [INFO] Campo de contrasena sin autocomplete
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: El navegador puede almacenar la contrasena en equipos compartidos
- Evidencia:
    - `input`: <input type="password" name="clave">
- Recomendacion: autocomplete="current-password" o "off"

### 85. [INFO] 1 iframe(s) sin atributo sandbox
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: El contenido embebido se ejecuta con los permisos de la pagina
- Evidencia:
    - `iframes`: ['<iframe src="https://externo.invalid/widget">']
- Recomendacion: Anadir sandbox a los iframes de terceros

### 86. [INFO] Meta generator revela el CMS y su version
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: <meta name="generator" content="PanelCMS 3.1.4">
- Evidencia:
    - `meta`: <meta name="generator" content="PanelCMS 3.1.4">
- Recomendacion: Eliminar la etiqueta generator

### 87. [INFO] 1 referencia(s) a almacenamiento externo
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Los buckets mal configurados son una fuga de datos habitual
- Evidencia:
    - `buckets`: ['https://panel-datos.s3.amazonaws.com']
- Recomendacion: Revisar las politicas del bucket

### 88. [INFO] 2 endpoint(s) de API referenciados
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Amplia la superficie de ataque conocida
- Evidencia:
    - `endpoints`: ['/api/v1/facturas', '/api/v1/usuarios']
- Recomendacion: Revisar que cada endpoint comprueba autorizacion

### 89. [INFO] El HTML enlaza paneles de administracion
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Facilita localizar la zona privilegiada
- Evidencia:
    - `rutas`: ['/admin/panel']
- Recomendacion: Restringir el acceso por red o autenticacion fuerte

### 90. [INFO] El cuerpo declara un numero de version
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Version visible: 3.1.4
- Evidencia:
    - `version`: 3.1.4
- Recomendacion: Ocultar las versiones de los componentes

### 91. [INFO] Copyright de 2019 (hace 7 anos)
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Suele indicar un sitio sin mantenimiento, con componentes antiguos
- Evidencia:
    - `anios`: [2019]
- Recomendacion: Actualizar y revisar dependencias

### 92. [INFO] 3 tecnologias identificadas por el contenido
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Detectadas: WordPress, Next.js, React
- Evidencia:
    - `tecnologias`: ['WordPress', 'Next.js', 'React']
- Recomendacion: Minimizar las huellas del stack

### 93. [INFO] No publica /.well-known/security.txt
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Sin canal declarado de reporte de vulnerabilidades
- Evidencia:
    - `status`: 404
- Recomendacion: Publicar security.txt con un contacto de seguridad

### 94. [INFO] sitemap.xml accesible
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Facilita el inventario de URLs del sitio
- Evidencia:
    - `bytes`: 66
- Recomendacion: Revisar si el sitemap debe ser publico

### 95. [INFO] Panel de administracion accesible (/admin/)
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Expone la interfaz de gestion del CMS
- Evidencia:
    - `ruta`: /admin/
    - `status`: 200
- Recomendacion: Restringir por IP o autenticacion adicional

### 96. [INFO] La pagina 404 revela el servidor y su version
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Firma encontrada: Apache/2.4.49
- Evidencia:
    - `firma`: Apache/2.4.49
    - `extracto`: <html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><address>Apache/2.4.49 (Unix) Server at 127.0.0.1 Port 8080</address></body></html>
- Recomendacion: Pagina 404 personalizada

### 97. [INFO] Tecnologia detectada: WordPress
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Firma encontrada: 'wp-content'
- Evidencia:
    - `tecnologia`: WordPress
    - `firma`: wp-content
- Recomendacion: Mantener la version al dia y revisar sus CVE conocidos

### 98. [INFO] Tecnologia detectada: Next.js
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Firma encontrada: '_next/static'
- Evidencia:
    - `tecnologia`: Next.js
    - `firma`: _next/static
- Recomendacion: Mantener la version al dia y revisar sus CVE conocidos

### 99. [INFO] Tecnologia detectada: React
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Firma encontrada: 'data-reactroot'
- Evidencia:
    - `tecnologia`: React
    - `firma`: data-reactroot
- Recomendacion: Mantener la version al dia y revisar sus CVE conocidos

### 100. [INFO] Tecnologia detectada: Ruby on Rails
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Firma encontrada: 'x-runtime'
- Evidencia:
    - `tecnologia`: Ruby on Rails
    - `firma`: x-runtime
- Recomendacion: Mantener la version al dia y revisar sus CVE conocidos

### 101. [INFO] El endpoint acepta text/plain en un cuerpo JSON
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: No se valida el tipo de contenido declarado
- Evidencia:
    - `status`: 200
- Recomendacion: Rechazar tipos no esperados con 415

### 102. [INFO] La respuesta con parametros no aplica CSP ni nosniff
- URL: `http://127.0.0.1:8080/buscar?q=test`
- Detalle: Una respuesta dinamica sin estas cabeceras es el escenario ideal para XSS
- Evidencia:
    - `faltan`: ['content-security-policy', 'x-content-type-options']
- Recomendacion: Aplicar las cabeceras de seguridad a todas las respuestas, no solo a la portada

## Analisis asistido por IA
```
1) LECTURA DEL GRAFO
   Nodos 115 / aristas 114. Superficie: cve=2, hallazgo=100, ip=1, objetivo=1, puerto=3, servicio=3, tecnologia=5.
   3 puerto(s) expuesto(s): cada servicio adicional amplia la superficie y merece identificacion de version.
   5 tecnologia(s) identificada(s): son el punto de partida para el mapeo a CVE.
   Indice de riesgo calculado: 100/100.

2) CADENA DE ATAQUE PROBABLE
   - Empezar por 2 CVE conocido(s) (CVE-2021-41773, CVE-2022-21661): si la version es la afectada, el exploit publico es el camino mas corto.
   - SQLi confirmada: encadenar con extraccion de esquema y, si hay privilegios, lectura de ficheros o escritura.
   - XSS reflejado: buscar el contexto de sesion (cookies sin HttpOnly) para escalar a robo de sesion.
   - Fallo de autorizacion por objeto (IDOR/BOLA): enumerar identificadores adyacentes para medir el alcance real.
   - Cabeceras ausentes (CSP/HSTS): facilitan el encadenado de XSS y los ataques de intermediario.

3) PRIORIDAD
   [CRITICO] CVE-2021-41773 - Apache 2.4.49: path traversal y posible RCE
   [CRITICO] Inyeccion SQL (basada en errores) en 'q'
   [CRITICO] CORS con credenciales y origen reflejado

4) SIGUIENTES PRUEBAS
   - Confirmar manualmente los criticos antes de reportar y capturar evidencia reproducible.
   - Verificar la version exacta del producto con una peticion de identificacion antes de citar el CVE.
   - Revisar IDOR/BOLA en endpoints con identificador de objeto usando dos cuentas del mismo rol.
   - Comprobar autorizacion horizontal y vertical en la API (roles bajos sobre recursos de rol alto).
```