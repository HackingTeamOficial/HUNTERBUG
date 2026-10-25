"""HunterBug - lector minimo de certificados X.509 (DER) sin dependencias.

Extrae lo justo para auditar un certificado: fechas de validez, CN y O del
sujeto y del emisor, algoritmo de firma y tamano de clave. No valida la
cadena de confianza; solo lee lo que el servidor presenta.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

# OIDs utiles (codificados en DER como bytes)
OID_CN = bytes.fromhex("550403")
OID_O = bytes.fromhex("55040a")
OID_OU = bytes.fromhex("55040b")
OID_SHA1RSA = bytes.fromhex("2a864886f70d010105")
OID_SHA256RSA = bytes.fromhex("2a864886f70d01010b")
OID_SHA384RSA = bytes.fromhex("2a864886f70d01010c")
OID_SHA512RSA = bytes.fromhex("2a864886f70d01010d")
OID_EC = bytes.fromhex("2a8648ce3d0201")
OID_RSA = bytes.fromhex("2a864886f70d010101")

FIRMAS = {
    OID_SHA1RSA: "sha1WithRSAEncryption",
    OID_SHA256RSA: "sha256WithRSAEncryption",
    OID_SHA384RSA: "sha384WithRSAEncryption",
    OID_SHA512RSA: "sha512WithRSAEncryption",
    OID_EC: "id-ecPublicKey",
    OID_RSA: "rsaEncryption",
}


def _leer_longitud(datos, pos):
    if pos >= len(datos):
        return 0, pos
    primero = datos[pos]
    pos += 1
    if primero < 0x80:
        return primero, pos
    n = primero & 0x7F
    if n == 0 or pos + n > len(datos):
        return 0, pos
    return int.from_bytes(datos[pos:pos + n], "big"), pos + n


def _recorrer(datos, inicio, fin, prof=0, salida=None):
    """Recorre los elementos TLV de un bloque DER."""
    if salida is None:
        salida = []
    pos = inicio
    while pos < fin and prof < 24:
        etiqueta = datos[pos]
        pos += 1
        largo, pos = _leer_longitud(datos, pos)
        if largo <= 0 or pos + largo > len(datos):
            break
        contenido = datos[pos:pos + largo]
        salida.append((etiqueta, pos, largo, contenido))
        # SEQUENCE (0x30), SET (0x31), contexto construido (0xA0-0xBF)
        if etiqueta in (0x30, 0x31) or 0xA0 <= etiqueta <= 0xBF:
            _recorrer(datos, pos, pos + largo, prof + 1, salida)
        pos += largo
    return salida


def _fecha(texto):
    try:
        texto = texto.strip()
        if re.fullmatch(r"\d{12}Z", texto):          # UTCTime YYMMDDHHMMSSZ
            anio = int(texto[0:2])
            anio += 2000 if anio < 50 else 1900
            return datetime(anio, int(texto[2:4]), int(texto[4:6]),
                            int(texto[6:8]), int(texto[8:10]), int(texto[10:12]),
                            tzinfo=timezone.utc)
        if re.fullmatch(r"\d{14}Z", texto):          # GeneralizedTime
            return datetime(int(texto[0:4]), int(texto[4:6]), int(texto[6:8]),
                            int(texto[8:10]), int(texto[10:12]), int(texto[12:14]),
                            tzinfo=timezone.utc)
    except Exception:
        pass
    return None


def _cadena(contenido):
    try:
        return contenido.decode("utf-8", "replace")
    except Exception:
        return ""


def analizar_cert(der):
    """Devuelve un dict con lo extraido del certificado DER."""
    datos = {"valido_desde": "", "valido_hasta": "", "sujeto": {},
             "emisor": {}, "firma": "", "clave": "", "bits_clave": 0,
             "sha1": False, "autofirmado": False}
    if not der:
        return datos

    nodos = _recorrer(der, 0, len(der))

    # --- fechas de validez: dos UTCTime/GeneralizedTime consecutivos ---
    fechas, pos_primera_fecha = [], None
    for etiqueta, pos, largo, contenido in nodos:
        if etiqueta in (0x17, 0x18):                 # UTCTime / GeneralizedTime
            f = _fecha(_cadena(contenido))
            if f:
                fechas.append(f)
                if pos_primera_fecha is None:
                    pos_primera_fecha = pos
    if len(fechas) >= 2:
        datos["valido_desde"] = fechas[0].isoformat()
        datos["valido_hasta"] = fechas[1].isoformat()

    # --- CN / O: en un certificado el orden es emisor -> validez -> sujeto,
    #     asi que lo anterior a la primera fecha es el emisor y lo posterior
    #     es el sujeto. Es mas fiable que contar apariciones. ---
    def valores(oid):
        antes, despues = [], []
        for etiqueta, pos, largo, contenido in nodos:
            if etiqueta in (0x0C, 0x13, 0x16, 0x14) and contenido:
                inicio = max(0, pos - 14)
                if oid not in der[inicio:pos]:
                    continue
                v = _cadena(contenido)
                if pos_primera_fecha is not None and pos < pos_primera_fecha:
                    antes.append(v)
                else:
                    despues.append(v)
        return antes, despues

    cn_e, cn_s = valores(OID_CN)
    o_e, o_s = valores(OID_O)
    if cn_e:
        datos["emisor"]["CN"] = cn_e[-1]
    if cn_s:
        datos["sujeto"]["CN"] = cn_s[0]
    if o_e:
        datos["emisor"]["O"] = o_e[-1]
    if o_s:
        datos["sujeto"]["O"] = o_s[0]

    # --- algoritmo de firma ---
    for oid, nombre in FIRMAS.items():
        if oid in der:
            datos["firma"] = nombre
            datos["sha1"] = "sha1" in nombre
            break

    # --- clave publica y tamano ---
    if OID_EC in der:
        datos["clave"] = "EC"
        datos["bits_clave"] = 256
    if OID_RSA in der:
        datos["clave"] = "RSA"
        datos["bits_clave"] = _bits_rsa(der)

    s, e = datos["sujeto"], datos["emisor"]
    if s and e and s == e:
        datos["autofirmado"] = True
    return datos


def _bits_rsa(der):
    """Tamano del modulo RSA leyendo el BIT STRING de la clave publica."""
    for etiqueta, pos, largo, contenido in _recorrer(der, 0, len(der)):
        if etiqueta != 0x03 or largo < 32:
            continue
        # BIT STRING: [bits no usados][SEQUENCE { INTEGER modulo, INTEGER exp }]
        if len(contenido) < 4 or contenido[1] != 0x30:
            continue
        _, p = _leer_longitud(contenido, 2)          # longitud del SEQUENCE
        if p >= len(contenido) or contenido[p] != 0x02:
            continue
        mod_len, _ = _leer_longitud(contenido, p + 1)
        if 64 <= mod_len <= 1024:
            return (mod_len - 1) * 8
    return 0


def dias_para_caducar(valido_hasta):
    """Dias que quedan de validez, o None si no se pudo leer."""
    if not valido_hasta:
        return None
    try:
        f = datetime.fromisoformat(valido_hasta)
        if f.tzinfo is None:
            f = f.replace(tzinfo=timezone.utc)
        return (f - datetime.now(timezone.utc)).days
    except Exception:
        return None


def caducado(valido_hasta):
    d = dias_para_caducar(valido_hasta)
    return None if d is None else d < 0
