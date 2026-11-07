"""HunterBug 1.1 — detector de tokens JWT y problemas de firma.

Los JWT (JSON Web Token) son ampliamente usados pero tienen problemas
de seguridad comunes: algoritmo 'none', claves públicas expuestas, firmas
significativamente débiles (HS256 con password corta).
"""

from __future__ import annotations

import re
import base64
import hashlib
import time

# Pattern para JWT
JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"
)

# Payloads comunes para testing
XSS_PAYLOAD = {"admin": True, "role": "admin", "id": 1, "elevated": True}


def _b64_decode(data):
    """Decodifica base64url sin padding."""
    try:
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)
    except Exception:
        return None


def _b64_encode(data):
    """Codifica a base64url sin padding."""
    if isinstance(data, dict):
        import json
        data = json.dumps(data, separators=(',', ':')).encode()
    elif isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_jwt(token):
    """Decodifica un JWT y devuelve header, payload, signature."""
    parts = token.split(".")
    if len(parts) != 3:
        return None

    header = _b64_decode(parts[0])
    payload = _b64_decode(parts[1])

    if header and payload:
        import json
        try:
            header = json.loads(header)
            payload = json.loads(payload)
        except json.JSONDecodeError:
            pass

    return {
        "header": header,
        "payload": payload,
        "signature": parts[2] if len(parts) > 2 else "",
        "raw_header": parts[0],
        "raw_payload": parts[1]
    }


def analizar_jwt(token, wordlists=None):
    """Analiza un JWT en busca de problemas de seguridad."""
    result = decode_jwt(token)
    if not result:
        return {"valido": False, "error": "No es un JWT válido"}

    header = result.get("header") or {}
    payload = result.get("payload") or {}
    issues = []
    confidence = 0

    # 1. Algoritmo 'none'
    if header.get("alg") == "none" or header.get("alg") is None:
        issues.append({
            "tipo": "alg_none",
            "severidad": "critico",
            "detalle": "El JWT no tiene algoritmo de firma (alg=none). "
                      "Cualquier cambio al payload es aceptado.",
            "recomendacion": "Exigir un algoritmo de firma fuerte (RS256, ES256)."
        })
        confidence = 100

    # 2. Algoritmo key-id vulnerable
    if header.get("alg") in ("HS256", "HS384", "HS512"):
        issues.append({
            "tipo": "alg_hs",
            "severidad": "medio",
            "detalle": "El JWT usa firma HMAC. Si el secret es conocido o "
                      "corto, se puede forjar el token.",
            "recomendacion": "Usar claves secretas largas y rotar periódicamente, "
                           "o preferir RS256/ES256."
        })
        if confidence < 50:
            confidence = 50

    # 3. exp claim muy lejana
    if "exp" in payload:
        exp_ts = payload.get("exp")
        if isinstance(exp_ts, (int, float)):
            tiempo_restante = exp_ts - time.time()
            if tiempo_restante > 86400 * 30:  # Mas de 30 dias
                issues.append({
                    "tipo": "exp_muy_lejana",
                    "severidad": "info",
                    "detalle": f"Expiración en {tiempo_restante//86400} dias. "
                              "Demasiado tiempo de expiración.",
                    "recomendacion": "Configurar expiración razonable (<= 1 hora para tokens sensibles)."
                })

    # 4. Auditoría del payload
    payload_str = str(payload).lower()
    sensitive_claims = ["admin", "role", "privilege", "id", "user_id", "uid"]
    found = [c for c in sensitive_claims if c in payload_str]
    if found:
        issues.append({
            "tipo": "claims_sensibles",
            "severidad": "bajo" if len(found) == 1 else "medio",
            "detalle": f"Claims sensibles en el payload: {found}.",
            "recomendacion": "No incluir privilegios en el JWT. Usar referencias "
                           "a roles en base de datos."
        })

    return {
        "valido": True,
        "tipo": "jwt",
        "alg": header.get("alg"),
        "issues": issues,
        "confidence": confidence,
        "payload": payload,
        "header": header
    }


def escanear_urls(url, cabeceras=None, log=None):
    """Escanea una URL y subida en busca de tokens JWT."""
    cabeceras = cabeceras or {}

    r = net.peticion_http(url, cabeceras=cabeceras, timeout=15)
    if r.status != 200:
        return {"url": url, "tokens": [], "error": "sin respuesta"}

    body = r.cuerpo or ""
    headers = {k.lower(): v for k, v in r.cabeceras}

    tokens_found = []

    # Buscar en headers
    for header_name in ["authorization", "x-auth-token", "x-jwt", "cookie"]:
        if header_name in headers:
            value = headers[header_name]
            m = JWT_PATTERN.search(value)
            if m:
                token = m.group(0)
                analysis = analizar_jwt(token)
                analysis["ubicacion"] = f"header: {header_name}"
                tokens_found.append(analysis)

    # Buscar en el cuerpo HTML/JS
    for m in JWT_PATTERN.finditer(body):
        token = m.group(0)
        analysis = analizar_jwt(token)
        analysis["ubicacion"] = "cuerpo"
        tokens_found.append(analysis)

    return {
        "url": url,
        "tokens": tokens_found,
        "total": len(tokens_found),
        "headers_inspeccionados": list(headers.keys())
    }


if __name__ == "__main__":
    import sys
    token = sys.argv[1] if len(sys.argv) > 1 else \
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    result = decode_jwt(token)
    print("Decoded JWT:")
    print(f"  Header: {result.get('header')}")
    print(f"  Payload: {result.get('payload')}")
    
    analysis = analizar_jwt(token)
    print(f"\nIssues: {analysis.get('issues', [])}")