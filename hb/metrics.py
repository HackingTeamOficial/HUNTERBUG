"""HunterBug - metricas, puntuacion y cuadros de mando.

Convierte el resultado de una evaluacion en numeros utilizables: puntuacion
de seguridad con letra, desglose por categoria, cobertura del catalogo,
estadisticas de red y de respuesta, y un cuadro listo para mostrar o exportar.
"""

from __future__ import annotations

import math
import time

PESO = {"critico": 10.0, "alto": 6.0, "medio": 3.0, "bajo": 1.0, "info": 0.2}

ORDEN_SEV = ["critico", "alto", "medio", "bajo", "info"]


def letra(puntos):
    if puntos >= 90:
        return "A"
    if puntos >= 80:
        return "B"
    if puntos >= 70:
        return "C"
    if puntos >= 60:
        return "D"
    if puntos >= 40:
        return "E"
    return "F"


def descripcion_letra(l):
    return {"A": "excelente", "B": "bueno", "C": "aceptable",
            "D": "mejorable", "E": "deficiente", "F": "critico"}.get(l, "?")


def _indice(penal_total, ejecutados):
    """Indice de seguridad 0-100 con decaimiento exponencial.

    Un modelo aditivo se satura en 0 en cuanto un objetivo acumula docenas de
    fallos, y deja de discriminar. Con decaimiento exponencial sobre la
    penalizacion media por chequeo, la escala sigue distinguiendo objetivos
    muy cargados de fallos de los simplemente descuidados.
    """
    if ejecutados <= 0:
        return 100.0
    return 100.0 * math.exp(-penal_total / (ejecutados * 0.35))


def puntuacion(resultados):
    """Puntuacion 0-100 con desglose por categoria.

    Cada chequeo fallido resta segun su severidad; los omitidos no penalizan
    (no se han podido comprobar) pero reducen la cobertura.
    """
    penal_total = 0.0
    por_cat = {}
    conteo = {s: 0 for s in ORDEN_SEV}
    estados = {"ok": 0, "fallo": 0, "omitido": 0, "error": 0}

    for r in resultados:
        estado = r.get("estado", "ok")
        estados[estado] = estados.get(estado, 0) + 1
        cat = r.get("categoria", "otros")
        c = por_cat.setdefault(cat, {"penal": 0.0, "fallos": 0, "total": 0})
        c["total"] += 1
        if estado == "fallo":
            sev = r.get("severidad", "info")
            p = PESO.get(sev, 0.2)
            penal_total += p
            c["penal"] += p
            c["fallos"] += 1
            if sev in conteo:
                conteo[sev] += 1

    ejecutados = estados["ok"] + estados["fallo"]
    puntos = max(0.0, min(100.0, _indice(penal_total, ejecutados)))
    categorias = []
    for cat, c in sorted(por_cat.items()):
        cej = c["total"] - (1 if c["fallos"] else 0)  # aproximacion: fallidos ya contados
        cp = max(0.0, min(100.0, _indice(c["penal"], max(1, c["total"]))))
        categorias.append({"categoria": cat, "puntos": round(cp, 1),
                           "letra": letra(cp), "fallos": c["fallos"],
                           "total": c["total"],
                           "penalizacion": round(c["penal"], 1)})
    categorias.sort(key=lambda x: x["puntos"])

    return {
        "puntos": round(puntos, 1),
        "letra": letra(puntos),
        "descripcion": descripcion_letra(letra(puntos)),
        "penalizacion": round(penal_total, 1),
        "penalizacion_media": round(penal_total / ejecutados, 3) if ejecutados else 0.0,
        "por_severidad": conteo,
        "estados": estados,
        "categorias": categorias,
        "ejecutados": ejecutados,
        "cobertura": round(ejecutados / max(1, len(resultados)) * 100, 1),
    }


def metricas_red(ctx):
    """Estadisticas de la actividad de red durante la evaluacion."""
    t = getattr(ctx, "t_total", 0.0) or 0.0
    pet = ctx.peticiones or 1
    return {
        "peticiones": ctx.peticiones,
        "bytes_recibidos": ctx.bytes_recibidos,
        "tiempo_total_s": round(t, 2),
        "tiempo_medio_ms": round(t / pet * 1000, 1),
        "peticiones_por_s": round(pet / t, 2) if t > 0 else 0.0,
        "cookies_recibidas": len(ctx.cookies),
        "cabeceras_recibidas": len(ctx.r.cabeceras),
        "cabeceras_enviadas": len(ctx.r.peticion_cruda.split("\n")) - 1,
    }


def metricas_respuesta(ctx):
    r = ctx.r
    return {
        "url": r.url,
        "status": r.status,
        "motivo": r.reason,
        "version_http": r.version,
        "ip": r.ip,
        "bytes_cuerpo": r.cuerpo_bytes,
        "tiempo_ms": round(r.tiempo * 1000, 1),
        "compresion": r.cabecera("content-encoding") or "ninguna",
        "content_type": r.cabecera("content-type") or "no declarado",
        "redirecciones": 1 if r.status in (301, 302, 303, 307, 308) else 0,
        "servidor": r.cabecera("server") or "no declarado",
    }


def metricas_tls(info_tls):
    if not info_tls:
        return {}
    cert = info_tls.get("cert") or {}
    return {
        "version": info_tls.get("version", ""),
        "cifrado": info_tls.get("cifrado", ""),
        "soporta_tls10": info_tls.get("soporta", {}).get("tls1.0", False),
        "soporta_tls11": info_tls.get("soporta", {}).get("tls1.1", False),
        "soporta_tls12": info_tls.get("soporta", {}).get("tls1.2", False),
        "soporta_tls13": info_tls.get("soporta", {}).get("tls1.3", False),
        "sujeto": (cert.get("sujeto") or {}).get("CN", ""),
        "emisor": (cert.get("emisor") or {}).get("O")
                  or (cert.get("emisor") or {}).get("CN", ""),
        "valido_hasta": (cert.get("valido_hasta") or "")[:10],
        "clave": "%s %s" % (cert.get("clave", ""), cert.get("bits_clave", "")),
        "firma": cert.get("firma", ""),
        "autofirmado": cert.get("autofirmado", False),
    }


def metricas_superficie(puertos=None, tecnologias=None, ips=None, dns=None,
                        hallazgos=None):
    return {
        "puertos_abiertos": len(puertos or []),
        "tecnologias": len(tecnologias or {}),
        "ips": len(ips or []),
        "registros_dns": sum(len(v) for v in (dns or {}).values()),
        "hallazgos": len(hallazgos or []),
    }


def metricas_grafo(grafo):
    if grafo is None:
        return {}
    res = grafo.resumen()
    n = res["nodos"] or 1
    return {
        "nodos": res["nodos"],
        "aristas": res["aristas"],
        "densidad": round(res["aristas"] / (n * (n - 1) / 2.0), 4) if n > 2 else 0.0,
        "tipos": len(res["por_tipo"]),
        "por_tipo": res["por_tipo"],
    }


def cuadro(resultados, ctx=None, tls=None, superficie=None, grafo=None):
    """Cuadro completo de metricas, listo para mostrar en tabla."""
    p = puntuacion(resultados)
    filas = [
        ("Puntuacion de seguridad", "%s / 100" % p["puntos"]),
        ("Calificacion", "%s (%s)" % (p["letra"], p["descripcion"])),
        ("Penalizacion acumulada", "%s puntos" % p["penalizacion"]),
        ("Chequeos en el catalogo", str(len(resultados))),
        ("Chequeos ejecutados", "%d (cobertura %.1f%%)"
                                % (p["ejecutados"], p["cobertura"])),
        ("Chequeos superados", str(p["estados"].get("ok", 0))),
        ("Chequeos fallidos", str(p["estados"].get("fallo", 0))),
        ("Omitidos (sin autorizacion o no aplicables)",
         str(p["estados"].get("omitido", 0))),
        ("Errores de ejecucion", str(p["estados"].get("error", 0))),
        ("Criticos", str(p["por_severidad"].get("critico", 0))),
        ("Altos", str(p["por_severidad"].get("alto", 0))),
        ("Medios", str(p["por_severidad"].get("medio", 0))),
        ("Bajos", str(p["por_severidad"].get("bajo", 0))),
        ("Informativos", str(p["por_severidad"].get("info", 0))),
    ]
    if ctx is not None:
        rn = metricas_red(ctx)
        filas += [
            ("Peticiones realizadas", str(rn["peticiones"])),
            ("Bytes recibidos", "{:,}".format(rn["bytes_recibidos"]).replace(",", ".")),
            ("Tiempo total", "%.2f s" % rn["tiempo_total_s"]),
            ("Tiempo medio por peticion", "%.1f ms" % rn["tiempo_medio_ms"]),
            ("Ritmo", "%.2f peticiones/s" % rn["peticiones_por_s"]),
            ("Cookies recibidas", str(rn["cookies_recibidas"])),
            ("Cabeceras recibidas", str(rn["cabeceras_recibidas"])),
        ]
        for k, v in metricas_respuesta(ctx).items():
            filas.append(("Respuesta · " + k, str(v)))
    if tls:
        for k, v in metricas_tls(tls).items():
            filas.append(("TLS · " + k, str(v)))
    if superficie:
        for k, v in superficie.items():
            filas.append(("Superficie · " + k, str(v)))
    if grafo:
        g = metricas_grafo(grafo)
        for k in ("nodos", "aristas", "densidad", "tipos"):
            filas.append(("Grafo · " + k, str(g.get(k, ""))))
    return p, filas


def texto_puntuacion(p):
    l = ["PUNTUACION: %s/100 (%s - %s)" % (p["puntos"], p["letra"],
                                           p["descripcion"]),
         "Cobertura: %d de %d chequeos ejecutados (%.1f%%)"
         % (p["ejecutados"], p["ejecutados"] + p["estados"].get("omitido", 0)
            + p["estados"].get("error", 0), p["cobertura"]),
         "Fallos por severidad: " + ", ".join(
             "%s=%d" % (s, p["por_severidad"].get(s, 0)) for s in ORDEN_SEV),
         "", "Por categoria (peor primero):"]
    for c in p["categorias"]:
        l.append("  %-12s %5.1f  %s  (%d fallo(s) de %d)"
                 % (c["categoria"], c["puntos"], c["letra"], c["fallos"],
                    c["total"]))
    return "\n".join(l)
