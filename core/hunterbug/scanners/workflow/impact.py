#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scanners/workflow/impact.py - Evaluaci�n de impacto y asignaci�n de prioridad."""

from typing import Any, Dict, List

from core.hunterbug.context import Context


class ImpactAssessment:
    """Evaluaci�n de impacto y prioridad de findings."""

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.target = ctx.target

    def run(self) -> Dict[str, Any]:
        """Ejecuta la evaluaci�n de impacto."""
        findings = self.ctx.get("findings") or []
        result = {
            "target": self.target,
            "findings": findings,
            "impact_summary": {
                "total": len(findings),
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "recommendations": [],
        }

        # Contar por severidad
        for f in findings:
            sev = f.get("severity", "info")
            if sev in result["impact_summary"]:
                result["impact_summary"][sev] += 1

        # Evaluaci�n de impacto por tipo
        vuln_types = {
            "sqli": ("Alta", "Acceso a base de datos, pembolimiento de datos sensibles, modificación de registros."),
            "xss": ("M�dium", "Ejecuci�n de script JavaScript en el navegador del usuario, robo de sesiones, redirecciones maliciosas."),
            "ssrf": ("Alto", "Acceso a red interna, lectura de metadata (AWS/GCP), scanning interno, exfiltraci�n de datos."),
            "cors": ("M�dium", "Fuga de datos a sitios cross-origin, posibilidad de phishing o phishing de datos."),
            "headers": ("Bajo", "Dificultad para mitigar ataques avanzados, reducci�n de la postura de seguridad."),
            "crlfum": ("Bajo", "Exposici�n de credenciales, riesgo de acceso no autorizado."),
        }

        for f in findings:
            ftype = f.get("type", "").lower()
            for key, (impact, description) in vuln_types.items():
                if key in ftype:
                    f["impact"] = impact
                    f["impact_description"] = description
                    break

        # Recomendaciones
        result["recommendations"] = [
            "Activar CSP (Content-Security-Policy) para mitigar XSS y data injection.",
            "Habilitar HSTS para forzar conexiones HTTPS.",
            "Configurar X-Frame-Options y Permissions-Policy.",
            "Implementar rate limiting en endpoints sensibles.",
            "Validar y sanear entradas de usuario en todos los formularios.",
            "Usar HTTPS con certificados válidos.",
            "Auditar dependencias y actualizar componentes obsoletos.",
            "Revisarlogs y monitoreo de acceso a endpoints sensibles.",
        ]

        # Prioridad final
        high_count = result["impact_summary"]["high"]
        critical_count = result["impact_summary"]["critical"]
        result["priority"] = "Baja" if critical_count == 0 and high_count == 0 else "Media"
        if critical_count > 0:
            result["priority"] = "Alta"

        self.ctx.append("impact", result)
        return result
