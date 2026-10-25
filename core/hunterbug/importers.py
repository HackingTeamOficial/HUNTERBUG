#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""core/hunterbug/importers.py - Importación de resultados de escáneres externos."""

from __future__ import annotations

import os
import json
from typing import Any, Dict, List, Optional

from .context import Context


class ScannerImporter:
    """Importador de resultados de escáneres externos.

    Convierte formatos comunes (JSON/Nuclei/Masscan) a findings de HunterBug.
    """

    def import_results(self, ctx: Context, scanner: str, results: Any, **kwargs) -> List[Dict]:
        """Importa resultados de un escáner."""
        if isinstance(results, str):
            # Es ruta de fichero
            results = self._load_file(results)

        if isinstance(results, dict):
            return self._import_dict(ctx, scanner, results, **kwargs)
        elif isinstance(results, list):
            findings = []
            for item in results:
                f = self._import_item(ctx, scanner, item, **kwargs)
                if f:
                    findings.append(f)
            return findings
        return []

    def _load_file(self, filepath: str) -> Any:
        """Carga un fichero."""
        with open(filepath, encoding="utf-8") as f:
            return json.load(f)

    def _import_dict(self, ctx: Context, scanner: str, data: Dict, **kwargs) -> List[Dict]:
        """Importa un diccionario."""
        findings = []
        for key, value in data.items():
            f = self._import_item(ctx, scanner, {"key": key, "value": value}, **kwargs)
            if f:
                findings.append(f)
        return findings

    def _import_item(self, ctx: Context, scanner: str, item: Dict, **kwargs) -> Optional[Dict]:
        """Importa un único hallazgo."""
        # Determinar título y detalle
        title = item.get("title") or item.get("key") or item.get("url") or str(item)
        detail = item.get("detail") or item.get("description") or str(item)

        # Detectar severidad
        severity = item.get("severity", "info")
        if severity not in ("high", "medium", "low", "info"):
            severity = "info"

        return {
            "type": f"{scanner}_finding",
            "title": title,
            "detail": detail,
            "severity": severity,
            "confidence": "high",
            "url": item.get("url"),
            "parameter": item.get("parameter"),
            "evidence": {
                "scanner": scanner,
                "raw": item,
                "module": "imported",
            },
            "module": "imported",
            "phase": "attack",
            "raw": item,
        }
