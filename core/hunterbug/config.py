#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""core/hunterbug/config.py - Configuración de HunterBug."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

DEFAULT_CONFIG: Dict[str, Any] = {
    # Integraciones de escáneres
    "integrations": {
        "nuclei": {"enabled": False, "path": "nuclei", "templates": ""},
        "masscan": {"enabled": False, "path": "masscan"},
        "nmap": {"enabled": False, "path": "nmap"},
        "ffuf": {"enabled": False, "path": "ffuf"},
        "amass": {"enabled": False, "path": "amass"},
        "subfinder": {"enabled": False, "path": "subfinder"},
        "httpx": {"enabled": False, "path": "httpx"},
    },
    # Escáneres de web app
    "webcore": {
        "headers_audit": {"enabled": True},
        "cors_scan": {"enabled": True},
        "security_headers": {"enabled": True},
        "ssrf_detect": {"enabled": True},
    },
    # Flujos de trabajo
    "workflows": {
        "recon": {"enabled": True, "run_order": ["dns", "subdomains", "tech"]},
        "webapp": {"enabled": True, "run_order": ["headers", "cors", "ssrf", "params"]},
        "security_assessment": {"enabled": True, "run_order": ["vulns", "impact"]},
    },
    # Reporte
    "reporting": {
        "format": "markdown",
        "output_dir": "reports",
        "include_evidence": True,
        "auto_generate": False,
    },
    # IA / LLM
    "ai": {
        "use_llm_review": False,
        "model": "ollama",
        "provider": "ollama",
        "max_findings_review": 50,
    },
    # Historia persistente
    "history": {
        "enabled": True,
        "store_dir": "reports",
    },
    # Dispositivos/escaner
    "scanners": {
        "timeout": 30,
        "max_concurrent": 4,
        "rate_limit": 20,
    },
}


@dataclass
class Config:
    """Configuración de HunterBug."""
    data: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.data = {**DEFAULT_CONFIG, **self.data}

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split(".")
        val: Any = self.data
        for k in keys:
            if isinstance(val, dict):
                val = val.get(k, default)
            else:
                return default
        return val

    def set(self, key: str, value: Any) -> None:
        keys = key.split(".")
        d = self.data
        for k in keys[:-1]:
            d = d.setdefault(k, {})
        d[keys[-1]] = value

    def load(self, filepath: str) -> None:
        """Carga la configuración de un fichero JSON."""
        import json
        with open(filepath, encoding="utf-8") as f:
            self.data = {**DEFAULT_CONFIG, **json.load(f)}

    def save(self, filepath: str) -> None:
        """Guarda la configuración a un fichero JSON."""
        import json
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
