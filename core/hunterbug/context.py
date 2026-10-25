#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""core/hunterbug/context.py - Contexto de evaluación compartido.

Sigue el estilo del Context de HT Forge:
- un Contexto por sesión de evaluación
- almacenamiento O(1) por clave (dict)
- expone req() para peticiones HTTP, finding() para hallazgos,
  log() para trazas, set()/get() para estado
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    """Modelo de hallazgo de seguridad (v1)."""
    type: str
    title: str
    detail: str = ""
    severity: str = "info"
    confidence: str = "medium"
    url: Optional[str] = None
    parameter: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    requires_human_review: bool = False
    module: str = ""
    phase: str = "recon"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    raw: Dict[str, Any] = field(default_factory=dict)


class Context:
    """Contexto de evaluación compartido.

    Los módulos de evaluación mutuamente comparten:
    - descubrimientos (URLs, endpoints, parámetros)
    - hallazgos acumulados y evidencias
    - activos, tecnologías, entorno de hosteación
    - assets de reconocimiento (subdominios, DNS, technology stack)
    """

    def __init__(self, target: str, engine: Any, session_id: Optional[str] = None):
        self.target = target
        self.session_id = session_id or str(uuid.uuid4())
        self.engine = engine
        self.phase: str = "recon"
        self.requester: Any = None

        # Almacenamiento O(1) compartido por módulos
        self._store: Dict[str, Any] = {
            "discovered_urls": [],
            "discovered_params": [],
            "technologies": [],
            "findings": [],
            "evidence": [],
            "assets": [],
            "subdomains": [],
            "dns_records": [],
            "scan_stats": {},
            "reports": [],
            "meta": {},
        }

        # Estado de ejecución
        self.status: str = "running"
        self.errors: List[str] = []
        self.started_at: str = datetime.utcnow().isoformat() + "Z"
        self._lock = threading.RLock()

        # Reportes del contexto actual (buffer por módulo)
        self._report: Dict[str, Any] = {"findings": []}
        self._report_meta: Dict[str, Any] = {"module": "unknown"}

        # Eventos de API (para UI/CLI)
        self.on_finding: Any = None
        self.on_log: Any = None
        self.on_progress: Any = None
        self.on_error: Any = None

    # ---- API de acceso al almacenamiento compartido ----

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._store.get(key, default)

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._store[key] = value

    def append(self, key: str, value: Any) -> None:
        with self._lock:
            if key not in self._store:
                self._store[key] = []
            if isinstance(self._store[key], list):
                self._store[key].append(value)

    def get_report(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._report)

    def set_report(self, report: Dict[str, Any]) -> None:
        with self._lock:
            self._report = report

    # ---- API de hallazgos ----

    def finding(self, finding: Dict[str, Any]) -> None:
        """Añade un hallazgo al contexto."""
        with self._lock:
            if not isinstance(finding, dict):
                return
            # Normalizar
            finding.setdefault("type", "unknown")
            finding.setdefault("severity", "info")
            finding.setdefault("confidence", "medium")
            finding.setdefault("module", self._report_meta.get("module", "unknown"))
            finding.setdefault("phase", self.phase)
            finding.setdefault("created_at", datetime.utcnow().isoformat() + "Z")
            finding.setdefault("raw", {})

            # Añadir a hallazgos
            self._store["findings"].append(finding)

            # Si hay on_finding registrado, disparar
            if self.on_finding:
                try:
                    self.on_finding(finding)
                except Exception:
                    pass

            # También añadir a report
            self._report.setdefault("findings", []).append(finding)

    # ---- API de trazas ----

    def log(self, level: str, msg: str) -> None:
        """Trazas del contexto."""
        if self.on_log:
            try:
                self.on_log({"level": level, "msg": msg, "session": self.session_id})
            except Exception:
                pass
        print(f"[{level.upper()}] {msg}")

    def error(self, msg: str) -> None:
        """Error del contexto."""
        self.errors.append(msg)
        self.log("error", msg)
        if self.on_error:
            self.on_error(msg)

    def progress(self, current: int, total: int, phase: str = "unknown") -> None:
        """Progreso del contexto."""
        if self.on_progress:
            try:
                self.on_progress({"current": current, "total": total, "phase": phase})
            except Exception:
                pass

    # ---- API de peticiones HTTP ----

    def req(self, method: str, url: str, **kwargs) -> Any:
        """Ejecuta petición HTTP con el cliente del motor."""
        if self.requester is None:
            return None
        try:
            return self.requester.request(method, url, **kwargs)
        except Exception as e:
            self.log("debug", f"req error {method} {url}: {e}")
            return None

    # ---- API de estado ----

    def stop(self) -> None:
        self.status = "stopped"

    def resume(self) -> None:
        self.status = "running"

    def __str__(self):
        return f"Context(session={self.session_id}, target={self.target}, phase={self.phase})"
