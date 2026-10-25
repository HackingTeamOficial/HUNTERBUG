#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""core/hunterbug/models.py - Modelos de datos del framework HunterBug."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .context import Finding


@dataclass
class ScannerResult:
    """Resultado de un escáner externo o módulo de偵."""
    scanner: str
    target: str
    data: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)
    status: str = "ok"
    error: Optional[str] = None
    scanned_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


@dataclass
class Project:
    """Proyecto de evaluación persistente."""
    id: str
    name: str
    owner: str
    target: str
    scope: Dict[str, Any] = field(default_factory=dict)
    settings: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    status: str = "active"


@dataclass
class Assessment:
    """Evaluación persistente dentro de un proyecto."""
    id: str
    project_id: str
    profile: str
    target: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    status: str = "completed"
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    completed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    report: Optional[str] = None


@dataclass
class Report:
    """Reporte generado para una evaluación."""
    id: str
    assessment_id: str
    format: str
    path: str
    title: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


@dataclass
class EvidenceFile:
    """Evidencia de captura (respuestas HTTP, peticiones, screenshots)."""
    id: str
    name: str
    content: bytes
    mimetype: str
    md5: str
    sha256: str
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
