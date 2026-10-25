#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""core/hunterbug/engine.py - Motor principal de HunterBug."""

from __future__ import annotations

import os
import time
import uuid
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

from .config import Config
from .context import Context
from .models import Project, Assessment
from .scanner_manager import ScannerManager
from .plugin import PluginManager


class HunterBugEngine:
    """Motor principal de HunterBug.

    Orquesta la evaluación siguiendo flujos:
    - Reconocimiento (DNS, subdominios, tecnologías)
    - Ataque (web app, API, parámetros, CORS, SSRF)
    - Validación y análisis de impacto
    - Generación de reportes profesionales
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.ctx = None
        self.session_id = str(uuid.uuid4())
        self.plugins = PluginManager()
        self.scanner_mgr = None
        self.status: str = "idle"
        self.target: str = ""
        self.project: Optional[Project] = None
        self.run_once = threading.Event()

    # ---- API de configuración ----

    def load_config(self, filepath: str) -> None:
        """Carga la configuración desde un fichero JSON."""
        self.config.load(filepath)
        self.scanner_mgr = ScannerManager(self.config, self.ctx)

    def save_config(self, filepath: str) -> None:
        """Guarda la configuración a un fichero."""
        self.config.save(filepath)

    # ---- API de sesión ----

    def create_project(self, name: str, target: str, owner: str = "hunter", scope: Optional[Dict] = None) -> Project:
        """Crea un proyecto de evaluación."""
        self.project = Project(
            id=str(uuid.uuid4()),
            name=name,
            owner=owner,
            target=target,
            scope=scope or {},
        )
        return self.project

    def create_session(self, project: Project, profile: str = "full") -> Context:
        """Crea una sesión de evaluación."""
        self.ctx = Context(project.target, self, session_id=str(uuid.uuid4()))
        self.ctx.phase = "recon"
        self.ctx.set("project", project)
        self.ctx.set("profile", profile)
        self.ctx.set("engine", self)
        self.ctx.set("manager", self.scanner_mgr)
        self.ctx.set("session_id", self.session_id)
        return self.ctx

    # ---- API de ejecución ----

    def run_profile(self, profile: str, target: str, config_file: Optional[str] = None) -> Context:
        """Ejecuta un perfil de evaluación completo."""
        if config_file:
            self.load_config(config_file)
        self.status = "running"
        project = self.create_project(
            name=profile,
            target=target,
            owner="hunter",
        )
        ctx = self.create_session(project, profile=profile)
        self.ctx = ctx
        # Iniciar motor
        self._run_profile(profile, target)
        # Finalizar
        ctx.status = "completed"
        ctx.set("completed_at", datetime.utcnow().isoformat() + "Z")
        self.status = "completed"
        return ctx

    def _run_profile(self, profile: str, target: str) -> None:
        """Ejecuta un perfil de evaluación."""
        profile_map = {
            "recon": ["dns", "subdomains", "tech"],
            "webapp": ["headers", "cors", "ssrf", "params"],
            "security_assessment": ["vulns", "impact"],
            "full": ["dns", "subdomains", "tech", "headers", "cors", "ssrf", "params", "vulns", "impact"],
        }
        modules = profile_map.get(profile, [])
        if not modules:
            modules = ["dns", "subdomains", "tech", "headers", "cors", "ssrf", "params", "vulns", "impact"]
        # Ejecutar cada módulo
        for i, module in enumerate(modules):
            self.run_single(module, target)
            if self.ctx.status != "running":
                break

    def run_single(self, module: str, target: str) -> None:
        """Ejecuta un módulo de evaluación."""
        self.ctx.set("current_module", module)
        self.ctx.set("phase", "recon" if module in ("dns", "subdomains", "tech") else "attack")

        # Si hay plugin para este módulo, ejecutarlo
        plugin = self.plugins.get(module)
        if plugin:
            try:
                result = plugin.run(self.ctx)
                if result and isinstance(result, dict):
                    findings = result.get("findings", [])
                    for f in findings:
                        self.ctx.finding(f)
            except Exception as e:
                self.ctx.error(f"Módulo {module}: {e}")
            return

        # Si no hay plugin, ejecutar escáner base
        if self.scanner_mgr:
            result = self.scanner_mgr.scan(module, target)
            self.ctx.append("scan_stats", {"module": module, "result": result})

        self.ctx.log("info", f"Módulo {module} completado")
