#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""core/hunterbug/scanner_manager.py - Orquestación de escáneres."""

from __future__ import annotations

import os
import subprocess
import time
from typing import Any, Dict, List, Optional

from .context import Context
from .config import Config


class ScannerManager:
    """Gestor de escáneres de HunterBug.

    Ejecuta escáneres externos e integra resultados mediante el contexto.
    """

    def __init__(self, config: Config, ctx: Context):
        self.config = config
        self.ctx = ctx
        self._processes: Dict[str, subprocess.Popen] = {}

    def _which(self, name: str, path: str = "") -> Optional[str]:
        """Busca el binario del escáner en PATH o ruta específica."""
        candidates = []
        if path:
            candidates.append(path)
        if os.name == "nt":
            for ext in (".exe", ""):
                candidates.append(f"{name}{ext}")
        else:
            candidates.append(name)

        candidates = list(dict.fromkeys(candidates))

        for c in candidates:
            exe = c
            if os.name == "nt":
                exe = c
                if not exe.endswith(".exe"):
                    exe += ".exe"
            if os.path.exists(exe) and os.access(exe, os.X_OK):
                return exe
            if os.path.exists(c):
                return c
        return None

    def run(self, scanner: str, target: str, **kwargs) -> Dict[str, Any]:
        """Ejecuta un escáner y devuelve resultados parseados."""
        config_scan = self.config.get(f"integrations.{scanner}", {})
        scanner_path = self._which(scanner, config_scan.get("path", ""))
        if not scanner_path:
            return {"status": "error", "error": f"Scanner {scanner} not found"}

        self.ctx.log("info", f"Iniciando escáner {scanner} sobre {target}")
        cmd = [scanner_path, target]
        # Añadir flags comunes
        if scanner == "subfinder":
            cmd.append("-silent")
        elif scanner == "httpx":
            cmd.append("-silent")
        elif scanner == "amass":
            cmd.append("enum")
            cmd.append("-active")

        self.ctx.log("debug", f"CMD: {' '.join(cmd)}")
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120, check=False
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            self.ctx.log("debug", f"stdout: {stdout[:500]}")
            self.ctx.log("debug", f"stderr: {stderr[:200]}")
            return {
                "status": "ok" if proc.returncode == 0 else "warn",
                "exit_code": proc.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "scanner": scanner,
            }
        except subprocess.TimeoutExpired as e:
            return {"status": "timeout", "error": str(e), "scanner": scanner}
        except Exception as e:
            return {"status": "error", "error": str(e), "scanner": scanner}

    def scan(self, scanner: str, target: str, **kwargs) -> Dict[str, Any]:
        """Ejecuta un escáner y parsea los resultados."""
        result = self.run(scanner, target, **kwargs)
        # Normalizar los resultados
        if result.get("status") == "ok":
            stdout = result.get("stdout", "") or ""
            # Guardar en contexto
            self.ctx.append(
                "scan_stats", {"scanner": scanner, "exit_code": result.get("exit_code"), "output": stdout}
            )
        return result
