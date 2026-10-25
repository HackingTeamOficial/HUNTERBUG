#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""core/hunterbug/plugin.py - Sistema de plugins de HunterBug."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable

# Directorio por defecto de plugins
DEFAULT_PLUGINS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "plugins")


from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Callable


@dataclass
class HunterBugPlugin:
    """Plugin de HunterBug."""
    name: str
    module: Any
    run_func: Callable
    metadata: Dict = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {
                'name': self.name,
                'version': getattr(self.module, '__version__', '1.0.0'),
                'description': getattr(self.module, '__doc__', ''),
                'author': getattr(self.module, '__author__', 'HT Forge Team'),
                'phase': getattr(self.module, 'PHASE', 'attack'),
                'requires': getattr(self.module, 'REQUIRES', []),
            }


class PluginManager:
    """Gestor de plugins de HunterBug.

    Carga plugins desde el directorio plugins/ o registrados manualmente.
    """

    def __init__(self, plugins_dir: Optional[str] = None):
        self.plugins: Dict[str, HunterBugPlugin] = {}
        self.plugins_dir = plugins_dir or os.path.abspath(DEFAULT_PLUGINS_DIR)
        self._load_all()

    def _load_all(self) -> None:
        """Carga todos los plugins del directorio."""
        plugins_path = Path(self.plugins_dir).resolve()
        if not plugins_path.exists():
            return

        # Inicializar paquete plugins si existe
        init_file = plugins_path / "__init__.py"
        if init_file.exists():
            try:
                spec = importlib.util.spec_from_file_location(
                    "plugins", init_file, submodule_search_locations=[str(plugins_path)]
                )
                pkg = importlib.util.module_from_spec(spec)
                sys.modules["plugins"] = pkg
                spec.loader.exec_module(pkg)
            except Exception as e:
                print(f"[WARN] plugins package init: {e}")

        for py_file in plugins_path.glob("*.py"):
            if py_file.name.startswith("_") or py_file.name == "__init__.py":
                continue
            self._load_plugin(py_file)

    def _load_plugin(self, py_file: Path) -> None:
        """Carga un plugin individual."""
        name = py_file.stem
        try:
            module_name = f"_hunterbug_plugin_{name}"
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            # Buscar función run
            run_func = getattr(module, "run", None) or getattr(module, "main", None)
            if not run_func:
                return

            plugin = HunterBugPlugin(name=name, module=module, run_func=run_func)
            self.plugins[name] = plugin
        except Exception as e:
            print(f"[WARN] No se pudo cargar plugin {name}: {e}")

    def register(self, name: str, run_func: Callable, metadata: Optional[Dict] = None) -> None:
        """Registra un plugin manualmente."""
        class DummyModule:
            pass
        module = DummyModule()
        if metadata:
            for k, v in metadata.items():
                setattr(module, k, v)

        plugin = HunterBugPlugin(
            name=name, module=module, run_func=run_func, metadata=metadata or {}
        )
        self.plugins[name] = plugin

    def get(self, name: str) -> Optional[HunterBugPlugin]:
        return self.plugins.get(name)

    def get_available(self) -> List[str]:
        return list(self.plugins.keys())

    def list_plugins(self) -> Dict[str, Dict]:
        """Lista todos los plugins con metadatos."""
        return {name: p.metadata for name, p in self.plugins.items()}

    def run(self, name: str, ctx: Any) -> Any:
        """Ejecuta un plugin por nombre."""
        plugin = self.get(name)
        if plugin:
            return plugin.run_func(ctx)
        return None
