#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HunterBug 2.3.0 - AI-Powered Security Assessment Framework.

Package hierarchy:
- hunterbug/ : Core API y motor de evaluaci�n
- scanners/  : M�dulos de esc�neres (recon, webcore, workflow)
- plugins/   : Wrappers de plugins para integraci�n con el Engine
- tools/     : Herramientas de soporte y utilidades
"""

__version__ = "2.3.0"
__author__ = "HunterBug Team"
__description__ = "AI-powered security assessment framework"

from .hunterbug import *

__all__ = [
    "Context",
    "Finding",
    "Project",
    "Assessment",
    "Report",
    "EvidenceFile",
    "Config",
    "HunterBugEngine",
    "ScannerManager",
    "ReportGenerator",
    "ScannerImporter",
    "PluginManager",
    "HunterBugPlugin",
]
