#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HunterBug 2.3.0 - AI-Powered Findings Analysis & Impact Assessment.

Framework de evaluaci�n de seguridad para:
- Reconocimiento avanzado y descubrimiento de activos
- Enumeraci�n de subdominios y an�lisis DNS
- Pest�a de bug bounty y flujos de pentesting
- Pruebas de seguridad de aplicaciones web y API
- Identificaci�n y validaci�n de vulnerabilidades
- Firma tecnol�gica y descubrimiento de superficie de ataque
- Flujos de evaluaci�n de seguridad automatizados
- Integraci�n de esc�neres externos y importaci�n de resultados
- Generaci�n de reportes profesionales
- Proyectos persistentes y historial de evaluaciones
- Investigaci�n de seguridad y pruebas con LLM
- Colecci�n de evidencias y organizaci�n de hallazgos
- Flujos de seguridad ofensivos optimizados
- Construido para pruebas de seguridad autorizadas
"""

__version__ = "2.3.0"
__author__ = "HunterBug Team"
__description__ = "AI-powered security assessment framework"

from .context import Context, Finding
from .models import Project, Assessment, Report, EvidenceFile
from .config import Config
from .engine import HunterBugEngine
from .scanner_manager import ScannerManager
from .reports import ReportGenerator
from .importers import ScannerImporter
from .plugin import PluginManager, HunterBugPlugin

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
