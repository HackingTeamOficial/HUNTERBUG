#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plugins/workflow_impact.py - Plugin de evaluaci�n de impacto (HunterBug)."""

from core.hunterbug.scanners.workflow.impact import ImpactAssessment
from core.hunterbug import Context


def run(ctx: Context):
    """Ejecuta la evaluaci�n de impacto."""
    impact = ImpactAssessment(ctx)
    result = impact.run()
    summary = result.get("impact_summary", {})
    ctx.log("info", f"Impacto: {summary.get('total')} hallazgos "
                     f"({summary.get('high')} high, {summary.get('medium')} medium)")
    return {"findings": []}
