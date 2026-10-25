"""HunterBug 1.0 - motor de evaluacion de seguridad para pruebas autorizadas."""

__version__ = "1.0"
__all__ = ["net", "vulns", "cve", "graph", "ai", "events", "checks",
           "metrics", "x509lite", "catalogo_a", "catalogo_b"]

# Importar los catalogos registra sus chequeos en hb.checks.CATALOGO.
from . import net, vulns, cve, graph, ai, events, checks, metrics, x509lite  # noqa: F401,E402
from . import catalogo_a, catalogo_b  # noqa: F401,E402
