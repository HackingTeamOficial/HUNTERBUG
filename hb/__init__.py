"""HunterBug 1.2 — Bug Hunter Edition.

Motor de evaluacion de seguridad para pruebas autorizadas.
"""

__version__ = "1.2"
__all__ = ["net", "vulns", "cve", "graph", "ai", "events", "checks",
           "metrics", "x509lite", "catalogo_a", "catalogo_b",
           # motores dedicados de 1.1
           "sqli", "xss", "authz", "validacion", "recon11", "bounty",
           "open_redirect", "traversal", "jwt", "recon_ajax",
           "integration",
           "informe", "informe_intercambio", "pdfmin", "ui_widgets"]

# Importar los catalogos registra sus chequeos en hb.checks.CATALOGO.
from . import net, vulns, cve, graph, ai, events, checks, metrics, x509lite  # noqa: F401,E402
from . import catalogo_a, catalogo_b  # noqa: F401,E402
# Motores dedicados de 1.1 (no registran chequeos en el catalogo).
from . import sqli, xss, authz, validacion, recon11, bounty  # noqa: F401,E402
from . import open_redirect, traversal, jwt, recon_ajax, integration  # noqa: F401,E402
from . import informe, informe_intercambio, pdfmin, ui_widgets  # noqa: F401,E402
