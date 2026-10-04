"""osint_app package."""
import os as _os
import sys as _sys


def _expose_interpreter_scripts() -> None:
    """Añade al PATH la carpeta de programas del Python que ejecuta SENTINEL (env\\Scripts o env/bin).

    Sherlock, Holehe, Maigret… se instalan con pip en esa carpeta. Si SENTINEL se abría sin activar el entorno
    virtual (doble clic, acceso directo, `env\\Scripts\\python.exe -m osint_app.main`), esos programas aparecían como
    "no instalados" aunque lo estuvieran (verificado 2026-10-04).
    """
    scripts = _os.path.dirname(_os.path.abspath(_sys.executable))
    entries = _os.environ.get("PATH", "").split(_os.pathsep)
    if _os.path.isdir(scripts) and not any(_os.path.normcase(e) == _os.path.normcase(scripts) for e in entries if e):
        _os.environ["PATH"] = scripts + _os.pathsep + _os.environ.get("PATH", "")


_expose_interpreter_scripts()

from .framework import OSINTFramework  # noqa: E402
from .core import QueryParameters, SearchResult  # noqa: E402

__all__ = ["OSINTFramework", "QueryParameters", "SearchResult"]
