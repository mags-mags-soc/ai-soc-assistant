"""Streamlit dashboard for the AI SOC Assistant.

The dashboard is a presentation layer only. It consumes the existing backend
package (``soc``) and never re-implements domain logic such as severity
mapping, MITRE extraction or alert parsing.

Importing this package puts ``backend/src`` on ``sys.path`` so that ``soc``
resolves both when Streamlit runs ``dashboard/app.py`` and when pytest runs
from the repository root.
"""

from __future__ import annotations

from .bootstrap import ensure_backend_on_path

ensure_backend_on_path()

__all__ = ["ensure_backend_on_path"]
__version__ = "0.4.0"
