"""Make the backend ``soc`` package importable from the dashboard process.

The backend lives in ``backend/src`` and is imported by pytest through the
``pythonpath`` setting in ``pytest.ini``. Streamlit has no equivalent setting,
so the path is resolved explicitly here. This module has no third-party
dependencies and must stay import-cheap.
"""

from __future__ import annotations

import sys
from pathlib import Path

#: Repository root, i.e. the directory that contains ``backend/`` and ``dashboard/``.
PROJECT_ROOT: Path = Path(__file__).resolve().parents[1]

#: Directory holding the importable backend source tree.
BACKEND_SRC: Path = PROJECT_ROOT / "backend" / "src"


class BackendNotFoundError(RuntimeError):
    """Raised when the backend source tree cannot be located."""


def ensure_backend_on_path() -> Path:
    """Insert ``backend/src`` at the front of ``sys.path``.

    Returns:
        The resolved backend source directory.

    Raises:
        BackendNotFoundError: If ``backend/src/soc`` does not exist.
    """
    if not (BACKEND_SRC / "soc").is_dir():
        raise BackendNotFoundError(
            f"Backend package not found at {BACKEND_SRC / 'soc'}. "
            "Run the dashboard from the repository root."
        )

    resolved = str(BACKEND_SRC)
    if resolved not in sys.path:
        sys.path.insert(0, resolved)
    return BACKEND_SRC
