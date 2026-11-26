"""Locate scripts in a checkout or an installed PhoneCluster wheel."""

from __future__ import annotations

import importlib.metadata
import os
import re
import stat
from pathlib import Path

_SCRIPT_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _is_trusted_script_file(path: Path, allowed_dir: Path | None = None) -> bool:
    try:
        if path.is_symlink():
            return False
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode):
            return False
        if os.name != "nt" and (st.st_mode & 0o002):
            return False
        if allowed_dir is not None and path.resolve().parent != allowed_dir.resolve():
            return False
        return True
    except OSError:
        return False


def bundled_script(name: str) -> Path | None:
    if not isinstance(name, str) or name in {".", ".."} or not _SCRIPT_NAME_RE.fullmatch(name):
        return None

    repo_root = Path(__file__).resolve().parent.parent
    if (repo_root / "pyproject.toml").is_file() or (repo_root / "phonecluster_cli.py").is_file():
        scripts_dir = repo_root / "scripts"
        checkout = scripts_dir / name
        if _is_trusted_script_file(checkout, scripts_dir):
            return checkout

    target = ("share", "phonecluster", "scripts", name)
    try:
        installed = importlib.metadata.files("phonecluster") or ()
    except importlib.metadata.PackageNotFoundError:
        return None
    for entry in installed:
        if entry.parts[-len(target):] == target:
            path = Path(entry.locate())
            if _is_trusted_script_file(path):
                return path
    return None
