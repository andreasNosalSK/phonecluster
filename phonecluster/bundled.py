"""Locate scripts in a checkout or an installed PhoneCluster wheel."""

from __future__ import annotations

import importlib.metadata
from pathlib import Path


def bundled_script(name: str) -> Path | None:
    checkout = Path(__file__).resolve().parent.parent / "scripts" / name
    if checkout.is_file():
        return checkout

    target = ("share", "phonecluster", "scripts", name)
    try:
        installed = importlib.metadata.files("phonecluster") or ()
    except importlib.metadata.PackageNotFoundError:
        return None
    for entry in installed:
        if entry.parts[-len(target):] == target:
            path = Path(entry.locate())
            if path.is_file():
                return path
    return None
