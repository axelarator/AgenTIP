"""Replace a function everywhere in the cluster code.

The code is split across cti/clusters/*.py and each module imports the names
it calls, so one function lives in several namespaces: where it is defined,
each module that imports it, and the cti.core view. Patching one of them
leaves the others calling the real thing, and a test then passes or fails
for the wrong reason. `patch_clusters` patches every namespace that holds
the name.

    patch_clusters(monkeypatch, "_sweep_lifecycle", lambda domains, ips: {})
"""
from __future__ import annotations

import importlib
import pkgutil

import cti.clusters
from cti import core


def _modules():
    return [core] + [importlib.import_module(f"cti.clusters.{m.name}")
                     for m in pkgutil.iter_modules(cti.clusters.__path__)]


def patch_clusters(monkeypatch, name: str, value) -> None:
    holders = [m for m in _modules() if hasattr(m, name)]
    assert holders, f"no cluster module has {name!r}"
    for module in holders:
        monkeypatch.setattr(module, name, value)
