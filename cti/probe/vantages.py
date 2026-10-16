"""Where observations are made from.

Every span and snapshot records its vantage, and `vantage:<name>` is a hunt
term, so "what did a Windows client see" is a question the store can answer.
This registry is what the pipeline asks about them: which exist, which are
configured on this host, and what each can do.

  probe   the Linux probe VM (vm_proxy): httpx, tlsx, dnsx, naabu, nmap,
          nuclei, zgrab2, JARM, dirsearch, subfinder, Wayback. Scanner view.
  win116  the Windows client VM (win_proxy): .NET/Schannel GET with an Edge
          User-Agent. Client view - what a victim's machine is served.
  zeek    passive: the lab sensor's view of sessions either of the above
          opened (JA4S, JA4TS, JA4X), read back from the SIEM. Not a target
          of requests; recorded so its spans can be told apart.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import vm_proxy, win_proxy


@dataclass(frozen=True)
class Vantage:
    name: str
    kind: str                     # "scanner" | "client" | "passive"
    description: str
    actions: tuple[str, ...]
    configured: Callable[[], bool]


VANTAGES: dict[str, Vantage] = {v.name: v for v in (
    Vantage("probe", "scanner",
            "Linux probe VM - full-stack scanning and passive lookups",
            ("observe", "netwatch", "jarm", "nmap", "dirsearch", "subfinder", "wayback"),
            lambda: bool(vm_proxy.PROBE_HOST)),
    Vantage(win_proxy.VANTAGE, "client",
            "Windows 11 client VM - what a Windows machine is served (Schannel, Edge UA)",
            ("fetch",),
            win_proxy.configured),
    Vantage("zeek", "passive",
            "Lab sensor - passive fingerprints of sessions the other vantages opened",
            (), lambda: True),
)}


def available() -> list[str]:
    return [name for name, v in VANTAGES.items() if v.configured()]
