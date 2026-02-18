import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple


def _norm_hostname(hostname: Optional[str]) -> Optional[str]:
    if not hostname:
        return None
    h = hostname.strip().lower()
    # Por si llega con punto final (FQDN con trailing dot)
    if h.endswith("."):
        h = h[:-1]
    return h or None


@dataclass(frozen=True)
class RoutesIndex:
    version: int
    default_router: str
    ip_to_router: Dict[str, str]
    host_to_router: Dict[str, str]


def load_routes(routes_path: str) -> RoutesIndex:
    path = Path(routes_path)
    data = json.loads(path.read_text(encoding="utf-8"))

    version = int(data.get("version", 1))
    default_router = data.get("default_router", "raw")

    ip_to_router: Dict[str, str] = {}
    host_to_router: Dict[str, str] = {}

    for r in data.get("routers", []):
        name = r["name"]

        for ip in r.get("ip_addresses", []) or []:
            ip_to_router[str(ip).strip()] = name

        for hn in r.get("hostnames", []) or []:
            nh = _norm_hostname(str(hn))
            if nh:
                host_to_router[nh] = name

    return RoutesIndex(
        version=version,
        default_router=default_router,
        ip_to_router=ip_to_router,
        host_to_router=host_to_router,
    )


def resolve_router(index: RoutesIndex, source_ip: str, hostname: Optional[str]) -> Tuple[str, str]:
    """
    Regresa (router_name, match_reason)
    match_reason: ip | hostname | default
    """
    if source_ip in index.ip_to_router:
        return index.ip_to_router[source_ip], "ip"

    nh = _norm_hostname(hostname)
    if nh and nh in index.host_to_router:
        return index.host_to_router[nh], "hostname"

    return index.default_router, "default"
