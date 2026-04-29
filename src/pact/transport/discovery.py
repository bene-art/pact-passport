"""mDNS discovery via zeroconf.

Service type: _pact._tcp.local.
TXT records: agent_id, caps (comma-separated), v (protocol version).
"""

from __future__ import annotations

import socket
import time

from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf

SERVICE_TYPE = "_pact._tcp.local."
PROTOCOL_VERSION = "1"


def _get_local_ip() -> str:
    """Get the machine's LAN IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def register_agent(
    zc: Zeroconf,
    name: str,
    agent_id: str,
    port: int,
    capabilities: list[str],
    host: str | None = None,
) -> ServiceInfo:
    """Register a PACT agent on the local network via mDNS."""
    ip = host or _get_local_ip()
    info = ServiceInfo(
        type_=SERVICE_TYPE,
        name=f"{name}.{SERVICE_TYPE}",
        addresses=[socket.inet_aton(ip)],
        port=port,
        properties={
            "agent_id": agent_id,
            "caps": ",".join(capabilities),
            "v": PROTOCOL_VERSION,
        },
    )
    zc.register_service(info)
    return info


def unregister_agent(zc: Zeroconf, info: ServiceInfo) -> None:
    """Unregister a PACT agent from mDNS."""
    zc.unregister_service(info)


class _PACTListener(ServiceListener):
    """Collects discovered PACT agents."""

    def __init__(self):
        self.agents: list[dict] = []
        self._zc: Zeroconf | None = None

    def set_zeroconf(self, zc: Zeroconf) -> None:
        self._zc = zc

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info and info.addresses:
            props = info.properties or {}
            self.agents.append({
                "name": name.split(".")[0],
                "agent_id": props.get(b"agent_id", b"").decode(),
                "capabilities": props.get(b"caps", b"").decode().split(","),
                "host": socket.inet_ntoa(info.addresses[0]),
                "port": info.port,
            })

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass


def discover_agents(timeout: float = 3.0) -> list[dict]:
    """Discover PACT agents on the local network.

    Returns a list of dicts with: name, agent_id, capabilities, host, port.
    """
    zc = Zeroconf()
    listener = _PACTListener()
    listener.set_zeroconf(zc)
    ServiceBrowser(zc, SERVICE_TYPE, listener)
    time.sleep(timeout)
    zc.close()
    return listener.agents


def resolve_agent(name_or_id: str, timeout: float = 3.0) -> dict | None:
    """Find a specific agent by name or agent_id prefix."""
    agents = discover_agents(timeout)
    for agent in agents:
        if agent["name"] == name_or_id:
            return agent
        if agent["agent_id"].startswith(name_or_id):
            return agent
    return None
