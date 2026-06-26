from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_network
from typing import Any


@dataclass(frozen=True)
class Interface:
    name: str
    role: str
    zone: str | None = None
    vlan: int | None = None
    access: bool = False


@dataclass(frozen=True)
class Device:
    name: str
    kind: str
    vendor: str
    management_ip: str
    site: str
    interfaces: tuple[Interface, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Zone:
    name: str
    vlan: int
    cidr: str
    description: str = ""

    def normalized_network(self) -> str:
        return str(ip_network(self.cidr, strict=False))


@dataclass(frozen=True)
class AclRule:
    name: str
    action: str
    src_zone: str
    dst_zone: str
    protocol: str = "ip"
    dst_port: str | None = None
    reason: str = ""


@dataclass(frozen=True)
class SecurityPolicy:
    name: str
    zones: tuple[Zone, ...]
    acl_rules: tuple[AclRule, ...]
    admin_sources: tuple[str, ...]
    syslog_servers: tuple[str, ...]
    ntp_servers: tuple[str, ...]
    snmp_contact: str
    banner: str
    access_port_shutdown: bool = True
    max_mac_addresses: int = 2

    @property
    def zone_map(self) -> dict[str, Zone]:
        return {zone.name: zone for zone in self.zones}


def _require(data: dict[str, Any], key: str) -> Any:
    if key not in data:
        raise ValueError(f"Missing required key: {key}")
    return data[key]


def load_inventory(data: dict[str, Any]) -> tuple[Device, ...]:
    devices: list[Device] = []
    for raw_device in _require(data, "devices"):
        interfaces = tuple(
            Interface(
                name=_require(raw_interface, "name"),
                role=_require(raw_interface, "role"),
                zone=raw_interface.get("zone"),
                vlan=raw_interface.get("vlan"),
                access=bool(raw_interface.get("access", False)),
            )
            for raw_interface in raw_device.get("interfaces", [])
        )
        devices.append(
            Device(
                name=_require(raw_device, "name"),
                kind=_require(raw_device, "kind"),
                vendor=_require(raw_device, "vendor"),
                management_ip=_require(raw_device, "management_ip"),
                site=_require(raw_device, "site"),
                interfaces=interfaces,
            )
        )
    return tuple(devices)


def load_policy(data: dict[str, Any]) -> SecurityPolicy:
    zones = tuple(
        Zone(
            name=_require(raw_zone, "name"),
            vlan=int(_require(raw_zone, "vlan")),
            cidr=_require(raw_zone, "cidr"),
            description=raw_zone.get("description", ""),
        )
        for raw_zone in _require(data, "zones")
    )
    acl_rules = tuple(
        AclRule(
            name=_require(raw_rule, "name"),
            action=_require(raw_rule, "action"),
            src_zone=_require(raw_rule, "src_zone"),
            dst_zone=_require(raw_rule, "dst_zone"),
            protocol=raw_rule.get("protocol", "ip"),
            dst_port=raw_rule.get("dst_port"),
            reason=raw_rule.get("reason", ""),
        )
        for raw_rule in _require(data, "acl_rules")
    )
    return SecurityPolicy(
        name=_require(data, "name"),
        zones=zones,
        acl_rules=acl_rules,
        admin_sources=tuple(_require(data, "admin_sources")),
        syslog_servers=tuple(data.get("syslog_servers", [])),
        ntp_servers=tuple(data.get("ntp_servers", [])),
        snmp_contact=data.get("snmp_contact", "network-security"),
        banner=data.get("banner", "Authorized access only."),
        access_port_shutdown=bool(data.get("access_port_shutdown", True)),
        max_mac_addresses=int(data.get("max_mac_addresses", 2)),
    )


def validate_policy(policy: SecurityPolicy) -> None:
    zone_names = set(policy.zone_map)
    for rule in policy.acl_rules:
        if rule.action not in {"permit", "deny"}:
            raise ValueError(f"Rule {rule.name} has unsupported action {rule.action!r}")
        if rule.src_zone not in zone_names:
            raise ValueError(f"Rule {rule.name} references unknown source zone {rule.src_zone!r}")
        if rule.dst_zone not in zone_names:
            raise ValueError(f"Rule {rule.name} references unknown destination zone {rule.dst_zone!r}")
