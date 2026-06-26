from __future__ import annotations

from abc import ABC, abstractmethod
from ipaddress import ip_network

from .models import AclRule, Device, SecurityPolicy, Zone


class ConfigRenderer(ABC):
    @abstractmethod
    def render(self, device: Device, policy: SecurityPolicy) -> list[str]:
        raise NotImplementedError

    def _zone_pair_name(self, rule: AclRule) -> str:
        return f"{rule.src_zone}_TO_{rule.dst_zone}".upper().replace("-", "_")


class CiscoIOSRenderer(ConfigRenderer):
    def render(self, device: Device, policy: SecurityPolicy) -> list[str]:
        commands = [
            "configure terminal",
            "service password-encryption",
            "ip ssh version 2",
            "no ip http server",
            "no ip http secure-server",
            f"banner motd ^{policy.banner}^",
            "ip access-list standard MGMT_SOURCES",
        ]
        for source in policy.admin_sources:
            commands.append(f" permit {source}")
        commands.extend(
            [
                " deny any log",
                "line vty 0 15",
                " access-class MGMT_SOURCES in",
                " transport input ssh",
                " exec-timeout 10 0",
            ]
        )
        commands.extend(self._telemetry(policy))
        commands.extend(self._segmentation(device, policy))
        commands.append("end")
        commands.append("write memory")
        return commands

    def _telemetry(self, policy: SecurityPolicy) -> list[str]:
        commands: list[str] = [f"snmp-server contact {policy.snmp_contact}"]
        commands.extend(f"logging host {server}" for server in policy.syslog_servers)
        commands.extend(f"ntp server {server}" for server in policy.ntp_servers)
        return commands

    def _segmentation(self, device: Device, policy: SecurityPolicy) -> list[str]:
        commands: list[str] = []
        if device.kind == "switch":
            for zone in policy.zones:
                commands.extend([f"vlan {zone.vlan}", f" name {zone.name.upper()}"])
            for interface in device.interfaces:
                commands.append(f"interface {interface.name}")
                if interface.access and interface.vlan:
                    commands.extend(
                        [
                            " switchport mode access",
                            f" switchport access vlan {interface.vlan}",
                            " spanning-tree portfast",
                            " spanning-tree bpduguard enable",
                            " switchport port-security",
                            f" switchport port-security maximum {policy.max_mac_addresses}",
                            " switchport port-security violation restrict",
                        ]
                    )
                    if policy.access_port_shutdown:
                        commands.append(" shutdown")
                else:
                    commands.append(" description SDN managed uplink")
        else:
            commands.extend(self._acl_commands(policy))
            for zone in policy.zones:
                commands.extend(
                    [
                        f"interface GigabitEthernet0/0.{zone.vlan}",
                        f" description {zone.name} gateway",
                        f" encapsulation dot1Q {zone.vlan}",
                        f" ip access-group SDN_{zone.name.upper()}_IN in",
                    ]
                )
        return commands

    def _acl_commands(self, policy: SecurityPolicy) -> list[str]:
        commands: list[str] = []
        zones = policy.zone_map
        for zone in policy.zones:
            commands.append(f"ip access-list extended SDN_{zone.name.upper()}_IN")
            for rule in policy.acl_rules:
                if rule.src_zone != zone.name:
                    continue
                commands.append(self._format_acl_line(rule, zones[rule.src_zone], zones[rule.dst_zone]))
            commands.append(" deny ip any any log")
        return commands

    def _format_acl_line(self, rule: AclRule, source: Zone, destination: Zone) -> str:
        destination_port = f" eq {rule.dst_port}" if rule.dst_port else ""
        return (
            f" {rule.action} {rule.protocol} {self._ios_network(source.cidr)} "
            f"{self._ios_network(destination.cidr)}{destination_port}"
        )

    def _ios_network(self, cidr: str) -> str:
        network = ip_network(cidr, strict=False)
        wildcard_octets = [str(255 - octet) for octet in network.netmask.packed]
        return f"{network.network_address} {'.'.join(wildcard_octets)}"


class AristaEOSRenderer(CiscoIOSRenderer):
    def render(self, device: Device, policy: SecurityPolicy) -> list[str]:
        commands = super().render(device, policy)
        return ["enable"] + [cmd for cmd in commands if cmd != "write memory"] + ["copy running-config startup-config"]


class JuniperJunosRenderer(ConfigRenderer):
    def render(self, device: Device, policy: SecurityPolicy) -> list[str]:
        commands = [
            "configure",
            "set system services ssh protocol-version v2",
            "delete system services telnet",
            f"set system login message \"{policy.banner}\"",
            f"set snmp contact \"{policy.snmp_contact}\"",
        ]
        for source in policy.admin_sources:
            commands.append(f"set firewall family inet filter MGMT term allow-{source.replace('/', '-')} from source-address {source}")
            commands.append(f"set firewall family inet filter MGMT term allow-{source.replace('/', '-')} then accept")
        commands.append("set firewall family inet filter MGMT term default-deny then discard")
        commands.extend(f"set system syslog host {server} any info" for server in policy.syslog_servers)
        commands.extend(f"set system ntp server {server}" for server in policy.ntp_servers)
        commands.extend(self._segmentation(device, policy))
        commands.extend(["commit confirmed 5 comment \"SDN security baseline\"", "commit"])
        return commands

    def _segmentation(self, device: Device, policy: SecurityPolicy) -> list[str]:
        commands: list[str] = []
        if device.kind == "switch":
            for zone in policy.zones:
                commands.append(f"set vlans {zone.name} vlan-id {zone.vlan}")
            for interface in device.interfaces:
                if interface.access and interface.vlan:
                    commands.append(f"set interfaces {interface.name} unit 0 family ethernet-switching vlan members {interface.vlan}")
                    commands.append(f"set ethernet-switching-options secure-access-port interface {interface.name} mac-limit {policy.max_mac_addresses}")
        else:
            zones = policy.zone_map
            for rule in policy.acl_rules:
                prefix = f"set firewall family inet filter SDN-{rule.src_zone}"
                commands.append(f"{prefix} term {rule.name} from source-address {zones[rule.src_zone].normalized_network()}")
                commands.append(f"{prefix} term {rule.name} from destination-address {zones[rule.dst_zone].normalized_network()}")
                commands.append(f"{prefix} term {rule.name} from protocol {rule.protocol}")
                if rule.dst_port:
                    commands.append(f"{prefix} term {rule.name} from destination-port {rule.dst_port}")
                commands.append(f"{prefix} term {rule.name} then {'accept' if rule.action == 'permit' else 'discard'}")
        return commands


def renderer_for(vendor: str) -> ConfigRenderer:
    normalized = vendor.lower().replace("_", "-")
    if normalized in {"cisco-ios", "ios", "cisco"}:
        return CiscoIOSRenderer()
    if normalized in {"arista-eos", "eos", "arista"}:
        return AristaEOSRenderer()
    if normalized in {"juniper-junos", "junos", "juniper"}:
        return JuniperJunosRenderer()
    raise ValueError(f"Unsupported vendor: {vendor}")
