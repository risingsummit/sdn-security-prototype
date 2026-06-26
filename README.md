# SDN Security Automation Prototype

This prototype turns centralized security intent into device-specific switch and router configuration. It demonstrates the core SDN/network automation workflow: define policy once, render vendor-specific commands, apply through a controller layer, and audit for configuration drift.

## What It Automates

- Management-plane hardening: SSH only, VTY restrictions, login banner, encrypted passwords where supported.
- Segmentation: VLANs for switches and subinterface ACL attachment for routers.
- Zero-trust style ACL intent: policy rules between named zones rather than one-off device commands.
- Edge switch security: access VLANs, PortFast/BPDU guard, MAC limits, port-security violation handling.
- Telemetry: syslog, NTP, and SNMP contact configuration.
- Drift detection: compares intended command fingerprints with simulated applied device state.

## Project Layout

- `sdnsec/models.py`: inventory and policy data models.
- `sdnsec/renderers.py`: Cisco IOS, Arista EOS, and Juniper Junos command renderers.
- `sdnsec/controller.py`: SDN-style intent compiler, simulated apply, and audit logic.
- `sdnsec/cli.py`: command-line interface.
- `examples/`: sample campus topology and zero-trust policy.
- `tests/`: unit tests for planning, applying, and auditing.

## Quick Start

From this directory:

```powershell
python -m sdnsec.cli plan
python -m sdnsec.cli apply
python -m sdnsec.cli audit
python -m unittest discover -s tests
```

If `python` is not on your `PATH`, use any Python 3.10+ interpreter directly.

## Example Workflow

Render the security plan without touching devices:

```powershell
python -m sdnsec.cli --inventory examples/inventory.json --policy examples/security_policy.json plan
```

Apply to simulated device state:

```powershell
python -m sdnsec.cli apply
```

The simulated transport writes per-device state files under `state/`. In a production version, this boundary is where you would swap in Netmiko, NAPALM, pyATS, gNMI, RESTCONF, or vendor controller APIs.

Audit compliance:

```powershell
python -m sdnsec.cli audit
```

## Extending The Prototype

Good next upgrades:

- Add a real transport driver for lab devices.
- Add YAML support if PyYAML is available in your environment.
- Add role-based policies for data center, campus, branch, and cloud edge profiles.
- Export generated configs as change tickets or pull-request artifacts.
- Integrate with a CI pipeline so policy changes must pass render and audit tests before deployment.
