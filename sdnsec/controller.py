from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .models import Device, SecurityPolicy
from .renderers import renderer_for


@dataclass(frozen=True)
class DevicePlan:
    device: Device
    commands: tuple[str, ...]

    @property
    def fingerprint(self) -> str:
        joined = "\n".join(self.commands).encode("utf-8")
        return hashlib.sha256(joined).hexdigest()[:16]


class SDNSecurityController:
    """Central intent compiler for security policy across mixed network devices."""

    def __init__(self, devices: tuple[Device, ...], policy: SecurityPolicy):
        self.devices = devices
        self.policy = policy

    def build_plan(self) -> tuple[DevicePlan, ...]:
        plans: list[DevicePlan] = []
        for device in self.devices:
            commands = renderer_for(device.vendor).render(device, self.policy)
            plans.append(DevicePlan(device=device, commands=tuple(commands)))
        return tuple(plans)

    def apply(self, state_dir: str | Path) -> tuple[DevicePlan, ...]:
        state_path = Path(state_dir)
        state_path.mkdir(parents=True, exist_ok=True)
        plans = self.build_plan()
        for plan in plans:
            device_state = {
                "device": plan.device.name,
                "vendor": plan.device.vendor,
                "management_ip": plan.device.management_ip,
                "policy": self.policy.name,
                "fingerprint": plan.fingerprint,
                "applied_at": datetime.now(timezone.utc).isoformat(),
                "commands": list(plan.commands),
            }
            with (state_path / f"{plan.device.name}.json").open("w", encoding="utf-8") as handle:
                json.dump(device_state, handle, indent=2)
        return plans

    def audit(self, state_dir: str | Path) -> list[dict[str, str]]:
        state_path = Path(state_dir)
        findings: list[dict[str, str]] = []
        for plan in self.build_plan():
            target = state_path / f"{plan.device.name}.json"
            if not target.exists():
                findings.append(
                    {
                        "device": plan.device.name,
                        "status": "missing",
                        "detail": "No applied state exists for this device.",
                    }
                )
                continue
            with target.open("r", encoding="utf-8") as handle:
                state = json.load(handle)
            if state.get("fingerprint") != plan.fingerprint:
                findings.append(
                    {
                        "device": plan.device.name,
                        "status": "drift",
                        "detail": f"Expected {plan.fingerprint}, found {state.get('fingerprint', 'unknown')}.",
                    }
                )
            else:
                findings.append(
                    {
                        "device": plan.device.name,
                        "status": "compliant",
                        "detail": f"Policy {self.policy.name} is applied.",
                    }
                )
        return findings
