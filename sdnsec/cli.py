from __future__ import annotations

import argparse
from pathlib import Path

from .config import load_inventory_file, load_policy_file
from .controller import DevicePlan, SDNSecurityController


def _controller(args: argparse.Namespace) -> SDNSecurityController:
    devices = load_inventory_file(args.inventory)
    policy = load_policy_file(args.policy)
    return SDNSecurityController(devices=devices, policy=policy)


def _print_plan(plans: tuple[DevicePlan, ...]) -> None:
    for plan in plans:
        print(f"\n# {plan.device.name} ({plan.device.vendor}, {plan.device.management_ip})")
        print(f"# fingerprint: {plan.fingerprint}")
        for command in plan.commands:
            print(command)


def plan(args: argparse.Namespace) -> int:
    _print_plan(_controller(args).build_plan())
    return 0


def apply(args: argparse.Namespace) -> int:
    plans = _controller(args).apply(args.state_dir)
    for plan in plans:
        print(f"applied {plan.device.name}: {len(plan.commands)} commands, fingerprint {plan.fingerprint}")
    return 0


def audit(args: argparse.Namespace) -> int:
    findings = _controller(args).audit(args.state_dir)
    exit_code = 0
    for finding in findings:
        print(f"{finding['device']}: {finding['status']} - {finding['detail']}")
        if finding["status"] != "compliant":
            exit_code = 2
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SDN security automation prototype")
    parser.add_argument("--inventory", default="examples/inventory.json", help="Path to network inventory JSON")
    parser.add_argument("--policy", default="examples/security_policy.json", help="Path to security policy JSON")
    parser.add_argument("--state-dir", default="state", help="Directory used by the simulated device transport")

    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("plan", help="Render security configuration without applying it").set_defaults(func=plan)
    subparsers.add_parser("apply", help="Apply rendered configuration to simulated device state").set_defaults(func=apply)
    subparsers.add_parser("audit", help="Audit simulated device state for drift").set_defaults(func=audit)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.inventory = Path(args.inventory)
    args.policy = Path(args.policy)
    args.state_dir = Path(args.state_dir)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
