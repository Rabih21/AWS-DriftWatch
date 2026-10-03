import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
WORLD_CIDRS = {"0.0.0.0/0", "::/0"}


def detect_findings(group, interface_ids):
    """Inspect inbound rules without claiming internet reachability."""
    findings = []

    for rule in group.get("IpPermissions", []):
        protocol = rule.get("IpProtocol")

        if protocol == "-1":
            ports = list(ADMIN_PORTS)
        elif protocol in ("tcp", "6"):
            start = rule.get("FromPort")
            end = rule.get("ToPort")

            if start is None or end is None:
                continue

            ports = [port for port in ADMIN_PORTS if start <= port <= end]
        else:
            continue

        sources = [
            entry["CidrIp"]
            for entry in rule.get("IpRanges", [])
            if "CidrIp" in entry
        ]
        sources += [
            entry["CidrIpv6"]
            for entry in rule.get("Ipv6Ranges", [])
            if "CidrIpv6" in entry
        ]

        for source in sorted(set(sources) & WORLD_CIDRS):
            for port in ports:
                findings.append({
                    "check_id": "SG_WORLD_OPEN_ADMIN",
                    "severity": "HIGH",
                    "group_id": group["GroupId"],
                    "service": ADMIN_PORTS[port],
                    "port": port,
                    "source": source,
                    "protocol": protocol,
                    "rule_from_port": rule.get("FromPort"),
                    "rule_to_port": rule.get("ToPort"),
                    "interface_ids": sorted(interface_ids),
                    "association_status": (
                        "ASSOCIATED" if interface_ids else "UNASSOCIATED"
                    ),
                    "recommendation": (
                        "Remove unrestricted administrative access or "
                        "restrict it to approved sources."
                    ),
                    "reachability": "NOT_ASSESSED",
                })

    return findings


def collect_report(profile, region):
    session = boto3.Session(profile_name=profile, region_name=region)

    if not session.region_name:
        raise ValueError(
            "No region configured. Supply --region or configure the profile."
        )

    config = Config(
        retries={"mode": "standard", "max_attempts": 3},
        connect_timeout=10,
        read_timeout=30,
    )
    identity = session.client("sts", config=config).get_caller_identity()
    ec2 = session.client("ec2", config=config)

    groups = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        groups.extend(page["SecurityGroups"])

    associations = {}
    for page in ec2.get_paginator("describe_network_interfaces").paginate():
        for interface in page["NetworkInterfaces"]:
            for group in interface.get("Groups", []):
                associations.setdefault(group["GroupId"], set()).add(
                    interface["NetworkInterfaceId"]
                )

    inventory = []
    findings = []

    for group in sorted(groups, key=lambda item: item["GroupId"]):
        interface_ids = associations.get(group["GroupId"], set())
        inventory.append({
            "configuration": group,
            "interface_ids": sorted(interface_ids),
        })
        findings.extend(detect_findings(group, interface_ids))

    return {
        "schema_version": 1,
        "status": "COMPLETE",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "account_id": identity["Account"],
        "region": session.region_name,
        "profile": profile,
        "security_group_count": len(groups),
        "finding_count": len(findings),
        "inventory": inventory,
        "findings": findings,
        "limitations": [
            "Only the selected region was scanned.",
            "Only unrestricted inbound SSH and RDP were checked.",
            "Interface associations do not prove internet reachability.",
            "This is an inventory snapshot, not yet a drift comparison.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="DriftWatch security-group scan")
    parser.add_argument("--profile", default="driftwatch")
    parser.add_argument("--region", default=None)
    args = parser.parse_args()

    try:
        report = collect_report(args.profile, args.region)

        output_dir = PROJECT_ROOT / "data"
        output_dir.mkdir(exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        output_path = output_dir / f"security-groups-{timestamp}.json"

        output_path.write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )
    except (BotoCoreError, ClientError, ValueError, OSError) as error:
        print(f"SCAN FAILED: {error}", file=sys.stderr)
        return 1

    print(f"Region: {report['region']}")
    print(f"Security groups scanned: {report['security_group_count']}")
    print(f"Findings: {report['finding_count']}")

    for finding in report["findings"]:
        print(
            f"[{finding['severity']}] {finding['group_id']} | "
            f"{finding['service']} | {finding['source']} | "
            f"{finding['association_status']}"
        )

    print(f"Report saved: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())