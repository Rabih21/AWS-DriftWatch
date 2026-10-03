import pytest

from src.security_group_scan import detect_findings


def make_group(protocol, start=None, end=None, ipv4=None, ipv6=None):
    rule = {"IpProtocol": protocol}

    if start is not None:
        rule["FromPort"] = start
    if end is not None:
        rule["ToPort"] = end
    if ipv4:
        rule["IpRanges"] = [{"CidrIp": ipv4}]
    if ipv6:
        rule["Ipv6Ranges"] = [{"CidrIpv6": ipv6}]

    return {
        "GroupId": "sg-test",
        "IpPermissions": [rule],
    }


@pytest.mark.parametrize(
    "group, expected_ports",
    [
        # Unrestricted IPv4 SSH.
        (make_group("tcp", 22, 22, ipv4="0.0.0.0/0"), {22}),

        # Unrestricted IPv6 RDP.
        (make_group("6", 3389, 3389, ipv6="::/0"), {3389}),

        # A TCP range containing both administrative ports.
        (make_group("tcp", 1, 4000, ipv4="0.0.0.0/0"), {22, 3389}),

        # All protocols implicitly include both ports.
        (make_group("-1", ipv4="0.0.0.0/0"), {22, 3389}),

        # SSH restricted to one address is outside this check.
        (make_group("tcp", 22, 22, ipv4="203.0.113.10/32"), set()),

        # Public HTTPS is outside this check.
        (make_group("tcp", 443, 443, ipv4="0.0.0.0/0"), set()),

        # This detector checks TCP administrative access.
        (make_group("udp", 22, 22, ipv4="0.0.0.0/0"), set()),
    ],
)
def test_admin_port_detection(group, expected_ports):
    findings = detect_findings(group, set())

    assert {finding["port"] for finding in findings} == expected_ports
    assert len(findings) == len(expected_ports)


def test_empty_inbound_rules():
    group = {"GroupId": "sg-test", "IpPermissions": []}

    assert detect_findings(group, set()) == []


def test_interface_association_is_not_proof_of_reachability():
    group = make_group("tcp", 22, 22, ipv4="0.0.0.0/0")

    finding = detect_findings(group, {"eni-test"})[0]

    assert finding["association_status"] == "ASSOCIATED"
    assert finding["interface_ids"] == ["eni-test"]
    assert finding["reachability"] == "NOT_ASSESSED"


def test_unassociated_group_still_reports_risky_configuration():
    group = make_group("tcp", 22, 22, ipv4="0.0.0.0/0")

    finding = detect_findings(group, set())[0]

    assert finding["association_status"] == "UNASSOCIATED"
    assert finding["interface_ids"] == []
    assert finding["source"] == "0.0.0.0/0"