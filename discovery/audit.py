"""Build device records and estimate exposure from observed LAN services."""


PORT_FINDINGS = {
    22: (10, "SSH is reachable on the LAN; verify it is needed and uses strong authentication."),
    23: (40, "Telnet is reachable and sends credentials without encryption."),
    53: (10, "DNS is reachable; verify this device is intended to provide DNS."),
    80: (15, "An unencrypted web interface is reachable on the LAN."),
    443: (5, "A web interface is reachable; its firmware and TLS configuration were not checked."),
    554: (25, "RTSP video streaming is reachable; verify authentication and access controls."),
    8080: (15, "An unencrypted web interface is reachable on the LAN."),
    8443: (5, "A web interface is reachable; its firmware and TLS configuration were not checked."),
}


def audit_device(ip: str, mac: str, open_ports: list[int]) -> dict:
    """Return a device-schema record with a transparent, port-based exposure score."""
    ports = sorted(set(open_ports))
    findings = [PORT_FINDINGS[port][1] for port in ports if port in PORT_FINDINGS]
    score = min(100, sum(PORT_FINDINGS[port][0] for port in ports if port in PORT_FINDINGS))

    if 554 in ports:
        device_type = "camera"
    elif 53 in ports:
        device_type = "router"
    else:
        device_type = "network_device"

    status = "at_risk" if score >= 30 else "safe"
    explanation = (
        f"Exposure score {score}/100 from {len(ports)} reachable service(s). "
        "This is a LAN-only port assessment; firmware vulnerabilities and internet reachability "
        "were not tested."
    )
    return {
        "mac": mac,
        "ip": ip,
        "type": device_type,
        "label": f"{device_type.replace('_', ' ').title()} at {ip}",
        "open_ports": ports,
        "exposure_score": score,
        "findings": findings,
        "status": status,
        "explanation": explanation,
    }
