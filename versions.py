"""Basic service exposure notes; no unsupported version claims are made."""

SERVICE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 5432: "PostgreSQL", 3389: "RDP",
}

def check_versions(open_ports):
    """Flag services for manual version review; port numbers cannot prove versions."""
    findings = []
    for port in open_ports:
        service = SERVICE_PORTS.get(port)
        if service:
            findings.append({
                "title": f"{service} service needs version review",
                "severity": "Info",
                "description": "The port suggests this service may be present. VulnScan does not reliably identify its software version; verify it on the host and check the vendor's security advisories.",
                "evidence": f"TCP port {port} is open.",
            })
    return findings
