"""Basic TCP port scanning helpers for authorized testing only."""
import socket

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 8080]

def parse_range(value=None):
    """Accepts values such as '22,80,443' or '1-1024'. Defaults to common ports."""
    if value is None or not str(value).strip():
        return COMMON_PORTS[:]
    ports = set()
    for part in str(value).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bits = part.split("-", 1)
            if not bits[0].isdigit() or not bits[1].isdigit():
                raise ValueError("Use ports like 22,80 or a range like 1-1024.")
            start, end = int(bits[0]), int(bits[1])
            if start > end:
                raise ValueError("Port range start must be less than or equal to its end.")
            if end - start > 2047:
                raise ValueError("Please scan no more than 2048 ports at a time.")
            ports.update(range(start, end + 1))
        else:
            if not part.isdigit():
                raise ValueError("Port values must be numbers.")
            ports.add(int(part))
    if not ports or any(p < 1 or p > 65535 for p in ports):
        raise ValueError("Ports must be between 1 and 65535.")
    if len(ports) > 2048:
        raise ValueError("Please scan no more than 2048 ports at a time.")
    return sorted(ports)

def scan_ports(host, ports, timeout=0.6):
    """Return open TCP ports. This is a basic connect scan, not a full audit."""
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                open_ports.append(port)
        except (OSError, TimeoutError):
            continue
    return open_ports

def risky_service_findings(open_ports):
    names = {
        21: ("FTP", "FTP may transmit credentials without encryption."),
        23: ("Telnet", "Telnet is unencrypted; prefer SSH."),
        445: ("SMB", "Review SMB exposure and restrict access to trusted networks."),
        3389: ("RDP", "Restrict Remote Desktop access and require strong authentication."),
        3306: ("MySQL", "Avoid exposing database ports to untrusted networks."),
        5432: ("PostgreSQL", "Avoid exposing database ports to untrusted networks."),
    }
    return [
        {"title": f"{names[p][0]} port {p} is open", "severity": "Medium",
         "description": names[p][1], "evidence": f"TCP port {p} accepted a connection."}
        for p in open_ports if p in names
    ]
