"""Simple HTTP response-header and TLS certificate checks."""
import socket
import ssl
import urllib.error
import urllib.request

def _http_url(host, port):
    scheme = "https" if port == 443 else "http"
    default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    return f"{scheme}://{host}" + ("" if default else f":{port}")

def check_web(host, open_ports):
    findings = []
    ports = [p for p in open_ports if p in (80, 443, 8000, 8080, 8443)]
    for port in ports:
        url = _http_url(host, port)
        req = urllib.request.Request(url, headers={"User-Agent": "VulnScan-Educational/1.0"}, method="HEAD")
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                headers = response.headers
        except (urllib.error.URLError, TimeoutError, OSError):
            continue
        checks = [
            ("X-Content-Type-Options", "Missing X-Content-Type-Options header", "Medium",
             "Add X-Content-Type-Options: nosniff."),
            ("Content-Security-Policy", "Missing Content-Security-Policy header", "Medium",
             "Consider a Content-Security-Policy suited to the application."),
            ("X-Frame-Options", "Missing clickjacking protection header", "Low",
             "Set X-Frame-Options or use frame-ancestors in Content-Security-Policy."),
        ]
        for header, title, severity, advice in checks:
            if not headers.get(header):
                findings.append({"title": title, "severity": severity,
                    "description": advice, "evidence": f"{url} did not return {header}."})
    return findings

def check_tls(host, open_ports):
    findings = []
    if 443 not in open_ports and 8443 not in open_ports:
        return findings
    port = 443 if 443 in open_ports else 8443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname=host) as conn:
                cert = conn.getpeercert()
                cipher = conn.cipher()
                if cipher:
                    findings.append({"title": "TLS connection established", "severity": "Info",
                        "description": "The scanner negotiated a TLS connection. This does not prove the full TLS configuration is secure.",
                        "evidence": f"Protocol: {conn.version()}; cipher: {cipher[0]}"})
                if not cert:
                    findings.append({"title": "Certificate details unavailable", "severity": "Low",
                        "description": "Review the server certificate configuration.", "evidence": host})
    except (OSError, ssl.SSLError) as exc:
        findings.append({"title": "TLS connection could not be verified", "severity": "Medium",
            "description": "Check certificate validity and TLS configuration manually.", "evidence": str(exc)[:180]})
    return findings
