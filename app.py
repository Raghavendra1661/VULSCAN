import ipaddress
import os
import socket
import time

from flask import Flask, jsonify, render_template, request

from scanner.ports import parse_range, risky_service_findings, scan_ports
from scanner.report import summarize
from scanner.versions import check_versions
from scanner.web_checks import check_tls, check_web

app = Flask(__name__)
last_result = {}


def allowed(host):
    """Only private/loopback hosts unless listed in SCAN_ALLOWED_HOSTS."""
    ip = ipaddress.ip_address(socket.gethostbyname(host))
    extra = [h.strip() for h in os.environ.get("SCAN_ALLOWED_HOSTS", "").split(",")]
    return ip.is_private or ip.is_loopback or host in extra


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    global last_result
    if not request.is_json:
        return jsonify(error="Send scan details as JSON."), 415

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="The request body must be a JSON object."), 400

    raw_host = data.get("target", "")
    if raw_host is None:
        raw_host = ""
    if not isinstance(raw_host, str):
        return jsonify(error="Target must be a hostname or IP address."), 400
    host = raw_host.strip()
    opts = data.get("options") or {}
    if not isinstance(opts, dict):
        return jsonify(error="Scan options must be an object."), 400

    if data.get("consent") is not True:
        return jsonify(error="Confirm you have permission to scan this target."), 400
    if not host:
        return jsonify(error="Enter a target host or IP."), 400
    port_input = data.get("ports")
    if port_input is not None and not isinstance(port_input, str):
        return jsonify(error="Ports must be entered as text."), 400

    for option_name in ("versions", "web", "tls"):
        if option_name in opts and not isinstance(opts[option_name], bool):
            return jsonify(error=f"The {option_name} option must be true or false."), 400

    try:
        if not allowed(host):
            return jsonify(error="That host is outside the allowed range. "
                                 "Scan localhost, a private IP, or add it to SCAN_ALLOWED_HOSTS."), 403
        ports = parse_range(port_input)
    except socket.gaierror:
        return jsonify(error="Could not resolve that host."), 400
    except ValueError as e:
        return jsonify(error=str(e)), 400

    # Keep timing around the scan itself, not request parsing or validation.
    start = time.monotonic()
    open_ports = scan_ports(host, ports)
    findings = risky_service_findings(open_ports)
    if opts.get("versions", True):
        findings += check_versions(open_ports)
    if opts.get("web", True):
        findings += check_web(host, open_ports)
    if opts.get("tls", False):
        findings += check_tls(host, open_ports)

    last_result = summarize(host, open_ports, findings, time.monotonic() - start, len(ports))
    return jsonify(last_result)


@app.route("/report")
def report():
    if not last_result:
        return "Run a scan first.", 404
    return render_template("report.html", r=last_result)


if __name__ == "__main__":
    app.run(debug=False, port=5000)
