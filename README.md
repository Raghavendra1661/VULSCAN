# VULSCAN

VulnScan is a small Python and Flask project for practising basic network
security checks in a local lab. It checks selected TCP ports and, when the
related options are enabled, looks at service banners, common HTTP headers,
cookies, and TLS certificates.

It is a learning tool, not a full vulnerability scanner. An open port or a
warning does not prove that a machine is vulnerable. Check important results
manually.

## What the project does

- Checks a selected list or range of TCP ports.
- Shows a service name for common ports.
- Gives warnings for a few services that should not be exposed carelessly.
- Compares recognised service banners with the small reference list in
  `data/min_versions.json`.
- Checks a few HTTP response headers and cookie flags.
- Can check certificate expiry and the negotiated TLS version.

The version list is maintained inside this project. It is not a live database,
does not cover every product, and should not be used as the only source for
patch decisions.

## Requirements

- Python 3.10 or later
- Flask 3.0 or later
- A web browser

## Start it on Windows

Open PowerShell in the `VULSCAN` project folder and run these commands:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py app.py
```

If PowerShell blocks virtual-environment activation, you can run the Python
commands using `.venv\Scripts\python.exe` without activating it.

## Start it on Linux or macOS

Open a terminal in the project folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

When Flask starts, open `http://127.0.0.1:5000` in your browser.

## Try a scan on your own computer

For a simple test, open a second terminal and start Python's local web server:

```bash
python -m http.server 8000
```

In VulnScan, use `127.0.0.1` as the target and choose port `8000`. Tick the
permission confirmation before starting the scan. Stop the test server with
`Ctrl+C` when finished.

Only scan a computer or network that you own or have clear permission to test.
By default, VulnScan accepts private and loopback addresses. You can add
specific authorised hostnames or addresses through the `SCAN_ALLOWED_HOSTS`
environment variable. Do not expose this student project as a public scanning
service.

## Run the automated tests

From the project folder, run:

```bash
python -m unittest discover -s tests -v
```

The tests cover port-list parsing, service warnings, version parsing, and
report summaries. They do not test every network condition or replace a
controlled manual test.

## Project layout

```text
VULSCAN/
├── app.py                  Flask routes and request checks
├── scanner/
│   ├── ports.py            TCP port checks and service warnings
│   ├── versions.py         Service banner and version checks
│   ├── web_checks.py       HTTP, cookie, and TLS checks
│   └── report.py           Scan result summary
├── data/
│   └── min_versions.json   Small local version reference
├── static/
│   ├── app.js              Form submission and result display
│   └── style.css           Page styling
├── templates/
│   ├── index.html          Scan form
│   └── report.html         Printable report
└── tests/                  Automated tests
```

## Current limitations

- It checks TCP, not UDP.
- Some services do not send a banner, and banners can be hidden or inaccurate.
- The version reference covers only a few services and may become outdated.
- HTTP checks look at selected headers and cookie attributes only.
- The TLS check only runs for ports 443 and 8443.
- The latest result is stored in application memory. It is not designed for
  multiple users or production use.
- It does not log in to services, exploit them, or perform a complete CVE scan.

## Before submitting or demonstrating

Run the application and the tests on your own machine. Complete
`DEVELOPMENT_NOTES.md` with the versions you used, the test you actually ran,
what you observed, and a limitation you noticed. Do not write that a test
passed unless you ran it.

List any tutorials, libraries, people, or AI tools that helped you, following
your course or institution's rules. Make sure you can explain the code and
the limits of the results.
