"""
BMC 2600 IP Finder — web server entry point.
Run:  python app.py
Then open http://localhost:5000 in your browser.
"""

import ipaddress
import json
import threading
import time
import concurrent.futures
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import scanner

# ── Scan state ────────────────────────────────────────────────────────────────
_scan_lock = threading.Lock()
_scan_state = {
    "running": False,
    "progress": 0,
    "total": 0,
    "results": [],      # list of host dicts; each has a "redfish" key (None until queried)
    "subnets": [],
    "started_at": None,
    "finished_at": None,
    "error": None,
}

# ── Redfish batch state ───────────────────────────────────────────────────────
_rf_lock = threading.Lock()
_rf_state = {
    "running": False,
    "done": 0,
    "total": 0,
    "error": None,
}


# ── Background workers ────────────────────────────────────────────────────────

def _run_scan(subnets: list[str]):
    all_results = []
    _scan_state["error"] = None
    _scan_state["started_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _scan_state["finished_at"] = None

    try:
        for subnet in subnets:
            total_hosts = len(list(ipaddress.IPv4Network(subnet, strict=False).hosts()))
            _scan_state["total"] += total_hosts

            offset = sum(
                len(list(ipaddress.IPv4Network(s, strict=False).hosts()))
                for s in subnets[: subnets.index(subnet)]
            )

            def progress(done, _total, _off=offset):
                _scan_state["progress"] = _off + done

            results = scanner.scan_subnet(subnet, progress_cb=progress)
            all_results.extend(results)
            _scan_state["results"] = sorted(
                all_results,
                key=lambda r: ipaddress.IPv4Address(r["ip"]),
            )
    except Exception as exc:
        _scan_state["error"] = str(exc)
    finally:
        _scan_state["running"] = False
        _scan_state["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")


def _run_redfish_batch(targets: list[str], username: str, password: str):
    """Query Redfish for every IP in targets and store results back into scan results."""
    _rf_state.update(running=True, done=0, total=len(targets), error=None)

    def _query_one(ip):
        return ip, scanner.probe_redfish(ip, username, password)

    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
        futures = {ex.submit(_query_one, ip): ip for ip in targets}
        for future in concurrent.futures.as_completed(futures):
            try:
                ip, rf_data = future.result()
                # Patch the matching entry in scan results
                for entry in _scan_state["results"]:
                    if entry["ip"] == ip:
                        entry["redfish"] = rf_data
                        # Prefer Redfish MAC if ARP gave nothing
                        if not entry["mac"]:
                            for nic in rf_data.get("ethernet", []):
                                if nic.get("mac"):
                                    entry["mac"] = nic["mac"]
                                    break
                        break
            except Exception:
                pass
            with _rf_lock:
                _rf_state["done"] += 1

    _rf_state["running"] = False


# ── HTTP handler ──────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, code: int, body, ctype: str = "text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data):
        self._send(200, json.dumps(data, ensure_ascii=False), "application/json")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            self._send(200, Path("index.html").read_bytes())

        elif path == "/api/status":
            self._json(dict(_scan_state))

        elif path == "/api/subnets":
            self._json({"subnets": scanner.get_local_subnet()})

        elif path == "/api/start":
            custom = params.get("subnet", [None])[0]
            with _scan_lock:
                if _scan_state["running"]:
                    self._json({"ok": False, "msg": "掃描進行中"})
                    return
                subnets = [custom] if custom else scanner.get_local_subnet()
                _scan_state.update(
                    running=True, progress=0, total=0,
                    results=[], subnets=subnets,
                    started_at=None, finished_at=None, error=None,
                )
            threading.Thread(target=_run_scan, args=(subnets,), daemon=True).start()
            self._json({"ok": True, "subnets": subnets})

        elif path == "/api/stop":
            _scan_state["running"] = False
            self._json({"ok": True})

        elif path == "/api/redfish_status":
            self._json(dict(_rf_state))

        elif path == "/api/redfish_fetch":
            username = params.get("user", [""])[0]
            password = params.get("pass", [""])[0]
            ip_filter = params.get("ip", [None])[0]  # optional single-IP mode

            with _rf_lock:
                if _rf_state["running"]:
                    self._json({"ok": False, "msg": "Redfish 查詢進行中"})
                    return

            if ip_filter:
                targets = [ip_filter]
            else:
                # Query all BMC candidates from last scan
                targets = [r["ip"] for r in _scan_state["results"] if r.get("is_bmc")]
                if not targets:
                    targets = [r["ip"] for r in _scan_state["results"]]

            if not targets:
                self._json({"ok": False, "msg": "尚無掃描結果"})
                return

            threading.Thread(
                target=_run_redfish_batch,
                args=(targets, username, password),
                daemon=True,
            ).start()
            self._json({"ok": True, "total": len(targets)})

        else:
            self._send(404, "Not found")


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 5000
    server = HTTPServer((HOST, PORT), Handler)
    print(f"BMC 2600 IP Finder running at  http://localhost:{PORT}")
    print("Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
