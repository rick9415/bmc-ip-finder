import subprocess
import socket
import concurrent.futures
import ipaddress
import platform
import re
import time
import json
import ssl
import urllib.request
import urllib.error
import base64
from typing import Optional

IPMI_PORT = 623
BMC_HTTP_PORT = 80
BMC_HTTPS_PORT = 443
SSH_PORT = 22
TIMEOUT = 1.5
MAX_WORKERS = 128
REDFISH_TIMEOUT = 6


# ── SSL context that ignores self-signed certs (common on BMCs) ──────────────
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


# ── Network helpers ───────────────────────────────────────────────────────────

def get_local_subnet() -> list[str]:
    subnets = []
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output("ipconfig", encoding="utf-8", errors="ignore")
            ip_blocks = re.findall(
                r"IPv4 Address.*?:\s*([\d.]+)\s*\n\s*Subnet Mask.*?:\s*([\d.]+)", out
            )
            for ip, mask in ip_blocks:
                try:
                    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                    if not net.is_loopback and not net.is_link_local:
                        subnets.append(str(net))
                except ValueError:
                    pass
        else:
            out = subprocess.check_output(
                ["ip", "-o", "-f", "inet", "addr"], encoding="utf-8", errors="ignore"
            )
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        net = ipaddress.IPv4Network(parts[3], strict=False)
                        if not net.is_loopback and not net.is_link_local:
                            subnets.append(str(net))
                    except ValueError:
                        pass
    except Exception:
        pass
    return subnets or ["192.168.1.0/24"]


def ping(ip: str) -> bool:
    flag = "-n" if platform.system() == "Windows" else "-c"
    try:
        result = subprocess.run(
            ["ping", flag, "1", "-w", "1000", ip]
            if platform.system() == "Windows"
            else ["ping", flag, "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        return result.returncode == 0
    except Exception:
        return False


def check_port(ip: str, port: int, udp: bool = False) -> bool:
    try:
        if udp:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(TIMEOUT)
            sock.sendto(
                b"\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x20\x18\xc8\x81\x04\x38\x00\x00\x00\x00\x00\x00\x00\x00",
                (ip, port),
            )
            data, _ = sock.recvfrom(64)
            sock.close()
            return len(data) > 0
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
    except Exception:
        return False


def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def get_mac(ip: str) -> str:
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(
                ["arp", "-a", ip], encoding="utf-8", errors="ignore", timeout=3
            )
            m = re.search(r"([\da-fA-F]{2}[:-]){5}[\da-fA-F]{2}", out)
            if m:
                return m.group(0).replace("-", ":").upper()
        else:
            with open("/proc/net/arp") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip and parts[3] != "00:00:00:00:00:00":
                        return parts[3].upper()
            out = subprocess.check_output(
                ["arp", "-n", ip], encoding="utf-8", errors="ignore", timeout=3
            )
            m = re.search(r"([\da-fA-F]{1,2}[:-]){5}[\da-fA-F]{1,2}", out)
            if m:
                return m.group(0).upper()
    except Exception:
        pass
    return ""


# ── Redfish helpers ───────────────────────────────────────────────────────────

def _rf_request(url: str, username: str, password: str) -> Optional[dict]:
    """GET a Redfish URL, return parsed JSON or None. Ignores TLS errors."""
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    if username:
        cred = base64.b64encode(f"{username}:{password}".encode()).decode()
        req.add_header("Authorization", f"Basic {cred}")
    try:
        with urllib.request.urlopen(req, timeout=REDFISH_TIMEOUT, context=_SSL_CTX) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        return {"_http_error": e.code}
    except Exception:
        return None


def _rf_get(ip: str, path: str, username: str, password: str) -> Optional[dict]:
    for scheme in ("https", "http"):
        data = _rf_request(f"{scheme}://{ip}{path}", username, password)
        if data is not None:
            return data
    return None


def _first_member(collection: Optional[dict]) -> Optional[str]:
    """Return the @odata.id of the first member in a Redfish collection."""
    if not collection:
        return None
    members = collection.get("Members", [])
    if members:
        return members[0].get("@odata.id")
    return None


def probe_redfish(ip: str, username: str = "", password: str = "") -> dict:
    """
    Query the Redfish API on one BMC and return a structured result.
    Fields returned:
      reachable, auth_ok, version,
      system: {manufacturer, model, serial, part_number, hostname,
               power_state, bios_version, cpu_count, cpu_model, memory_gib, health},
      bmc:    {firmware, model, health},
      ethernet: [{name, mac, ipv4, speed_mbps}],
      error
    """
    result = {
        "reachable": False,
        "auth_ok": False,
        "version": "",
        "system": {},
        "bmc": {},
        "ethernet": [],
        "error": None,
    }

    # ── Service root ──────────────────────────────────────────────
    root = _rf_get(ip, "/redfish/v1/", username, password)
    if root is None:
        result["error"] = "Redfish 無回應"
        return result
    if root.get("_http_error") == 401:
        result["reachable"] = True
        result["error"] = "認證失敗 (401)"
        return result

    result["reachable"] = True
    result["auth_ok"] = True
    result["version"] = root.get("RedfishVersion", "")

    # ── Systems ───────────────────────────────────────────────────
    sys_col = _rf_get(ip, "/redfish/v1/Systems", username, password)
    sys_path = _first_member(sys_col) or "/redfish/v1/Systems/1"
    sys_data = _rf_get(ip, sys_path, username, password) or {}

    proc_sum = sys_data.get("ProcessorSummary", {})
    mem_sum  = sys_data.get("MemorySummary", {})
    status   = sys_data.get("Status", {})

    result["system"] = {
        "manufacturer": sys_data.get("Manufacturer", ""),
        "model":        sys_data.get("Model", ""),
        "serial":       sys_data.get("SerialNumber", ""),
        "part_number":  sys_data.get("PartNumber", ""),
        "sku":          sys_data.get("SKU", ""),
        "hostname":     sys_data.get("HostName", ""),
        "power_state":  sys_data.get("PowerState", ""),
        "bios_version": sys_data.get("BiosVersion", ""),
        "cpu_count":    proc_sum.get("Count", ""),
        "cpu_model":    proc_sum.get("Model", ""),
        "memory_gib":   mem_sum.get("TotalSystemMemoryGiB", ""),
        "health":       status.get("Health", ""),
        "state":        status.get("State", ""),
    }

    # ── Managers (BMC firmware) ───────────────────────────────────
    mgr_col  = _rf_get(ip, "/redfish/v1/Managers", username, password)
    mgr_path = _first_member(mgr_col) or "/redfish/v1/Managers/1"
    mgr_data = _rf_get(ip, mgr_path, username, password) or {}
    mgr_status = mgr_data.get("Status", {})

    result["bmc"] = {
        "firmware": mgr_data.get("FirmwareVersion", ""),
        "model":    mgr_data.get("Model", ""),
        "health":   mgr_status.get("Health", ""),
    }

    # ── Ethernet interfaces (NIC MACs from Redfish) ───────────────
    eth_col_path = mgr_data.get("EthernetInterfaces", {}).get("@odata.id", "")
    if eth_col_path:
        eth_col = _rf_get(ip, eth_col_path, username, password) or {}
        for member in eth_col.get("Members", []):
            eth_path = member.get("@odata.id", "")
            if not eth_path:
                continue
            eth = _rf_get(ip, eth_path, username, password) or {}
            ipv4 = ""
            for addr in eth.get("IPv4Addresses", []):
                if addr.get("Address"):
                    ipv4 = addr["Address"]
                    break
            result["ethernet"].append({
                "name":       eth.get("Name", eth.get("Id", "")),
                "mac":        eth.get("MACAddress", "").upper(),
                "ipv4":       ipv4,
                "speed_mbps": eth.get("SpeedMbps", ""),
                "link_up":    eth.get("LinkStatus", ""),
            })

    return result


# ── Host probe (network scan) ─────────────────────────────────────────────────

def probe_host(ip: str) -> Optional[dict]:
    alive = ping(ip)

    open_ports = {}
    for port, label in [(BMC_HTTP_PORT, "HTTP"), (BMC_HTTPS_PORT, "HTTPS"), (SSH_PORT, "SSH")]:
        if check_port(ip, port):
            open_ports[label] = port
            alive = True

    ipmi_up = check_port(ip, IPMI_PORT, udp=True)
    if ipmi_up:
        open_ports["IPMI"] = IPMI_PORT
        alive = True

    if not alive:
        return None

    is_bmc_candidate = (
        ipmi_up
        or ("HTTP" in open_ports and "SSH" in open_ports)
        or ("HTTPS" in open_ports and "SSH" in open_ports)
    )

    hostname = get_hostname(ip)
    mac = get_mac(ip)

    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "alive": alive,
        "ipmi": ipmi_up,
        "ports": open_ports,
        "is_bmc": is_bmc_candidate,
        "redfish": None,
        "timestamp": time.strftime("%H:%M:%S"),
    }


def scan_subnet(subnet: str, progress_cb=None) -> list[dict]:
    network = ipaddress.IPv4Network(subnet, strict=False)
    hosts = list(network.hosts())
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(probe_host, str(h)): i for i, h in enumerate(hosts)}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            if progress_cb:
                progress_cb(done, len(hosts))
            try:
                r = future.result()
                if r:
                    results.append(r)
            except Exception:
                pass

    results.sort(key=lambda r: ipaddress.IPv4Address(r["ip"]))
    return results
