#!/usr/bin/env python3
"""CSPB AdGuard block page server.

AdGuard Home answers blocked DNS queries with this server's IP
(blocking_mode: custom_ip). The browser then connects here while still
asking for the blocked site, so the Host header names the site the user
tried to open. Every path returns the block page; the page calls
/__blockpage/info, which asks AdGuard's check_host API why that host is
blocked for that client and returns a small JSON summary.

Standard library only. Configuration comes from the environment:

  ADGUARD_URL        AdGuard Home base URL (default http://127.0.0.1:3000)
  ADGUARD_USER       AdGuard admin user
  ADGUARD_PASSWORD   AdGuard admin password (never logged)
  ADGUARD_PASSWORD_FILE  alternative to ADGUARD_PASSWORD
  BLOCKPAGE_LISTEN   host:port to bind (default 0.0.0.0:8080)
  BLOCKPAGE_TRUST_PROXY  "1" to take the client IP from X-Forwarded-For
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PUBLIC_DIR = Path(__file__).resolve().parent / "public"
INFO_PATH = "/__blockpage/info"
ASSET_PREFIX = "/__blockpage/"
ASSETS = {
    "cspb-logo.png": "image/png",
}
MANILA = timezone(timedelta(hours=8), "Asia/Manila")
HOST_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9_])?$")
CACHE_SECONDS = 300
TIMEOUT_SECONDS = 3

# Ordered: the first keyword found in a filter list's name decides its category.
LIST_CATEGORIES = [
    (("porn", "adult"), "Adult content"),
    (("phish",), "Phishing"),
    (("scam",), "Scam"),
    (("gambling",), "Gambling"),
    (("piracy",), "Piracy"),
    (("dating",), "Dating"),
    (("vpn", "proxy", "bypass", "encrypted dns", "tor"), "VPN and proxy bypass"),
    (("dyndns", "dynamic dns"), "Dynamic DNS"),
    (("nocoin", "cryptojacking", "coin"), "Cryptojacking"),
    (("malware", "urlhaus", "badware", "threat", "hacked"), "Malware and security threats"),
    (("adguard dns filter", "adaway", "ads", "tracker"), "Ads and trackers"),
]

BLOCK_TYPES = {
    "FilteredBlackList": "Blocklist",
    "FilteredBlockedService": "Blocked service",
    "FilteredSafeBrowsing": "Safe browsing",
    "FilteredParental": "Parental control",
    "FilteredSafeSearch": "Safe search",
    "FilteredInvalid": "Invalid request",
}


def normalize_host(raw: str | None) -> str | None:
    """Return a lowercase hostname without port, or None if it is not a hostname."""
    if not raw:
        return None
    host = raw.strip().lower()
    if host.startswith("["):  # IPv6 literal, e.g. [::1]:80
        return None
    host = host.split(":", 1)[0].rstrip(".")
    if len(host) > 253 or not HOST_RE.match(host):
        return None
    return host


def category_for_list(name: str) -> str:
    lowered = name.lower()
    for keywords, category in LIST_CATEGORIES:
        if any(k in lowered for k in keywords):
            return category
    return name


class AdGuardClient:
    def __init__(self, base_url: str, user: str, password: str):
        self.base_url = base_url.rstrip("/")
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self._auth = f"Basic {token}"
        self._lock = threading.Lock()
        self._lists: dict[int, str] = {}
        self._services: dict[str, str] = {}
        self._loaded_at = 0.0

    def _get(self, path: str, params: dict[str, str] | None = None):
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={"Authorization": self._auth})
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return json.load(resp)

    def _refresh_names(self) -> None:
        with self._lock:
            if time.monotonic() - self._loaded_at < CACHE_SECONDS and self._loaded_at:
                return
            lists: dict[int, str] = {}
            status = self._get("/control/filtering/status")
            for f in (status.get("filters") or []) + (status.get("whitelist_filters") or []):
                lists[int(f["id"])] = f.get("name") or f.get("url") or str(f["id"])
            services: dict[str, str] = {}
            try:
                for s in self._get("/control/blocked_services/all").get("blocked_services") or []:
                    services[s["id"]] = s.get("name") or s["id"]
            except (urllib.error.URLError, ValueError, KeyError):
                pass  # service names are cosmetic; ids still work
            self._lists, self._services = lists, services
            self._loaded_at = time.monotonic()

    def check(self, host: str, client_ip: str | None) -> dict:
        params = {"name": host}
        if client_ip:
            params["client"] = client_ip
        result = self._get("/control/filtering/check_host", params)
        try:
            self._refresh_names()
        except (urllib.error.URLError, ValueError, KeyError):
            pass
        return describe(result, self._lists, self._services)


def describe(result: dict, lists: dict[int, str], services: dict[str, str]) -> dict:
    """Turn an AdGuard check_host result into what the block page shows."""
    reason = result.get("reason") or ""
    rules = result.get("rules") or []
    if not rules and result.get("rule"):  # pre-v0.107 shape
        rules = [{"text": result.get("rule"), "filter_list_id": result.get("filter_id")}]
    rule_text = next((r.get("text") for r in rules if r.get("text")), None)
    list_names: list[str] = []
    for r in rules:
        list_id = r.get("filter_list_id")
        # Negative ids are AdGuard's built-in sources (-2 blocked services,
        # -1 system hosts, ...), not filter lists the user can name.
        if list_id in (None, "") or int(list_id) < 0:
            continue
        name = "Custom school rules" if int(list_id) == 0 else lists.get(int(list_id), f"Filter list {list_id}")
        if name not in list_names:
            list_names.append(name)

    blocked = reason.startswith("Filtered")
    block_type = BLOCK_TYPES.get(reason, "Not blocked" if not blocked else reason)
    service_id = result.get("service_name") or None
    service = services.get(service_id, service_id) if service_id else None

    if reason == "FilteredBlockedService":
        categories = [service or "Blocked service"]
    elif reason == "FilteredSafeBrowsing":
        categories = ["Malware or phishing"]
    elif reason == "FilteredParental":
        categories = ["Adult content"]
    elif reason == "FilteredSafeSearch":
        categories = ["Safe search enforced"]
    elif reason == "FilteredBlackList":
        categories = []
        for name in list_names:
            c = "Custom school rule" if name == "Custom school rules" else category_for_list(name)
            if c not in categories:
                categories.append(c)
        categories = categories or ["Blocklist"]
    else:
        categories = []

    return {
        "blocked": blocked,
        "reason": reason or None,
        "blockType": block_type,
        "category": ", ".join(categories) or None,
        "lists": list_names,
        "service": service,
        "rule": rule_text,
    }


def load_config() -> dict:
    password = os.environ.get("ADGUARD_PASSWORD", "")
    pw_file = os.environ.get("ADGUARD_PASSWORD_FILE")
    if not password and pw_file:
        password = Path(pw_file).read_text().strip()
    return {
        "adguard_url": os.environ.get("ADGUARD_URL", "http://127.0.0.1:3000"),
        "user": os.environ.get("ADGUARD_USER", ""),
        "password": password,
        "listen": os.environ.get("BLOCKPAGE_LISTEN", "0.0.0.0:8080"),
        "trust_proxy": os.environ.get("BLOCKPAGE_TRUST_PROXY") == "1",
    }


def make_handler(client: AdGuardClient | None, trust_proxy: bool):
    page = (PUBLIC_DIR / "index.html").read_bytes()

    class Handler(BaseHTTPRequestHandler):
        server_version = "cspb-blockpage"
        sys_version = ""

        def log_message(self, fmt, *args):  # keep logs free of query strings
            sys.stderr.write(f"{self.address_string()} {self.command} {self.headers.get('Host', '-')!r}\n")

        def _client_ip(self) -> str:
            if trust_proxy:
                fwd = self.headers.get("X-Forwarded-For", "")
                if fwd:
                    return fwd.split(",")[0].strip()
            return self.client_address[0]

        def _send(self, status: int, body: bytes, content_type: str, cache: str = "no-store"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            path = urllib.parse.urlsplit(self.path).path
            if path == INFO_PATH:
                return self._info()
            if path.startswith(ASSET_PREFIX):
                name = path[len(ASSET_PREFIX):]
                if name in ASSETS:
                    return self._send(200, (PUBLIC_DIR / name).read_bytes(), ASSETS[name], "public, max-age=86400")
            # Every other path on every host is the block page.
            self._send(403, page, "text/html; charset=utf-8")

        do_POST = do_GET

        def _info(self):
            host = normalize_host(self.headers.get("Host"))
            ip = self._client_ip()
            data: dict = {
                "host": host,
                "clientIp": ip,
                "checkedAt": datetime.now(MANILA).isoformat(timespec="seconds"),
            }
            if host is None:
                data["error"] = "no_host"
            elif client is None:
                data["error"] = "lookup_unconfigured"
            else:
                try:
                    data.update(client.check(host, ip))
                except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
                    sys.stderr.write(f"check_host failed for {host}: {type(exc).__name__}\n")
                    data["error"] = "lookup_failed"
            self._send(200, json.dumps(data).encode(), "application/json")

    return Handler


def main() -> None:
    cfg = load_config()
    client = None
    if cfg["user"] and cfg["password"]:
        client = AdGuardClient(cfg["adguard_url"], cfg["user"], cfg["password"])
    else:
        sys.stderr.write("ADGUARD_USER/ADGUARD_PASSWORD not set: block details will be unavailable\n")
    bind_host, _, port = cfg["listen"].rpartition(":")
    httpd = ThreadingHTTPServer((bind_host or "0.0.0.0", int(port)), make_handler(client, cfg["trust_proxy"]))
    sys.stderr.write(f"block page listening on {cfg['listen']}\n")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
