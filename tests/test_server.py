import base64
import http.client
import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server  # noqa: E402

AUTH = "Basic " + base64.b64encode(b"admin:secret").decode()

FILTERS = {
    "filters": [
        {"id": 1, "name": "AdGuard DNS filter", "url": "x"},
        {"id": 47, "name": "HaGeZi's Gambling Blocklist", "url": "x"},
        {"id": 99, "name": "StevenBlack Porn Blocklist", "url": "x"},
    ],
    "whitelist_filters": [],
}
SERVICES = {"blocked_services": [{"id": "tinder", "name": "Tinder"}]}
CHECKS = {
    "bet.example": {"reason": "FilteredBlackList", "rules": [{"text": "||bet.example^", "filter_list_id": 47}], "service_name": ""},
    "tinder.com": {"reason": "FilteredBlockedService", "rules": [{"text": "||tinder.com^", "filter_list_id": -2}], "service_name": "tinder"},
    "custom.example": {"reason": "FilteredBlackList", "rules": [{"text": "||custom.example^", "filter_list_id": 0}]},
    "evil.example": {"reason": "FilteredSafeBrowsing", "rules": []},
    "ok.example": {"reason": "NotFilteredNotFound", "rules": []},
}


class FakeAdGuard(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.headers.get("Authorization") != AUTH:
            self.send_response(401)
            self.end_headers()
            return
        u = urlsplit(self.path)
        q = parse_qs(u.query)
        if u.path == "/control/filtering/status":
            body = FILTERS
        elif u.path == "/control/blocked_services/all":
            body = SERVICES
        elif u.path == "/control/filtering/check_host":
            FakeAdGuard.seen.append(q)
            name = q["name"][0]
            if name == "boom.example":
                self.send_response(500)
                self.end_headers()
                return
            body = CHECKS.get(name, {"reason": "NotFilteredNotFound", "rules": []})
        else:
            self.send_response(404)
            self.end_headers()
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def serve(handler):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


class BlockPageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.agh = serve(FakeAdGuard)
        client = server.AdGuardClient(f"http://127.0.0.1:{cls.agh.server_port}", "admin", "secret")
        cls.page = serve(server.make_handler(client, trust_proxy=False))
        bad = server.AdGuardClient(f"http://127.0.0.1:{cls.agh.server_port}", "admin", "wrong")
        cls.badpage = serve(server.make_handler(bad, trust_proxy=False))
        cls.unconfigured = serve(server.make_handler(None, trust_proxy=False))
        cls.proxied = serve(server.make_handler(None, trust_proxy=True))
        cls.untrusted_proxy = serve(server.make_handler(None, trust_proxy=True, proxy_ips=frozenset({"10.9.9.9"})))

    @classmethod
    def tearDownClass(cls):
        for s in (cls.agh, cls.page, cls.badpage, cls.unconfigured, cls.proxied, cls.untrusted_proxy):
            s.shutdown()

    def get(self, srv, path, host, headers=None):
        req = urllib.request.Request(f"http://127.0.0.1:{srv.server_port}{path}", headers={"Host": host, **(headers or {})})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    def info(self, host, srv=None):
        status, headers, body = self.get(srv or self.page, server.INFO_PATH, host)
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        return json.loads(body)

    def test_any_path_on_any_host_returns_the_block_page(self):
        status, headers, body = self.get(self.page, "/some/deep/path?q=1", "bet.example")
        self.assertEqual(status, 403)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b"This site is blocked", body)

    def test_subresource_requests_get_a_tiny_reply(self):
        for dest in ("script", "image", "style", "empty"):
            with self.subTest(dest=dest):
                status, headers, body = self.get(self.page, "/ad.js", "ads.example", {"Sec-Fetch-Dest": dest})
                self.assertEqual(status, 403)
                self.assertIn("text/plain", headers["Content-Type"])
                self.assertNotIn(b"<html", body)

    def test_navigation_and_frames_get_the_page(self):
        for dest in ("document", "iframe"):
            with self.subTest(dest=dest):
                _, _, body = self.get(self.page, "/", "bet.example", {"Sec-Fetch-Dest": dest})
                self.assertIn(b"This site is blocked", body)

    def test_proxy_list_accepts_cidrs(self):
        srv = serve(server.make_handler(None, trust_proxy=True, proxy_ips=server.parse_networks("127.0.0.0/8")))
        try:
            _, _, body = self.get(srv, server.INFO_PATH, "bet.example", {"X-Forwarded-For": "10.123.210.9"})
            self.assertEqual(json.loads(body)["clientIp"], "10.123.210.9")
        finally:
            srv.shutdown()

    def test_requests_through_cloudflare_get_404_and_no_lookup(self):
        for hdr in ({"CF-Ray": "8a1b2c3d4e5f-SIN"}, {"CF-Connecting-IP": "203.0.113.9"}, {"CDN-Loop": "cloudflare"}):
            for path in ("/", server.INFO_PATH):
                with self.subTest(hdr=hdr, path=path):
                    before = len(FakeAdGuard.seen)
                    status, _, body = self.get(self.page, path, "bet.example", {**hdr, "X-Forwarded-For": "10.1.2.3"})
                    self.assertEqual(status, 404)
                    self.assertNotIn(b"html", body)
                    self.assertEqual(len(FakeAdGuard.seen), before)

    def test_logo_asset_is_served(self):
        status, headers, body = self.get(self.page, "/__blockpage/cspb-logo.png", "bet.example")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "image/png")
        self.assertTrue(body.startswith(b"\x89PNG"))

    def test_unknown_asset_falls_back_to_block_page(self):
        status, _, body = self.get(self.page, "/__blockpage/../server.py", "bet.example")
        self.assertEqual(status, 403)
        self.assertIn(b"<!doctype html>", body)

    def test_blocklist_reports_list_name_and_category(self):
        d = self.info("Bet.Example:80")
        self.assertEqual(d["host"], "bet.example")
        self.assertTrue(d["blocked"])
        self.assertEqual(d["blockType"], "Blocklist")
        self.assertEqual(d["category"], "Gambling")
        self.assertEqual(d["lists"], ["HaGeZi's Gambling Blocklist"])
        self.assertEqual(d["rule"], "||bet.example^")
        self.assertEqual(d["clientIp"], "127.0.0.1")

    def test_check_host_receives_client_ip(self):
        self.info("bet.example")
        self.assertEqual(FakeAdGuard.seen[-1]["client"], ["127.0.0.1"])

    def test_blocked_service_reports_service_name(self):
        d = self.info("tinder.com")
        self.assertEqual(d["blockType"], "Blocked service")
        self.assertEqual(d["category"], "Tinder")
        self.assertEqual(d["service"], "Tinder")
        self.assertEqual(d["lists"], [])

    def test_custom_rule(self):
        d = self.info("custom.example")
        self.assertEqual(d["category"], "Custom school rule")
        self.assertEqual(d["lists"], ["Custom school rules"])

    def test_safe_browsing(self):
        d = self.info("evil.example")
        self.assertEqual(d["blockType"], "Safe browsing")
        self.assertEqual(d["category"], "Malware or phishing")

    def test_not_blocked_any_more(self):
        d = self.info("ok.example")
        self.assertFalse(d["blocked"])
        self.assertEqual(d["blockType"], "Not blocked")

    def test_upstream_error_is_reported_not_raised(self):
        self.assertEqual(self.info("boom.example")["error"], "lookup_failed")

    def test_bad_credentials_report_lookup_failed(self):
        self.assertEqual(self.info("bet.example", self.badpage)["error"], "lookup_failed")

    def test_unconfigured_server_still_names_the_host(self):
        d = self.info("bet.example", self.unconfigured)
        self.assertEqual(d["host"], "bet.example")
        self.assertEqual(d["error"], "lookup_unconfigured")

    def test_forwarded_for_uses_the_proxys_own_entry(self):
        _, _, body = self.get(self.proxied, server.INFO_PATH, "bet.example",
                              {"X-Forwarded-For": "10.0.0.66, 10.116.192.50"})
        self.assertEqual(json.loads(body)["clientIp"], "10.116.192.50")

    def raw_info(self, srv, xff_lines):
        conn = http.client.HTTPConnection("127.0.0.1", srv.server_port)
        conn.putrequest("GET", server.INFO_PATH, skip_host=True)
        conn.putheader("Host", "bet.example")
        for line in xff_lines:
            conn.putheader("X-Forwarded-For", line)
        conn.endheaders()
        body = json.loads(conn.getresponse().read())
        conn.close()
        return body

    def test_forwarded_for_reads_every_header_line(self):
        d = self.raw_info(self.proxied, ["10.0.0.66", "10.116.192.50"])
        self.assertEqual(d["clientIp"], "10.116.192.50")

    def test_forwarded_for_must_be_an_ip(self):
        d = self.raw_info(self.proxied, ["not-an-ip"])
        self.assertEqual(d["clientIp"], "127.0.0.1")

    def test_forwarded_for_ignored_from_unlisted_peer(self):
        _, _, body = self.get(self.untrusted_proxy, server.INFO_PATH, "bet.example",
                              {"X-Forwarded-For": "10.0.0.66"})
        self.assertEqual(json.loads(body)["clientIp"], "127.0.0.1")

    def test_forwarded_for_ignored_when_proxy_trust_off(self):
        _, _, body = self.get(self.page, server.INFO_PATH, "bet.example", {"X-Forwarded-For": "10.0.0.66"})
        self.assertEqual(json.loads(body)["clientIp"], "127.0.0.1")

    def test_invalid_host_header_is_not_looked_up(self):
        before = len(FakeAdGuard.seen)
        d = self.info("<script>.example")
        self.assertIsNone(d["host"])
        self.assertEqual(d["error"], "no_host")
        self.assertEqual(len(FakeAdGuard.seen), before)


class CategoryTest(unittest.TestCase):
    def test_list_names_map_to_categories(self):
        cases = {
            "StevenBlack Porn Blocklist": "Adult content",
            "Phishing URL Blocklist (PhishTank and OpenPhish)": "Phishing",
            "Scam Blocklist by DurableNapkin": "Scam",
            "The Big List of Hacked Malware Web Sites": "Malware and security threats",
            "Malicious URL Blocklist (URLHaus)": "Malware and security threats",
            "HaGeZi's Anti-Piracy Blocklist": "Piracy",
            "ShadowWhisperer's Dating List": "Dating",
            "HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass": "VPN and proxy bypass",
            "HaGeZi's Threat Intelligence Feeds (medium)": "Malware and security threats",
            "HaGeZi's DynDNS Blocklist": "Dynamic DNS",
            "NoCoin Filter List (cryptojacking)": "Cryptojacking",
            "AdGuard DNS filter": "Ads and trackers",
            "Some Unknown List": "Some Unknown List",
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(server.category_for_list(name), expected)

    def test_normalize_host(self):
        self.assertEqual(server.normalize_host("WWW.Example.com.:8080"), "www.example.com")
        self.assertIsNone(server.normalize_host("[::1]:80"))
        self.assertIsNone(server.normalize_host(""))
        self.assertIsNone(server.normalize_host("a b.com"))


if __name__ == "__main__":
    unittest.main()
