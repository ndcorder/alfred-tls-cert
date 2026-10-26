"""Run: /usr/bin/python3 -B -m unittest test_cert  (from this folder). No network: subprocess is mocked."""
import base64
import datetime
import hashlib
import os
import plistlib
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import cert

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 10, 24, 12, 0, tzinfo=UTC)
DER = b"\x30\x82fake-der-bytes"
PEM = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----" % base64.b64encode(DER).decode()

# Trimmed real outputs (OpenSSL 4.0.3 and LibreSSL 3.3.6 print these lines differently).
OPENSSL_S_CLIENT = """Connecting to 140.82.113.4
CONNECTED(00000005)
---
Certificate chain
 0 s:CN=github.com
   i:C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36
 1 s:C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36
   i:C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication Root E46
---
Server certificate
%s
subject=CN=github.com
---
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256
Protocol: TLSv1.3
Verify return code: 0 (ok)
""" % PEM

LIBRESSL_S_CLIENT = """CONNECTED(00000005)
---
Certificate chain
 0 s:/CN=*.badssl.com
   i:/C=US/O=Let's Encrypt/CN=YR1
---
Server certificate
%s
---
New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES128-GCM-SHA256
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES128-GCM-SHA256
    Verify return code: 0 (ok)
""" % PEM


def x509_text(not_after="Nov 29 23:59:59 2026 GMT", sans="DNS:github.com, DNS:www.github.com",
              subject="CN=github.com"):
    return """Certificate:
    Data:
        Issuer: C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36
        Validity
            Not Before: Sep  1 00:00:00 2026 GMT
            Not After : %s
        Subject: %s
        Subject Public Key Info:
        X509v3 extensions:
            X509v3 Subject Alternative Name:
                %s
""" % (not_after, subject, sans)


def fake_run(version, s_client_out, x509_out=None, calls=None):
    def run(cmd, **kw):
        if calls is not None:
            calls.append(cmd)
        if cmd[1] == "version":
            return subprocess.CompletedProcess(cmd, 0, version + "\n", "")
        if cmd[1] == "s_client":
            return subprocess.CompletedProcess(cmd, 0, s_client_out.encode(), b"")
        return subprocess.CompletedProcess(cmd, 0, (x509_out or x509_text()).encode(), b"")
    return run


def result(not_after, not_before="2026-09-01T00:00:00+00:00", **kw):
    r = {"host": "example.com", "port": 443, "subject": "CN=example.com", "cn": "example.com",
         "sans": ["example.com"], "issuer": "C=US, O=Let's Encrypt, CN=R11",
         "not_before": not_before, "not_after": not_after, "protocol": "TLSv1.3",
         "cipher": "TLS_AES_128_GCM_SHA256", "verify_code": 0, "verify_text": "ok", "hostname_ok": True,
         "chain": ["example.com", "R11"], "fingerprint": "AA:BB", "openssl": "OpenSSL 4.0.3",
         "checked_at": NOW.isoformat()}
    r.update(kw)
    return r


class TargetParsing(unittest.TestCase):
    # People paste whatever they have at hand: a bare host, host:port, or a full URL.
    def test_url_scheme_path_and_userinfo_are_stripped(self):
        self.assertEqual(cert.parse_target("https://Login.Example.edu/sso/saml?x=1"), ("login.example.edu", 443))
        self.assertEqual(cert.parse_target("https://user:pw@example.com:8443/x"), ("example.com", 8443))

    def test_default_port_is_443(self):
        self.assertEqual(cert.parse_target("example.com"), ("example.com", 443))
        self.assertEqual(cert.parse_target("example.com:"), ("example.com", 443))  # mid-typing

    def test_explicit_port_and_ipv6(self):
        self.assertEqual(cert.parse_target("mail.example.com:993"), ("mail.example.com", 993))
        self.assertEqual(cert.parse_target("[2606:4700::1]:8443"), ("2606:4700::1", 8443))
        self.assertEqual(cert.parse_target("2606:4700::1"), ("2606:4700::1", 443))

    def test_garbage_is_rejected_before_any_network_call(self):
        for q in ("example.com:99999", "example.com:abc", "-oProxyCommand=x", "exa$mple.com", "://"):
            self.assertIsNone(cert.parse_target(q), q)

    def test_ip_literal_skips_sni_and_verifies_ip(self):
        cmd = cert.s_client_cmd("/x/openssl", "1.2.3.4", 443, True)
        self.assertNotIn("-servername", cmd)
        self.assertEqual(cmd[-2:], ["-verify_ip", "1.2.3.4"])


class OpensslFlags(unittest.TestCase):
    def test_openssl_gets_sni_and_hostname_verification(self):
        cmd = cert.s_client_cmd("/opt/homebrew/bin/openssl", "example.com", 8443, True)
        self.assertEqual(cmd[2:], ["-connect", "example.com:8443", "-servername", "example.com",
                                   "-verify_hostname", "example.com"])

    def test_homebrew_openssl_is_preferred_over_system_libressl(self):
        # Apple silicon Homebrew, then Intel Homebrew, then LibreSSL (which can't verify host names).
        self.assertEqual(cert.OPENSSL_PATHS, ("/opt/homebrew/bin/openssl", "/usr/local/bin/openssl", "/usr/bin/openssl"))
        for present, want in ((cert.OPENSSL_PATHS, "/opt/homebrew/bin/openssl"),
                              (("/usr/local/bin/openssl", "/usr/bin/openssl"), "/usr/local/bin/openssl"),
                              (("/usr/bin/openssl",), "/usr/bin/openssl"),
                              ((), None)):
            with mock.patch.object(cert.os, "access", side_effect=lambda p, mode: p in present):
                self.assertEqual(cert.find_openssl(), want, present)

    def test_libressl_never_gets_verify_hostname(self):
        # LibreSSL 3.3 aborts on unknown options, which would look like a broken host.
        cmd = cert.s_client_cmd("/usr/bin/openssl", "example.com", 443, False)
        self.assertIn("-servername", cmd)
        self.assertNotIn("-verify_hostname", cmd)


class ExpiryThreshold(unittest.TestCase):
    # The warning is what gets a certificate renewed before it lapses.
    def level(self, delta, threshold=30):
        return cert.expiry_status("2026-01-01T00:00:00+00:00", (NOW + delta).isoformat(), NOW, threshold)

    def test_under_threshold_warns(self):
        self.assertEqual(self.level(datetime.timedelta(days=29, hours=23)), ("warn", 29))

    def test_exactly_threshold_does_not_warn(self):
        self.assertEqual(self.level(datetime.timedelta(days=30, hours=1)), ("ok", 30))

    def test_threshold_comes_from_warn_days_variable(self):
        with mock.patch.dict(os.environ, {"WARN_DAYS": "60"}):
            items = cert.result_items(result((NOW + datetime.timedelta(days=45)).isoformat()), now=NOW)
        self.assertTrue(items[0]["title"].startswith("example.com · expires in 45 days"))
        self.assertEqual(items[0]["icon"], {"path": "icons/expiring.png"})  # the icon carries the warning
        with mock.patch.dict(os.environ, {"WARN_DAYS": "junk"}):
            self.assertEqual(cert.warn_days(), 30)

    def test_expired_is_flagged_even_one_second_past(self):
        self.assertEqual(self.level(datetime.timedelta(seconds=-1))[0], "expired")
        items = cert.result_items(result("2015-04-12T23:59:59+00:00"), now=NOW, threshold=30)
        self.assertEqual(items[0]["icon"], {"path": "icons/expired.png"})
        self.assertIn("EXPIRED", items[0]["title"])
        self.assertIn("expired", items[0]["arg"])

    def test_days_since_expiry_are_not_overstated(self):
        # Quoted in reports: "expired 1 day ago" for a cert that lapsed 3 hours ago is wrong.
        def title(delta):
            return cert.result_items(result((NOW - delta).isoformat()), now=NOW, threshold=30)[0]["title"]
        self.assertIn("EXPIRED today", title(datetime.timedelta(hours=3)))
        self.assertIn("EXPIRED 1 day ago", title(datetime.timedelta(hours=36)))
        self.assertIn("EXPIRED 4213 days ago", title(datetime.timedelta(days=4213, hours=2)))

    def test_not_yet_valid_is_flagged(self):
        r = result("2027-12-01T00:00:00+00:00", not_before="2026-11-01T00:00:00+00:00")
        self.assertIn("NOT YET VALID", cert.result_items(r, now=NOW, threshold=30)[0]["title"])

    def test_healthy_cert_title_has_no_warning(self):
        items = cert.result_items(result("2026-12-05T00:00:00+00:00"), now=NOW, threshold=30)
        self.assertEqual(items[0]["title"], "example.com · expires in 41 days (2026-12-05)")


class HostnameMatching(unittest.TestCase):
    def test_wildcard_covers_exactly_one_label(self):
        sans = [["DNS", "*.badssl.com"], ["DNS", "badssl.com"]]
        self.assertTrue(cert.hostname_matches("expired.badssl.com", sans))
        self.assertFalse(cert.hostname_matches("wrong.host.badssl.com", sans))

    def test_cn_ignored_when_sans_present(self):
        self.assertFalse(cert.hostname_matches("legacy.example.com", [["DNS", "other.example.com"]], "legacy.example.com"))

    def test_ip_matches_only_ip_sans(self):
        self.assertTrue(cert.hostname_matches("1.2.3.4", [["IP Address", "1.2.3.4"]]))
        self.assertFalse(cert.hostname_matches("1.2.3.4", [["DNS", "1.2.3.4"]]))


class CheckWithMockedOpenssl(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        mock.patch.object(cert, "CACHE_DIR", self.tmp).start()
        mock.patch.object(cert, "find_openssl", return_value="/opt/homebrew/bin/openssl").start()
        self.addCleanup(mock.patch.stopall)

    def test_openssl_output_is_fully_reported(self):
        with mock.patch.object(cert.subprocess, "run", fake_run("OpenSSL 4.0.3 29 Sep 2026", OPENSSL_S_CLIENT)):
            r = cert.check("github.com", 443)
        self.assertEqual((r["cn"], r["protocol"], r["cipher"], r["verify_code"]),
                         ("github.com", "TLSv1.3", "TLS_AES_128_GCM_SHA256", 0))
        self.assertEqual(r["sans"], ["github.com", "www.github.com"])
        self.assertEqual(r["not_after"], "2026-11-29T23:59:59+00:00")
        self.assertEqual(r["chain"], ["github.com", "Sectigo Public Server Authentication CA DV E36"])
        self.assertEqual(r["fingerprint"].replace(":", ""), hashlib.sha256(DER).hexdigest().upper())

    def test_libressl_ok_but_name_mismatch_is_reported_as_failure(self):
        # LibreSSL can't verify the name, so its "0 (ok)" must not be trusted on its own.
        x = x509_text(sans="DNS:*.badssl.com, DNS:badssl.com", subject="CN=*.badssl.com")
        with mock.patch.object(cert.subprocess, "run", fake_run("LibreSSL 3.3.6", LIBRESSL_S_CLIENT, x)):
            r = cert.check("wrong.host.badssl.com", 443)
        self.assertEqual((r["protocol"], r["verify_code"], r["verify_text"]), ("TLSv1.2", 62, "hostname mismatch"))
        self.assertIn("✗ hostname mismatch", cert.result_items(r, now=NOW, threshold=30)[0]["subtitle"])

    def test_success_is_cached_for_retyping(self):
        calls = []
        with mock.patch.object(cert.subprocess, "run", fake_run("OpenSSL 4", OPENSSL_S_CLIENT, calls=calls)):
            cert.cached_check("github.com", 443)
            n = len(calls)
            cert.cached_check("github.com", 443)
        self.assertEqual(len(calls), n)
        self.assertEqual([f for f in os.listdir(self.tmp) if f.endswith(".tmp")], [])

    def test_errors_are_not_cached(self):
        calls = []
        with mock.patch.object(cert.subprocess, "run", fake_run("OpenSSL 4", "connect: Connection refused", calls=calls)):
            for _ in range(2):
                with self.assertRaises(cert.CertError):
                    cert.cached_check("example.com", 1)
        self.assertEqual(sum(1 for c in calls if c[1] == "s_client"), 2)


class ErrorClassification(unittest.TestCase):
    # Each failure needs a different fix (typo vs. firewall vs. wrong port), so they must not blur together.
    CASES = {
        "dns": ["807F:error:10080002:BIO routines:BIO_lookup_ex:system lib:crypto/bio/bio_addr.c:772:"
                "nodename nor servname provided, or not known",
                "getaddrinfo: nodename nor servname provided, or not known"],
        "refused": ["807F:error:8000003D:system library:BIO_connect:Connection refused:crypto/bio/bio_sock2.c:183:",
                    "connect: Connection refused\nconnect:errno=61"],
        "handshake": ["807F:error:0A00010B:SSL routines:tls_validate_record_header:wrong version number:x.c:67:\n"
                      "CONNECTED(00000005)\nno peer certificate available",
                      "828:error:1404B42E:SSL routines:ST_CONNECT:tlsv1 alert protocol version:/A/b.c:151:"],
        "timeout": ["connect: Operation timed out"],
    }

    def test_real_outputs_classify(self):
        for kind, outputs in self.CASES.items():
            for out in outputs:
                self.assertEqual(cert.classify_error(out), kind, out)

    def test_handshake_message_names_the_reason(self):
        e = cert.error_for("handshake", "example.com:80", self.CASES["handshake"][0])
        self.assertEqual(e.subtitle, "wrong version number (not TLS on this port?)")

    def test_subprocess_timeout_becomes_a_readable_item(self):
        def run(cmd, **kw):
            if cmd[1] == "version":
                return subprocess.CompletedProcess(cmd, 0, "OpenSSL 4\n", "")
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 8))
        with mock.patch.object(cert, "find_openssl", return_value="/x/openssl"), \
                mock.patch.object(cert, "CACHE_DIR", tempfile.gettempdir()), \
                mock.patch.object(cert.subprocess, "run", run):
            item = cert.items_for("10.255.255.1")[0]
        self.assertEqual(item["title"], "Timed out after 8 s: 10.255.255.1")
        self.assertEqual(item["mods"]["cmd"]["arg"], "https://crt.sh/?q=10.255.255.1")

    def test_missing_openssl_still_returns_an_item(self):
        with mock.patch.object(cert, "find_openssl", return_value=None), \
                mock.patch.object(cert, "CACHE_DIR", tempfile.gettempdir()):
            self.assertEqual(cert.items_for("example.com")[0]["title"], "openssl not found")


class ItemsAndPlist(unittest.TestCase):
    def test_every_item_copies_summary_and_cmd_opens_crtsh(self):
        items = cert.result_items(result("2026-12-05T00:00:00+00:00"), now=NOW, threshold=30)
        self.assertEqual(len(items), 3)
        for it in items:
            self.assertIn("SHA-256: AA:BB", it["arg"])
            self.assertEqual(it["text"]["largetype"], it["arg"])
            self.assertEqual(it["mods"]["cmd"]["arg"], "https://crt.sh/?q=example.com")

    def test_plist_wires_exactly_the_emitted_mods(self):
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "info.plist"), "rb") as f:
            pl = plistlib.load(f)
        sf = next(o["uid"] for o in pl["objects"] if o["type"] == "alfred.workflow.input.scriptfilter")
        types = {o["uid"]: o["type"] for o in pl["objects"]}
        wired = {c["modifiers"]: types[c["destinationuid"]] for c in pl["connections"][sf]}
        self.assertEqual(wired, {0: "alfred.workflow.output.clipboard", 1048576: "alfred.workflow.action.openurl"})
        emitted = set(cert.result_items(result("2026-12-05T00:00:00+00:00"), now=NOW, threshold=30)[0]["mods"])
        self.assertEqual(emitted, {"cmd"})


def icon_name(item):
    return os.path.basename(item["icon"]["path"])[:-len(".png")]


class Icons(unittest.TestCase):
    # The icon is read before the title: a red icon must mean "act now", grey "couldn't check",
    # and a green lock only a cert that is in date, trusted and matches the host.
    def summary_icon(self, days_left, threshold=30, **kw):
        r = result((NOW + datetime.timedelta(days=days_left, hours=1)).isoformat(), **kw)
        return icon_name(cert.result_items(r, now=NOW, threshold=threshold)[0])

    def test_healthy_cert_gets_the_lock(self):
        self.assertEqual(self.summary_icon(41), "valid")

    def test_expiry_warning_band_boundary(self):
        # Same boundary as the title warning: 29 days left warns, 30 does not.
        self.assertEqual(self.summary_icon(29), "expiring")
        self.assertEqual(self.summary_icon(30), "valid")
        self.assertEqual(self.summary_icon(59, threshold=60), "expiring")

    def test_expired_and_not_yet_valid(self):
        self.assertEqual(self.summary_icon(-1), "expired")
        r = result("2027-12-01T00:00:00+00:00", not_before="2026-11-01T00:00:00+00:00")
        self.assertEqual(icon_name(cert.result_items(r, now=NOW, threshold=30)[0]), "expired")

    def test_expired_beats_untrusted(self):
        # openssl reports an expired cert as verify code 10; the icon should say why it failed.
        self.assertEqual(self.summary_icon(-5, verify_code=10, verify_text="certificate has expired"), "expired")

    def test_trust_and_name_failures_get_the_shield(self):
        self.assertEqual(self.summary_icon(41, verify_code=18, verify_text="self-signed certificate"), "untrusted")
        self.assertEqual(self.summary_icon(41, verify_code=20, verify_text="unable to get local issuer"), "untrusted")
        self.assertEqual(self.summary_icon(41, verify_code=62, verify_text="hostname mismatch", hostname_ok=False),
                         "untrusted")
        # Untrusted outranks "expires soon": renewing won't fix a trust problem.
        self.assertEqual(self.summary_icon(5, verify_code=18, verify_text="self-signed certificate"), "untrusted")

    def test_sans_and_chain_items(self):
        ok = cert.result_items(result("2026-12-05T00:00:00+00:00"), now=NOW, threshold=30)
        bad = cert.result_items(result("2026-12-05T00:00:00+00:00", verify_code=19, verify_text="self-signed"),
                                now=NOW, threshold=30)
        self.assertEqual([icon_name(i) for i in ok[1:]], ["sans", "chain-ok"])
        self.assertEqual([icon_name(i) for i in bad[1:]], ["sans", "chain-bad"])

    def test_check_failures(self):
        def item_for(kind):
            with mock.patch.object(cert, "cached_check", side_effect=cert.error_for(kind, "example.com")):
                return cert.items_for("example.com")[0]
        got = {k: icon_name(item_for(k)) for k in ("dns", "refused", "unreachable", "timeout", "handshake", "unknown")}
        self.assertEqual(got, {"dns": "network", "refused": "network", "unreachable": "network",
                               "timeout": "timeout", "handshake": "error", "unknown": "error"})

    def test_prompt_and_bad_input(self):
        self.assertEqual(icon_name(cert.items_for("")[0]), "hint")
        self.assertEqual(icon_name(cert.items_for("exa$mple.com")[0]), "warning")

    def test_every_icon_is_rendered(self):
        # Fails if ICONS changed without re-running make_icons.py.
        for name in cert.ICONS:
            self.assertTrue(os.path.getsize(os.path.join(cert.HERE, "icons", name + ".png")) > 0, name)

    def test_missing_png_leaves_alfreds_default_icon(self):
        # Not rendered or not yet synced by iCloud: no icon key, never a broken path.
        empty = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, empty)
        with mock.patch.object(cert, "HERE", empty):
            items = cert.result_items(result("2026-12-05T00:00:00+00:00"), now=NOW, threshold=30)
        self.assertTrue(all("icon" not in i for i in items))
        self.assertEqual(len(items), 3)

    def test_unknown_icon_name_is_a_bug(self):
        with self.assertRaises(KeyError):
            cert.icon("expird")


class MakeIcons(unittest.TestCase):
    def setUp(self):
        import make_icons
        self.mk = make_icons

    def test_jobs_cover_every_icon(self):
        jobs = self.mk.jobs("/x")
        self.assertEqual(sorted(os.path.basename(j["out"]) for j in jobs), sorted(n + ".png" for n in cert.ICONS))
        self.assertTrue(all(j["symbol"] and j["bg"].startswith("#") for j in jobs))

    def test_partial_render_fails_loudly(self):
        # iconkit skips an icon it can't draw (e.g. unknown SF Symbol); the script must not report success.
        n = len(cert.ICONS)
        for out, code in (("%d/%d" % (n - 1, n), 1), ("%d/%d" % (n, n), 0), ("", 1)):
            done = subprocess.CompletedProcess([], 0, out + "\n", "")
            with mock.patch.object(self.mk.subprocess, "run", return_value=done), \
                    mock.patch.object(self.mk, "HERE", tempfile.mkdtemp()) as here, \
                    mock.patch("sys.stdout"):
                self.assertEqual(self.mk.main(), code, out)
            shutil.rmtree(here)


if __name__ == "__main__":
    unittest.main()
