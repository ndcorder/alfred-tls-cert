#!/usr/bin/env python3
"""Alfred Script Filter: TLS certificate check.

  cert.py <host | host:port | URL>

Runs `openssl s_client` (SNI + hostname verification) and `openssl x509` on the
leaf. Homebrew OpenSSL is preferred; /usr/bin/openssl (LibreSSL 3.3) has no
-verify_hostname, so the hostname is also matched against the SANs here.
"""
import base64
import datetime
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse

OPENSSL_PATHS = ("/opt/homebrew/bin/openssl", "/usr/bin/openssl")
TIMEOUT = 8
CACHE_DIR = os.environ.get("alfred_workflow_cache", "/tmp/alfred-cert-check")
CACHE_TTL = 300
HOST_RE = re.compile(r"^[a-z0-9_*]([a-z0-9_.*-]*[a-z0-9_])?$")
UTC = datetime.timezone.utc
HERE = os.path.dirname(os.path.abspath(__file__))

# Static icon set: name -> (background, white SF Symbol). make_icons.py renders it into icons/.
OK, WARN, BAD, NEUTRAL, INFO = "#15803D", "#B45309", "#B91C1C", "#4B5563", "#1D4ED8"
ICONS = {
    "valid": (OK, "lock.fill"),
    "expiring": (WARN, "clock.badge.exclamationmark.fill"),
    "expired": (BAD, "xmark.seal.fill"),  # also "not yet valid": outside the validity window either way
    "untrusted": (BAD, "exclamationmark.shield.fill"),
    "sans": (INFO, "list.bullet"),
    "chain-ok": (OK, "link"),
    "chain-bad": (BAD, "link"),
    "network": (NEUTRAL, "network.slash"),
    "timeout": (WARN, "hourglass"),
    "warning": (WARN, "exclamationmark.triangle.fill"),
    "error": (BAD, "xmark.octagon.fill"),
    "hint": (INFO, "lightbulb.fill"),
}
# CertError.kind -> icon. Network-level failures are grey: they say nothing about the certificate.
ERROR_ICONS = {"dns": "network", "refused": "network", "unreachable": "network", "timeout": "timeout"}


class CertError(Exception):
    def __init__(self, kind, title, subtitle):
        Exception.__init__(self, title)
        self.kind, self.title, self.subtitle = kind, title, subtitle


# --- input -----------------------------------------------------------------

def parse_target(query):
    """'https://Example.com:8443/path' -> ('example.com', 8443). None if unusable."""
    q = query.strip()
    q = re.sub(r"^[a-z][a-z0-9+.-]*://", "", q, flags=re.I)
    q = re.split(r"[/?#\s]", q, 1)[0]
    q = q.rsplit("@", 1)[-1]  # drop user:pass@
    if q.startswith("["):
        m = re.match(r"^\[([0-9a-fA-F:.]+)\](?::(\d*))?$", q)
        if not m:
            return None
        host, port = m.group(1), m.group(2)
    elif q.count(":") > 1:  # bare IPv6 literal, no port
        host, port = q, None
    else:
        host, _, port = q.partition(":")
    host = host.rstrip(".").lower()
    if not host:
        return None
    if not is_ip(host) and not HOST_RE.match(host):
        return None
    if port:
        if not port.isdigit() or not 0 < int(port) < 65536:
            return None
        return host, int(port)
    return host, 443


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def target_label(host, port):
    shown = "[%s]" % host if ":" in host else host
    return shown if port == 443 else "%s:%d" % (shown, port)


# --- openssl ---------------------------------------------------------------

def find_openssl():
    return next((p for p in OPENSSL_PATHS if os.access(p, os.X_OK)), None)


def openssl_version(openssl):
    out = subprocess.run([openssl, "version"], capture_output=True, text=True, timeout=3).stdout
    return out.strip() or "unknown"


def s_client_cmd(openssl, host, port, modern):
    """modern = OpenSSL (has -verify_hostname/-verify_ip); LibreSSL 3.3 rejects them."""
    connect = "[%s]:%d" % (host, port) if ":" in host else "%s:%d" % (host, port)
    cmd = [openssl, "s_client", "-connect", connect]
    if is_ip(host):
        if modern:
            cmd += ["-verify_ip", host]
    else:
        cmd += ["-servername", host]
        if modern:
            cmd += ["-verify_hostname", host]
    return cmd


# Checked in order: "no peer certificate" also appears after a refused handshake.
ERROR_PATTERNS = (
    ("dns", ("nodename nor servname", "name or service not known", "getaddrinfo",
             "no address associated", "bio_lookup")),
    ("refused", ("connection refused",)),
    ("timeout", ("timed out",)),
    ("unreachable", ("no route to host", "network is unreachable", "host is down")),
    ("handshake", ("wrong version number", "handshake failure", "alert", "unexpected eof",
                   "packet length too long", "connection reset", "no peer certificate",
                   "ssl routines")),
)


def classify_error(output):
    low = output.lower()
    for kind, needles in ERROR_PATTERNS:
        if any(n in low for n in needles):
            return kind
    return "unknown"


def error_for(kind, label, output=""):
    if kind == "dns":
        return CertError(kind, "Can't resolve %s" % label, "DNS lookup failed: check the host name")
    if kind == "refused":
        return CertError(kind, "Connection refused: %s" % label, "Nothing is listening on that port")
    if kind == "timeout":
        return CertError(kind, "Timed out after %d s: %s" % (TIMEOUT, label),
                         "Host down, port filtered, or very slow")
    if kind == "unreachable":
        return CertError(kind, "Network unreachable: %s" % label, "No route to host (VPN?)")
    detail = last_error_line(output)
    if kind == "handshake":
        hint = " (not TLS on this port?)" if "wrong version" in output.lower() else ""
        return CertError(kind, "TLS handshake failed: %s" % label, (detail or "no certificate received") + hint)
    return CertError(kind, "Check failed: %s" % label, detail or "openssl gave no certificate")


def last_error_line(output):
    """'...:SSL routines:x:wrong version number:file.c:67:' -> 'wrong version number'."""
    for line in output.splitlines():
        if ":error:" in line:
            parts = [p for p in line.split(":") if p]
            # OpenSSL: ...:func:reason:file:line ; reason is the human-readable bit
            for p in reversed(parts):
                if " " in p and not p.startswith("/") and "." not in p.split()[0]:
                    return p.strip()
    return ""


def parse_s_client(output):
    pem = re.search(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", output, re.S)
    if not pem:
        return None
    proto = re.search(r"^\s*Protocol\s*:\s*(\S+)", output, re.M)
    cipher = re.search(r"Cipher is (\S+)", output) or re.search(r"^\s*Cipher\s*:\s*(\S+)", output, re.M)
    verify = re.search(r"Verify return code: (\d+) \(([^)]*)\)", output)
    chain = [dn_name(m) for m in re.findall(r"^\s*\d+ s:(.*)$", output, re.M)]
    return {
        "pem": pem.group(0),
        "protocol": proto.group(1) if proto else "?",
        "cipher": cipher.group(1) if cipher else "?",
        "verify_code": int(verify.group(1)) if verify else -1,
        "verify_text": verify.group(2) if verify else "no verify result",
        "chain": chain,
    }


def dn_attr(dn, attr):
    found = re.findall(r"(?:^|[,/])\s*%s\s*=\s*([^,/]+)" % attr, dn)
    return found[-1].strip() if found else ""


def dn_name(dn):
    return dn_attr(dn, "CN") or dn_attr(dn, "O") or dn.strip()


def parse_x509_text(text):
    def field(pattern):
        m = re.search(pattern, text, re.M)
        return m.group(1).strip() if m else ""

    san_line = field(r"X509v3 Subject Alternative Name:.*\n\s*(.+)$")
    sans = []
    for entry in filter(None, (s.strip() for s in san_line.split(","))):
        kind, _, value = entry.partition(":")
        sans.append([kind.strip(), value.strip()])
    return {
        "subject": field(r"^\s*Subject:\s*(.*)$"),
        "issuer": field(r"^\s*Issuer:\s*(.*)$"),
        "not_before": parse_date(field(r"Not Before\s*:\s*(.+)$")),
        "not_after": parse_date(field(r"Not After\s*:\s*(.+)$")),
        "sans": sans,
    }


def parse_date(s):
    """'Nov 29 23:59:59 2026 GMT' -> ISO 8601 UTC string (JSON-cacheable)."""
    if not s:
        return ""
    dt = datetime.datetime.strptime(s.replace(" GMT", ""), "%b %d %H:%M:%S %Y")
    return dt.replace(tzinfo=UTC).isoformat()


def sha256_fingerprint(pem):
    body = "".join(l for l in pem.splitlines() if l and not l.startswith("-----"))
    digest = hashlib.sha256(base64.b64decode(body)).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def hostname_matches(host, sans, subject_cn=""):
    """RFC 6125: SANs only (CN only if no SANs); a wildcard covers exactly one left-most label."""
    if is_ip(host):
        want = ipaddress.ip_address(host)
        for kind, value in sans:
            if kind.upper().startswith("IP"):
                try:
                    if ipaddress.ip_address(value) == want:
                        return True
                except ValueError:
                    pass
        return False
    names = [v for k, v in sans if k.upper() == "DNS"] or ([subject_cn] if subject_cn else [])
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and "." in host:
            first, rest = host.split(".", 1)
            if first and rest == name[2:]:
                return True
    return False


def check(host, port):
    """Network check. Returns a JSON-serialisable dict or raises CertError."""
    label = target_label(host, port)
    openssl = find_openssl()
    if not openssl:
        raise CertError("missing", "openssl not found", " or ".join(OPENSSL_PATHS))
    version = openssl_version(openssl)
    modern = version.startswith("OpenSSL")
    try:
        r = subprocess.run(s_client_cmd(openssl, host, port, modern), input=b"",
                           capture_output=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        raise error_for("timeout", label)
    output = (r.stdout + b"\n" + r.stderr).decode("utf-8", "replace")
    conn = parse_s_client(output)
    if not conn:
        raise error_for(classify_error(output), label, output)

    x = subprocess.run([openssl, "x509", "-noout", "-text"], input=conn["pem"].encode(),
                       capture_output=True, timeout=TIMEOUT)
    leaf = parse_x509_text(x.stdout.decode("utf-8", "replace"))
    if not leaf["not_after"]:
        raise CertError("parse", "Could not read the certificate: %s" % label,
                        x.stderr.decode("utf-8", "replace").strip()[:200] or "openssl x509 gave no dates")

    cn = dn_attr(leaf["subject"], "CN")
    host_ok = hostname_matches(host, leaf["sans"], cn)
    code, text = conn["verify_code"], conn["verify_text"]
    if code == 0 and not host_ok:  # LibreSSL path: openssl did not check the name
        text = "IP address mismatch" if is_ip(host) else "hostname mismatch"
        code = 64 if is_ip(host) else 62
    return {
        "host": host, "port": port,
        "subject": leaf["subject"], "cn": cn or dn_name(leaf["subject"]),
        "sans": [v if k.upper() == "DNS" else "%s:%s" % (k, v) for k, v in leaf["sans"]],
        "issuer": leaf["issuer"],
        "not_before": leaf["not_before"], "not_after": leaf["not_after"],
        "protocol": conn["protocol"], "cipher": conn["cipher"],
        "verify_code": code, "verify_text": text, "hostname_ok": host_ok,
        "chain": conn["chain"],
        "fingerprint": sha256_fingerprint(conn["pem"]),
        "openssl": version,
        "checked_at": datetime.datetime.now(UTC).isoformat(),
    }


# --- cache -----------------------------------------------------------------

def cache_path(host, port):
    key = hashlib.sha1(("%s:%d" % (host, port)).encode()).hexdigest()
    return os.path.join(CACHE_DIR, key + ".json")


def cached_check(host, port):
    """Only successful checks are cached, so a timeout or refused port retries on the next keystroke."""
    path = cache_path(host, port)
    if os.path.exists(path) and time.time() - os.path.getmtime(path) < CACHE_TTL:
        try:
            with open(path) as f:
                return json.load(f)
        except ValueError:
            pass
    result = check(host, port)
    os.makedirs(CACHE_DIR, exist_ok=True)
    tmp = "%s.%d.tmp" % (path, os.getpid())
    with open(tmp, "w") as f:
        json.dump(result, f)
    os.replace(tmp, path)  # Alfred kills the previous run on each keystroke
    return result


# --- rendering -------------------------------------------------------------

def warn_days():
    try:
        return int(os.environ.get("WARN_DAYS", "30"))
    except ValueError:
        return 30


def expiry_status(not_before, not_after, now, threshold):
    """-> (level, days left). level: expired | notyet | warn | ok."""
    end = datetime.datetime.fromisoformat(not_after)
    days = (end - now).days  # floors: 29 d 23 h left counts as 29
    if now >= end:
        return "expired", -(now - end).days  # floor the time since expiry: 3 h ago = "today"
    if not_before and now < datetime.datetime.fromisoformat(not_before):
        return "notyet", days
    if days < threshold:
        return "warn", days
    return "ok", days


def plural(n, word):
    return "%d %s%s" % (n, word, "" if n == 1 else "s")


def expiry_phrase(level, days, end_date, start_date):
    if level == "expired":
        ago = -days if days < 0 else 0
        return "EXPIRED %s ago (%s)" % (plural(ago, "day"), end_date) if ago else "EXPIRED today (%s)" % end_date
    if level == "notyet":
        return "NOT YET VALID until %s" % start_date
    if days == 0:
        return "expires in under a day (%s)" % end_date
    return "expires in %s (%s)" % (plural(days, "day"), end_date)


def issuer_short(issuer):
    cn, org = dn_attr(issuer, "CN"), dn_attr(issuer, "O")
    if cn and org and org not in cn:
        return "%s (%s)" % (cn, org)
    return cn or org or issuer


def verify_label(r):
    if r["verify_code"] == 0:
        return "✓ trusted"
    return "✗ %s" % r["verify_text"]


def summary_text(r, level, days, threshold):
    start, end = r["not_before"][:19].replace("T", " "), r["not_after"][:19].replace("T", " ")
    if level == "expired":
        left = "expired %s ago" % plural(-days, "day") if days < 0 else "expired today"
    else:
        left = "%s left%s" % (plural(days, "day"), " (under %d-day warning)" % threshold if level == "warn" else "")
    lines = [
        "TLS certificate: %s:%d (checked %s UTC)" % (r["host"], r["port"], r["checked_at"][:16].replace("T", " ")),
        "Subject CN: %s" % r["cn"],
        "SANs (%d): %s" % (len(r["sans"]), ", ".join(r["sans"]) or "none"),
        "Issuer: %s" % r["issuer"],
        "Valid from: %s UTC%s" % (start, " (NOT YET VALID)" if level == "notyet" else ""),
        "Valid until: %s UTC (%s)" % (end, left),
        "Verify: %s (code %d)" % ("OK" if r["verify_code"] == 0 else r["verify_text"], r["verify_code"]),
        "Hostname match: %s" % ("yes" if r["hostname_ok"] else "NO"),
        "Protocol: %s" % r["protocol"],
        "Cipher: %s" % r["cipher"],
        "Chain: %s" % (" ← ".join(r["chain"]) or "?"),
        "SHA-256: %s" % r["fingerprint"],
    ]
    return "\n".join(lines)


def crtsh_url(host):
    return "https://crt.sh/?q=" + urllib.parse.quote(host)


def icon(name):
    """Alfred icon for a static icon name. None if the PNG is missing (set not rendered or not
    synced yet): the item then gets no icon key and Alfred shows the workflow icon."""
    rel = "icons/%s.png" % name
    ICONS[name]  # KeyError on a typo, so a wrong name fails in tests rather than showing no icon
    return {"path": rel} if os.path.exists(os.path.join(HERE, rel)) else None


def with_icon(item, name):
    found = icon(name)
    if found:
        item["icon"] = found
    return item


def status_icon(r, level):
    """Worst problem first. An expired cert also fails verification (code 10); expiry is the
    more specific reason. A trust or name failure outranks a cert that merely expires soon."""
    if level in ("expired", "notyet"):
        return "expired"
    if r["verify_code"] != 0 or not r["hostname_ok"]:
        return "untrusted"
    return "expiring" if level == "warn" else "valid"


def result_items(r, now=None, threshold=None):
    now = now or datetime.datetime.now(UTC)
    threshold = warn_days() if threshold is None else threshold
    level, days = expiry_status(r["not_before"], r["not_after"], now, threshold)
    label = target_label(r["host"], r["port"])
    summary = summary_text(r, level, days, threshold)
    cmd = {"arg": crtsh_url(r["host"]), "subtitle": "Open crt.sh for %s" % r["host"]}

    def item(uid, title, subtitle, copy, icon_name):
        return with_icon({"uid": uid, "title": title, "subtitle": subtitle, "arg": summary, "valid": True,
                          "text": {"copy": copy, "largetype": summary}, "mods": {"cmd": dict(cmd)}}, icon_name)

    sans = r["sans"]
    covers = "✓ covers %s" % r["host"] if r["hostname_ok"] else "✗ does not cover %s" % r["host"]
    if r["verify_code"] == 0:
        vtitle = "Verify: OK · hostname matches"
    else:
        vtitle = "Verify failed: %s (code %d)" % (r["verify_text"], r["verify_code"])
    return [
        item("summary", "%s · %s" % (label, expiry_phrase(level, days, r["not_after"][:10], r["not_before"][:10])),
             "%s · %s · %s" % (issuer_short(r["issuer"]), r["protocol"], verify_label(r)), summary,
             status_icon(r, level)),
        item("sans", "%s: %s" % (plural(len(sans), "SAN"), ", ".join(sans) or "none"), covers, "\n".join(sans),
             "sans"),
        item("verify", vtitle, "Chain: %s · %s" % (" ← ".join(r["chain"]) or "?", r["cipher"]), r["fingerprint"],
             "chain-ok" if r["verify_code"] == 0 else "chain-bad"),
    ]


def message(title, subtitle="", arg=None, mods=None, icon_name="error"):
    item = {"title": title, "subtitle": subtitle, "valid": arg is not None}
    if arg is not None:
        item["arg"] = arg
    if mods:
        item["mods"] = mods
    return with_icon(item, icon_name)


def items_for(query):
    if not query.strip():
        return [message("Check a TLS certificate", "host, host:port or URL · ↩ copy summary · ⌘↩ crt.sh · ⌘L details",
                        icon_name="hint")]
    target = parse_target(query)
    if not target:
        return [message("Not a host, host:port or URL: %s" % query.strip(), "e.g. example.com, example.com:8443, https://example.com/x",
                        icon_name="warning")]
    host, port = target
    try:
        return result_items(cached_check(host, port))
    except CertError as e:
        cmd = {"arg": crtsh_url(host), "subtitle": "Open crt.sh for %s" % host, "valid": True}
        return [message(e.title, e.subtitle, "%s: %s (%s)" % (target_label(host, port), e.title, e.subtitle), {"cmd": cmd},
                        icon_name=ERROR_ICONS.get(e.kind, "error"))]


def main():
    query = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        items = items_for(query)
    except Exception as e:  # every query must still print valid Script Filter JSON
        items = [message("cert error: %s" % e.__class__.__name__, str(e)[:200])]
    json.dump({"items": items, "skipknowledge": True}, sys.stdout)


if __name__ == "__main__":
    main()
