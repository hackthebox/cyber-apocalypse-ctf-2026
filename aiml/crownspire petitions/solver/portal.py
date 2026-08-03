#!/usr/bin/env python3
"""Minimal, dependency-free client for the Crownspire Petitions WEB portal.

Stdlib only (urllib + http.cookiejar). The portal is passwordless: POST a Subject Number to
`/api/session`, which validates it server-side and sets an httpOnly `cp_session` cookie whose
role is derived from the number. `/developers` then renders a BACKEND-DRIVEN, role-based agent
directory (citizen: the Docket Agent only; qa: additionally the hidden Casework Agent host and a
storage-layout note). This client logs in and scrapes those hosts out of the rendered HTML, so
the solver never hardcodes the hidden hostname.
"""
import http.cookiejar
import json
import re
import urllib.error
import urllib.request

CROWNSPIRE_SUFFIX = r"[a-z0-9-]+\.crownspire-petitions\.htb"


class Portal:
    """Passwordless web session. `login(sn)` then `developers()` / `hosts()`."""

    def __init__(self, base):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.role = None

    def login(self, subject_number, timeout=30):
        """POST the Subject Number to /api/session. Returns the role, or None if rejected."""
        data = json.dumps({"subjectNumber": subject_number}).encode()
        req = urllib.request.Request(
            self.base + "/api/session", data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with self.opener.open(req, timeout=timeout) as r:
                body = json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code == 401:
                self.role = None
                return None
            raise
        self.role = body.get("role")
        return self.role

    def logout(self, timeout=30):
        req = urllib.request.Request(self.base + "/api/session", method="DELETE")
        try:
            self.opener.open(req, timeout=timeout).read()
        except urllib.error.HTTPError:
            pass
        self.jar.clear()
        self.role = None

    def developers(self, timeout=30):
        """GET the session-gated /developers page HTML (redirects to /login without a session)."""
        req = urllib.request.Request(self.base + "/developers", method="GET")
        with self.opener.open(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")

    def hosts(self, timeout=30):
        """Return every crownspire-petitions.htb host named in the role's /developers directory."""
        html = self.developers(timeout=timeout)
        seen, out = set(), []
        for h in re.findall(CROWNSPIRE_SUFFIX, html):
            if h not in seen and not h.startswith("www."):
                seen.add(h)
                out.append(h)
        return out

    def petitions_dir(self, timeout=30):
        """Scrape the Backup Status note for the directory the Docket Agent reads (qa role only)."""
        html = self.developers(timeout=timeout)
        # New Backup Status card: "Petition storage</dt><dd><code ...>/opt/petitions</code>".
        m = re.search(r"Petition storage.*?<code[^>]*>\s*([^<\s]+)", html, re.S | re.I)
        if not m:  # fall back to the older free-text storage note
            m = re.search(r"reads petition records from\s+([^\s<]+)", html)
        return m.group(1) if m else None
