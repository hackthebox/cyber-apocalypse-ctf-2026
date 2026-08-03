![img](../../assets/banner.png)



<img src='./assets/logo.png' style='zoom: 70%;' align=left /> <font size='10'>Withered Registry</font>

26<sup>th</sup> June 2026

Prepared By: `Pyp`

Challenge Author(s): `Pyp`

Difficulty: <font color='orange'>Medium</font>

<br><br>
<br><br>

# Synopsis

Withered Registry is a secure-coding challenge built around a Go relay and an Android field client. Scribes can authenticate to a web ledger and may read records belonging to their own house. A separate field slate can issue crown writs that raise a house's standing.

The slate signs requests with a **shared** HMAC key. The relay treats that seal as authorization and accepts the target house from a request field instead of the authenticated principal. A low-privilege scribe can recover the signing scheme from the APK, authenticate normally, and issue a crown writ for another house. This level of impersonation is what must warrant a privileged action to the authenticated scribe while preserving the slate seal as an integrity check.

## Description
Chancellor Veylen Marr summons Rin Kagetsura after a forbidden recognition appears against the Ash-Vault roll, though no authorised Registry hand admits invoking it. At the next council bell, the Registry will seal its new crown roll; if the false recognition remains, Vaultrune can present a manufactured lineage as lawful proof and claim a place in the struggle for the Salt Crown. Rin must reverse the warded slate, follow seven records to discover how the rite entered the Registry, and repair the breach before Veylen seals the roll.

## Skills Required

- Go HTTP handler and middleware analysis
- Android APK and native-library reversing
- HMAC request-signing concepts
- Authentication and authorization boundaries
- BOLA and IDOR analysis
- Basic Git and pull-request workflow

## Skills Learned

- A shared application secret identifies a client build, not an authorized user.
- Privileged object scope must come from the authenticated principal.
- Mobile-only endpoints are not hidden from an attacker.
- Existing authorization checks on safe routes can reveal a missing check on a privileged route.

# Enumeration

## Application access

The web application is served at:

```text
http://[IP]:[PORT]/app/
```

The landing page is a public chronicle. Sign in at `/app/login`; an authenticated scribe then lands on their own house desk. The seeded accounts represent the current canonical houses:

```text
rin      / salt-vein-7732       Free Clans, common
veylen   / registry-hand-9051   Registry Hand, sworn custodian
damas    / brass-scale-2240     Eastreach, common
cassian  / corrected-line-6618  Vaultrune, common
```

Signing in as `rin` exposes only Free Clans records. Veylen Marr serves as the Registry Hand and can access the Registry Crown Desk because his authenticated account is assigned custody of the Ash-Vault roll.

Ash-Vault begins at `sworn` standing. A crown-standing house exposes an additional packet in its public dossier, making an unauthorized standing change observable at `/app/houses/ashvault`.

## Field slate

Download the Android client and checksum from the authenticated home desk or:

```text
http://[IP]:[PORT]/registry.apk
http://[IP]:[PORT]/registry.apk.sha256
```

The slate lets an authenticated scribe affirm their house's standing. Its UI only ever affirms the scribe's own house, so the backing route and its signing format are not visible from normal use and must be recovered from the client.

### Reversing the client

Decompiling the APK with a tool such as `jadx` or `apktool` exposes the network layer under `realm.witheredregistry.slate.net`:

- `WitheredRegistryApi` declares the endpoints the slate calls, including the slate-only `rite/recognise` route that the web UI never exposes;
- `SlateSeal` and `SigningInterceptor` build and attach the per-request signature;
- `SlateSecrets.slateSealKey()` reassembles the HMAC key, and part of that material is held in the bundled native library `libslate_secrets.so` rather than in Java, so the key is split across the DEX and an `.so` and only reconstructed at runtime.

The native half is recoverable statically by reading the strings and reconstruction routine out of `libslate_secrets.so`, or dynamically by attaching an instrumentation tool such as Frida to `slateSealKey()` and reading the returned value. Neither approach requires a rooted device beyond a standard emulator.

### The signing scheme

Once the key is recovered, `SigningInterceptor` shows exactly what is signed. The HMAC input is a newline-joined canonical string:

```text
timestamp + "\n" + method + "\n" + relay_path + "\n" + sha256(body)
```

The HMAC-SHA256 of that string, keyed with the reconstructed ASCII slate key, is sent in `X-Slate-Seal`, and the same `timestamp` is echoed in `X-Slate-Ts`. The relay path excludes the `/app` prefix because the perimeter strips that mount before forwarding, so the value signed for the recognition call is `/rite/recognise`, not `/app/rite/recognise`. The leading slash remains part of the path and therefore part of the signature.

The request passes through three distinct checks:

| Check | Evidence | What it proves |
|---|---|---|
| Session | `slate_session` cookie | Which scribe is signed in |
| Slate seal | `X-Slate-Ts` and `X-Slate-Seal` | The request body and relay-visible path were signed with the shared client key |
| House authorization | Missing on `handleRecognise` | Whether that scribe may act for the named `house_id` |

The first two checks succeed during the exploit. The vulnerability is the missing third decision, not a failure to authenticate the scribe or validate the HMAC.

### Issuing a foreign writ

The signature covers the body, so changing `house_id` after signing would invalidate it. That does not create authorization. An attacker who holds the shared key chooses a foreign `house_id` first and then signs those exact bytes. The relay confirms that the submitted body was not altered, but never checks whether the authenticated scribe may act on the object named inside it.

The following request logs in as Rin through the JSON API, keeps the resulting session cookie, signs a body naming Ash-Vault, and submits the same bytes it hashed:

```python
import hashlib, hmac, time, requests

KEY = b"<reconstructed ASCII slate key>"
body = b'{"house_id":"ashvault"}'
ts = str(int(time.time()))
canonical = "\n".join([ts, "POST", "/rite/recognise", hashlib.sha256(body).hexdigest()])
seal = hmac.new(KEY, canonical.encode(), hashlib.sha256).hexdigest()

s = requests.Session()
s.post(
    "http://[IP]:[PORT]/app/api/login",
    json={"username": "rin", "password": "salt-vein-7732"},
).raise_for_status()

r = s.post(
    "http://[IP]:[PORT]/app/rite/recognise",
    data=body,
    headers={"Content-Type": "application/json", "X-Slate-Ts": ts, "X-Slate-Seal": seal},
)
r.raise_for_status()
print(r.json())
```

The response names `ashvault` at crown standing. The state change is also visible in the public dossier at `/app/houses/ashvault`, where crown standing exposes the additional packet.

## Repository access

```bash
git clone http://htb_developer:HTBDeveloperPassword@[IP]:[PORT]/git/core_application.git
cd core_application
git checkout -b developer
```

The relevant backend files are:

```text
registry-backend/internal/server/
|-- routes.go      # recognition and read handlers
|-- signing.go     # slate signature validation
`-- authz.go       # principal-to-house authorization helpers
```

`auth.go` establishes the session principal. The decree read path already uses `ownsHouse` to reject cross-house reads.

# Identifying the Vulnerability

## The seal is not user authority

`handleRecognise` calls `requireSlate`, which recomputes the HMAC over the canonical string and rejects the request if `X-Slate-Seal` does not match or the timestamp is stale. That check answers one question only: was this request produced with the slate key. Because every distributed slate embeds the same signing material, a valid seal proves the request came from a build of the client, not that the signed-in scribe may act for the named house.

Signing changes do not close the authorization gap. Once the key is recovered from the APK it can sign any body the attacker chooses, so strengthening the HMAC, shortening the timestamp window, or rotating the embedded key leaves object scope under caller control.

## Request-controlled object scope

The vulnerable handler takes the target house from the request itself. `targetHouse` reads `house_id` from either the query string or the JSON body, and the result is passed straight into the grant:

```go
house := targetHouse(r, &body)
writ, err := s.store.GrantCrownWrit(house, p.Username)
```

The authenticated principal `p` is present, but it is used only to fill the audit name on the writ. It does not constrain which house is raised. A signed-in Free Clans scribe can therefore submit a validly sealed request naming `ashvault` and raise a house they do not serve. This is a broken-object-level-authorization (BOLA/IDOR) flaw: the object the action mutates is named by the caller and never checked against the caller's own scope.

The inconsistency is the tell. The same server already knows how to do this correctly elsewhere: the decree read path and the Registry Crown Desk both call `ownsHouse` and derive their scope from `p`, rejecting cross-house access. Only the more privileged recognition path skips that check, so the fix is not a new mechanism but the application of an existing one to the route that is missing it.

# Real-World Impact

The same failure appears in multi-tenant APIs when a valid user can change another tenant's settings, approve another account's transaction, or write records outside their organization. Session and signature checks may both pass; the missing decision is whether that principal may act on that object.

The second half is the assumption that a secret shipped inside a mobile or desktop client can serve as authorization. A distributed binary is not a trust boundary: keys embedded in DEX, native libraries, or obfuscated storage are all recoverable by a motivated attacker, so a signature made with such a key attests to the software, never to the user. Any object identifier supplied by that client must still be validated against the authenticated principal's scope on the server, which is the only place the trust boundary actually holds.

# Solution

The relay must derive the grant from the authenticated principal. A request may name a house for compatibility, but any different house must be rejected.

The canonical `handleRecognise` logic is:

```go
if !s.requireSlate(w, r) {
    return
}

p, _ := principalFrom(r)

var body recogniseRequest
if r.Body != nil {
    _ = json.NewDecoder(r.Body).Decode(&body)
}

if named := targetHouse(r, &body); named != "" && !ownsHouse(p, named) {
    writeJSON(w, http.StatusForbidden, map[string]string{
        "error": "a scribe may only act for the house they serve",
    })
    return
}

house := houseOf(p)
writ, err := s.store.GrantCrownWrit(house, p.Username)
```

This preserves the slate signature as an integrity check, reuses the existing ownership primitive, and makes the verified session the authority for object scope.

The validation varies query, body, mixed, and case-normalized target channels. It also confirms that the legitimate own-house flow and the public ledger still work. Field-specific blocks, stricter timestamps, and HMAC-only changes remain incomplete because they do not restore principal-bound authorization.

Why partial fixes fail:
- Blocking `ashvault` protects one seeded record while leaving every other foreign house writable.
- Reading only the JSON body leaves the query-string path, which `targetHouse` gives precedence.
- Rotating or hiding the slate key does not turn a distributed client secret into user authority.
- Requiring a valid session and valid seal changes nothing; the vulnerable request already has both.
- Comparing a request field with the session but still passing caller-selected scope into the store keeps authority dependent on input. The grant itself must use `houseOf(p)`.

## Submitting the Patch

```bash
git add registry-backend/internal/server/routes.go
git commit -m "bind recognition to the authenticated house"
git push -u origin developer
```

The push creates a pull request. Follow its status at:

```text
http://[IP]:[PORT]/pulls
```

## Getting the Flag

After the hard and soft validation gates pass:

```bash
curl -s http://[IP]:[PORT]/flag | jq
```
