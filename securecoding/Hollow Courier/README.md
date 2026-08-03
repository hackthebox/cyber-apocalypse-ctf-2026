![img](../../assets/banner.png)



<img src='./assets/logo.png' style='zoom: 70%;' align=left /> <font size='10'>The Hollow Courier</font>

24<sup>th</sup> June 2026

Prepared By: `Pyp`

Challenge Author(s): `Pyp`

Difficulty: <font color='green'>Easy</font>

<br><br>
<br><br>

# Synopsis

The Hollow Courier is a secure-coding challenge built around a Flask checkpoint service behind a Caddy reverse proxy. A privileged inner endpoint seals crown decrees for callers whose origin address belongs to an internal network.

That origin address is not the caller's real one. Werkzeug reconstructs it from the `X-Forwarded-For` chain, the application trusts one forwarding hop too many, and the perimeter trusts a proxy range broad enough to carry a forwarded address inward instead of replacing it with the real peer. The address the gate evaluates is therefore drawn from the forwarding chain, so a request that presents a forwarded address across the public perimeter resolves to a private, internal-looking one. The inner desk answers it.

The patch must make the perimeter own the forwarding chain so network position cannot be reached from outside the wall, without breaking the Watch's own internal traffic.

## Description
Lysa Harrowmere has intercepted a Vaultrune route packet ordering the Ashguard away from a Crownspire supply road. She warns Garran Voss that one of tonight's couriers is carrying the order through Salt Gate under a convincing writ. If the decree is sealed before the watch changes, Vaultrune gains an undefended road into Crownspire and another lie acquires the force of law. Garran must identify the compromised passage, uncover how it survived the gate's checks, and stop it without blocking genuine inner-yard runners.
objective: Restore trustworthy forwarded-client provenance across the Caddy and Flask boundary while preserving the legitimate internal route.

## Skills Required

- HTTP forwarding-header semantics
- Reverse-proxy trust boundaries
- Flask and Werkzeug middleware
- Caddy reverse-proxy configuration
- Basic Git and pull-request workflow

## Skills Learned

- Treat forwarding headers as untrusted until a known proxy establishes them.
- Match `ProxyFix` hop counts to the deployed proxy topology.
- Make the perimeter authoritative for the client-address chain.
- Apply defense in depth across proxy and application boundaries.

# Enumeration

## Application access

The Git and pull-request interface is served at `/`. The checkpoint application is served at:

```text
http://[IP]:[PORT]/app
```

The Checkpoint Ledger records passages and accepts signed writs. Its public workflow functions normally.

## Repository access

Clone the repository and create the required development branch:

```bash
git clone http://htb_developer:HTBDeveloperPassword@[IP]:[PORT]/git/core_application.git
cd core_application
git checkout -b developer
```

The relevant files are under `checkpoint/`:

```text
checkpoint/
|-- app/routes.py       # privileged route
|-- app/gate.py         # internal-origin decision
|-- app/__init__.py     # ProxyFix configuration
`-- conf/Caddyfile      # application perimeter
```

# Identifying the Vulnerability

## Origin-based authority

`app/gate.py` accepts private network ranges and the watch relay's loopback alias as internal:

```python
INTERNAL_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.2/32"),
)

def is_internal_request() -> bool:
    try:
        origin = ipaddress.ip_address(request.remote_addr or "")
    except ValueError:
        return False
    return any(origin in network for network in INTERNAL_NETWORKS)
```

`app/routes.py` uses this result to guard `POST /app/gate/decree`. The check is only as trustworthy as `request.remote_addr`, and `request.remote_addr` is not the socket peer here. It is reconstructed from forwarding headers.

## The origin is reconstructed, not observed

The app reconstructs the client address with `ProxyFix`:

```python
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=2, x_proto=1, x_host=1)
```

`ProxyFix` reads the `X-Forwarded-For` chain from the right and, with `x_for=2`, trusts two hops: it walks past the last address and takes the second from the right as the client. That is correct only if exactly two proxies it trusts actually wrote those entries. The decree desk sits behind a single application perimeter, so trusting two hops reaches one entry too far, into forwarding data the perimeter has not established.

## The perimeter carries the forwarding chain inward

The application perimeter, `checkpoint/conf/Caddyfile`, is the boundary the request crosses:

```caddy
:8000 {
    reverse_proxy 127.0.0.1:5000 {
        trusted_proxies private_ranges
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

Caddy replaces `X-Forwarded-For` with the immediate peer by default, and only preserves an incoming chain when that peer is a trusted proxy. `private_ranges` is broad: it covers every RFC1918 network and loopback. So instead of overwriting the forwarding data with the real peer, this perimeter treats a private upstream as trusted and carries its forwarded address inward, where `ProxyFix(x_for=2)` selects it as the origin.

## Reaching the inner desk from outside

Because the perimeter trusts a broad forwarding range rather than replacing the chain, an `X-Forwarded-For` value that a courier presents at the wall is carried inward instead of being discarded. A request that crosses the public perimeter with a forged forwarding entry therefore reaches the app as that entry followed by the perimeter's own hop:

```text
X-Forwarded-For: 10.0.0.5, 127.0.0.1
```

`ProxyFix(x_for=2)` walks one hop past the perimeter and selects `10.0.0.5`, the origin check sees an address inside `10.0.0.0/8`, and the desk treats the courier as internal. No special tooling is required, only a single forged header:

```bash
curl -s -H 'X-Forwarded-For: 10.0.0.5' -d 'order=clear the Vaultrune road' http://[IP]:[PORT]/app/gate/decree
```

```json
{"authority": "CROWN", "decree": 1, "order": "clear the Vaultrune road", "sealed": true}
```

A courier on the road has sealed a crown decree. Any private, internal-listed value works the same way, so the boundary cannot be restored by handling one address or one header spelling: validation exercises supplied forwarding headers across several header names, casings, and private ranges, and a fix must neutralize the whole class rather than a single observed value.

# Real-World Impact

Deriving authority from network position is fragile because the network position an application sees is itself assembled from forwarding metadata. When the proxy tier trusts that metadata too broadly and the application counts one hop too many, an outside request resolves to an inside address and privileged, internal-only routes answer the public. The same mistake bypasses IP allowlists, corrupts audit trails that record a manufactured origin, and turns rate limits or access rules into attacker-influenced policy. Each component looks reasonable alone; the flaw lives in the contract between them.

# Solution

The perimeter must own the forwarding chain, and the application must trust only the proxy hops that actually exist.

Remove the over-broad proxy trust and explicitly replace the forwarded address in `checkpoint/conf/Caddyfile`, so the perimeter establishes the origin from its real peer rather than carrying an upstream value inward:

```caddy
:8000 {
    reverse_proxy 127.0.0.1:5000 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

Then correct the hop count in `checkpoint/app/__init__.py` so the app trusts only that single perimeter:

```python
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
```

With both changes the address the gate evaluates becomes the perimeter's real peer instead of a forwarded value, so a request crossing the public perimeter no longer resolves to an internal address and the decree desk turns it away. The Watch's own runners, which reach the service on its internal address without crossing the wall, still pass. Deploying both halves is defense in depth: each independently removes the extra hop of trust. A production system should also avoid using network location as the sole authorization factor.

## Submitting the Patch

```bash
git add checkpoint/conf/Caddyfile checkpoint/app/__init__.py
git commit -m "restore forwarded-origin provenance"
git push -u origin developer
```

The push creates a pull request for automated review. Follow its status at:

```text
http://[IP]:[PORT]/pulls
```

The validation sends supplied forwarding chains across header names, casing, formats, and private ranges, and confirms none of them reaches the inner desk once the request has crossed the public perimeter. It also confirms that the legitimate internal path and the public ledger remain available.

## Getting the Flag

After the pull request reaches the required hard and soft scores:

```bash
curl -s http://[IP]:[PORT]/flag | jq
```

Incomplete fixes, such as blocking one address or one header spelling, leave the origin derivable from forwarding data and do not pass validation.
