#!/usr/bin/env python3
"""Check an AirPlay receiver password with HTTP Digest over RTSP.

This talks to the AirPlay port directly (no pair-verify, no encryption) and
prints the response for an authenticated SETUP request. It helps to tell a
wrong password (401) apart from a receiver that silently ignores the remote
control channel.

Example:
    python3 airplay_password_check.py \
        --host 192.168.10.84 \
        --local-ip 192.168.10.10 \
        --password-file /var/lib/homebridge/appletv-enhanced/8A1F2B85830B/airplay-password
"""

import argparse
import hashlib
import re
import socket


def _md5(value):
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def _digest(method, uri, username, realm, password, nonce):
    ha1 = _md5(f"{username}:{realm}:{password}")
    ha2 = _md5(f"{method}:{uri}")
    return _md5(f"{ha1}:{nonce}:{ha2}")


def _request(sock, raw):
    sock.sendall(raw)
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        return "TIMEOUT"
    return data.decode("utf-8", errors="replace")


def _check(host, port, uri, password, username):
    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(5)
    try:
        challenge = _request(
            sock,
            b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n"
            b"User-Agent: MediaControl/1.0\r\n\r\n",
        )
        if challenge == "TIMEOUT":
            return "TIMEOUT while requesting challenge", ""

        realm = re.search(r'realm="([^"]*)"', challenge)
        nonce = re.search(r'nonce="([^"]*)"', challenge)
        if realm is None or nonce is None:
            return "no Digest challenge", challenge

        authorization = (
            f'Digest username="{username}", realm="{realm.group(1)}", '
            f'nonce="{nonce.group(1)}", uri="{uri}", '
            f'response="{_digest("SETUP", uri, username, realm.group(1), password, nonce.group(1))}"'
        )
        response = _request(
            sock,
            (
                f"SETUP {uri} RTSP/1.0\r\nCSeq: 2\r\n"
                f"User-Agent: AirPlay/550.10\r\n"
                f"Authorization: {authorization}\r\n"
                f"Content-Length: 0\r\n\r\n"
            ).encode("utf-8"),
        )
        if response == "TIMEOUT":
            return "TIMEOUT after authenticated SETUP", challenge
        status = response.split("\r\n", 1)[0]
        return status, response
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, help="Apple TV IP address")
    parser.add_argument("--port", type=int, default=7000)
    parser.add_argument("--local-ip", default=None, help="local IP used in the RTSP URI")
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--username", action="append", default=None)
    args = parser.parse_args()

    with open(args.password_file, encoding="utf-8") as password_file:
        password = password_file.read().rstrip("\r\n")

    local_ip = args.local_ip
    if local_ip is None:
        local_ip = socket.gethostbyname(socket.gethostname())
    uri = f"rtsp://{local_ip}/1"

    print(f"receiver: {args.host}:{args.port}, uri: {uri}")
    print(f"password length: {len(password)}")

    for username in args.username or ["AirPlay", "pyatv", "iTunes"]:
        status, response = _check(args.host, args.port, uri, password, username)
        print(f"username={username}: {status}")
        if status.startswith("RTSP/1.0 200") or (
            status.startswith("RTSP/1.0 4") and not status.startswith("RTSP/1.0 401")
        ):
            print(response)


if __name__ == "__main__":
    main()
