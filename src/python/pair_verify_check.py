#!/usr/bin/env python3
"""Check AirPlay pair-verify against an Apple TV and print every response.

pyatv ignores the response of the final pair-verify request ("TODO: check
status code") and enables encryption even if the receiver rejected the
verification. The receiver then silently drops all encrypted traffic, which
looks like a timeout in the plugin.

This script performs pair-verify directly and prints the status code and TLV
body of each step, optionally preceded by an unauthenticated OPTIONS request,
so the effect of that request can be compared.

Example:
    /var/lib/homebridge/appletv-enhanced/.venv/bin/python3 \
        /var/lib/homebridge/appletv-enhanced/pair_verify_check.py \
        --host 192.168.10.84 \
        --credentials-file /var/lib/homebridge/appletv-enhanced/8A1F2B85830B/credentials.txt
"""

import argparse
import asyncio

from pyatv.auth import hap_tlv8
from pyatv.auth.hap_pairing import parse_credentials
from pyatv.protocols.airplay.auth import verify_connection
from pyatv.protocols.airplay.auth.hap import AirPlayHapPairVerifyProcedure
from pyatv.support.http import http_connect


def _describe(body):
    if isinstance(body, bytes):
        try:
            return hap_tlv8.read_tlv(body)
        except Exception:  # pylint: disable=broad-except
            return body.hex()
    return body


def _install_logger():
    original_send = AirPlayHapPairVerifyProcedure._send

    async def _send(self, data):
        response = await original_send(self, data)
        print(
            f"pair-verify response: {response.code} {response.message} "
            f"body={_describe(response.body)}",
            flush=True,
        )
        return response

    AirPlayHapPairVerifyProcedure._send = _send


async def _check(args, credentials):
    connection = await http_connect(args.host, args.port)
    try:
        if args.preauth:
            response = await connection.send_and_receive(
                "OPTIONS",
                "*",
                allow_error=True,
                timeout=5,
                protocol="RTSP/1.0",
                user_agent="MediaControl/1.0",
            )
            print(
                f"pre-auth OPTIONS * -> {response.code} {response.message}",
                flush=True,
            )

        await verify_connection(credentials, connection)
        print("pair-verify finished, encryption enabled", flush=True)

        try:
            response = await connection.send_and_receive(
                "GET",
                "/info",
                allow_error=True,
                timeout=5,
                protocol="RTSP/1.0",
                user_agent="AirPlay/550.10",
            )
            print(
                f"encrypted GET /info -> {response.code} {response.message}",
                flush=True,
            )
        except Exception as ex:  # pylint: disable=broad-except
            print(f"encrypted GET /info failed: {ex!r}", flush=True)
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, help="Apple TV IP address")
    parser.add_argument("--port", type=int, default=7000)
    parser.add_argument("--credentials-file", required=True)
    parser.add_argument(
        "--preauth",
        action="store_true",
        help="send an unauthenticated OPTIONS * before pair-verify",
    )
    args = parser.parse_args()

    with open(args.credentials_file, encoding="utf-8") as credentials_file:
        credentials = parse_credentials(credentials_file.read().strip())

    print(f"credentials type: {credentials.type}", flush=True)
    _install_logger()
    asyncio.run(_check(args, credentials))


if __name__ == "__main__":
    main()
