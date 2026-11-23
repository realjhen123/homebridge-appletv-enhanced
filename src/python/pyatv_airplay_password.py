"""AirPlay password (HTTP Digest) support for pyatv.

pyatv 0.18 supports the receiver password for classic RAOP/AirPlay streaming,
but it never sends it on the AirPlay 2 remote control channel. A password
protected Apple TV answers the first RTSP request with

    RTSP/1.0 401 Unauthorized
    WWW-Authenticate: Digest realm="airplay", nonce="..."

pyatv does not retry with an Authorization header, so the remote control
channel setup fails.

This module monkey-patches ``RtspSession.exchange``: when a request is
challenged, it retries it with an HTTP Digest ``Authorization`` header built
from the AirPlay password in ``PYATV_AIRPLAY_PASSWORD``.

The module is a no-op when the environment variable is not set.
"""

import logging
import os
import re
import weakref

_LOGGER = logging.getLogger(__name__)

_PASSWORD = os.environ.get("PYATV_AIRPLAY_PASSWORD")

if _PASSWORD:
    from pyatv import exceptions
    from pyatv.support import rtsp
    from pyatv.support.http import http_connect

    # The documented AirPlay digest username is "AirPlay" (RAOP uses "iTunes").
    _AUTH_USERNAME = "AirPlay"
    _REALM_RE = re.compile(r'realm="([^"]*)"', re.IGNORECASE)
    _NONCE_RE = re.compile(r'nonce="([^"]*)"', re.IGNORECASE)

    _original_exchange = rtsp.RtspSession.exchange
    _connection_challenges = weakref.WeakKeyDictionary()

    def _challenge(response):
        headers = response.headers
        www_authenticate = headers.get("www-authenticate") or headers.get(
            "WWW-Authenticate"
        )
        if not www_authenticate:
            return None
        realm = _REALM_RE.search(www_authenticate)
        nonce = _NONCE_RE.search(www_authenticate)
        if realm is None or nonce is None:
            return None
        return realm.group(1), nonce.group(1)

    def _install_preauth_probe():
        """Ask for a challenge on the plain connection, before pair-verify.

        ``AP2Session.connect`` verifies the HAP credentials first and only
        afterwards creates the RTSP session. By then the connection is
        encrypted, and the receiver might silently drop an unauthenticated
        RTSP request. Patching ``verify_connection`` lets us send ``OPTIONS *``
        on the still plaintext connection and keep the nonce for the later
        ``SETUP``.
        """
        from pyatv.protocols.airplay import ap2_session

        original_verify_connection = ap2_session.verify_connection

        async def verify_connection(credentials, connection):
            try:
                response = await connection.send_and_receive(
                    "OPTIONS",
                    "*",
                    allow_error=True,
                    timeout=5,
                    protocol="RTSP/1.0",
                    user_agent="MediaControl/1.0",
                )
                if response.code == 401:
                    challenge = _challenge(response)
                    if challenge is not None:
                        _connection_challenges[connection] = challenge
                        _LOGGER.debug(
                            "AirPlay password challenge received before pair-verify"
                        )
            except Exception:  # pylint: disable=broad-except
                _LOGGER.debug(
                    "Could not fetch AirPlay password challenge before pair-verify",
                    exc_info=True,
                )
            return await original_verify_connection(credentials, connection)

        ap2_session.verify_connection = verify_connection

    _install_preauth_probe()

    async def _fetch_challenge(connection):
        """Return the Digest challenge for this connection, if available."""
        challenge = _connection_challenges.get(connection)
        if challenge is not None:
            del _connection_challenges[connection]
            return challenge

        transport = getattr(connection, "transport", None)
        if transport is None:
            return None

        peer = transport.get_extra_info("peername")
        if not peer:
            return None

        probe = None
        try:
            probe = await http_connect(peer[0], peer[1])
            response = await probe.send_and_receive(
                "OPTIONS",
                "*",
                allow_error=True,
                timeout=5,
                protocol="RTSP/1.0",
                # Apple TV replies 403 to OPTIONS with pyatv's user agent
                user_agent="MediaControl/1.0",
            )
            if response.code == 401:
                return _challenge(response)
        except Exception:  # pylint: disable=broad-except
            _LOGGER.debug(
                "Could not fetch AirPlay password challenge in advance",
                exc_info=True,
            )
        finally:
            if probe is not None:
                probe.close()
        return None

    async def _exchange(
        self,
        method,
        uri=None,
        content_type=None,
        headers=None,
        body=None,
        allow_error=False,
        protocol="RTSP/1.0",
    ):
        if self.digest_info is not None:
            return await _original_exchange(
                self, method, uri, content_type, headers, body, allow_error, protocol
            )

        # Prefer a challenge fetched over a separate plain connection. This
        # also works when the encrypted control connection drops unauthenticated
        # requests without replying.
        challenge = await _fetch_challenge(self.connection)
        if challenge is not None:
            realm, nonce = challenge
            _LOGGER.debug(
                "AirPlay password challenge received in advance (realm=%s)", realm
            )
            self.digest_info = rtsp.DigestInfo(
                _AUTH_USERNAME, realm, _PASSWORD, nonce
            )
            return await _original_exchange(
                self, method, uri, content_type, headers, body, allow_error, protocol
            )

        # Send the first request with allow_error so a Digest challenge can be
        # inspected instead of being raised by pyatv's HTTP implementation.
        response = await _original_exchange(
            self, method, uri, content_type, headers, body, True, protocol
        )

        if response.code == 401:
            challenge = _challenge(response)
            if challenge is not None:
                realm, nonce = challenge
                _LOGGER.debug(
                    "AirPlay password challenge received (realm=%s), retrying", realm
                )
                self.digest_info = rtsp.DigestInfo(
                    _AUTH_USERNAME, realm, _PASSWORD, nonce
                )
                return await _original_exchange(
                    self,
                    method,
                    uri,
                    content_type,
                    headers,
                    body,
                    allow_error,
                    protocol,
                )

        if response.code == 403:
            raise exceptions.AuthenticationError("not authenticated")
        if 200 <= response.code < 300 or allow_error:
            return response
        raise exceptions.HttpError(
            f"RTSP method {method} failed with code {response.code}: "
            f"{response.message}",
            response.code,
        )

    rtsp.RtspSession.exchange = _exchange
