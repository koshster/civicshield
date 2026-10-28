"""TLS prober: certificate retrieval and protocol/cipher support probes.

Every connection goes through the Gateway (scope + SSRF + rate limit), exactly like HTTP.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass

from civicshield.engine.net.errors import TargetUnreachableError
from civicshield.engine.net.gateway import Gateway
from civicshield.engine.net.tls_wire import (
    ProbeReply,
    TLSVersion,
    build_client_hello,
    parse_server_reply,
    record_length,
)


@dataclass(frozen=True)
class CertFetch:
    leaf_der: bytes | None
    verified: bool
    # OpenSSL verify result when verification failed, e.g. 10 = expired,
    # 18 = self-signed leaf, 20 = unable to get local issuer (incomplete chain or
    # unknown CA), 62 = hostname mismatch.
    verify_code: int | None
    verify_message: str | None
    protocol: str | None  # negotiated by our default client, e.g. "TLSv1.3"
    cipher: str | None


class TLSProber:
    def __init__(self, gateway: Gateway, ssl_context: ssl.SSLContext, timeout: float) -> None:
        self.gateway = gateway
        self.ssl_context = ssl_context
        self.timeout = timeout

    async def _handshake(
        self, host: str, port: int, ctx: ssl.SSLContext
    ) -> tuple[bytes | None, str | None, str | None]:
        host, ip = await self.gateway.connect_target(host)
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(str(ip), port, ssl=ctx, server_hostname=host),
                self.timeout,
            )
        except (TimeoutError, ConnectionError, OSError) as exc:
            if isinstance(exc, ssl.SSLCertVerificationError):
                raise
            raise TargetUnreachableError(f"TLS connection to {host}:{port} failed: {exc}") from exc
        try:
            sslobj = writer.get_extra_info("ssl_object")
            der = sslobj.getpeercert(binary_form=True) if sslobj else None
            cipher = sslobj.cipher()[0] if sslobj and sslobj.cipher() else None
            return der, sslobj.version() if sslobj else None, cipher
        finally:
            writer.close()

    async def fetch_certificate(self, host: str, port: int = 443) -> CertFetch:
        """Handshake with full verification; on failure, fetch the cert unverified.

        The second, unverified handshake exists so we can still *describe* a broken
        certificate (expiry date, names) instead of only saying "verification failed".
        """
        try:
            der, proto, cipher = await self._handshake(host, port, self.ssl_context)
            return CertFetch(der, True, None, None, proto, cipher)
        except ssl.SSLCertVerificationError as exc:
            code, message = exc.verify_code, exc.verify_message
        insecure = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        der, proto, cipher = await self._handshake(host, port, insecure)
        return CertFetch(der, False, code, message, proto, cipher)

    async def probe(
        self, host: str, version: TLSVersion, cipher_suites: tuple[int, ...], port: int = 443
    ) -> ProbeReply:
        """Send one hand-built ClientHello and classify the server's first reply."""
        host, ip = await self.gateway.connect_target(host)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(str(ip), port), self.timeout
            )
        except (TimeoutError, OSError) as exc:
            raise TargetUnreachableError(f"connect to {host}:{port} failed: {exc}") from exc
        try:
            writer.write(build_client_hello(host, version, cipher_suites))
            await writer.drain()
            try:
                header = await asyncio.wait_for(reader.readexactly(5), self.timeout)
                payload = await asyncio.wait_for(
                    reader.readexactly(min(record_length(header), 16384)), self.timeout
                )
            except asyncio.IncompleteReadError as exc:
                # Many servers just close the connection instead of sending an alert.
                return parse_server_reply(exc.partial)
            except (TimeoutError, ConnectionError) as exc:
                return ProbeReply(False, detail=f"no response: {exc}")
            reply = parse_server_reply(header + payload)
            # A server that answers with a *different* version than offered didn't
            # accept ours (e.g. we offered 1.0, it insists on 1.2 → protocol error).
            if reply.accepted and reply.version != version:
                return ProbeReply(
                    False, version=reply.version, detail="server answered with a different version"
                )
            return reply
        finally:
            writer.close()
