"""Outbound URL validation (SR-6), the control against SSRF.

Partners register a webhook URL that our service will later call. Without
checks, a partner (or anyone holding a stolen partner token) could point it
at http://169.254.169.254/ and read the instance's AWS credentials, or at an
internal admin service. Defense in depth: this check + IMDSv2 with hop limit 1
(terraform) + egress through a proxy in production."""
import ipaddress
import socket
from typing import Callable, Iterable
from urllib.parse import urlsplit

Resolver = Callable[[str], Iterable[str]]


class UnsafeURL(ValueError):
    pass


def _system_resolver(host: str) -> list[str]:
    return [info[4][0] for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)]


def validate_outbound_url(url: str, allowed_hosts: frozenset, resolve: Resolver = _system_resolver) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise UnsafeURL("only https is allowed")
    if parts.username or parts.password:
        raise UnsafeURL("credentials in URL are not allowed")
    host = (parts.hostname or "").lower()
    if host not in allowed_hosts:
        raise UnsafeURL("host is not on the partner allowlist")
    if parts.port not in (None, 443):
        raise UnsafeURL("only port 443 is allowed")
    # Allowlisted names can still resolve somewhere bad (DNS takeover, a typo
    # in the allowlist), so check every address the name resolves to.
    addresses = list(resolve(host))
    if not addresses:
        raise UnsafeURL("host does not resolve")
    for addr in addresses:
        ip = ipaddress.ip_address(addr)
        if not ip.is_global:
            raise UnsafeURL("host resolves to a non-public address")
    return url
