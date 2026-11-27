# Copyright 2026 Roberto Locatelli
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
omega_evidence._crl_fetch — the one place that downloads a CRL named by a certificate: a closed rule (20/11/2026).

A CRL distribution point is a URL written by whoever made the certificate. Until 0.12.0 `timestamp._fetch_crls` gave
every such URL of every certificate of a token to `urllib.request.urlopen` after checking only its scheme: a GET to
`http://127.0.0.1:<port>/latest/meta-data/...` named by the self-made certificate of a token nobody had verified was
sent, and the answer was stored in the timestamp sidecar (measured 20/11/2026). `timestamp.extract_validation_material`
decides WHICH certificates may name a URL (only those of the signer's chain of a token verified against the caller's
trust anchor); this module decides which URL is asked and what is kept of the answer.

The rule (everything not listed is refused, with the reason, before any connection):

1. the URL is a string without white space, control characters or a backslash; scheme `http` or `https` (compared
   without case, RFC 3986 §3.1); a host; no userinfo; no percent sign in the host; a port, when written, from 1 to
   65535;
2. the host is judged as the ADDRESS that is connected to, not as text: an IP literal in any form `inet_aton` reads
   (`127.1`, `2130706433`, `0x7f000001`, `0177.0.0.1`) or `inet_pton` reads as IPv6; a host with characters outside
   ASCII in its IDNA form (fullwidth digits become ASCII digits); a name by EVERY address the resolver gives for it. An
   IPv6 address that carries an IPv4 one (IPv4-mapped, 6to4, Teredo, NAT64 64:ff9b::/96) is judged by that one too;
3. only a public address is asked: loopback, unspecified, link-local, private, shared (100.64.0.0/10), site-local,
   multicast, reserved, and whatever else `ipaddress` does not call global, are refused. `localhost` and names under
   `.localhost` are refused without asking the resolver; a name that does not resolve is refused;
4. the connection goes to the address that was judged (the name is not resolved a second time: an answer that changes
   between the check and the connection cannot move it), directly: the proxies of the environment are not used;
5. redirects are not followed: any status but 200 is an error that names the status;
6. the answer is read up to `max_bytes` + 1 and, from the moment the connection is made, within `timeout` seconds in
   all (not per read: a server that sends one byte at a time is cut at the deadline); beyond either it is dropped,
   never kept in part;
7. the bytes are kept only when they are one DER CertificateList, read by its structure in strict DER (RFC 5280 §5.1:
   a SEQUENCE of tbsCertList, signatureAlgorithm and a BIT STRING; tbsCertList begins with an optional INTEGER
   version, the signature algorithm, the issuer and thisUpdate as a UTCTime or GeneralizedTime — a certificate, whose
   outer structure is the same, has a validity SEQUENCE there): RFC 5280 §4.2.1.13, "When the HTTP or FTP URI scheme is used, the URI MUST point to a single
   DER encoded CRL as specified in [RFC2585]" (read at rfc-editor.org on 20/11/2026; RFC 5280 is not obsoleted). Its
   signature and its issuer are NOT checked here: what is kept is material for a later validation, not a verdict.

Reading the host as an address follows `cryptovalid_net.py` of cryptovalid-opencore (same author; SPEC v0.12 §20 rule
1, 19/11/2026): the logic of its `_address` is written again here, not imported. There a redirect is followed after
the same check and a name is resolved twice; here neither happens (rules 4 and 5).

Not closed, stated: with https the certificate of the server is checked against the system's trust store as usual; a
public host is asked on whatever port the certificate's author wrote.

URLs the CALLER gives (`ask`, 20/11/2026): the TSA of `timestamp.stamp`, the calendars of `ots.submit`, the feed and the
update of `chip_registry.discover_online` / `fetch_signed_update_online`. Their address is the caller's choice and is
not judged (a TSA on the local network is legitimate); what the SERVER decides is: rule 1 (the URL), rule 5 (a redirect
is never followed: until 0.12.0 each of the four followed one to another host, and `ots.submit` wrote the answer of the
second host in the `.ots.json` sidecar, measured 20/11/2026) and a bound on bytes (each caller names it; until 0.12.0
none: a 70 MiB answer of a calendar was stored whole). Time: `timeout` for each read, and an answer still arriving
after `timeout` seconds in all is dropped. The proxies of the environment are used, as before.
"""

from __future__ import annotations

import errno
import http.client
import ipaddress
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from typing import List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from . import _tsa_keyid

CRL_MAX_BYTES = 8 * 1024 * 1024          # one CRL
CRL_TOTAL_MAX_BYTES = 32 * 1024 * 1024   # all the CRLs of one capture: base64 in the sidecar stays under the 64 MiB a verifier reads
CRL_MAX_URLS = 16                        # distribution points asked in one capture

_SHARED = ipaddress.ip_network("100.64.0.0/10")   # RFC 6598; `is_private` is False for it and `is_global` too
_NAT64 = ipaddress.ip_network("64:ff9b::/96")     # RFC 6052: the last 32 bits are an IPv4 address


class Refused(ValueError):
    """the rule of this module refuses the URL or the answer; the message is the reason"""


def address_of(host) -> Optional[ipaddress._BaseAddress]:
    """The IP address a host string IS, or None when it is a name. The IPv4 forms of inet_aton (one to four parts, each
    decimal, octal or hexadecimal) are read as the system reads them; brackets and a final dot are dropped; a host
    outside ASCII is read in its IDNA form. An IPv4-mapped IPv6 address is the IPv4 address inside it."""
    if not isinstance(host, str) or not host:
        return None
    h = host.strip("[]").split("%", 1)[0].rstrip(".")
    if not h.isascii():
        try:
            h = h.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    if not h or any(c.isspace() for c in h):   # inet_aton stops at white space and reads what came before it
        return None
    try:
        if ":" in h:
            a = ipaddress.IPv6Address(socket.inet_pton(socket.AF_INET6, h))
        else:
            a = ipaddress.IPv4Address(socket.inet_aton(h))
    except (OSError, ValueError, UnicodeError):
        return None
    return (a.ipv4_mapped or a) if a.version == 6 else a


def _carried(a) -> List[ipaddress.IPv4Address]:
    """the IPv4 addresses an IPv6 address carries (6to4, Teredo server and client, NAT64)"""
    if a.version != 6:
        return []
    out = [x for x in (a.sixtofour,) if x is not None]
    if a.teredo is not None:
        out.extend(a.teredo)
    if a in _NAT64:
        out.append(ipaddress.IPv4Address(int(a) & 0xFFFFFFFF))
    return out


def why_not_public(a) -> Optional[str]:
    """None for an address this module may ask, else the kind that refuses it (rule 3)."""
    for kind, hit in (("loopback", a.is_loopback), ("unspecified", a.is_unspecified), ("link-local", a.is_link_local),
                      ("shared (100.64.0.0/10)", a.version == 4 and a in _SHARED),
                      ("site-local", a.version == 6 and a.is_site_local), ("private", a.is_private),
                      ("multicast", a.is_multicast), ("reserved", a.is_reserved), ("not global", not a.is_global)):
        if hit:
            return kind
    for inner in _carried(a):
        why = why_not_public(inner)
        if why:
            return f"{why} (the IPv4 address {inner} carried by {a})"
    return None


def check_url(url) -> Tuple[str, str, int, str]:
    """(scheme, host, port, request target) of a URL rule 1 accepts, the host without brackets or final dot and in
    ASCII; Refused otherwise. No I/O."""
    if not isinstance(url, str):
        raise Refused(f"a URL is a string, not {type(url).__name__}")
    if any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F or c == "\\" for c in url):
        raise Refused("white space, a control character or a backslash in the URL")
    try:
        u = urlsplit(url)
        host, port = u.hostname, u.port
    except ValueError:
        raise Refused("not a URL (urllib.parse refuses it)") from None   # its message repeats the port or the host (0.14.1)
    scheme = u.scheme.lower()
    if scheme not in ("http", "https"):
        raise Refused("the scheme is not http or https")   # not repeated: a password typed in its place (0.14.1)
    if "@" in u.netloc:
        raise Refused("userinfo in the URL")
    if not host:
        raise Refused("no host")
    if "%" in host:
        raise Refused("a percent sign in the host")
    if port is not None and not 1 <= port <= 65535:
        raise Refused("port out of range")
    host = host.rstrip(".")
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise Refused("the host has no IDNA form") from None
    if not host:
        raise Refused("no host")
    return scheme, host, port or (443 if scheme == "https" else 80), (u.path or "/") + ("?" + u.query if u.query else "")


def reason(e: BaseException) -> str:
    """What the error of asking a URL may say (0.14.1): a refusal of this module, whose reasons repeat nothing of the URL,
    or else the exception's type and errno name, never str(e), which a library may fill with the URL it was given."""
    if isinstance(e, Refused):
        return f"Refused: {e}"
    n = getattr(e, "errno", None)
    if not isinstance(n, int):
        n = getattr(getattr(e, "reason", None), "errno", None)   # urllib.error.URLError wraps the OSError
    return type(e).__name__ + (f" ({errno.errorcode.get(n, n)})" if isinstance(n, int) else "")


def url_for_record(url) -> str:
    """The URL a record names (0.14.1): scheme, host, port and path of a URL rule 1 accepts (so no userinfo), without its
    query and fragment, which can carry an access token. Refused for a URL rule 1 refuses."""
    check_url(url)
    u = urlsplit(url)
    return urlunsplit((u.scheme.lower(), u.netloc, u.path, "", ""))


def _resolve(host: str, port: int) -> List[str]:
    """every address the system's resolver gives for a name (tests replace it to answer without a network)"""
    return [info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]


def target_address(host: str, port: int) -> str:
    """The address to connect to for `host` (rules 2 and 3), or Refused."""
    low = host.lower()
    if low == "localhost" or low.endswith(".localhost"):
        raise Refused("the host is localhost")
    a = address_of(host)
    if a is not None:
        found = [a]
    else:
        try:
            got = _resolve(host, port)
        except (OSError, UnicodeError) as e:
            raise Refused(f"the host does not resolve here ({type(e).__name__})") from None
        found = [address_of(x) for x in got]
        if not found or any(x is None for x in found):
            raise Refused("the host does not resolve to IP addresses here")
    for x in found:
        why = why_not_public(x)
        if why:
            raise Refused(f"the host is a {why} address" if a is not None else f"the host resolves to a {why} address")
    return str(found[0])


def _connect(address: str, port: int, timeout: float) -> socket.socket:
    """the only place that opens a socket (tests replace it); `address` is an IP literal, never a name"""
    return socket.create_connection((address, port), timeout=timeout)


class _Pinned(http.client.HTTPConnection):
    """An HTTP(S) connection to the address that was judged; the Host header and, with TLS, the name the server's
    certificate is checked against stay the URL's host."""

    def __init__(self, scheme: str, host: str, port: int, address: str, timeout: float):
        self.default_port = 443 if scheme == "https" else 80   # the Host header names the port only when it is not this
        super().__init__(host, port, timeout=timeout)
        self._scheme, self._address = scheme, address

    def connect(self):
        self.sock = _connect(self._address, self.port, self.timeout)
        if self._scheme == "https":
            self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)


def is_der_crl(data: bytes) -> bool:
    """rule 7: one CertificateList in strict DER, by its structure (RFC 5280 section 5.1)"""
    try:
        parts = _tsa_keyid._items(_tsa_keyid._one(bytes(data), "CertificateList", 0x30), "CertificateList")
        if [t for t, _ in parts] != [0x30, 0x30, 0x03]:
            return False
        tbs = [t for t, _ in _tsa_keyid._items(parts[0][1], "tbsCertList")]
        if tbs[:1] == [0x02]:      # version, optional
            tbs = tbs[1:]
        return tbs[:2] == [0x30, 0x30] and tbs[2:3] in ([0x17], [0x18])
    except ValueError:
        return False


def _cut(sock) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)   # wakes a read that is waiting: the deadline is for the whole answer
    except OSError:
        pass


def fetch(url, timeout: float = 20, max_bytes: int = CRL_MAX_BYTES) -> bytes:
    """The DER CRL at `url`, under the rule of this module. Refused (a ValueError) when the rule refuses the URL or
    the answer; OSError and http.client.HTTPException for a connection that fails."""
    scheme, host, port, target = check_url(url)
    address = target_address(host, port)
    deadline = time.monotonic() + timeout
    late = Refused(f"no whole answer within {timeout:g} s")
    conn = _Pinned(scheme, host, port, address, timeout)
    timer = None
    try:
        conn.connect()
        timer = threading.Timer(max(0.0, deadline - time.monotonic()), _cut, (conn.sock,))
        timer.daemon = True
        timer.start()
        try:
            conn.request("GET", target, headers={"User-Agent": "omega-evidence/crl", "Accept": "application/pkix-crl",
                                                 "Accept-Encoding": "identity", "Connection": "close"})
            resp = conn.getresponse()
            if resp.status != 200:
                raise Refused(f"HTTP status {resp.status}" + (" (redirects are not followed)" if 300 <= resp.status < 400 else ""))
            chunks, total = [], 0
            while total <= max_bytes:
                b = resp.read1(min(65536, max_bytes + 1 - total))   # one read of the socket at most: the bounds are checked between reads
                if time.monotonic() >= deadline:
                    raise late
                if not b:
                    break
                chunks.append(b)
                total += len(b)
        except (OSError, http.client.HTTPException):
            if time.monotonic() >= deadline:
                raise late from None
            raise
        if total > max_bytes:
            raise Refused(f"the answer exceeds {max_bytes} bytes")
    finally:
        if timer is not None:
            timer.cancel()
        conn.close()
    data = b"".join(chunks)
    if not is_der_crl(data):
        raise Refused("the answer is not a DER CRL (RFC 5280 section 4.2.1.13)")
    return data


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """rule 5 for `ask`: a 3xx is refused, its Location never asked"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refused(f"HTTP status {code} (redirects are not followed)")


def ask(url, data: Optional[bytes] = None, headers: Optional[dict] = None, timeout: float = 20,
        max_bytes: int = CRL_MAX_BYTES) -> bytes:
    """The body of a status-200 answer to a URL the CALLER gave (POST when `data` is given, else GET), under rule 1,
    rule 5 and a bound of `max_bytes` (see the module docstring). Refused (a ValueError) for the URL, a redirect, another
    status or an answer beyond the bounds; OSError / http.client.HTTPException for a connection that fails."""
    check_url(url)
    req = urllib.request.Request(url, data=data, headers=dict(headers or {}), method="GET" if data is None else "POST")
    deadline = time.monotonic() + timeout
    try:
        resp = urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout)   # nosec B310 - rule 1 checked
    except urllib.error.HTTPError as e:
        e.close()
        raise Refused(f"HTTP status {e.code}") from None
    with resp:
        if resp.status != 200:
            raise Refused(f"HTTP status {resp.status}")
        chunks, total = [], 0
        while total <= max_bytes:
            b = resp.read1(min(65536, max_bytes + 1 - total))
            if time.monotonic() >= deadline:
                raise Refused(f"no whole answer within {timeout:g} s")
            if not b:
                break
            chunks.append(b)
            total += len(b)
    if total > max_bytes:
        raise Refused(f"the answer exceeds {max_bytes} bytes")
    return b"".join(chunks)
