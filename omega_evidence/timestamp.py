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
omega_evidence.timestamp — RFC 3161 trusted timestamping via openssl.

Graceful degradation: if openssl is absent, verification returns None
("recorded but not verified") — never a false positive. A qualified TSA (on the
EU Trusted List) additionally carries legal presumption of time; judging
qualification is left to the consumer of the evidence.
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess  # nosec B404 - fixed-arg openssl calls, no shell
import tempfile
import urllib.request
from urllib.parse import urlparse
from typing import Dict, Optional


def stamp(digest_hex: str, tsa_url: str, timeout: int = 20) -> Dict:
    """Request an RFC 3161 token for digest_hex from a TSA. Returns
    {anchored, tsa, tsr_b64} or {anchored: False, note}."""
    if urlparse(tsa_url).scheme not in ("http", "https"):
        return {"anchored": False, "note": "TSA URL scheme not allowed"}
    exe = shutil.which("openssl")
    if not exe:
        return {"anchored": False, "note": "openssl absent (RFC 3161 optional)"}
    d = tempfile.mkdtemp()
    try:
        tsq = os.path.join(d, "q.tsq")
        r = subprocess.run(  # nosec B603
            [exe, "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", tsq],
            capture_output=True, timeout=timeout)
        if r.returncode != 0 or not os.path.exists(tsq):
            return {"anchored": False, "note": "openssl ts-query failed"}
        req = open(tsq, "rb").read()
        http = urllib.request.Request(tsa_url, data=req, method="POST",
                                      headers={"Content-Type": "application/timestamp-query"})
        resp = urllib.request.urlopen(http, timeout=timeout).read()  # nosec B310 - scheme checked
        return {"anchored": True, "tsa": tsa_url, "tsr_b64": base64.b64encode(resp).decode()}
    except Exception as e:  # noqa: BLE001
        return {"anchored": False, "note": f"{type(e).__name__}: {str(e)[:80]}"}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def verify(tsr_b64: str, expected_digest_hex: str, timeout: int = 15) -> Dict:
    """Verify an RFC 3161 token: status Granted AND message-imprint == expected.
    openssl absent → {verified: None}."""
    exe = shutil.which("openssl")
    if not exe:
        return {"verified": None, "note": "openssl absent — token recorded but NOT verified"}
    d = tempfile.mkdtemp()
    try:
        tsr = os.path.join(d, "t.tsr")
        open(tsr, "wb").write(base64.b64decode(tsr_b64))
        r = subprocess.run(  # nosec B603
            [exe, "ts", "-reply", "-in", tsr, "-text"], capture_output=True, text=True, timeout=timeout)
        text = r.stdout or ""
        granted = "Status: Granted" in text or "Granted." in text
        grab, hexbytes = False, []
        for ln in text.splitlines():
            if "Message data:" in ln:
                grab = True
                continue
            if grab:
                if ln.strip() and ln[0] not in " \t":
                    break
                if " - " not in ln:
                    continue
                hexpart = ln.split(" - ", 1)[1].split("   ")[0]
                for tok in hexpart.replace("-", " ").split():
                    if len(tok) == 2 and all(c in "0123456789abcdefABCDEF" for c in tok):
                        hexbytes.append(tok.lower())
        imprint_ok = "".join(hexbytes) == expected_digest_hex.lower()
        return {"verified": bool(granted and imprint_ok), "granted": granted, "imprint_ok": imprint_ok}
    except Exception as e:  # noqa: BLE001
        return {"verified": False, "note": f"{type(e).__name__}: {str(e)[:80]}"}
    finally:
        shutil.rmtree(d, ignore_errors=True)
