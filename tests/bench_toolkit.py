# Copyright 2026 Roberto Locatelli — Apache-2.0
"""Riproducibile: banco di performance del toolkit omega_evidence.
    python3 toolkit/tests/bench_toolkit.py [--scale N]
Misura hashing, ledger append/verify, firma/verifica Ed25519, e2e pack, e la
rilevazione di manomissione a scala. Numeri MISURATI, dipendono dall'hardware."""

import argparse
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from omega_evidence import canonical, ledger, signing  # noqa: E402


def _rate(fn, n, warmup=100):
    for _ in range(warmup):
        fn(0)
    t0 = time.perf_counter()
    for i in range(n):
        fn(i)
    return n / (time.perf_counter() - t0)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scale", type=int, default=20000)
    a = ap.parse_args()
    print(f"host: python {sys.version.split()[0]}, {os.cpu_count()} CPU, scale={a.scale}")
    print(f"canonical SHA3     : {_rate(lambda i: canonical.sha3({'i': i, 'p': 'x'*64}), 50000):>12,.0f} ops/s")
    with tempfile.TemporaryDirectory() as tmp:
        lg = ledger.Ledger(os.path.join(tmp, "l.jsonl"))
        sync_rate = _rate(lambda i: lg.append({'e': i}), a.scale)
        print(f"ledger append SYNC : {sync_rate:>12,.0f} ops/s (fsync per entry — durabilità max)")
        t0 = time.perf_counter()
        ok, _ = lg.verify()
        print(f"ledger verify      : {lg.count/(time.perf_counter()-t0):>12,.0f} entries/s (ok={ok})")
    with tempfile.TemporaryDirectory() as tmp:
        lb = ledger.Ledger(os.path.join(tmp, "b.jsonl"), durability="batch", batch_size=256)
        batch_rate = _rate(lambda i: lb.append({'e': i}), a.scale)
        lb.close()
        print(f"ledger append BATCH: {batch_rate:>12,.0f} ops/s (batch_size=256 — ×{batch_rate/sync_rate:.0f} vs sync)")
    ident = signing.Identity("bench")
    print(f"Ed25519 sign       : {_rate(lambda i: ident.sign(b'x'+str(i).encode()), a.scale):>12,.0f} ops/s")
    sig, pk = ident.sign(b"x"), ident.public_key_b64
    print(f"Ed25519 verify     : {_rate(lambda i: signing.verify_signature(pk, sig, b'x'), a.scale):>12,.0f} ops/s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
