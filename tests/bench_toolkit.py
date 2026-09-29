# Copyright 2026 Roberto Locatelli — Apache-2.0
"""Reproducible performance bench of the omega_evidence toolkit (stdlib only). Numbers are MEASURED on the host that runs
it and mean nothing without that host; the JSON output declares it.

    python3 tests/bench_toolkit.py [--scale N] [--big N] [--latency-n N] [--json OUT] [--smoke]

Measures: canonical SHA3 throughput; ledger append in sync mode (fsync per entry) and batch mode — throughput and
per-append latency p50/p95/p99; ledger verify() throughput and latency over repeated runs; verify_pack() end-to-end
latency on a signed + anchored pack; tamper detection at scale; peak memory of verify() (tracemalloc: Python
allocations; ru_maxrss: the process); and the batch-mode scale run: --big entries (default 1 000 000) appended, then
verified, with time and peak memory. --smoke shrinks everything so a CI runner only checks that it runs (no threshold:
shared runners are not a measurement)."""

import argparse
import json
import os
import platform
import resource
import statistics
import sys
import tempfile
import time
import tracemalloc

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from omega_evidence import canonical, ledger, pack, signing, trust, verify_pack  # noqa: E402


def _host():
    cpu = platform.processor() or platform.machine()
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as fh:
            for ln in fh:
                if ln.startswith("model name"):
                    cpu = ln.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    mem = None
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for ln in fh:
                if ln.startswith("MemTotal"):
                    mem = int(ln.split()[1]) // 1024
                    break
    except OSError:
        pass
    return {"cpu": cpu, "cpus": os.cpu_count(), "mem_mib": mem, "python": sys.version.split()[0],
            "implementation": platform.python_implementation(), "os": platform.platform(), "machine": platform.machine(),
            "signing_backend": signing.BACKEND, "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def _pct(samples_ns, p):
    s = sorted(samples_ns)
    if not s:
        return None
    k = max(0, min(len(s) - 1, int(round(p / 100.0 * (len(s) - 1)))))
    return s[k]


def _lat(samples_ns):
    """p50/p95/p99/max in microseconds, plus the mean."""
    return {"n": len(samples_ns), "p50_us": _pct(samples_ns, 50) / 1e3, "p95_us": _pct(samples_ns, 95) / 1e3,
            "p99_us": _pct(samples_ns, 99) / 1e3, "max_us": max(samples_ns) / 1e3, "mean_us": statistics.fmean(samples_ns) / 1e3}


def _timed(fn, n, warmup=0):
    """Run fn(i) n times; return (ops/s, per-call latency samples in ns)."""
    for i in range(warmup):
        fn(i)
    samples = []
    t0 = time.perf_counter()
    for i in range(n):
        a = time.perf_counter_ns()
        fn(i)
        samples.append(time.perf_counter_ns() - a)
    return n / (time.perf_counter() - t0), samples


def _rss_mib():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def _peak_alloc(fn):
    """(result, peak tracemalloc bytes) of one call: Python allocations only, measured with tracing on (slower)."""
    tracemalloc.start()
    try:
        r = fn()
        return r, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def bench(scale, big, latency_n, batch_size=256):
    out = {"params": {"scale": scale, "big": big, "latency_n": latency_n, "batch_size": batch_size}, "results": {}}
    R = out["results"]

    rate, _ = _timed(lambda i: canonical.sha3({"i": i, "p": "x" * 64}), max(1000, scale), warmup=100)
    R["canonical_sha3_ops_s"] = rate

    with tempfile.TemporaryDirectory() as tmp:
        lg = ledger.Ledger(os.path.join(tmp, "s.jsonl"))
        rate, lat = _timed(lambda i: lg.append({"e": i}), latency_n, warmup=10)
        R["ledger_append_sync"] = {"ops_s": rate, "latency": _lat(lat), "note": "fsync per entry; bounded by the disk, not by Python"}

    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "b.jsonl")
        lb = ledger.Ledger(p, durability="batch", batch_size=batch_size)
        rate, lat = _timed(lambda i: lb.append({"e": i}), scale, warmup=100)
        lb.close()
        R["ledger_append_batch"] = {"ops_s": rate, "latency": _lat(lat), "entries": scale + 100, "file_bytes": os.path.getsize(p)}
        reps = 5
        n = scale + 100
        text = ledger.read_input(p).decode("utf-8")
        vrate, vlat = _timed(lambda i: ledger.verify_text(text), reps, warmup=1)
        R["ledger_verify"] = {"entries": n, "entries_s": n * vrate, "latency_per_run": _lat(vlat), "runs": reps,
                              "note": "verify_text over the text read once: the verifier's ledger-chain path (strict profile, idx, links, hashes)"}
        (ok, bad), peak = _peak_alloc(lambda: ledger.verify_text(ledger.read_input(p).decode("utf-8")))   # read + verify, as the verifier does
        R["ledger_verify"]["peak_tracemalloc_mib"] = peak / 2**20
        R["ledger_verify"]["ok"] = ok
        lrate, llat = _timed(lambda i: ledger.Ledger(p), reps, warmup=1)
        R["ledger_load"] = {"entries": n, "entries_s": n * lrate, "latency_per_run": _lat(llat), "runs": reps,
                            "note": "Ledger(path): the strict replay of the chain at open (what every writer pays once)"}
        del text
        # tamper at scale: one byte inside the middle entry
        raw = bytearray(open(p, "rb").read())
        mid = raw.find(b'"e":' + str(n // 2).encode())
        raw[mid + 4] = ord("9") if raw[mid + 4] != ord("9") else ord("8")
        open(p, "wb").write(bytes(raw))
        a = time.perf_counter()
        ok2, bad2 = ledger.verify_text(open(p, "rb").read().decode("utf-8"))
        R["tamper_detection"] = {"entries": n, "detected": (not ok2), "bad_lines_reported": len(bad2), "seconds": time.perf_counter() - a}

    ident = signing.Identity("bench")
    rate, lat = _timed(lambda i: ident.sign(b"x" + str(i).encode()), scale, warmup=10)
    R["ed25519_sign"] = {"ops_s": rate, "latency": _lat(lat), "backend": signing.BACKEND}
    sig, pk = ident.sign(b"x"), ident.public_key_b64
    rate, lat = _timed(lambda i: signing.verify_signature(pk, sig, b"x"), scale, warmup=10)
    R["ed25519_verify"] = {"ops_s": rate, "latency": _lat(lat), "backend": signing.BACKEND}

    with tempfile.TemporaryDirectory() as tmp:   # end-to-end: a signed + anchored pack with a trust store, verified repeatedly
        pp = os.path.join(tmp, "p.json")
        pack.write_pack(pp, pack.build_pack("bench", {"claim": "x", "n": 1}, "Proves integrity; does NOT prove the claim."))
        pack.anchor_pack(pp, pp[:-5] + ".ledger.jsonl")
        pack.sign_pack(pp, ident)
        store = os.path.join(tmp, "trust.jsonl")
        trust.TrustRegistry(store).trust("bench", ident.public_key_b64)
        rate, lat = _timed(lambda i: verify_pack(pp, trust_store=store), max(50, latency_n // 4), warmup=5)
        r0 = verify_pack(pp, trust_store=store)
        R["verify_pack_e2e"] = {"ops_s": rate, "latency": _lat(lat), "valid": r0["valid"], "authenticated": r0["authenticated"],
                                "note": "pack + ledger + signature sidecar + trust store, all layers, files re-read each call"}

    if big:
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "big.jsonl")
            rss0 = _rss_mib()
            a = time.perf_counter()
            with ledger.Ledger(p, durability="batch", batch_size=batch_size) as lb:
                for i in range(big):
                    lb.append({"e": i, "p": "payload-" + str(i)})
            t_append = time.perf_counter() - a
            a = time.perf_counter()
            lg = ledger.Ledger(p)                       # strict load of the whole chain
            t_load = time.perf_counter() - a
            a = time.perf_counter()
            ok, bad = lg.verify()
            t_verify = time.perf_counter() - a
            rss1 = _rss_mib()
            (ok3, _), peak = _peak_alloc(lambda: ledger.verify_text(open(p, "rb").read().decode("utf-8")))
            R["scale_batch"] = {"entries": big, "file_mib": os.path.getsize(p) / 2**20, "append_seconds": t_append, "append_ops_s": big / t_append,
                                "load_seconds": t_load, "verify_seconds": t_verify, "verify_entries_s": big / t_verify, "ok": ok and ok3,
                                "peak_tracemalloc_verify_text_mib": peak / 2**20, "ru_maxrss_mib_before": rss0, "ru_maxrss_mib_after_verify": rss1,
                                "note": "batch mode, fsync every batch_size; the ledger read whole into memory (Ledger.verify has no 64 MiB bound: that bound is the verifier's)"}
    R["ru_maxrss_mib_end"] = _rss_mib()
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--scale", type=int, default=20000, help="entries / operations for the throughput runs")
    ap.add_argument("--big", type=int, default=1_000_000, help="entries of the batch-mode scale run (0 = skip)")
    ap.add_argument("--latency-n", type=int, default=1000, help="samples for the sync-append and e2e latency runs")
    ap.add_argument("--batch-size", type=int, default=256)
    ap.add_argument("--json", help="write the full result here")
    ap.add_argument("--smoke", action="store_true", help="tiny scale: only checks that the bench runs")
    a = ap.parse_args()
    if a.smoke:
        a.scale, a.big, a.latency_n = 2000, 20000, 200
    host = _host()
    print(f"host: {host['cpu']}, {host['cpus']} CPU, {host['mem_mib']} MiB, python {host['python']}, {host['os']}, signing={host['signing_backend']}, {host['date_utc']}")
    print(f"params: scale={a.scale} big={a.big} latency_n={a.latency_n} batch_size={a.batch_size}")
    out = bench(a.scale, a.big, a.latency_n, a.batch_size)
    out["host"] = host
    R = out["results"]

    def lat(d):
        L = d["latency"]
        return f"p50 {L['p50_us']:>9,.1f} µs  p95 {L['p95_us']:>9,.1f} µs  p99 {L['p99_us']:>9,.1f} µs  (n={L['n']})"
    print(f"canonical SHA3     : {R['canonical_sha3_ops_s']:>12,.0f} ops/s")
    print(f"ledger append SYNC : {R['ledger_append_sync']['ops_s']:>12,.0f} ops/s   {lat(R['ledger_append_sync'])}  fsync per entry")
    print(f"ledger append BATCH: {R['ledger_append_batch']['ops_s']:>12,.0f} ops/s   {lat(R['ledger_append_batch'])}  batch_size={a.batch_size}")
    v = R["ledger_verify"]
    print(f"ledger verify      : {v['entries_s']:>12,.0f} entries/s  per run of {v['entries']:,}: p50 {v['latency_per_run']['p50_us']/1e3:,.1f} ms  p99 {v['latency_per_run']['p99_us']/1e3:,.1f} ms  peak alloc {v['peak_tracemalloc_mib']:,.1f} MiB  ok={v['ok']}")
    ld = R["ledger_load"]
    print(f"ledger load (open) : {ld['entries_s']:>12,.0f} entries/s  per run of {ld['entries']:,}: p50 {ld['latency_per_run']['p50_us']/1e3:,.1f} ms  p99 {ld['latency_per_run']['p99_us']/1e3:,.1f} ms")
    t = R["tamper_detection"]
    print(f"tamper detection   : {t['entries']:,} entries, one byte changed → detected={t['detected']} in {t['seconds']*1e3:,.0f} ms")
    print(f"Ed25519 sign       : {R['ed25519_sign']['ops_s']:>12,.0f} ops/s   {lat(R['ed25519_sign'])}  [{signing.BACKEND}]")
    print(f"Ed25519 verify     : {R['ed25519_verify']['ops_s']:>12,.0f} ops/s   {lat(R['ed25519_verify'])}")
    e = R["verify_pack_e2e"]
    print(f"verify_pack e2e    : {e['ops_s']:>12,.0f} ops/s   {lat(e)}  valid={e['valid']} authenticated={e['authenticated']}")
    if "scale_batch" in R:
        s = R["scale_batch"]
        print(f"scale (batch)      : {s['entries']:,} entries, {s['file_mib']:,.0f} MiB — append {s['append_seconds']:,.1f} s ({s['append_ops_s']:,.0f}/s), "
              f"load {s['load_seconds']:,.1f} s, verify {s['verify_seconds']:,.1f} s ({s['verify_entries_s']:,.0f}/s), ok={s['ok']}, "
              f"peak alloc verify_text {s['peak_tracemalloc_verify_text_mib']:,.0f} MiB, ru_maxrss {s['ru_maxrss_mib_after_verify']:,.0f} MiB")
    print(f"ru_maxrss at end   : {R['ru_maxrss_mib_end']:,.0f} MiB")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=1)
        print(f"json: {a.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
