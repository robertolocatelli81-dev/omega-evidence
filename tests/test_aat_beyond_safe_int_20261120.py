"""verify_chain warns about every integer outside +/-(2^53-1) in a foreign AAT chain (2026-11-20).

On VERIFY such integers are hashed as the nearest double (ES6), so 2^53 and 2^53+1 hash alike: the chain still
verifies (foreign records, RFC 8785 §3.1 / RFC 7493 §2.2), but the value read in Python may not be the signed one.
Positive control: on 11f5aa0 (0.12.0) the swapped chain verified with no warning; these tests failed there."""
import json
import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from omega_evidence.interop import aat  # noqa: E402
import test_toolkit  # noqa: E402  (module import: its test classes are not collected here)

LIM = 2 ** 53 - 1


def _rehash(recs):
    for k in range(1, len(recs)):
        recs[k]["prev_hash"] = aat.record_hash(recs[k - 1], strict=False)
    return recs


def _warned(res):
    return [w for w in res["warnings"] if "outside +/-(2^53-1)" in w["why"]]


class TestBeyondSafeInt(unittest.TestCase):
    def _chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            entries = list(test_toolkit.TestAATInterop._log(test_toolkit.TestAATInterop(), tmp)._ledger.entries())
        return next(iter(aat.from_omega(entries, agent_version="1.0", close=True).values()))

    def test_swap_2p53_plus_1_still_verifies_but_is_warned(self):
        recs = json.loads(json.dumps(self._chain()))
        recs[1]["action_detail"]["amount"] = 2 ** 53
        _rehash(recs)
        signed = aat.verify_chain(recs)
        swapped = json.loads(json.dumps(recs))
        swapped[1]["action_detail"]["amount"] = 2 ** 53 + 1      # never "signed": same JCS bytes
        res = aat.verify_chain(swapped)
        self.assertEqual(res["ok"], signed["ok"])                  # verdict unchanged (foreign format)
        self.assertEqual(res["problems"], signed["problems"])
        w = _warned(res)
        self.assertEqual(len(w), 1, res["warnings"])
        self.assertEqual(w[0]["i"], 1)
        self.assertIn("/action_detail/amount", w[0]["why"])

    def test_generated_bounds_both_signs_and_bools(self):
        rng = random.Random(20261120)
        base = json.loads(json.dumps(self._chain()))
        for _ in range(300):
            v = rng.choice([LIM, -LIM, LIM + 1, -LIM - 1, 2 ** 60, -(2 ** 64), rng.randint(-LIM, LIM), True, False, 0])
            where = rng.choice(["flat", "list", "nested"])
            recs = json.loads(json.dumps(base))
            d = recs[1]["action_detail"]
            if where == "flat":
                d["x"] = v
                ptr = "/action_detail/x"
            elif where == "list":
                d["x"] = [0, v]
                ptr = "/action_detail/x/1"
            else:
                d["a/b~c"] = {"y": v}
                ptr = "/action_detail/a~1b~0c/y"
            _rehash(recs)
            w = _warned(aat.verify_chain(recs))
            bad = type(v) is int and abs(v) > LIM
            self.assertEqual(bool(w), bad, (v, where))
            if bad:
                self.assertIn(ptr, w[0]["why"])

    def test_clean_chain_has_no_such_warning(self):
        self.assertEqual(_warned(aat.verify_chain(self._chain())), [])

    def _one(self, detail_extra):
        recs = json.loads(json.dumps(self._chain()))
        recs[1]["action_detail"].update(detail_extra)
        _rehash(recs)
        w = _warned(aat.verify_chain(recs))
        self.assertEqual(len(w), 1, w)
        return w[0]["why"]

    def test_pointers_in_order_first_five_and_count(self):
        why = self._one({"L": [2 ** 53] * 7, "a": -(2 ** 53)})
        self.assertIn("at /action_detail/L/0, /action_detail/L/1, /action_detail/L/2, /action_detail/L/3, "
                      "/action_detail/L/4 (+3 more): ", why)
        why = self._one({"L": [2 ** 53] * 4, "a": -(2 ** 53)})
        self.assertIn("at /action_detail/L/0, /action_detail/L/1, /action_detail/L/2, /action_detail/L/3, "
                      "/action_detail/a: ", why)

    def test_batch_is_not_named(self):
        # `batch` is detached: no hash and no signature covers it, so its integers are not "hashed as doubles"
        recs = json.loads(json.dumps(self._chain()))
        recs[1]["batch"] = {"epoch_id": "8f5ad8b4-6a3e-4c43-9a51-5b8a2b1f6c11", "merkle_root": "0" * 64, "leaf_index": 2 ** 53}
        self.assertEqual(_warned(aat.verify_chain(recs)), [])

    def test_non_string_keys_are_a_problem_not_a_crash(self):
        recs = json.loads(json.dumps(self._chain()))
        recs[1]["action_detail"][1] = 2 ** 53
        res = aat.verify_chain(recs)
        self.assertTrue(any("not canonicalizable" in p["why"] for p in res["problems"]), res["problems"])

    def test_root_pointer_is_empty_string(self):
        self.assertEqual(aat._beyond_safe_int(2 ** 53), [""])                    # RFC 6901: "" is the whole value
        self.assertEqual(aat._beyond_safe_int({"": 2 ** 53}), ["/"])             # "/" is the member named ""

    def test_verify_epochs_alone_warns(self):
        recs = json.loads(json.dumps(self._chain()))
        recs[1]["action_detail"]["amount"] = 2 ** 53
        _rehash(recs)
        leaves = [aat.leaf_hash(r) for r in recs]                                 # strict=False: a foreign epoch
        root, paths, eid = aat.merkle_root(leaves), aat.audit_paths(leaves), "8f5ad8b4-6a3e-4c43-9a51-5b8a2b1f6c11"
        for k, r in enumerate(recs):
            r["batch"] = {"epoch_id": eid, "merkle_root": root.hex(), "leaf_index": k, "inclusion_proof": paths[k]}
        anchor = {"epoch_id": eid, "merkle_root": root.hex(), "leaf_count": len(recs),
                  "hash": "RFC 6962 / SHA-256 (leaf 0x00 || JCS(record without batch), node 0x01)"}
        recs[1]["action_detail"]["amount"] = 2 ** 53 + 1                         # same leaf hash
        res = aat.verify_epochs(recs, [anchor])
        self.assertTrue(res["ok"], res["problems"])
        w = _warned(res)
        self.assertEqual([x["i"] for x in w], [1], res["warnings"])
        self.assertIn("/action_detail/amount", w[0]["why"])
        recs[1]["action_detail"]["amount"] = 2 ** 53 + 2                         # positive control: a different double
        self.assertFalse(aat.verify_epochs(recs, [anchor])["ok"])



class TestProducersRefuse(unittest.TestCase):
    """Producing side (2026-11-20): sign_record / sign_record_hybrid refuse a signed content with an integer outside
    +/-(2^53-1); to_jsonl refuses an integer it would write changed. Positive control: on 7de1e14 these fail."""

    def setUp(self):
        self.recs = TestBeyondSafeInt._chain(TestBeyondSafeInt())
        try:                       # the CI runs this file without cryptography too: a refusal needs no key
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ec
        except ImportError:
            self.pem = b"not a key: refused before it is read"
        else:
            self.pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    def _need_es256(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("signing with ES256 needs cryptography")

    def _with(self, v, where="detail"):
        r = json.loads(json.dumps(self.recs[1]))
        if where == "detail":
            r["action_detail"]["n"] = v
        else:
            r["batch"] = {"n": v}
        return r

    def test_sign_record_refuses_both_signs_and_names_the_pointer(self):
        for v in (LIM + 1, -LIM - 1, 2 ** 53 + 1, 2 ** 64):
            with self.assertRaises(ValueError) as cm:
                aat.sign_record(self._with(v), self.pem)
            self.assertIn("/action_detail/n", str(cm.exception))

    def test_sign_record_accepts_the_bound_and_ignores_batch(self):
        self._need_es256()
        for v in (LIM, -LIM, 0):
            aat.sign_record(self._with(v), self.pem)
        aat.sign_record(self._with(2 ** 60, where="batch"), self.pem)     # batch is not signed

    def test_sign_record_hybrid_refuses_before_any_key_is_used(self):
        class Never:
            public_key_b64 = ""
            def sign(self, m):
                raise AssertionError("signed")
        with self.assertRaises(ValueError) as cm:
            aat.sign_record_hybrid(self._with(LIM + 1), Never(), self.pem)
        self.assertIn("outside", str(cm.exception))

    def test_to_jsonl_refuses_inexact_writes_exact(self):
        for v in (2 ** 53 + 1, -(2 ** 53) - 1, 2 ** 60, 2 ** 64 + 1, 10 ** 400):    # 2^60 is a double, written ...847000
            recs = json.loads(json.dumps(self.recs))
            recs[1]["action_detail"]["n"] = v
            with self.assertRaises(ValueError) as cm:
                aat.to_jsonl(recs)
            self.assertIn("record 1", str(cm.exception))
        recs = json.loads(json.dumps(self.recs))
        recs[1]["action_detail"]["a"] = 2 ** 53                                  # written as is, then one that is not
        recs[1]["action_detail"]["b"] = 2 ** 53 + 1
        with self.assertRaises(ValueError) as cm:
            aat.to_jsonl(recs)
        self.assertIn("/action_detail/b", str(cm.exception))
        self.assertNotIn("/action_detail/a,", str(cm.exception))
        for v in (2 ** 53, -(2 ** 53), 10 ** 20, LIM):                            # JCS text = the digits
            recs = json.loads(json.dumps(self.recs))
            recs[1]["action_detail"]["a/b~"] = [v]
            line = aat.to_jsonl(recs).splitlines()[1]
            self.assertEqual(json.loads(line)["action_detail"]["a/b~"], [v])

    def test_a_tuple_is_an_array_for_every_check(self):
        """jcs() writes a tuple as an array: on 61d755d an integer beyond the bound inside a tuple was signed, written
        changed by to_jsonl and not warned by verify_chain (measured 20/11/2026)."""
        for v in ((2 ** 53 + 1,), (1, (LIM + 1,))):
            with self.assertRaises(ValueError) as cm:
                aat.sign_record(self._with(v), self.pem)
            self.assertIn("/action_detail/n/", str(cm.exception))
            recs = json.loads(json.dumps(self.recs))
            recs[1]["action_detail"]["n"] = v
            if v == (2 ** 53 + 1,):
                with self.assertRaises(ValueError):
                    aat.to_jsonl(recs)
            res = aat.verify_chain(_rehash(recs))
            self.assertEqual([w["i"] for w in _warned(res)], [1], res["warnings"])
        recs = json.loads(json.dumps(self.recs))
        recs[1]["action_detail"]["n"] = (2 ** 53,)                      # written as is: exported unchanged
        self.assertEqual(json.loads(aat.to_jsonl(recs).splitlines()[1])["action_detail"]["n"], [2 ** 53])

    def test_what_jcs_refuses_keeps_its_reason(self):
        """a key that is not a string: on 61d755d sign_record and to_jsonl raised "'<' not supported between ..."
        from the walk, before jcs() gave its reason."""
        for d in ({1: 2 ** 60, "a": 1}, {1: 1, "b": 2}):
            r = self._with(0)
            r["action_detail"] = d
            for f in (lambda: aat.sign_record(r, self.pem), lambda: aat.to_jsonl([r])):
                with self.assertRaises(TypeError) as cm:
                    f()
                self.assertIn("object keys must be strings", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
