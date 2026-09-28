#!/usr/bin/env python3
"""Read-only comparison of frozen public vectors with the independent model."""
import copy
import hashlib
import json
from pathlib import Path
import platform
from pool_shuffle_rev9_reference import build_vectors


def verify(path):
    original = path.read_bytes()
    expected = json.loads(original)
    actual = build_vectors()
    if expected != actual:
        raise SystemExit("FAIL: frozen shuffle vectors differ")
    rejected = 0
    for index in range(11):
        for field in ("recordSha256", "firstOrderSha256", "secondOrderSha256", "q1", "q2", "publicXor1", "publicXor2"):
            bad = copy.deepcopy(expected)
            value = bad["pools"][index][field]
            bad["pools"][index][field] = ("1" if value[0] == "0" else "0") + value[1:]
            if bad == actual:
                raise SystemExit("FAIL: mutated fixture accepted")
            rejected += 1
    if original != path.read_bytes():
        raise SystemExit("FAIL: verifier changed its fixture")
    print(json.dumps(dict(status="PASS", pools=11, records=actual["records"],
                         rejectedMutations=rejected, fixtureUnchanged=True,
                         fixtureSha256=hashlib.sha256(original).hexdigest(),
                         python=platform.python_version(),
                         scope="Public Python model only; product tests are separate"), indent=2))


if __name__ == "__main__":
    verify(Path(__file__).with_name("pool_shuffle_rev9_public_vectors.json"))
