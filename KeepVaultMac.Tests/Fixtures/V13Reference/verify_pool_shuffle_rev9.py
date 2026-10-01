#!/usr/bin/env python3
"""Read-only comparison of frozen public vectors with the independent model."""
import argparse
import copy
from datetime import datetime, timezone
import tempfile
import hashlib
import json
from pathlib import Path
import platform
from pool_shuffle_rev9_reference import build_vectors


def verify(path, report=True):
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
    result = dict(status="PASS", pools=11, records=actual["records"],
                  rejectedMutations=rejected, fixtureUnchanged=True,
                  runUtc=datetime.now(timezone.utc).isoformat(),
                  fixtureSha256=hashlib.sha256(original).hexdigest(),
                  verifierSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  modelSha256=hashlib.sha256(Path(__file__).with_name("pool_shuffle_rev9_reference.py").read_bytes()).hexdigest(),
                  python=platform.python_version(),
                  scope="Public Python model only; product tests are separate")
    if report:
        print(json.dumps(result, indent=2))
    return result


def self_test(frozen):
    original = frozen.read_bytes()
    verify(frozen, report=False)
    rejected = 0
    with tempfile.TemporaryDirectory(prefix="keepvault-golden-readonly-") as directory:
        target = Path(directory) / "fixture.json"
        try:
            verify(target, report=False)
        except FileNotFoundError:
            rejected += 1
        else:
            raise SystemExit("FAIL: missing fixture accepted")
        if target.exists():
            raise SystemExit("FAIL: missing fixture was generated")
        target.write_bytes(b"invalid JSON")
        try:
            verify(target, report=False)
        except json.JSONDecodeError:
            rejected += 1
        else:
            raise SystemExit("FAIL: invalid fixture accepted")
        if target.read_bytes() != b"invalid JSON":
            raise SystemExit("FAIL: invalid fixture was overwritten")
        for field in ("recordSha256", "firstOrderSha256", "secondOrderSha256", "q1", "q2", "publicXor1", "publicXor2", "count", "epoch"):
            data = json.loads(original)
            value = data["pools"][0][field]
            data["pools"][0][field] = value + 1 if isinstance(value, int) else ("1" if value[0] == "0" else "0") + value[1:]
            mutation = json.dumps(data).encode()
            target.write_bytes(mutation)
            try:
                verify(target, report=False)
            except SystemExit:
                rejected += 1
            else:
                raise SystemExit("FAIL: on-disk mutation accepted: " + field)
            if target.read_bytes() != mutation:
                raise SystemExit("FAIL: rejected mutation was overwritten: " + field)
    if frozen.read_bytes() != original:
        raise SystemExit("FAIL: self-test altered frozen fixture")
    print(json.dumps(dict(status="PASS", runUtc=datetime.now(timezone.utc).isoformat(),
                         rejectedOnDiskFixtures=rejected, fixtureUnchanged=True,
                         fixtureSha256=hashlib.sha256(original).hexdigest(),
                         scope="Read-only verifier failure paths; product tests are separate"), indent=2))



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=Path(__file__).with_name("pool_shuffle_rev9_public_vectors.json"))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test(args.fixture)
    else:
        verify(args.fixture)
