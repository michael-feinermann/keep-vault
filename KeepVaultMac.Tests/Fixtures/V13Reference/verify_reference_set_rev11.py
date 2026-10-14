#!/usr/bin/env python3
"""Read-only model/freeze checks and real on-disk negative tests. Public data only."""
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from check_nonce_vectors import candidate as nonce_model
from pool_finalization_rev9_reference import values as finalization_model
from pool_shuffle_rev9_reference import build_vectors as shuffle_model

root = Path(__file__).resolve().parent
names = ("pool_shuffle_rev9_public_vectors.json", "pool_finalization_rev9_vectors.json",
         "nonce_rev6_public_vectors.json", "cascade_composition_rev9.json")
originals = {name: (root / name).read_bytes() for name in names}
models = {names[0]: shuffle_model(), names[1]: finalization_model(), names[2]: nonce_model()}


def verify(name, path):
    raw = path.read_bytes()
    if name in models:
        if json.loads(raw) != models[name]:
            raise ValueError("Frozen bytes differ from the independent model")
    else:
        completed = subprocess.run([sys.executable, "-B", str(root / "verify_cascade_fixture.py"), str(path)],
                                   capture_output=True, check=False)
        if completed.returncode != 0:
            raise ValueError("Frozen composition failed hash/structure verification")
    if raw != path.read_bytes():
        raise RuntimeError("Verifier changed the fixture")


for name in names:
    verify(name, root / name)

# The factor halves are the public XOR results in purposes 0..3. The nonce
# route and AAD are separate independent fixtures, never regenerated here.
mutations = [(names[0], ("pools", p, "publicXor1"), f"factor-half-{p}") for p in range(4)]
mutations += [(names[0], ("pools", p, "q2"), f"second-round-{p}") for p in (0, 2, 3)]
mutations += [(names[0], ("pools", 0, "recordSha256"), "record-layout"),
              (names[1], ("firstNonce",), "first-nonce-xor"),
              (names[1], ("secondNonce",), "second-nonce-xor"),
              (names[2], ("cases", 0, "stage_buffer_hex"), "nonce-route"),
              (names[2], ("cases", 21, "basis_hex"), "nonce-basis"),
              (names[3], ("cases", 0, "aad"), "aad"),
              (names[3], ("cases", 0, "tag"), "tag")]
rejected = []
with tempfile.TemporaryDirectory(prefix="keepvault-reference-set-") as directory:
    target = Path(directory) / "candidate.json"
    for name, path, label in mutations:
        data = json.loads(originals[name])
        cursor = data
        for component in path[:-1]:
            cursor = cursor[component]
        value = cursor[path[-1]]
        cursor[path[-1]] = ("1" if value[0] == "0" else "0") + value[1:]
        changed = json.dumps(data).encode()
        target.write_bytes(changed)
        try:
            verify(name, target)
        except ValueError:
            rejected.append(label)
        else:
            raise SystemExit("FAIL: on-disk mutation accepted: " + label)
        if target.read_bytes() != changed:
            raise SystemExit("FAIL: on-disk mutation overwritten: " + label)

for name, original in originals.items():
    if (root / name).read_bytes() != original:
        raise SystemExit("FAIL: frozen reference changed")
print(json.dumps(dict(status="PASS", runUtc=datetime.now(timezone.utc).isoformat(),
    rejectedOnDiskMutations=rejected, fixturesUnchanged=True,
    fixtureHashes={name: hashlib.sha256(raw).hexdigest() for name, raw in originals.items()},
    verifierSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    scope="Independent public Python models and pinned composition freeze; product comparisons are separate"), indent=2))
