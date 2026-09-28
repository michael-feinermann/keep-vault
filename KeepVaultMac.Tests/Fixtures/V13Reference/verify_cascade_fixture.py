#!/usr/bin/env python3
"""Read-only freeze verifier; never updates expected outputs or their hash."""
import argparse, base64, hashlib, json, pathlib
SHA256 = "287319cdcf4de2132370e4caa5fefa62315f0b22f2c4f26dec5256477b6ea6a9"
p = argparse.ArgumentParser()
p.add_argument("fixture", nargs="?", type=pathlib.Path, default=pathlib.Path(__file__).with_name("cascade_composition_rev9.json"))
a = p.parse_args()
raw = a.fixture.read_bytes()
if hashlib.sha256(raw).hexdigest() != SHA256:
    raise SystemExit("FAIL: frozen cascade fixture SHA256 mismatch")
d = json.loads(raw)
assert d["schema"] == 1 and d["publicSyntheticOnly"] is True
assert d["marsKats"] == 10 and d["shacalKats"] == 1024 and len(d["cases"]) == 28
b = lambda value: base64.b64decode(value, validate=True)
lengths = [0,1,15,16,17,63,64,65,127,128,129,1025,4097,65537]
seen = set()
for c in d["cases"]:
    suite, n = c["suiteId"], c["length"]
    assert suite in (2,3) and n in lengths and (suite,n) not in seen
    seen.add((suite,n))
    assert len(b(c["plaintext"])) == n and len(b(c["aad"])) == 36
    assert len(c["stages"]) == (4 if suite == 2 else 8)
    assert b(c["key"]) == b"".join(b(s["key"]) for s in c["stages"])
    assert b(c["stageNonce"]) == b"".join(b(s["nonce"]) for s in c["stages"])
    assert all(len(b(s["output"])) == n for s in c["stages"])
    assert b(c["ciphertext"]) == b(c["libsodiumCiphertext"]) == b(c["goCiphertext"]) == b(c["stages"][-1]["output"])
    assert b(c["tag"]) == b(c["libsodiumTag"]) == b(c["goTag"]) == b(c["stages"][-1]["tag"])
    assert len(b(c["tag"])) == 16
print("PASS: 28 frozen cascade cases, read-only hash and structural verification")
