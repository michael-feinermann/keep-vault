"""Read-only verifier. Regeneration is deliberately a separate manual command.
The reference code is transcribed from REV9 section 8.9.1.1. Names retain rev6,
because the active-prefix transcript originated there and is unchanged in REV9.
"""
import contextlib
import copy
import io
import json
from pathlib import Path
import nonce_rev6_reference as reference

def candidate():
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        reference.main()
    return json.loads(output.getvalue())

def verify(expected, actual):
    if expected != actual:
        raise ValueError("Frozen nonce fixture differs; no file has been changed")

def main():
    path = Path(__file__).with_name("nonce_rev6_public_vectors.json")
    before = path.read_bytes()
    expected = json.loads(before)
    actual = candidate()
    verify(expected, actual)
    mutations = 0
    for case_index in (0, 14, 21, 83):
        for field in ("active_rotated_hex", "stage_buffer_hex", "basis_hex", "algorithm"):
            bad = copy.deepcopy(actual)
            value = bad["cases"][case_index][field]
            bad["cases"][case_index][field] = ("0" if value[0] != "0" else "1") + value[1:]
            try:
                verify(expected, bad)
            except ValueError:
                mutations += 1
            else:
                raise AssertionError("Modified candidate incorrectly passed")
    if before != path.read_bytes():
        raise AssertionError("Validation modified the frozen fixture")
    print(f"PASS {len(actual['cases'])} frozen cases; {mutations} candidate mutations rejected; golden bytes unchanged")

if __name__ == "__main__":
    main()
