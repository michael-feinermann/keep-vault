"""Read-only positive/negative check of the frozen public pool fixture."""
import hashlib
import json
from pathlib import Path
from pool_finalization_rev9_reference import values

path = Path(__file__).with_name('pool_finalization_rev9_vectors.json')
before = path.read_bytes()
assert hashlib.sha256(before).hexdigest() == '87156ec384cc129f233e93bb07bc23c9ff5c0f61aba1f0e2f70852eb491fabbd'
reference = values()
assert json.loads(before) == reference
for purpose in range(11):
    for branch in ('first', 'second'):
        mutant = json.loads(before)
        mutant['pools'][purpose][branch] = '00' * 64
        assert mutant != reference
assert path.read_bytes() == before
print('PASS: 22 finalization and 2 XOR values; 22 negative mutations; frozen file unchanged')
