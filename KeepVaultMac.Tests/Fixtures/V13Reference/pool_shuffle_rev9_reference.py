#!/usr/bin/env python3
"""Independent PUBLIC test model. Never imports Keep Vault or rewrites a fixture.

Generate a candidate using --candidate NEW_PATH. Review and explicitly adopt it
outside the verifier. Python objects are not secret-memory implementations.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

DOMAIN = b"KeepVault REV9 public fixture v1/"


class PublicStream:
    def __init__(self, label, purpose, round_number):
        self.prefix = DOMAIN + label.encode("ascii") + struct.pack("<II", purpose, round_number)
        self.counter = 0
        self.pending = b""

    def take(self, size):
        while len(self.pending) < size:
            self.pending += hashlib.sha512(self.prefix + struct.pack("<Q", self.counter)).digest()
            self.counter += 1
        result, self.pending = self.pending[:size], self.pending[size:]
        return result


def shuffle(order, stream):
    # Prefix selection writes a separate destination, rather than invoking any
    # product helper. Each selected item occupies the next final suffix slot.
    remaining = list(order)
    result = [0] * len(order)
    for index in range(len(order) - 1, 0, -1):
        bound = index + 1
        width = 4 if bound <= 2**32 else 8
        limit = 2**(8 * width) - 2**(8 * width) % bound
        for attempt in range(128):
            candidate = int.from_bytes(stream.take(width), "little")
            if candidate < limit:
                break
        else:
            raise ValueError("rejection budget")
        selected = candidate % bound
        result[index] = remaining[selected]
        remaining[selected] = remaining[-1]
        remaining.pop()
    if remaining:
        result[0] = remaining[0]
    return result


def replay(records, order, purpose, epoch, hash_function):
    state = bytes(64)
    for position in order:
        record = records[position]
        state = hash_function(state + record + record[72:80] + struct.pack("<I", purpose)).digest()
    return hash_function(state + struct.pack("<QII", epoch, 0, purpose)).digest()


def build_vectors():
    pools = []
    sequence = 0
    for purpose in range(11):
        count = 1024 + 37 * purpose
        epoch = 0x0102030405060700 + purpose
        records = [bytes((purpose * 19 + index * 7 + byte * 13) & 255 for byte in range(72))
                   + struct.pack("<q", sequence + index) for index in range(count)]
        sequence += count
        first = shuffle(range(count), PublicStream("shuffle", purpose, 1))
        second = shuffle(first, PublicStream("shuffle", purpose, 2))
        q1 = replay(records, first, purpose, epoch, hashlib.sha3_512)
        q2 = replay(records, second, purpose, epoch, hashlib.sha512)
        def order_hash(order):
            return hashlib.sha256(b"".join(struct.pack("<Q", i) for i in order)).hexdigest().upper()
        def xor(q, round_number):
            return bytes(a ^ b for a, b in zip(q, PublicStream("xor", purpose, round_number).take(64))).hex().upper()
        pools.append(dict(purpose=purpose, count=count, epoch=str(epoch),
                          recordSha256=hashlib.sha256(b"".join(records)).hexdigest().upper(),
                          firstOrderSha256=order_hash(first), secondOrderSha256=order_hash(second),
                          q1=q1.hex().upper(), q2=q2.hex().upper(),
                          publicXor1=xor(q1, 1), publicXor2=xor(q2, 2)))
    return dict(schema="KeepVault.PublicShuffleFixture.v1", records=sequence, pools=pools)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    args = parser.parse_args()
    frozen = Path(__file__).with_name("pool_shuffle_rev9_public_vectors.json").resolve()
    if args.candidate.resolve() == frozen:
        parser.error("refusing to write the frozen fixture; use a new candidate path")
    with args.candidate.open("x", encoding="utf-8") as output:
        json.dump(build_vectors(), output, indent=2)
        output.write("\n")
