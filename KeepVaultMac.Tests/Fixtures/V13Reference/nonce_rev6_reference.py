"""Öffentliche Spezifikationsreferenz für Revision 6; keine Produktkryptografie.

Ausführen: python3 nonce_rev6_reference.py > nonce_rev6_public_vectors.json
Keine echten Schlüssel, Mauspools oder Zufallswerte eingeben.
"""
from __future__ import annotations

import hashlib
import json
import struct

MODE = "Seed320-Blockwise64-SHA3-512-ActivePrefix-v3"
DOMAIN = b"Kalyna-ZPAQ/v13/chunk-nonce/Blockwise64-ActivePrefix-SHA3-512-v3"
MAC_SUFFIX = "+HMAC-SHA3-512+Skein-MAC-1024"
# Noncebreiten in Byte; Reihenfolge innen nach außen.
STAGES = {
    0: (("Kalyna-512/512", 64),),
    1: (("Threefish-1024", 128),),
    2: (("AES-256", 16), ("Kalyna-512/512", 64),
        ("Threefish-1024", 128), ("XChaCha20-Poly1305", 24)),
    3: (("AES-256", 16), ("MARS-448", 16), ("Camellia-256", 16),
        ("Serpent-256", 16), ("SHACAL-2-512", 32), ("Kalyna-512/512", 64),
        ("Threefish-1024", 128), ("XChaCha20-Poly1305", 24)),
    4: (("AES-256", 16), ("XChaCha20-Poly1305", 24)),
    5: (("AES-256", 16),),
    6: (("MARS-448", 16),),
    7: (("SHACAL-2-512", 32),),
    8: (("XChaCha20-Poly1305", 24),),
    9: (("AES-256", 16), ("Threefish-1024", 128), ("XChaCha20-Poly1305", 24)),
    10: (("Camellia-256", 16),),
    11: (("Serpent-256", 16),),
}


def algorithm(suite: int) -> bytes:
    if type(suite) is not int or suite not in STAGES:
        raise ValueError("Nichtkatalogisierte Suite")
    result = ""
    for cipher, _ in STAGES[suite]:
        name = cipher if cipher == "XChaCha20-Poly1305" else cipher + "-CTR"
        result = name if not result else name + "(" + result + ")"
    return (result + MAC_SUFFIX).encode("utf-8")


def le32(value: int) -> bytes:
    if type(value) is not int or not 0 <= value <= 0xffffffff:
        raise ValueError("Wert nicht als UInt32 darstellbar")
    return struct.pack("<I", value)


def lp(value: bytes) -> bytes:
    return le32(len(value)) + value


def layout(suite: int) -> tuple[int, int, int]:
    algorithm(suite)  # Katalog und Typ prüfen; bool ist keine Suite-ID.
    capacity = 10 if suite == 3 else 5
    width = sum(n for _, n in STAGES[suite])
    count = 1 + (width - 1) // 64
    if not 1 <= count <= capacity:
        raise ValueError("Aktiver Noncebedarf überschreitet die Basis")
    return capacity, width, count


def derive(suite: int, basis: bytes, chunk_index: int
           ) -> tuple[bytes, tuple[bytes, ...]]:
    """Aktive volle Hashblöcke und ausschließlich durch Slicing erzeugte IVs."""
    a = algorithm(suite)
    capacity, width, count = layout(suite)
    if type(chunk_index) is not int or not 0 <= chunk_index <= (1 << 63) - 1:
        raise ValueError("Chunkindex außerhalb der Int64-Domäne")
    if not isinstance(basis, bytes) or len(basis) != 64 * capacity:
        raise ValueError("Falsche Basislänge")
    prefix = (lp(DOMAIN) + le32(13) + le32(suite) + lp(a)
              + le32(capacity) + le32(count) + le32(width)
              + struct.pack(">Q", chunk_index))
    blocks = []
    for j in range(count):  # NICHT range(capacity)
        message = (prefix + struct.pack(">I", j)
                   + basis[64 * j:64 * (j + 1)])
        blocks.append(hashlib.sha3_512(message).digest())
    active = b"".join(blocks)
    stage_buffer = active[:width]
    offset = 0
    nonces = []
    for _, n in STAGES[suite]:
        nonces.append(stage_buffer[offset:offset + n])
        offset += n
    if offset != width:
        raise AssertionError("Inkonsistenter Testkatalog")
    return active, tuple(nonces)


def public_bases() -> tuple[bytes, bytes]:
    """Unveränderte synthetische Pool-/OS-Eingaben; kein CSPRNG."""
    first, second = [], []
    for purpose in range(6, 11):
        pool = bytes((17 * purpose + t) % 256 for t in range(64))
        epoch = 0x0102030405060700 + purpose
        message = pool + struct.pack("<QII", epoch, 0, purpose)
        first.append(hashlib.sha3_512(message).digest())
        second.append(hashlib.sha512(message).digest())
    r1 = bytes(t % 256 for t in range(320))
    r2 = bytes((255 - t) % 256 for t in range(320))
    b1 = bytes(x ^ y for x, y in zip(b"".join(first), r1))
    b2 = bytes(x ^ y for x, y in zip(b"".join(second), r2))
    return b1, b2


def main() -> None:
    b1, b2 = public_bases()
    cases = []
    for suite in range(12):
        capacity, width, count = layout(suite)
        for i in (0, 1, 16384, 65536, 262144, 1 << 32, (1 << 63) - 1):
            basis = b1 + b2 if suite == 3 else b1
            active, nonces = derive(suite, basis, i)
            cases.append({
                "suite_id": suite, "algorithm": algorithm(suite).decode(),
                "chunk_index": i, "basis_hex": basis.hex(),
                "capacity_blocks": capacity, "active_blocks": count,
                "rotation_hashes": count, "stage_hashes": 0,
                "active_rotated_hex": active.hex(),
                "stage_nonce_hex": [n.hex() for n in nonces],
                "stage_buffer_hex": b"".join(nonces).hex(),
                "stage_bytes": width,
                "reserve_input_bytes": len(basis) - 64 * count,
            })
    print(json.dumps({"mode": MODE, "public_test_data_only": True,
                      "b1_hex": b1.hex(), "b2_hex": b2.hex(),
                      "cases": cases}, indent=2))


if __name__ == "__main__":
    main()
