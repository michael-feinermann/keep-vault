"""Independent public finalization/XOR reference; stdout only, no fixture writes."""
import hashlib
import json
import struct


def values():
    result = []
    for purpose in range(11):
        epoch = [0, 1, 2**32 - 1, 2**64 - 1][purpose % 4]
        accumulator = bytes((i * 17 + purpose * 23 + 5) & 255 for i in range(64))
        transcript = accumulator + struct.pack('<QII', epoch, 0, purpose)
        result.append(dict(purpose=purpose, epoch=str(epoch), accumulator=accumulator.hex(),
            first=hashlib.sha3_512(transcript).hexdigest(), second=hashlib.sha512(transcript).hexdigest()))
    os_group = bytes((i * 31 + 29) & 255 for i in range(320))
    nonce1 = b''.join(bytes.fromhex(v['first']) for v in result[6:])
    nonce2 = b''.join(bytes.fromhex(v['second']) for v in result[6:])
    return dict(schema=1, pools=result, os320=os_group.hex(),
        firstNonce=bytes(a ^ b for a, b in zip(nonce1, os_group)).hex(),
        secondNonce=bytes(a ^ b for a, b in zip(nonce2, os_group)).hex())


if __name__ == '__main__':
    print(json.dumps(values(), sort_keys=True, separators=(',', ':')))
