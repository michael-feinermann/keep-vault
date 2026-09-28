#!/usr/bin/env python3
"""Public-only independent credential transcript encoder, no product import.
The lone UTF-16 surrogate test uses .NET's UTF-8 replacement U+FFFD explicitly.
Run prints candidates; it never overwrites test expectations.
"""
import hashlib, json, struct
algorithm = "Kalyna-512/512-CTR+HMAC-SHA3-512+Skein-MAC-1024"
factor_a, factor_b = bytes(range(128)), bytes(255-i for i in range(128))
inputs = [("", ""), ("p", "1"), ("x"*257, "1"*17), ("é", "0001"), ("e\u0301", "0001"), ("\ufffd", "0")]
lp = lambda v: struct.pack("<I", len(v)) + v
rows = []
for case, (password, pin) in enumerate(inputs):
    halves = []
    for half in range(2):
        domain = f"Kalyna-ZPAQ/v13/{algorithm}/SHA3-512/User+PIN+Factors-A{half+1}+B{half+1}".encode("utf-8")
        values = [domain, password.encode("utf-8"), pin.encode("ascii"), factor_a[half*64:(half+1)*64], factor_b[half*64:(half+1)*64]]
        halves.append(hashlib.sha3_512(b"".join(lp(v) for v in values)).digest())
    rows.append({"case":case, "password_utf8_hex":password.encode().hex(), "pin_ascii_hex":pin.encode().hex(), "sha3_credential_v13":b"".join(halves).hex().upper()})
print(json.dumps(rows, indent=2))
