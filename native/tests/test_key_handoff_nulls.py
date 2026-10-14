#!/usr/bin/env python3
"""Owned-buffer/NULL ABI tests, one isolated process per library/architecture.

No fabricated non-NULL addresses, expired handles, or key bytes are emitted.
Run managed NativeKeyHandoffTests separately for independent constant-key
oracles. This harness does not claim false-success fault detection by the ABI.
"""
import argparse
import ctypes as C
import datetime as D
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

P = C.POINTER(C.c_ubyte)
Z = C.c_size_t
U = C.c_uint32
LIBRARIES = {
    "argon2": "libargon2_ref.dylib",
    "aes": "libaes_ref.dylib",
    "mars": "libmars_ref.dylib",
    "shacal2": "libshacal2_ref.dylib",
    "kalyna": "libkalyna_v13.dylib",
    "threefish": "libthreefish_ref.dylib",
    "camellia": "libcamellia_v13.dylib",
    "serpent": "libserpent_v13.dylib",
    "xchacha": "libxchachapoly_v13.dylib",
    "sha3": "libsha3_ref.dylib",
}


def utc():
    return D.datetime.now(D.timezone.utc).isoformat()


def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def buf(length, value=0x27):
    return (C.c_ubyte * length)(*([value] * length))


class Cases:
    def __init__(self, library):
        self.lib = library
        self.results = []

    def fn(self, name, types, result=C.c_int):
        function = getattr(self.lib, name)
        function.argtypes = types
        function.restype = result
        return function

    def check(self, label, function, arguments, sentinels=(), success=False):
        before = [bytes(item) for item in sentinels]
        started = time.monotonic()
        result = function(*arguments)
        good = result == 0 if success else result != 0
        unchanged = all(bytes(item) == old for item, old in zip(sentinels, before))
        if not good or (not success and not unchanged):
            raise AssertionError(label)
        self.results.append({"case": label, "status": "PASS", "native_status": result,
                             "output_unchanged": unchanged if not success else None,
                             "elapsed_seconds": time.monotonic() - started})
        return result

    def matrix(self, label, function, arguments, pointer_names, sentinels=()):
        for index, name in pointer_names:
            changed = list(arguments)
            changed[index] = None
            self.check(label + ".null." + name, function, changed, sentinels)


def argon(cases):
    password, salt, secret, aad, output = buf(128), buf(64), buf(128, 0x19), buf(17), buf(64, 0xA5)
    types = [U, U, U, P, U, P, U, P, U, P, U, P, U, U]
    for suffix, memory in [("with_budget", 1048576), ("kat_with_budget", 8192)]:
        name = "keepvault_argon2id_v13_" + suffix
        fn = cases.fn(name, types)
        arguments = [4, memory, 4, password, 128, salt, 64, secret, 128, aad, 17, output, 64, 1]
        cases.matrix(name, fn, arguments, [(3, "password"), (5, "salt"), (7, "secret"),
                                         (9, "associated_data"), (11, "output")], [output])
        for index, value, label in [(4, 127, "password_width"), (6, 63, "salt_width"),
                                    (8, 127, "secret_width"), (10, 0, "associated_data_empty"),
                                    (12, 63, "output_width"), (13, 0, "worker_zero")]:
            changed = list(arguments)
            changed[index] = value
            cases.check(name + ".invalid." + label, fn, changed, [output])
        changed = list(arguments)
        changed[8] = 0
        cases.check(name + ".invalid.secret_present_length_zero", fn, changed, [output])
    legacy = cases.fn("phc_argon2id_hash_raw", [U, U, U, P, U, P, U, P, U])
    cases.matrix("phc_argon2id_hash_raw", legacy,
                 [4, 1048576, 4, password, 128, salt, 64, output, 64],
                 [(3, "password"), (5, "salt"), (7, "output")], [output])
    # Optional secret=NULL,len=0 is a valid v13 first-round input. Only this
    # dedicated 8 MiB KAT entry is evaluated; no production matrix allocation.
    positive = cases.fn("keepvault_argon2id_v13_kat_with_budget", types)
    args = [4, 8192, 4, password, 128, salt, 64, None, 0, aad, 17, output, 64, 1]
    cases.check("argon2.kat.optional_null_secret.allowed", positive, args, success=True)
    if bytes(password) != bytes(128):
        raise AssertionError("argon2.kat.password_one_call_copy_not_erased")
    cases.results.append({"case": "argon2.kat.password_one_call_copy_erased", "status": "PASS"})


def ctr(cases, algorithm):
    widths = {"aes": (32, 16), "mars": (56, 16), "shacal2": (64, 32),
              "kalyna": (64, 64), "threefish": (128, 128), "camellia": (32, 16), "serpent": (32, 16)}
    key_bytes, block_bytes = widths[algorithm]
    key, nonce, input_, output = buf(key_bytes), buf(block_bytes, 0x13), buf(129), buf(129, 0xA5)
    if algorithm in ("aes", "mars", "shacal2"):
        symbol = {"aes": "aes_256", "mars": "mars_448", "shacal2": "shacal2_512"}[algorithm]
        fn = cases.fn(symbol + "_ctr_xcrypt_v13_with_workers", [P, P, P, P, Z, U])
        args = [key, nonce, input_, output, 129, 1]
        cases.matrix(symbol, fn, args, [(0, "key"), (1, "nonce"), (2, "input"), (3, "output")], [output])
        cases.check(symbol + ".worker_zero", fn, [*args[:-1], 0], [output])
        block = cases.fn(algorithm + "_encrypt_block", [P, Z, P, P])
        cases.matrix(algorithm + ".block", block, [key, key_bytes, input_, output],
                     [(0, "key"), (2, "input"), (3, "output")], [output])
        cases.check(algorithm + ".block.key_width", block, [key, 1, input_, output], [output])
    elif algorithm in ("camellia", "serpent"):
        name = "keepvault_v13_" + algorithm + "_256_ctr_xcrypt"
        fn = cases.fn(name, [P, Z, P, Z, P, Z, P, Z, U])
        args = [key, 32, nonce, 16, input_, 129, output, 129, 1]
        cases.matrix(name, fn, args, [(0, "key"), (2, "nonce"), (4, "input"), (6, "output")], [output])
        for index, value, label in [(1, 31, "key_width"), (3, 15, "nonce_width"),
                                    (7, 128, "output_capacity"), (8, 0, "worker_zero")]:
            changed = list(args)
            changed[index] = value
            cases.check(name + ".invalid." + label, fn, changed, [output])
        block = cases.fn("keepvault_test_v13_" + algorithm + "_256_encrypt_block", [P, Z, P, Z, P, Z])
        cases.matrix(algorithm + ".block", block, [key, 32, input_, 16, output, 129],
                     [(0, "key"), (2, "input"), (4, "output")], [output])
        cases.check(name + ".empty_null_data.allowed", fn, [key, 32, nonce, 16, None, 0, None, 0, 1], success=True)
    elif algorithm == "kalyna":
        for suffix, extra in [("_with_workers", [1]), ("_scalar", [])]:
            name = "keepvault_v13_kalyna_512_512_ctr_xcrypt" + suffix
            fn = cases.fn(name, [P, P, P, P, Z] + ([U] if extra else []))
            args = [key, nonce, input_, output, 129] + extra
            cases.matrix(name, fn, args, [(0, "key"), (1, "nonce"), (2, "input"), (3, "output")], [output])
            cases.check(name + ".empty_null_data.allowed", fn, [key, nonce, None, None, 0] + extra, success=True)
        worker = cases.fn("keepvault_v13_kalyna_512_512_ctr_xcrypt_with_workers", [P, P, P, P, Z, U])
        cases.check("kalyna.worker_zero", worker, [key, nonce, input_, output, 129, 0], [output])
    else:
        tweak = buf(16)
        name = "threefish_1024_ctr_xcrypt_v13_with_workers"
        fn = cases.fn(name, [P, P, P, P, P, Z, U])
        args = [key, tweak, nonce, input_, output, 129, 1]
        cases.matrix(name, fn, args, [(0, "key"), (1, "tweak"), (2, "nonce"), (3, "input"), (4, "output")], [output])
        cases.check(name + ".worker_zero", fn, [*args[:-1], 0], [output])
        cases.check(name + ".empty_null_data.allowed", fn, [key, tweak, nonce, None, None, 0, 1], success=True)
        block = cases.fn("threefish_1024_encrypt_block", [P, P, P, P])
        cases.matrix("threefish.block", block, [key, tweak, input_, output],
                     [(0, "key"), (1, "tweak"), (2, "input"), (3, "output")], [output])


def skein(cases):
    key, input_, output, pers = buf(128), buf(17), buf(128, 0xA5), buf(17)
    create = cases.fn("skein_1024_mac_create", [P, Z], C.c_void_p)
    if create(None, 128) is not None or create(key, 127) is not None:
        raise AssertionError("skein.mac_create.null_or_invalid_key")
    cases.results.extend([{"case": "skein.mac_create.null_key", "status": "PASS"},
                          {"case": "skein.mac_create.invalid_key_width", "status": "PASS"}])
    update = cases.fn("skein_1024_update", [C.c_void_p, P, Z])
    final = cases.fn("skein_1024_final", [C.c_void_p, P, Z])
    destroy = cases.fn("skein_1024_destroy", [C.c_void_p], None)
    cases.check("skein.update.null_handle", update, [None, input_, 17])
    cases.check("skein.final.null_handle", final, [None, output, 128], [output])
    handle = create(key, 128)
    if handle is None:
        raise AssertionError("skein.valid_locked_state_create")
    try:
        cases.check("skein.update.null_data_positive_length", update, [handle, None, 17])
        cases.check("skein.update.empty_null_data.allowed", update, [handle, None, 0], success=True)
        cases.check("skein.final.null_output", final, [handle, None, 128], [output])
        cases.check("skein.final.invalid_output_width", final, [handle, output, 127], [output])
        cases.check("skein.valid_state.final", final, [handle, output, 128], success=True)
        cases.check("skein.final.already_finalized", final, [handle, output, 128], [output])
    finally:
        destroy(handle)
    destroy(None)
    cases.results.append({"case": "skein.destroy.null_handle.allowed", "status": "PASS"})
    hash_ = cases.fn("skein_1024_hash", [P, Z, P])
    cases.matrix("skein.hash", hash_, [input_, 17, output], [(0, "input"), (2, "output")], [output])
    mac = cases.fn("skein_1024_mac", [P, Z, P, Z, P])
    cases.matrix("skein.mac", mac, [key, 128, input_, 17, output],
                 [(0, "key"), (2, "input"), (4, "output")], [output])
    cases.check("skein.mac.invalid_key_width", mac, [key, 127, input_, 17, output], [output])
    personalized = cases.fn("skein_1024_personalized_mac", [P, Z, P, Z, P, Z, P])
    cases.matrix("skein.personalized_mac", personalized, [key, 128, pers, 17, input_, 17, output],
                 [(0, "key"), (2, "personalization"), (4, "input"), (6, "output")], [output])


def xchacha(cases):
    key, nonce, aad, input_, output, tag = buf(32), buf(24), buf(17), buf(129), buf(129, 0xA5), buf(16, 0xA7)
    types = [P, Z, P, Z, P, Z, P, Z, P, Z, P, Z, U]
    for operation in ("encrypt", "decrypt"):
        name = "keepvault_xchacha20poly1305_v13_" + operation + "_with_budget"
        fn = cases.fn(name, types)
        args = [key, 32, nonce, 24, aad, 17, input_, 129, output, 129, tag, 16, 1]
        cases.matrix(name, fn, args, [(0, "key"), (2, "nonce"), (4, "aad"),
                                    (6, "input"), (8, "output"), (10, "tag")], [output, tag])
        for index, value, label in [(1, 31, "key_width"), (3, 23, "nonce_width"),
                                    (9, 128, "output_capacity"), (11, 15, "tag_width"), (12, 0, "worker_zero")]:
            changed = list(args)
            changed[index] = value
            cases.check(name + ".invalid." + label, fn, changed, [output, tag])
    hchacha = cases.fn("keepvault_test_hchacha20_v13", [P, Z, P, Z, P, Z])
    cases.matrix("hchacha", hchacha, [key, 32, nonce, 16, output, 32],
                 [(0, "key"), (2, "nonce"), (4, "output")], [output])
    create = cases.fn("poly1305_create", [P], C.c_void_p)
    update = cases.fn("poly1305_update", [C.c_void_p, P, Z])
    final = cases.fn("poly1305_final", [C.c_void_p, P])
    destroy = cases.fn("poly1305_destroy", [C.c_void_p], None)
    if create(None) is not None:
        raise AssertionError("poly1305.create.null_key")
    cases.results.append({"case": "poly1305.create.null_key", "status": "PASS"})
    cases.check("poly1305.update.null_handle", update, [None, input_, 129])
    cases.check("poly1305.final.null_handle", final, [None, tag], [tag])
    handle = create(key)
    if handle is None:
        raise AssertionError("poly1305.valid_state_create")
    try:
        cases.check("poly1305.update.null_data_positive_length", update, [handle, None, 129])
        cases.check("poly1305.update.empty_null_data.allowed", update, [handle, None, 0], success=True)
        cases.check("poly1305.final.null_output", final, [handle, None], [tag])
    finally:
        destroy(handle)
    destroy(None)
    cases.results.append({"case": "poly1305.destroy.null_handle.allowed", "status": "PASS"})


def sha3(cases):
    key, data, output = buf(64), buf(17), buf(64, 0xA5)
    fn = cases.fn("sha3_512_reference_hash", [P, Z, P, Z])
    cases.matrix("sha3.hash", fn, [data, 17, output, 64], [(0, "input"), (2, "output")], [output])
    mac = cases.fn("hmac_sha3_512_reference", [P, Z, P, Z, P, Z])
    cases.matrix("sha3.hmac", mac, [key, 64, data, 17, output, 64],
                 [(0, "key"), (2, "input"), (4, "output")], [output])
    cases.check("sha3.hmac.empty_null_key_and_message.allowed", mac, [None, 0, None, 0, output, 64], success=True)


def child(args):
    path = Path(args.native_dir).resolve() / LIBRARIES[args.library]
    initial = digest(path)
    report = {"schema": "keepvault.native-key-handoff-null-child.v1", "pid": os.getpid(),
              "started_utc": utc(), "architecture": platform.machine(), "library": args.library,
              "library_sha256": initial, "status": "FAIL"}
    try:
        cases = Cases(C.CDLL(str(path)))
        if args.library == "argon2":
            argon(cases)
        elif args.library == "xchacha":
            xchacha(cases)
        elif args.library == "sha3":
            sha3(cases)
        else:
            ctr(cases, args.library)
            if args.library == "threefish":
                skein(cases)
        if digest(path) != initial:
            raise AssertionError("library_bytes_changed_during_child")
        report.update(status="PASS", checks=len(cases.results), cases=cases.results)
    except Exception as error:
        report.update(error_type=type(error).__name__, failed_case=str(error),
                      checks=len(cases.results) if "cases" in locals() else 0,
                      cases=cases.results if "cases" in locals() else [])
    report["finished_utc"] = utc()
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


def parent(args):
    if sys.platform != "darwin":
        raise SystemExit("This ABI harness targets macOS dylibs.")
    native = Path(args.native_dir).resolve(strict=True)
    output = Path(args.output).resolve()
    if output.exists():
        raise SystemExit("Refusing to overwrite an earlier test receipt.")
    repo = Path(__file__).resolve().parents[2]
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True,
                              capture_output=True, text=True).stdout.strip()
    tracked = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=repo,
                             check=True, capture_output=True, text=True).stdout
    report = {"schema": "keepvault.native-key-handoff-nulls.v1", "pid": os.getpid(),
              "started_utc": utc(), "source_head": revision, "tracked_worktree_dirty": bool(tracked),
              "harness_sha256": digest(Path(__file__)), "requested_architecture": args.arch,
              "native_directory": str(native), "status": "FAIL", "children": [],
              "scope": "NULL ABI rejection and legitimate optional NULL; independent constant-key oracles are separate managed tests",
              "no_invalid_nonnull_addresses_or_expired_handles": True,
              "no_production_argon2_allocation": True}
    for algorithm, filename in LIBRARIES.items():
        path = native / filename
        before = digest(path)
        command = ["/usr/bin/arch", "-" + args.arch, args.python, str(Path(__file__).resolve()),
                   "--child", "--library", algorithm, "--native-dir", str(native)]
        started = utc()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            stdout, stderr = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
        entry = {"library": algorithm, "library_sha256": before, "child_pid": process.pid,
                 "started_utc": started, "finished_utc": utc(), "exit_code": process.returncode,
                 "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
                 "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest()}
        try:
            receipt = json.loads(stdout)
            entry["receipt"] = receipt
            entry["binding_valid"] = (receipt["pid"] == process.pid
                                      and receipt["architecture"] == args.arch
                                      and receipt["library_sha256"] == before == digest(path))
        except (ValueError, KeyError):
            entry["binding_valid"] = False
        report["children"].append(entry)
    report["finished_utc"] = utc()
    report["status"] = "PASS" if all(item["exit_code"] == 0 and item["binding_valid"]
                                          and item["receipt"]["status"] == "PASS"
                                          for item in report["children"]) else "FAIL"
    report["checks"] = sum(item.get("receipt", {}).get("checks", 0) for item in report["children"])
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "x", encoding="utf-8") as destination:
        json.dump(report, destination, indent=2, sort_keys=True)
        destination.write("\n")
    print(json.dumps({"status": report["status"], "checks": report["checks"],
                      "receipt": str(output), "receipt_sha256": digest(output)}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-dir", required=True)
    parser.add_argument("--output")
    parser.add_argument("--arch", choices=["arm64", "x86_64"], default=platform.machine())
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--library", choices=list(LIBRARIES), help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if arguments.child and arguments.library:
        sys.exit(child(arguments))
    if not arguments.output:
        parser.error("--output is required for the parent runner")
    sys.exit(parent(arguments))
