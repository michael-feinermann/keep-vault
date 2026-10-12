#!/usr/bin/env python3
"""Curate only explicitly selected, immutable public handoff captures.

No tests, binaries, shell commands, Git operations or signing are executed.
Missing evidence fails closed. This collector cannot grant release approval.
Copied originals retain their exact bytes; no sanitized/reconstructed text is
presented as a capture. Python standard library only, Python 3.9 or later.
"""
import argparse
from collections import Counter
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

PRODUCT_IDS = (
    "security.kdf-handoff-fault-matrix", "security.kdf-null-width-round-contracts",
    "security.kdf-key-owner-contracts", "security.kdf-handoff-destination-cleanup",
    "security.native-managed-null-contracts", "security.native-managed-width-contracts",
    "crypto.native-constant-key-oracles", "kdf.native-constant-argon-inputs",
    "security.downstream-suite-handoff-faults", "security.downstream-mac-handoff-faults",
    "security.downstream-recovery-handoff-faults", "security.downstream-disposed-owner-faults",
    "security.downstream-null-width-contracts",
)
AUDIT_IDS = ("audit.fixed-cli-isolation", "audit.passive-cpu-observer", "audit.metadata-allowlist")
# Fixed reviewed/registered lifecycle case only; no arbitrary extra IDs.
AUDIT_LIFECYCLE_ID = "audit.initialization-close-join"
SUITES = frozenset(("Kalyna512_512", "Threefish1024", "StandardCascade", "ParanoiaCascade",
    "XChaChaOverAes", "Aes256", "Mars448", "Shacal2_512", "XChaCha20Poly1305", "MixedCascade", "Camellia256", "Serpent256"))
LIBRARIES = {"argon2": "libargon2_ref.dylib", "aes": "libaes_ref.dylib", "mars": "libmars_ref.dylib",
    "shacal2": "libshacal2_ref.dylib", "kalyna": "libkalyna_v13.dylib", "threefish": "libthreefish_ref.dylib",
    "camellia": "libcamellia_v13.dylib", "serpent": "libserpent_v13.dylib",
    "xchacha": "libxchachapoly_v13.dylib", "sha3": "libsha3_ref.dylib"}
PRODUCT_LIBRARIES = frozenset(value for key, value in LIBRARIES.items() if key != "sha3")
MAC_IDS = frozenset(("mac/tree/sha3-parent-consumer", "mac/tree/skein-parent-consumer",
    "mac/tree/sha3-leaf-derived", "mac/tree/sha3-root-derived", "mac/tree/skein-leaf-derived", "mac/tree/skein-root-derived",
    "mac/tree/sha3-root-consumer", "mac/tree/skein-root-consumer", "mac/tree/sha3-leaf-consumer", "mac/tree/skein-leaf-consumer"))
RECOVERY_IDS = frozenset(("recovery/parent/sha3-consumer", "recovery/parent/skein-consumer",
    "recovery/certification/sha3-output", "recovery/certification/skein-output",
    "recovery/certification/sha3-consumer", "recovery/certification/skein-consumer"))
PREFIXES = {PRODUCT_IDS[0]: "KDF_HANDOFF_MATRIX ", PRODUCT_IDS[8]: "handoff_fault_matrix=",
    PRODUCT_IDS[9]: "handoff_fault_matrix=", PRODUCT_IDS[10]: "handoff_fault_matrix=", PRODUCT_IDS[11]: "handoff_owner_lifecycle="}
HEX64 = re.compile(r"[0-9a-fA-F]{64}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9_. /()+-]{1,512}\Z")
MAX_CAPTURE = 8 << 20


class Unavailable(Exception):
    pass


def require(condition, label):
    if not condition:
        raise Unavailable(label)


def fields(value, required, label, optional=()):
    require(isinstance(value, dict) and set(required) <= value.keys()
        and value.keys() <= set(required) | set(optional), label)


def number(value, label, minimum=0, integer=False):
    require(type(value) in ((int,) if integer else (int, float))
        and math.isfinite(value) and value >= minimum, label)


def public_text(value, label, maximum=4096):
    require(isinstance(value, str) and len(value) <= maximum and "\x00" not in value, label)
    return value


def hash_text(value, label):
    require(isinstance(value, str) and HEX64.fullmatch(value), label)
    return value.lower()


def timestamp(value, label):
    try:
        result = dt.datetime.fromisoformat(public_text(value, label).replace("Z", "+00:00"))
    except ValueError:
        raise Unavailable(label) from None
    require(result.tzinfo is not None, label)
    return result


def sha(value):
    return hashlib.sha256(value).hexdigest()


def document(value, label):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            require(key not in result, label + ".duplicate-field")
            result[key] = item
        return result
    def invalid_constant(_):
        raise Unavailable(label + ".nonfinite")
    try:
        return json.loads(value, object_pairs_hook=unique, parse_constant=invalid_constant)
    except (ValueError, UnicodeError):
        raise Unavailable(label + ".json") from None


def read_regular(path, label, capture=True):
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)), "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and (not capture or before.st_size <= MAX_CAPTURE), label + ".regular-bounded")
            if capture:
                value = stream.read(MAX_CAPTURE + 1)
                require(len(value) == before.st_size, label + ".size")
            else:
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(chunk)
                value = digest.hexdigest()
            after = os.fstat(stream.fileno())
            require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), label + ".changed-during-read")
            return value
    except OSError:
        raise Unavailable(label + ".unavailable") from None


class Captures:
    def __init__(self):
        self.files = {}
        self.rechecks = {}

    def read(self, source, output, label):
        value = read_regular(source, label)
        require(output not in self.files, "collector.duplicate-output")
        self.files[output] = value
        self.rechecks[str(source)] = sha(value)
        return value

    def json(self, source, output, label):
        return document(self.read(source, output, label), label)

    def artifact(self, source, expected, label):
        expected = hash_text(expected, label + ".hash")
        require(read_regular(source, label, capture=False) == expected, label + ".hash-mismatch")
        self.rechecks[str(source)] = expected

    def unchanged(self):
        for path, expected in self.rechecks.items():
            require(read_regular(path, "collector.final-recheck", capture=False) == expected, "collector.final-hash-mismatch")


def diagnostic(value, test_id, result_name):
    try:
        lines = value.decode("utf-8").splitlines()
    except UnicodeError:
        raise Unavailable("stdout.utf8") from None
    prefix = PREFIXES.get(test_id)
    matches = []
    for line in lines:
        if not line:
            continue
        if prefix and line.startswith(prefix):
            require(len(line) <= 1 << 20, "stdout.diagnostic-bounded")
            matches.append(document(line[len(prefix):], "stdout.diagnostic"))
        else:
            require(line.startswith(("scheduler: ", "wall clock ", "results written to "))
                or line == "1 macOS groups: 1 passed, 0 failed, 0 blocked."
                or line.startswith("FULL PASS " + result_name + " ("), "stdout.unallowlisted-line")
            require(not re.search(r"[0-9a-fA-F]{129,}|0x[0-9a-fA-F]{9,}", line), "stdout.raw-value")
    require(len(matches) == (1 if prefix else 0), "stdout.required-matrix-missing-or-duplicate")
    return matches[0] if matches else None


def kdf_matrix(value):
    fields(value, ("status", "profile", "suiteCount", "boundaryCount", "caseCount", "rows"), "kdf.shape")
    require(value["status"] == "PASS" and value["profile"] == "internal-8-MiB-fault-injection-only"
        and (value["suiteCount"], value["boundaryCount"], value["caseCount"]) == (12, 626, 2504), "kdf.expected-counts-profile")
    rows = value["rows"]
    require(isinstance(rows, list) and len(rows) == 12 and {row.get("suite") for row in rows if isinstance(row, dict)} == SUITES, "kdf.suites")
    boundaries = cases = 0
    for row in rows:
        fields(row, ("suite", "boundaryCount", "caseCount", "boundaries", "faults", "status"), "kdf.row")
        names = row["boundaries"]
        require(isinstance(names, list) and all(isinstance(name, str) and IDENTIFIER.fullmatch(name) for name in names), "kdf.metadata-ids")
        require(row["status"] == "PASS" and len(names) == len(set(names)) == row["boundaryCount"]
            and row["caseCount"] == 4 * len(names) and row["faults"] == ["00", "01", "FF", "missing-output"], "kdf.row-counts")
        boundaries += len(names)
        cases += row["caseCount"]
    require((boundaries, cases) == (626, 2504), "kdf.actual-totals")
    return {"suites": 12, "boundaries": boundaries, "cases": cases, "profile": value["profile"],
        "assertionScope": "Actual per-suite boundary inventories/counts; per-case hit/rejection/cleanup assertions run in the bound test, not individually exported KDF receipts"}


def downstream_matrix(value, test_id):
    fields(value, ("TestId", "Cases", "Normal", "Scope"), "downstream.shape")
    require(value["TestId"] == test_id, "downstream.test-id")
    public_text(value["Scope"], "downstream.scope")
    normal, expected = value["Normal"], {}
    if test_id == PRODUCT_IDS[8]:
        require(isinstance(normal, list) and len(normal) == 12, "downstream.suite-count")
        for row in normal:
            fields(row, ("Suite", "Boundaries", "SuccessfulProductionChunk"), "downstream.suite-normal-shape")
            require(row["Suite"] in SUITES and row["Suite"] not in expected and row["SuccessfulProductionChunk"] is True, "downstream.suite-normal")
            expected[row["Suite"]] = row["Boundaries"]
        require(set(expected) == SUITES, "downstream.suite-inventory")
    elif test_id == PRODUCT_IDS[9]:
        require(isinstance(normal, list) and len(normal) == 2, "downstream.mac-contexts")
        for row in normal:
            fields(row, ("Workers", "Leaves", "PeakActualCpuPermits", "Boundaries", "SuccessfulProductionMac"), "downstream.mac-normal-shape")
            require(row["Workers"] in (1, 2) and row["Leaves"] == 3 and row["SuccessfulProductionMac"] is True
                and type(row["PeakActualCpuPermits"]) is int and row["PeakActualCpuPermits"] >= row["Workers"], "downstream.actual-cpu-permits")
            require(isinstance(row["Boundaries"], list) and set(row["Boundaries"]) == MAC_IDS, "downstream.mac-inventory")
            context = "MAC workers=" + str(row["Workers"])
            require(context not in expected, "downstream.duplicate-context")
            expected[context] = row["Boundaries"]
        require(set(expected) == {"MAC workers=1", "MAC workers=2"}, "downstream.serial-parallel")
    else:
        fields(normal, ("Boundaries",), "downstream.recovery-normal-shape")
        require(isinstance(normal["Boundaries"], list) and set(normal["Boundaries"]) == RECOVERY_IDS, "downstream.recovery-six-guards")
        expected["KPAR2 certification"] = normal["Boundaries"]
    for names in expected.values():
        require(isinstance(names, list) and all(isinstance(name, str) and IDENTIFIER.fullmatch(name) for name in names)
            and len(names) == len(set(names)), "downstream.normal-metadata-ids")
    if test_id == PRODUCT_IDS[8]:
        require(sum(sum(name.endswith("/aead-copy") for name in names) for names in expected.values()) == 5, "downstream.five-aead-copies")
    cases, actual = value["Cases"], Counter()
    require(isinstance(cases, list), "downstream.cases")
    for row in cases:
        fields(row, ("Boundary", "Fault", "Context", "InjectionHits", "NoCompletedResult", "CallerOwnedAliasesErased",
            "LockAllocationBaselineRestored", "ErasureObservationScope"), "downstream.case-shape")
        require(row["Context"] in expected and row["Boundary"] in expected[row["Context"]], "downstream.guard-context")
        require(row["Fault"] in ("Missing", "Zero", "ByteOne", "AllBitsOne") and row["InjectionHits"] == 1
            and row["NoCompletedResult"] is True and row["CallerOwnedAliasesErased"] is True
            and row["LockAllocationBaselineRestored"] is True, "downstream.actual-rejection-cleanup")
        public_text(row["ErasureObservationScope"], "downstream.erasure-scope")
        actual[(row["Context"], row["Boundary"], row["Fault"])] += 1
    wanted = Counter((context, name, fault) for context, names in expected.items() for name in names
        for fault in ("Missing", "Zero", "ByteOne", "AllBitsOne"))
    require(actual == wanted, "downstream.complete-fault-contexts")
    return {"contexts": len(expected), "guardContexts": sum(map(len, expected.values())), "faultCases": len(cases),
        "injectionHitOnce": True, "noCompletedResult": True, "callerOwnedAliasesErased": True, "lockAllocationBaselineRestored": True,
        "erasureScope": "Original per-case scopes apply; private internal temporary spans are not retained"}


def lifecycle(value):
    fields(value, ("OwnerTypes", "SuccessAndFailedUnlockCases", "GettersClosed", "ActualAliasesErased", "LockAllocationBaselineRestored"), "owner.shape")
    require(value["OwnerTypes"] == ["LockedSensitiveBuffer", "SuiteKeyMaterial", "RecoveryKeys"]
        and value["SuccessAndFailedUnlockCases"] == 6 and value["GettersClosed"] is True
        and value["ActualAliasesErased"] is True and value["LockAllocationBaselineRestored"] is True, "owner.actual-lifecycle")
    return value


def campaign(captures, path):
    value = captures.json(path, "managed/campaign-terminal.json", "campaign")
    fields(value, ("status", "binding", "cases", "finishedUtc", "scope"), "campaign.shape")
    require(value["status"] == "PASS", "campaign.status")
    timestamp(value["finishedUtc"], "campaign.finished")
    public_text(value["scope"], "campaign.scope")
    binding = value["binding"]
    fields(binding, ("harnessSha256", "productSha256", "sdkHostSha256", "nativeFiles"), "campaign.binding-shape")
    for name in ("harnessSha256", "productSha256", "sdkHostSha256"):
        hash_text(binding[name], "campaign.binding-hash")
    native = binding["nativeFiles"]
    require(isinstance(native, dict) and set(native) == set(LIBRARIES.values()) | {"libmldsa87_ref.dylib"}, "campaign.native-test-inventory")
    for digest in native.values():
        hash_text(digest, "campaign.native-hash")
    rows = value["cases"]
    require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows), "campaign.cases")
    ids = [row.get("testId") for row in rows]
    wanted = set(PRODUCT_IDS) | set(AUDIT_IDS)
    require(len(ids) == len(set(ids)) and (set(ids) == wanted or set(ids) == wanted | {AUDIT_LIFECYCLE_ID}), "campaign.exact-13-plus-audit-ids")
    pids, identity, executable_args, outcomes, matrices = set(), None, None, [], {}
    for row in rows:
        fields(row, ("testId", "pid", "startedUtc", "args", "exitCode", "terminalUtc", "stdoutSha256", "binaryBindingStable", "resultsSha256"), "campaign.row-shape")
        ident, args = row["testId"], row["args"]
        number(row["pid"], "campaign.pid", 1, True)
        require(row["pid"] not in pids and row["exitCode"] == 0 and row["binaryBindingStable"] is True, "campaign.process-terminal")
        pids.add(row["pid"])
        require(timestamp(row["startedUtc"], "campaign.start") <= timestamp(row["terminalUtc"], "campaign.terminal"), "campaign.time-order")
        require(isinstance(args, list) and len(args) == 8 and all(isinstance(arg, str) for arg in args)
            and args[2:] == ["--full", "--no-smoke", "--only", ident, "--parallel", "1"], "campaign.exact-worker-command")
        require(Path(args[0]).is_absolute() and Path(args[0]).name == "dotnet"
            and Path(args[1]).is_absolute() and Path(args[1]).name == "KeepVaultMac.Tests.dll", "campaign.binary-paths")
        if executable_args is None:
            executable_args = args[:2]
        require(args[:2] == executable_args, "campaign.same-bound-binaries")
        raw = captures.read(path.parent / (ident + "-results.json"), "managed/" + ident + "-results.json", "result")
        stdout = captures.read(path.parent / (ident + ".stdout"), "managed/" + ident + ".stdout", "stdout")
        require(sha(raw) == hash_text(row["resultsSha256"], "campaign.result-hash")
            and sha(stdout) == hash_text(row["stdoutSha256"], "campaign.stdout-hash"), "campaign.original-capture-hashes")
        result = document(raw, "result")
        fields(result, ("schemaVersion", "head", "testInventoryHash", "platform", "osArchitecture", "processArchitecture", "hardware", "budget", "tests"), "result.shape")
        require(result["schemaVersion"] == 3 and result["platform"] == "macos"
            and result["osArchitecture"] == result["processArchitecture"] == "arm64"
            and isinstance(result["head"], str) and re.fullmatch(r"[0-9a-fA-F]{40}", result["head"]), "result.platform-source")
        current = (result["head"], hash_text(result["testInventoryHash"], "result.inventory"), result["hardware"], result["budget"])
        if identity is None:
            identity = current
        require(current == identity, "result.consistent-source-inventory-host-budget")
        public_text(result["hardware"], "result.hardware", 256)
        fields(result["budget"], ("maxWorkers", "cpuTokens", "memoryMiB", "argonSlots", "zpaqSlots"), "result.budget-shape")
        for grant in result["budget"].values():
            number(grant, "result.budget", 1, True)
        require(result["budget"]["maxWorkers"] == 1, "result.single-worker")
        tests = result["tests"]
        require(isinstance(tests, list) and len(tests) == 1, "result.exact-single-test")
        test = tests[0]
        fields(test, ("id", "name", "status", "seconds", "peakRssMiB", "seed", "failure"), "result.test-shape")
        require(test["id"] == ident and test["status"] == "PASS" and test["failure"] is None, "result.test-status")
        public_text(test["name"], "result.name", 512)
        require(isinstance(test["seed"], str) and re.fullmatch(r"0x[0-9a-fA-F]{8}", test["seed"]), "result.public-fixture-seed")
        number(test["seconds"], "result.seconds")
        number(test["peakRssMiB"], "result.rss", 0, True)
        emitted = diagnostic(stdout, ident, test["name"])
        if ident == PRODUCT_IDS[0]:
            matrices["kdf"] = kdf_matrix(emitted)
        elif ident in PRODUCT_IDS[8:11]:
            matrices[ident] = downstream_matrix(emitted, ident)
        elif ident == PRODUCT_IDS[11]:
            matrices["owners"] = lifecycle(emitted)
        outcomes.append({"testId": ident, "coordinatorPid": row["pid"], "status": "PASS", "seconds": test["seconds"], "peakRssMiB": test["peakRssMiB"]})
    sdk, harness = map(Path, executable_args)
    captures.artifact(sdk, binding["sdkHostSha256"], "campaign.sdk-binary")
    captures.artifact(harness, binding["harnessSha256"], "campaign.harness-binary")
    captures.artifact(harness.parent / "Keep Vault.dll", binding["productSha256"], "campaign.product-binary")
    for name, digest in native.items():
        captures.artifact(harness.parent / "Native" / name, digest, "campaign.native-test-binary")
    return {"binding": binding, "sourceHead": identity[0], "inventoryHash": identity[1], "hardware": identity[2],
        "productGroups": 13, "auditGroups": len(ids) - 13, "groups": len(ids), "tests": outcomes, "matrices": matrices}


def native(captures, path, architecture, managed):
    value = captures.json(path, "native/native-null-" + architecture + ".json", "native")
    fields(value, ("schema", "pid", "started_utc", "source_head", "tracked_worktree_dirty", "harness_sha256",
        "requested_architecture", "native_directory", "status", "children", "scope", "no_invalid_nonnull_addresses_or_expired_handles",
        "no_production_argon2_allocation", "finished_utc", "checks"), "native.parent-shape")
    require(value["schema"] == "keepvault.native-key-handoff-nulls.v1" and value["status"] == "PASS"
        and value["requested_architecture"] == architecture and value["checks"] == 161
        and value["source_head"] == managed["sourceHead"] and type(value["tracked_worktree_dirty"]) is bool
        and value["no_invalid_nonnull_addresses_or_expired_handles"] is True
        and value["no_production_argon2_allocation"] is True, "native.parent-status-scope")
    number(value["pid"], "native.parent-pid", 1, True)
    timestamp(value["started_utc"], "native.parent-start")
    timestamp(value["finished_utc"], "native.parent-finish")
    public_text(value["scope"], "native.scope")
    directory = Path(public_text(value["native_directory"], "native.directory"))
    require(directory.is_absolute(), "native.absolute-directory")
    harness_hash = hash_text(value["harness_sha256"], "native.harness-hash")
    source = Path(__file__).absolute().parent.parent / "native/tests/test_key_handoff_nulls.py"
    captures.artifact(source, harness_hash, "native.harness-source")
    children, pids, checks, reference = value["children"], set(), 0, None
    require(isinstance(children, list) and len(children) == 10
        and {row.get("library") for row in children if isinstance(row, dict)} == set(LIBRARIES), "native.child-inventory")
    for row in children:
        fields(row, ("library", "library_sha256", "child_pid", "started_utc", "finished_utc", "exit_code", "stdout_sha256", "stderr_sha256", "receipt", "binding_valid"), "native.child-shape")
        library, digest = row["library"], hash_text(row["library_sha256"], "native.library-hash")
        if library != "sha3":
            require(digest == managed["binding"]["nativeFiles"][LIBRARIES[library]].lower(), "native.same-nine-product-library-bytes")
        else:
            # The independent SHA3 ABI oracle is test-only. Its per-slice binary
            # is deliberately separate from the nine universal product libs.
            reference = {"library": LIBRARIES[library], "sha256": digest, "architecture": architecture, "shippedProductComponent": False}
        captures.artifact(directory / LIBRARIES[library], digest, "native.actual-library")
        number(row["child_pid"], "native.child-pid", 1, True)
        require(row["child_pid"] != value["pid"] and row["child_pid"] not in pids
            and row["exit_code"] == 0 and row["binding_valid"] is True, "native.actual-pid-exit-binding")
        pids.add(row["child_pid"])
        require(timestamp(row["started_utc"], "native.child-start") <= timestamp(row["finished_utc"], "native.child-finish"), "native.time-order")
        hash_text(row["stdout_sha256"], "native.stdout-hash")
        require(hash_text(row["stderr_sha256"], "native.stderr-hash") == sha(b""), "native.no-unexpected-stderr")
        receipt = row["receipt"]
        fields(receipt, ("schema", "pid", "architecture", "library", "library_sha256", "status", "started_utc", "finished_utc", "checks", "cases"), "native.receipt-shape")
        require(receipt["schema"] == "keepvault.native-key-handoff-null-child.v1" and receipt["pid"] == row["child_pid"]
            and receipt["architecture"] == architecture and receipt["library"] == library
            and hash_text(receipt["library_sha256"], "native.receipt-hash") == digest and receipt["status"] == "PASS", "native.actual-slice-library-pid")
        canonical_stdout = (json.dumps(receipt, sort_keys=True) + "\n").encode("utf-8")
        require(sha(canonical_stdout) == row["stdout_sha256"].lower(), "native.child-original-json-hash")
        cases = receipt["cases"]
        require(isinstance(cases, list) and len(cases) == receipt["checks"] and len(cases) > 0, "native.child-case-count")
        names = []
        for case in cases:
            fields(case, ("case", "status"), "native.case-shape", ("native_status", "output_unchanged", "elapsed_seconds"))
            name = public_text(case["case"], "native.case-id", 512)
            require(IDENTIFIER.fullmatch(name) and case["status"] == "PASS", "native.case-status-id")
            names.append(name)
            if "native_status" in case:
                require(type(case["native_status"]) is int and "output_unchanged" in case, "native.abi-status")
                require(case["output_unchanged"] is (True if case["native_status"] != 0 else None), "native.validation-output-contract")
                number(case.get("elapsed_seconds"), "native.case-duration")
        require(len(names) == len(set(names)), "native.unique-case-ids")
        checks += len(cases)
    require(checks == 161, "native.actual-161-checks")
    return {"architecture": architecture, "parentPid": value["pid"], "childPids": sorted(pids), "checks": checks,
        "harnessSha256": harness_hash, "trackedWorktreeDirty": value["tracked_worktree_dirty"],
        "nineActualProductLibrariesMatchCampaign": True, "separateTestReference": reference,
        "scope": "Actual owned-buffer/NULL ABI and legitimate optional NULL calls; no invalid non-NULL/UAF addresses or production Argon allocation"}


def owner_comparison(captures, path, managed):
    value = captures.json(path, "owner-before-after/comparison-receipt.json", "comparison")
    fields(value, ("schemaVersion", "status", "beforePid", "afterPid", "beforeProductSha256", "afterProductSha256",
        "matchesCampaign03ProductSha256", "matchesCampaign03HarnessProductCopySha256", "sourceProbeReusedWithoutRebuild",
        "receiptSha256", "probeSourceRoot", "probeSourceSha256", "campaign03Binding", "completeOldMatrixExecuted",
        "nativeMemoryLockInvoked", "releaseApproved", "scope"), "comparison.shape")
    require(value["schemaVersion"] == 1 and value["status"] == "NARROW_OLD_FAILURE_NEW_PASS_PROVEN_FINAL_MANAGED_BINDING"
        and value["matchesCampaign03ProductSha256"] is True and value["matchesCampaign03HarnessProductCopySha256"] is True
        and value["sourceProbeReusedWithoutRebuild"] is True and value["campaign03Binding"] == managed["binding"]
        and value["nativeMemoryLockInvoked"] is False and value["completeOldMatrixExecuted"] is False
        and value["releaseApproved"] is False, "comparison.narrow-scope-status")
    require(hash_text(value["afterProductSha256"], "comparison.after-hash") == managed["binding"]["productSha256"].lower(), "comparison.same-campaign-after-product")
    hash_text(value["beforeProductSha256"], "comparison.before-hash")
    public_text(value["scope"], "comparison.public-scope")
    source_root = Path(public_text(value["probeSourceRoot"], "comparison.source-root"))
    require(source_root.is_absolute(), "comparison.absolute-source-root")
    hashes = value["probeSourceSha256"]
    require(isinstance(hashes, dict) and set(hashes) == {"OwnerBeforeAfterProbe.csproj", "Program.cs", "global.json", "Directory.Build.props",
        "Directory.Build.targets", "NuGet.Config", "bin/Release/net10.0/OwnerBeforeAfterProbe.dll"}, "comparison.exact-public-inputs")
    for name, digest in hashes.items():
        captures.artifact(source_root / name, digest, "comparison.public-input")
        if not name.endswith(".dll"):
            raw_source = captures.read(source_root / name, "owner-before-after/probe-source/" + name, "comparison.public-source")
            require(sha(raw_source) == digest.lower(), "comparison.public-source-copy")
    receipt_hashes = value["receiptSha256"]
    fields(receipt_hashes, ("before-receipt.json", "after-receipt.json"), "comparison.receipt-hashes")
    for variant in ("before", "after"):
        raw = captures.read(path.parent / (variant + "-receipt.json"), "owner-before-after/" + variant + "-receipt.json", "comparison.receipt")
        require(sha(raw) == hash_text(receipt_hashes[variant + "-receipt.json"], "comparison.receipt-hash"), "comparison.original-receipt-hash")
        receipt = document(raw, "comparison.receipt")
        fields(receipt, ("schemaVersion", "testId", "variant", "status", "securityGatePassed", "expectedObservationMatched", "createdUtc", "actualPid",
            "productAssemblyPath", "productAssemblySha256", "productAssemblyIdentity", "productArtifactUnchangedDuringExecution", "probeAssemblySha256",
            "framework", "processArchitecture", "initialGetterMatchesCallerAlias", "firstDisposeReportedInjectedFailure", "aliasErasedBeforeFailedUnlockReturn",
            "getterReturnedAliasAfterFailure", "getterRejectedAfterFailure", "fakeUnlockAttempts", "retryCompleted", "getterRejectedAfterRetry",
            "completedDisposeIsIdempotent", "scope"), "comparison.receipt-shape")
        after = variant == "after"
        number(receipt["actualPid"], "comparison.pid", 1, True)
        require(receipt["schemaVersion"] == 1 and receipt["testId"] == "security.owner-failed-dispose-before-after" and receipt["variant"] == variant
            and receipt["status"] == ("NEW_REGRESSION_PASS" if after else "OLD_SECURITY_FAILURE_REPRODUCED")
            and receipt["securityGatePassed"] is after and receipt["expectedObservationMatched"] is True
            and receipt["actualPid"] == value[variant + "Pid"] and receipt["productArtifactUnchangedDuringExecution"] is True
            and receipt["initialGetterMatchesCallerAlias"] is True and receipt["firstDisposeReportedInjectedFailure"] is True
            and receipt["aliasErasedBeforeFailedUnlockReturn"] is True and receipt["getterReturnedAliasAfterFailure"] is (not after)
            and receipt["getterRejectedAfterFailure"] is after and receipt["fakeUnlockAttempts"] == 2 and receipt["retryCompleted"] is True
            and receipt["getterRejectedAfterRetry"] is True and receipt["completedDisposeIsIdempotent"] is True
            and receipt["processArchitecture"] == "Arm64", "comparison.actual-owner-behavior")
        require(hash_text(receipt["productAssemblySha256"], "comparison.product-hash") == value[variant + "ProductSha256"].lower()
            and hash_text(receipt["probeAssemblySha256"], "comparison.probe-hash") == hashes["bin/Release/net10.0/OwnerBeforeAfterProbe.dll"].lower(), "comparison.actual-binary-binding")
        captures.artifact(Path(public_text(receipt["productAssemblyPath"], "comparison.product-path")), receipt["productAssemblySha256"], "comparison.actual-product")
        for key in ("productAssemblyIdentity", "framework", "scope"):
            public_text(receipt[key], "comparison.public-receipt-metadata")
        timestamp(receipt["createdUtc"], "comparison.created")
    require(value["beforePid"] != value["afterPid"], "comparison.separate-processes")
    return {"status": value["status"], "beforePid": value["beforePid"], "afterPid": value["afterPid"],
        "afterMatchesCampaignProduct": True, "completeOldMatrixExecuted": False, "nativeMemoryLockInvoked": False, "scope": value["scope"]}


def superseded_attempts(captures, args, managed):
    attempts = []
    if args.superseded_native_x64:
        path = Path(args.superseded_native_x64).absolute()
        # A loader error can contain memory addresses. Retain only its original
        # digest and a verified classification, not raw loader text in GitHub.
        raw = read_regular(path, "superseded.native")
        captures.rechecks[str(path)] = sha(raw)
        value = document(raw, "superseded.native")
        require(value.get("schema") == "keepvault.native-key-handoff-nulls.v1" and value.get("status") == "FAIL"
            and value.get("requested_architecture") == "x86_64" and value.get("checks") == 155, "superseded.native-expected-failure")
        children = value.get("children")
        require(isinstance(children, list) and len(children) == 10
            and {row.get("library") for row in children} == set(LIBRARIES), "superseded.native-inventory")
        for row in children:
            if row["library"] == "sha3":
                require(row.get("exit_code") == 1 and row.get("receipt", {}).get("error_type") == "OSError"
                    and row.get("receipt", {}).get("status") == "FAIL" and row.get("receipt", {}).get("checks") == 0, "superseded.only-sha3-loader-failed")
            else:
                require(row.get("exit_code") == 0 and row.get("binding_valid") is True
                    and row.get("receipt", {}).get("status") == "PASS"
                    and hash_text(row.get("library_sha256"), "superseded.native-library-hash")
                        == managed["binding"]["nativeFiles"][LIBRARIES[row["library"]]].lower(), "superseded.nine-product-libraries-passed")
        attempts.append({"kind": "x86_64-native-staging", "originalReceiptSha256": sha(raw), "status": "SUPERSEDED_REFERENCE_ASSET_LOAD_FAILURE",
            "checksPassed": 155, "nineProductLibraryChildrenPassed": True, "failedReference": "libsha3_ref.dylib",
            "referenceChecksUnavailable": 6, "errorType": "OSError", "rawLoaderTextPublished": False,
            "classificationScope": "Only test-reference loading failed; corrected independently bound per-slice reference is tested by the final 161-check receipt"})
    if args.superseded_build_terminal:
        value = captures.json(Path(args.superseded_build_terminal).absolute(), "superseded/build-attempt-terminal.json", "superseded.build")
        fields(value, ("pid", "exitCode", "completedUtc", "logSha256"), "superseded.build-shape")
        number(value["pid"], "superseded.build-pid", 1, True)
        require(value["exitCode"] == 1, "superseded.build-failed")
        timestamp(value["completedUtc"], "superseded.build-terminal")
        hash_text(value["logSha256"], "superseded.build-log-hash")
        attempts.append({"kind": "managed-harness-build", "status": "SUPERSEDED_COMPILE_FAILURE", "exitCode": 1,
            "actualPid": value["pid"], "rawBuildLogPublished": False, "scope": "Terminal metadata only; no release or successful-build claim"})
    if args.superseded_campaign:
        path = Path(args.superseded_campaign).absolute()
        value = captures.json(path, "superseded/campaign01-terminal.json", "superseded.campaign")
        fields(value, ("status", "binding", "cases", "finishedUtc", "scope"), "superseded.campaign-shape")
        rows = value["cases"]
        old_ids = (set(PRODUCT_IDS) - {PRODUCT_IDS[4]}) | set(AUDIT_IDS)
        require(value["status"] == "PASS" and isinstance(rows, list) and len(rows) == 15
            and {row.get("testId") for row in rows} == old_ids
            and all(row.get("exitCode") == 0 and row.get("binaryBindingStable") is True for row in rows), "superseded.campaign-15-groups")
        for row in rows:
            if row["testId"] in PREFIXES:
                raw = read_regular(path.parent / (row["testId"] + ".stdout"), "superseded.stdout")
                captures.rechecks[str(path.parent / (row["testId"] + ".stdout"))] = sha(raw)
                require(sha(raw) == hash_text(row["stdoutSha256"], "superseded.stdout-hash")
                    and PREFIXES[row["testId"]].encode() not in raw, "superseded.original-matrix-unavailable")
        attempts.append({"kind": "managed-campaign01", "status": "SUPERSEDED_INCOMPLETE_CAPTURE", "reportedPassingGroups": 15,
            "missingActualManagedNullGroup": True, "missingAuditCloseJoinGroup": True, "workerMatrixJsonSuppressed": True,
            "scope": "Original group outcomes retained; unavailable handoff matrices were never inferred as PASS evidence"})
    return attempts


def write_new(path, value):
    with path.open("xb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def collect(args):
    captures = Captures()
    managed = campaign(captures, Path(args.campaign).absolute())
    arm = native(captures, Path(args.native_arm64).absolute(), "arm64", managed)
    x64 = native(captures, Path(args.native_x64).absolute(), "x86_64", managed)
    require(arm["harnessSha256"] == x64["harnessSha256"], "native.same-harness")
    comparison = owner_comparison(captures, Path(args.owner_comparison).absolute(), managed)
    superseded = superseded_attempts(captures, args, managed)
    captures.unchanged()
    destination = Path(args.destination).absolute()
    if destination.exists():
        require(destination.is_dir() and not destination.is_symlink() and all(entry.name == "README.md"
            and entry.is_file() and not entry.is_symlink() for entry in destination.iterdir()), "collector.destination-not-fresh")
    else:
        destination.mkdir(parents=True)
    report = {"schemaVersion": 1, "status": "TARGETED_CAPTURE_VERIFIED", "preliminary": True,
        "proposedCandidate": "v5.0.3-rc.build21", "releaseApproved": False,
        "createdUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "collectorSha256": sha(read_regular(Path(__file__).absolute(), "collector.source")),
        "managed": managed, "native": [arm, x64], "ownerBeforeAfter": comparison, "supersededAttempts": superseded,
        "remainingGates": ["Frozen candidate/source provenance", "Full in-scope production release checks and performance",
            "Real installed NativeAOT GUI campaign", "Fresh signing/notarization", "Public-download and installed-artifact verification"],
        "limitations": ["8 MiB KDF fault injection is not a full production-cost/performance run",
            "Audit harness tests do not execute the actual native GUI campaign",
            "The narrow old/new probe does not replay the complete old KDF matrix",
            "Nine product native libraries are bound across slices; SHA3 is a separate per-slice test-only reference",
            "NULL ABI tests never use invalid non-NULL addresses or expired handles",
            "Cleanup observations have the original caller-array/lock-accounting scope; private temporary spans are not retained",
            "Reported source HEAD may refer to a dirty worktree; executed-byte binding is not complete independent source attestation"]}
    for name, value in sorted(captures.files.items()):
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        write_new(target, value)
    encoded = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    write_new(destination / "collection.json", encoded)
    hashes = {name: sha(value) for name, value in captures.files.items()}
    hashes["collection.json"] = sha(encoded)
    if (destination / "README.md").exists():
        hashes["README.md"] = sha(read_regular(destination / "README.md", "collector.readme"))
    manifest = "".join(value + "  " + name + "\n" for name, value in sorted(hashes.items())).encode("ascii")
    write_new(destination / "SHA256SUMS", manifest)
    print(json.dumps({"status": report["status"], "preliminary": True, "releaseApproved": False,
        "managedGroups": managed["groups"], "kdfBoundaries": managed["matrices"]["kdf"]["boundaries"],
        "kdfCases": managed["matrices"]["kdf"]["cases"], "nativeArm64Checks": arm["checks"], "nativeX64Checks": x64["checks"],
        "collectionSha256": sha(encoded), "manifestSha256": sha(manifest)}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", required=True, help="Exact terminal JSON, with known per-ID captures beside it")
    parser.add_argument("--native-arm64", required=True, help="Exact arm64 ABI parent receipt")
    parser.add_argument("--native-x64", required=True, help="Exact x86_64 ABI parent receipt")
    parser.add_argument("--owner-comparison", required=True, help="Exact narrow comparison JSON, with its named public inputs beside it")
    parser.add_argument("--destination", required=True, help="Fresh public directory, optionally containing only its prepared README")
    parser.add_argument("--superseded-native-x64", help="Exact failed SHA3-reference staging receipt; only digest/classification is exported")
    parser.add_argument("--superseded-build-terminal", help="Exact failed build terminal metadata; raw build log is never exported")
    parser.add_argument("--superseded-campaign", help="Exact initial 15-group terminal capture with suppressed worker matrix JSON")
    args = parser.parse_args()
    try:
        collect(args)
    except Unavailable as error:
        print(json.dumps({"status": "UNAVAILABLE", "releaseApproved": False, "validation": str(error)}, sort_keys=True))
        return 2
    except (OSError, ValueError, TypeError, KeyError):
        # Do not print raw parsed values, input logs, paths, argv or tracebacks.
        # Any partial output from an I/O failure remains unavailable evidence.
        print(json.dumps({"status": "UNAVAILABLE", "releaseApproved": False, "validation": "collector.schema-or-io"}, sort_keys=True))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
