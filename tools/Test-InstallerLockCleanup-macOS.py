#!/usr/bin/python3
"""Exercise the installer's real lock cleanup under a PTY, using synthetic files."""

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def extract_release_lock(installer):
    source = installer.read_text(encoding="utf-8")
    starts = list(re.finditer(r"(?m)^release_lock\(\) \{\n", source))
    require(len(starts) == 1, "Expected exactly one top-level release_lock function")
    start = starts[0].start()
    end = source.find("\n}\n", starts[0].end())
    require(end >= 0, "Missing top-level release_lock closing brace")
    # The function's top-level closing brace is unindented. Keep every byte of
    # its body, including all identity checks; never source the full installer.
    return source[start:end + 3]


def read_available(fd):
    try:
        return os.read(fd, 65536)
    except OSError as error:
        if error.errno in (errno.EIO, errno.EAGAIN):
            return b""
        raise


def run_under_pty(script, fixture, scenario, expect_prompt=False):
    master, slave = pty.openpty()
    os.set_blocking(master, False)
    process = None
    output = bytearray()
    prompt_at = None
    deadline = time.monotonic() + 5.0
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            ["/bin/zsh", "-f", str(script), str(fixture), scenario],
            stdin=slave, stdout=slave, stderr=slave,
            cwd=fixture, start_new_session=True,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
        )
        os.close(slave)
        slave = None
        while True:
            readable, _, _ = select.select([master], [], [], 0.05)
            if readable:
                output.extend(read_available(master))
            require(len(output) <= 65536, "Unexpectedly large cleanup output")
            now = time.monotonic()
            if b"override " in output and prompt_at is None:
                prompt_at = now
            if process.poll() is not None:
                output.extend(read_available(master))
                require(not expect_prompt, "Old-rm mutation did not block for terminal input")
                require(process.returncode == 0, "Cleanup returned nonzero: " + output.decode("utf-8", "replace"))
                require(prompt_at is None, "Cleanup prompted for input")
                require(b"installer_cleanup_pty=true" in output, "Child did not confirm terminal descriptors")
                return {"elapsed_seconds": round(now - started, 3), "exit_code": 0, "prompt": False}
            if expect_prompt and prompt_at is not None and now - prompt_at >= 0.2:
                require(b"installer-bound-delete?" in output, "Unexpected prompt target")
                require(b"installer_cleanup_pty=true" in output, "Mutation did not run on a terminal")
                # No input is ever written to the PTY. The old command must
                # remain blocked; terminate only this fixture's process group.
                return {"elapsed_seconds": round(now - started, 3), "blocked_without_input": True, "prompt": True}
            require(now < deadline, "Cleanup timed out: " + output.decode("utf-8", "replace"))
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)
        if slave is not None:
            os.close(slave)
        os.close(master)


SETUP = r'''
[[ -t 0 && -t 1 && -t 2 ]] || exit 70
lock_parent=$1
scenario=$2
find_path=/usr/bin/find
lock_parent_identity=$(stat -f '%d:%i' ${lock_parent})
lock_directory=${lock_parent}/install.lock
lock_directory_identity=$(stat -f '%d:%i' ${lock_directory})
lock_directory_owned=1
lock_file=${lock_directory}/owner
print -r -- $$ > ${lock_file}
chmod 0600 ${lock_file}
lock_file_identity=$(stat -f '%d:%i' ${lock_file})
lock_file_owned=1
bound_delete_helper=${lock_directory}/installer-bound-delete
bound_delete_helper_identity=$(stat -f '%d:%i:%u:%Lp:%z:%m:%c:%l' ${bound_delete_helper})
case ${scenario} in
  replacement) /bin/mv -f -- ${lock_parent}/replacement ${bound_delete_helper} ;;
  symlink)
    /bin/rm -f -- ${bound_delete_helper}
    /bin/ln -s -- ../sentinel ${bound_delete_helper}
    ;;
esac
print -r -- installer_cleanup_pty=true
trap release_lock EXIT
exit 0
'''


def write_private(path, contents, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(contents)


def run_case(parent, function, scenario):
    fixture = parent / scenario
    fixture.mkdir(mode=0o700)
    lock = fixture / "install.lock"
    lock.mkdir(mode=0o700)
    helper = lock / "installer-bound-delete"
    write_private(helper, b"#!/bin/sh\nexit 0\n", 0o500)
    sentinel = fixture / "sentinel"
    sentinel_bytes = b"synthetic sentinel outside the lock directory\n"
    write_private(sentinel, sentinel_bytes)
    sentinel_identity = (sentinel.stat().st_dev, sentinel.stat().st_ino)
    replacement = b"synthetic replacement must remain intact\n"
    write_private(fixture / "replacement", replacement, 0o500)
    script = fixture / "fixture.zsh"
    write_private(script, ("set -euo pipefail\numask 077\n" + function + SETUP).encode("utf-8"))
    require(stat.S_IMODE(fixture.stat().st_mode) == 0o700, "Fixture is not private")
    require(stat.S_IMODE(lock.stat().st_mode) == 0o700, "Lock is not private")
    require(stat.S_IMODE(helper.stat().st_mode) == 0o500, "Helper must be non-writable")
    outcome = run_under_pty(script, fixture, scenario, expect_prompt=scenario == "old-rm")
    if scenario == "positive":
        require(not lock.exists(), "Successful cleanup left the lock directory")
    elif scenario == "old-rm":
        require(helper.is_file() and not helper.is_symlink(), "Prompt mutation unexpectedly removed helper")
        require((lock / "owner").is_file(), "Prompt mutation progressed beyond blocked removal")
    else:
        require(lock.is_dir(), "Rejected helper must preserve the lock directory")
        require(not (lock / "owner").exists(), "Owned PID record was not removed")
        if scenario == "replacement":
            require(not helper.is_symlink() and helper.read_bytes() == replacement, "Replacement helper was removed or changed")
        else:
            require(helper.is_symlink() and os.readlink(helper) == "../sentinel", "Symlink helper was removed or changed")
    require(sentinel.read_bytes() == sentinel_bytes, "External sentinel bytes changed")
    require((sentinel.stat().st_dev, sentinel.stat().st_ino) == sentinel_identity, "External sentinel was replaced")
    return {"case": scenario, "result": "pass", **outcome}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installer", type=Path, default=Path(__file__).resolve().with_name("Install-KeepVault-macOS.sh"))
    args = parser.parse_args()
    require(sys.platform == "darwin", "This regression requires macOS rm semantics")
    require(os.geteuid() != 0, "Run as a regular user; root changes write-access semantics")
    require(args.installer.is_file() and not args.installer.is_symlink(), "Installer source must be a regular file")
    function = extract_release_lock(args.installer)
    with tempfile.TemporaryDirectory(prefix="keep-vault-installer-pty-", dir="/private/tmp") as temporary:
        parent = Path(temporary)
        results = [run_case(parent, function, "positive")]
        fixed = "      rm -f -- ${bound_delete_helper}\n"
        require(function.count(fixed) == 1, "Expected exactly one fixed helper-removal command for the mutation")
        mutation = function.replace(fixed, "      rm -- ${bound_delete_helper}\n", 1)
        results.append(run_case(parent, mutation, "old-rm"))
        results.extend(run_case(parent, function, case) for case in ("replacement", "symlink"))
    print(json.dumps({"release_lock_sha256": hashlib.sha256(function.encode("utf-8")).hexdigest(), "results": results}, sort_keys=True))
    print("installer_lock_cleanup_pty=pass cases=4")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, subprocess.SubprocessError) as error:
        print("installer_lock_cleanup_pty=fail: " + str(error), file=sys.stderr)
        sys.exit(1)
