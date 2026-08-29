#!/usr/bin/env python3
"""Deploy and verify the workflow-owned Frida server on a rooted device."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path


def run(command: list[str], timeout: int = 60) -> dict:
    completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=timeout)
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip()[-20000:],
        "stderr": completed.stderr.strip()[-20000:],
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def adb_prefix(serial: str | None) -> list[str]:
    return ["adb", *( ["-s", serial] if serial else [] )]


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--remote-server", default="/data/local/tmp/media-server")
    parser.add_argument("--device")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--expected-version", default="17.9.1")
    parser.add_argument("--log", type=Path)
    args = parser.parse_args()

    server = args.server.resolve()
    result = {
        "status": "error",
        "device": args.device,
        "local_server": str(server),
        "remote_server": args.remote_server,
        "expected_version": args.expected_version,
        "steps": [],
    }
    if not server.is_file():
        result["error"] = f"Frida server is missing: {server}"
        print(json.dumps(result, ensure_ascii=False))
        return 2

    local_hash = sha256_file(server)
    result["local_sha256"] = local_hash
    if args.expected_sha256 and local_hash != args.expected_sha256.upper():
        result["error"] = "local Frida server SHA-256 does not match the manifest"
        print(json.dumps(result, ensure_ascii=False))
        return 2

    adb = adb_prefix(args.device)
    device_check = run(adb + ["get-state"])
    result["steps"].append(device_check)
    if device_check["returncode"] or device_check["stdout"] != "device":
        result["error"] = "ADB device is not ready"
        print(json.dumps(result, ensure_ascii=False))
        return 3

    root_check = run(adb + ["shell", "su", "-c", "id"])
    result["steps"].append(root_check)
    if root_check["returncode"] or "uid=0" not in root_check["stdout"]:
        result["error"] = "root shell is unavailable"
        print(json.dumps(result, ensure_ascii=False))
        return 3

    host_version_check = run(["frida", "--version"])
    result["steps"].append(host_version_check)
    result["host_version"] = host_version_check["stdout"].splitlines()[-1] if host_version_check["stdout"] else ""
    if host_version_check["returncode"] or args.expected_version not in result["host_version"]:
        result["error"] = "host Frida client version does not match the profile"
        print(json.dumps(result, ensure_ascii=False))
        return 5

    # Stop both stock and workflow-owned servers before replacing the binary.
    stop = run(adb + ["shell", "su", "-c",
                      "killall frida-server frida-server-17.9.1 fs1791 media-server 2>/dev/null; true"])
    result["steps"].append(stop)
    process_snapshot = run(adb + ["shell", "su", "-c", "ps -A"])
    stale_pids = []
    for line in process_snapshot["stdout"].splitlines():
        if not any(name in line for name in ("frida-server", "fs1791", "media-server")):
            continue
        fields = line.split()
        if len(fields) > 1 and fields[1].isdigit():
            stale_pids.append(fields[1])
    if stale_pids:
        kill = run(adb + ["shell", "su", "-c", "kill -9 " + " ".join(stale_pids)])
        result["steps"].append(kill)
    process_snapshot["stdout"] = f"identified {len(stale_pids)} stale Frida server process(es)"
    result["steps"].append(process_snapshot)
    time.sleep(0.5)

    push = run(adb + ["push", str(server), args.remote_server], timeout=180)
    result["steps"].append(push)
    if push["returncode"]:
        result["error"] = "failed to push the custom Frida server"
        print(json.dumps(result, ensure_ascii=False))
        return 4

    chmod = run(adb + ["shell", "su", "-c", f"chmod 755 {args.remote_server}"])
    result["steps"].append(chmod)
    if chmod["returncode"]:
        result["error"] = "failed to chmod the custom Frida server"
        print(json.dumps(result, ensure_ascii=False))
        return 4

    remote_hash_check = run(adb + ["shell", "su", "-c", f"sha256sum {args.remote_server}"])
    result["steps"].append(remote_hash_check)
    remote_hash = remote_hash_check["stdout"].split()[0].upper() if remote_hash_check["stdout"] else ""
    result["remote_sha256"] = remote_hash
    if remote_hash != local_hash:
        result["error"] = "device Frida server SHA-256 differs from the local binary"
        print(json.dumps(result, ensure_ascii=False))
        return 4

    version_check = run(adb + ["shell", "su", "-c", f"{args.remote_server} --version"])
    result["steps"].append(version_check)
    result["server_version"] = version_check["stdout"].splitlines()[-1] if version_check["stdout"] else ""
    if version_check["returncode"] or args.expected_version not in result["server_version"]:
        result["error"] = "device Frida server version does not match the host profile"
        print(json.dumps(result, ensure_ascii=False))
        return 5

    remote_log = "/data/local/tmp/vmpwf-media-server.log"
    start = run(adb + ["shell", "su", "-c",
                       f"nohup {args.remote_server} </dev/null >{remote_log} 2>&1 &"])
    result["steps"].append(start)
    time.sleep(2)
    process_check = run(adb + ["shell", "su", "-c", "ps -A | grep media-server"])
    result["steps"].append(process_check)
    result["process"] = process_check["stdout"]
    process_lines = [line for line in process_check["stdout"].splitlines() if "media-server" in line]
    if process_check["returncode"] or len(process_lines) != 1:
        server_log = run(adb + ["shell", "su", "-c", f"tail -n 200 {remote_log}"])
        result["steps"].append(server_log)
        result["error"] = "exactly one custom Frida server must remain running"
        print(json.dumps(result, ensure_ascii=False))
        return 6

    host_check = run(["frida-ps", "-U"], timeout=30)
    if host_check["returncode"] == 0:
        host_check["stdout"] = "USB process enumeration succeeded"
    result["steps"].append(host_check)
    if host_check["returncode"]:
        result["error"] = "host Frida client cannot enumerate the USB device"
        print(json.dumps(result, ensure_ascii=False))
        return 7

    result["status"] = "ok"
    result["remote_log"] = remote_log
    if args.log:
        args.log.parent.mkdir(parents=True, exist_ok=True)
        args.log.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
