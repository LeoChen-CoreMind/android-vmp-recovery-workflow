#!/usr/bin/env python3
"""Parameterised Frida spawn-gating runner for the SO dump agent."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import frida


REPO_ROOT = Path(__file__).resolve().parents[3]


def adb_prefix(serial: str | None) -> list[str]:
    return ["adb", *(["-s", serial] if serial else [])]


def write_log(path: Path | None, name: str, content: str) -> None:
    if path is None:
        return
    path.mkdir(parents=True, exist_ok=True)
    (path / name).write_text(content or "", encoding="utf-8", errors="replace")


def collect_diagnostics(adb: list[str], package: str, log_dir: Path | None) -> dict:
    diagnostics = {}
    commands = {
        "logcat.txt": adb + ["logcat", "-d", "-v", "threadtime", "-t", "2000"],
        "exit-info.txt": adb + ["shell", "dumpsys", "activity", "exit-info", package],
        "processes.txt": adb + ["shell", "su", "-c", "ps -A"],
        "frida-server-log.txt": adb + ["shell", "su", "-c",
                                  "tail -n 500 /data/local/tmp/vmpwf-media-server.log"],
    }
    for name, command in commands.items():
        completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                   errors="replace", timeout=30)
        content = (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")
        write_log(log_dir, name, content)
        diagnostics[name] = {"returncode": completed.returncode, "bytes": len(content.encode("utf-8"))}
    return diagnostics


def resolve_spawn_identifier(device, spawn, attempts: int = 20, delay: float = 0.01) -> str:
    """Resolve Frida spawn events whose identifier is populated asynchronously."""
    identifier = getattr(spawn, "identifier", "") or ""
    if identifier:
        return identifier
    pid = getattr(spawn, "pid", None)
    for attempt in range(attempts):
        try:
            pending_spawns = device.enumerate_pending_spawn()
        except Exception:
            return ""
        for pending in pending_spawns:
            if getattr(pending, "pid", None) == pid:
                identifier = getattr(pending, "identifier", "") or ""
                if identifier:
                    return identifier
        if attempt + 1 < attempts and delay > 0:
            time.sleep(delay)
    return ""


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--script", type=Path, required=True)
    parser.add_argument("--config", type=Path, help="JSON values merged into dump_linker.js CONFIG")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--device")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--server", type=Path, default=REPO_ROOT / "tools/frida/media-server")
    parser.add_argument("--remote-server", default="/data/local/tmp/media-server")
    parser.add_argument("--server-sha256")
    parser.add_argument("--server-version", default="17.9.1")
    parser.add_argument("--no-prepare-server", action="store_true")
    parser.add_argument("--log-dir", type=Path)
    args = parser.parse_args()
    adb = adb_prefix(args.device)
    if not args.no_prepare_server:
        prepare_log = args.log_dir / "frida-prepare.json" if args.log_dir else None
        prepare = [
            sys.executable,
            str(REPO_ROOT / "scripts/device/prepare_frida_server.py"),
            "--server", str(args.server),
            "--remote-server", args.remote_server,
            "--expected-version", args.server_version,
        ]
        if args.device:
            prepare += ["--device", args.device]
        if args.server_sha256:
            prepare += ["--expected-sha256", args.server_sha256]
        if prepare_log:
            prepare += ["--log", str(prepare_log)]
        prepared = subprocess.run(prepare, capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=240)
        write_log(args.log_dir, "frida-prepare.stdout.txt", prepared.stdout)
        write_log(args.log_dir, "frida-prepare.stderr.txt", prepared.stderr)
        if prepared.returncode:
            print(json.dumps({"status": "server-prepare-failed", "returncode": prepared.returncode,
                              "stdout": prepared.stdout[-20000:], "stderr": prepared.stderr[-20000:]},
                             ensure_ascii=False))
            return 4
    overrides = json.loads(args.config.read_text(encoding="utf-8")) if args.config else {}
    agent_code = "globalThis.VMPWF_CONFIG=" + json.dumps(overrides) + ";\n" + args.script.read_text(encoding="utf-8")
    device = frida.get_device(args.device, timeout=10) if args.device else frida.get_usb_device(timeout=10)
    done = {"value": False, "info": None, "failed": None}
    sessions = []
    agent_events = []
    spawn_events = []
    attached_pids = set()

    def on_message(message, _data):
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("event") == "dumped":
                done.update(value=True, info=payload)
            elif isinstance(payload, dict) and payload.get("event") in {"dump-failed", "config-error"}:
                done["failed"] = payload
            agent_events.append(payload)
            print(json.dumps(payload, ensure_ascii=False), flush=True)
        elif message.get("type") == "error":
            done["failed"] = message
            agent_events.append(message)
            print("[JS-ERROR] " + message.get("description", "unknown"), flush=True)

    def ensure_attached(pid: int) -> bool:
        if pid in attached_pids:
            return True
        session = device.attach(pid)
        script = session.create_script(agent_code)
        script.on("message", on_message)
        script.load()
        sessions.append(session)
        attached_pids.add(pid)
        return True

    def ensure_resumed(pid: int) -> bool:
        # Spawn gating also reports exec transitions that reuse a PID. Each event
        # needs its own resume even when that PID was resumed previously.
        device.resume(pid)
        return True

    def on_spawn(spawn):
        raw_identifier = getattr(spawn, "identifier", "") or ""
        identifier = resolve_spawn_identifier(device, spawn)
        pid = getattr(spawn, "pid", None)
        event = {"pid": pid, "parent_pid": getattr(spawn, "parent_pid", None),
                 "raw_identifier": raw_identifier, "resolved_identifier": identifier,
                 "source": "spawn-added", "target": args.package in identifier,
                 "attached": False, "resumed": False}
        try:
            if event["target"]:
                event["attached"] = ensure_attached(pid)
        except Exception as exc:
            event["error"] = f"{type(exc).__name__}: {exc}"
            if event["target"]:
                done["failed"] = {"event": "spawn-attach-failed", **event}
        finally:
            try:
                event["resumed"] = ensure_resumed(pid)
            except Exception as exc:
                event["resume_error"] = f"{type(exc).__name__}: {exc}"
            spawn_events.append(event)

    subprocess.run(adb + ["shell", "am", "force-stop", args.package], check=False)
    device.on("spawn-added", on_spawn)
    device.enable_spawn_gating()
    launched = subprocess.run(
        adb + ["shell", "monkey", "-p", args.package,
               "-c", "android.intent.category.LAUNCHER", "1"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    write_log(args.log_dir, "launcher.txt", launched.stdout + "\n" + launched.stderr)
    deadline = time.time() + args.timeout
    while not done["value"] and done["failed"] is None and time.time() < deadline:
        time.sleep(0.2)
    device.disable_spawn_gating()
    write_log(args.log_dir, "frida-agent-events.json", json.dumps(agent_events, ensure_ascii=False, indent=2))
    write_log(args.log_dir, "spawn-events.json", json.dumps(spawn_events, ensure_ascii=False, indent=2))
    pulled = []
    if done["value"] and done["info"].get("path"):
        args.output_dir.mkdir(parents=True, exist_ok=True)
        remote = done["info"]["path"]
        for source in (remote, remote + ".json"):
            completed = subprocess.run(adb + ["pull", source, str(args.output_dir)], capture_output=True, text=True)
            if completed.returncode == 0:
                pulled.append(source)
    status = "ok" if done["value"] else ("agent-failed" if done["failed"] is not None else "timeout")
    diagnostics = {} if done["value"] else collect_diagnostics(adb, args.package, args.log_dir)
    print(json.dumps({"status": status, "dump": done["info"], "failure": done["failed"],
                      "pulled": pulled, "diagnostics": diagnostics}, ensure_ascii=False))
    return 0 if done["value"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
