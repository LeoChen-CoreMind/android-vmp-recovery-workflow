#!/usr/bin/env python3
"""Parameterised Frida spawn-gating runner for the SO dump agent."""
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

import frida


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True)
    parser.add_argument("--script", type=Path, required=True)
    parser.add_argument("--config", type=Path, help="JSON values merged into dump_linker.js CONFIG")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--device")
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()
    overrides = json.loads(args.config.read_text(encoding="utf-8")) if args.config else {}
    agent_code = "globalThis.VMPWF_CONFIG=" + json.dumps(overrides) + ";\n" + args.script.read_text(encoding="utf-8")
    device = frida.get_device(args.device, timeout=10) if args.device else frida.get_usb_device(timeout=10)
    done = {"value": False, "info": None}
    sessions = []

    def on_message(message, _data):
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("event") == "dumped":
                done.update(value=True, info=payload)
            print(json.dumps(payload, ensure_ascii=False), flush=True)
        elif message.get("type") == "error":
            print("[JS-ERROR] " + message.get("description", "unknown"), flush=True)

    def on_spawn(spawn):
        identifier = spawn.identifier or ""
        try:
            if args.package in identifier:
                session = device.attach(spawn.pid); sessions.append(session)
                script = session.create_script(agent_code); script.on("message", on_message); script.load()
        finally:
            device.resume(spawn.pid)

    device.on("spawn-added", on_spawn)
    device.enable_spawn_gating()
    adb = ["adb"] + (["-s", args.device] if args.device else [])
    subprocess.run(adb + ["shell", "am", "force-stop", args.package], check=False)
    subprocess.run(adb + ["shell", "monkey", "-p", args.package, "-c", "android.intent.category.LAUNCHER", "1"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    deadline = time.time() + args.timeout
    while not done["value"] and time.time() < deadline:
        time.sleep(0.2)
    device.disable_spawn_gating()
    pulled = []
    if done["value"] and done["info"].get("path"):
        args.output_dir.mkdir(parents=True, exist_ok=True)
        remote = done["info"]["path"]
        for source in (remote, remote + ".json"):
            completed = subprocess.run(adb + ["pull", source, str(args.output_dir)], capture_output=True, text=True)
            if completed.returncode == 0:
                pulled.append(source)
    print(json.dumps({"status": "ok" if done["value"] else "timeout", "dump": done["info"], "pulled": pulled}, ensure_ascii=False))
    return 0 if done["value"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
