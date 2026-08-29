# Frida Prepare

Use `scripts/device/prepare_frida_server.py` with the profile's `tools/frida/media-server`, remote path, version, and SHA-256. Stop stock or stale Frida services, push without deleting the local source, verify the device hash, chmod 755, launch as root, and require `frida-ps -U` to succeed.

The host Frida client and device server must be the same version. Repeat preparation after every device reboot. Do not late-attach to the protected process; the SO dump stage must enable spawn-gating before launching the app. Preserve the preparation JSON and server log in the case revision.
