# Target Confirm

For device mode verify package name, version, install paths, application UID, primary ABI, root capability (`adbd` or `su`), serial, and SELinux through ADB. Reject an ABI outside the selected profile. Device execution must be explicit. Fixture mode must record `source=fixture`.

Before leaving this stage, run `scripts/device/prepare_frida_server.py` or confirm that `run_gating.py` will run it at the next stage. The only accepted server is the profile-owned `tools/frida/media-server`; verify its local/device SHA-256, Frida version, root process name, and `frida-ps -U`. Stop stock `frida-server`, `fs1791`, or stale `media-server` processes. A reboot invalidates this check.
