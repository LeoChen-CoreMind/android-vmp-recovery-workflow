import pytest

from vmpwf.core import StageBlocked
from vmpwf.engine import init_case, load_context
from vmpwf.plugins.target_confirm import TargetConfirm
import vmpwf.plugins.target_confirm as target_module


def test_arm64_profile_rejects_32bit_target(tmp_path, sample_inputs, monkeypatch):
    apk, _ = sample_inputs
    case_dir = tmp_path / "case"
    init_case(case_dir, "com.example.fixture", "serial", [], str(apk), "android-arm64-360-dexvmp")

    def fake(command, *args, **kwargs):
        joined = " ".join(command)
        if "dumpsys package" in joined:
            stdout = "userId=10123\n versionCode=7 versionName=1.2.3\n primaryCpuAbi=armeabi-v7a\n"
        elif "pm path" in joined:
            stdout = "package:/data/app/com.example.fixture/base.apk\n"
        elif "getenforce" in joined:
            stdout = "Enforcing\n"
        elif "adb version" in joined:
            stdout = "Android Debug Bridge version 1.0.41\n"
        else:
            stdout = "uid=0(root) gid=0(root)\n"
        return {"command": command, "returncode": 0, "stdout": stdout, "stderr": ""}

    monkeypatch.setattr(target_module, "run_command", fake)
    context = load_context(case_dir, execute_device=True)
    context.profile_snapshot = {"supported_abis": ["arm64-v8a"]}
    with pytest.raises(StageBlocked, match="not supported"):
        TargetConfirm().run(context)
