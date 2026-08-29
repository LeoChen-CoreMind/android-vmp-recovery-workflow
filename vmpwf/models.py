from __future__ import annotations

STAGES = [
    "apk-ingest", "dex-extract", "target-confirm", "so-dump", "so-repair",
    "ida-export", "vm-static", "native-sim", "dex-restore", "independent-validate",
]

STAGE_SUCCESS = {
    "apk-ingest": "APK_INGESTED",
    "dex-extract": "DEX_READY",
    "target-confirm": "TARGET_CONFIRMED",
    "so-dump": "SO_DUMPED",
    "so-repair": "SO_REPAIRED",
    "ida-export": "IDA_EXTRACTED",
    "vm-static": "VM_STATIC_RECOVERED",
    "native-sim": "SIMULATION_CONFIRMED",
    "dex-restore": "DEX_RESTORED",
    "independent-validate": "VALIDATED",
}

STATES = ["INIT", *STAGE_SUCCESS.values(), "BLOCKED"]
DOWNSTREAM = {stage: STAGES[index + 1:] for index, stage in enumerate(STAGES)}

CASE_DIRS = [
    "input/apk", "input/dex", "input/manifest", "dump/dex/static",
    "dump/dex/records", "dump/so/raw", "dump/so/metadata", "fix/so",
    "fix/dex", "ida/requests", "ida/responses", "ida/tables",
    "simulation/inputs", "simulation/results", "reports", "logs",
]
