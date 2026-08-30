"""Pure helpers for recognizing the AArch64 dispatch stubs used by IDA scripts."""

from collections.abc import Collection

CMP_DISPATCH_PREFIX = ("ADRP", "CSET", "ADD", "LDR")
DIRECT_DISPATCH_PREFIX = ("ADRP", "LDR")
MAX_DISPATCH_GAP = 3

CONTROL_FLOW_MNEMONICS = {
    "B",
    "BL",
    "BLR",
    "BR",
    "BRK",
    "CBNZ",
    "CBZ",
    "ERET",
    "HLT",
    "HVC",
    "RET",
    "RETAA",
    "RETAB",
    "SMC",
    "SVC",
    "TBNZ",
    "TBZ",
}


def canonical_register(operand: str) -> str | None:
    value = operand.strip().upper()
    if len(value) < 2 or value[0] not in "WX" or not value[1:].isdigit():
        return None
    return f"X{value[1:]}"


def exact_memory_register(operand: str) -> str | None:
    value = operand.strip().upper().replace(" ", "")
    if not (value.startswith("[") and value.endswith("]")):
        return None
    return canonical_register(value[1:-1])


def decoder_max_unit_index(unit_index: int, unit_count: int = 1) -> int:
    if unit_index < 0 or unit_count <= 0:
        raise ValueError("decoder unit range must be non-negative and non-empty")
    return unit_index + unit_count - 1


def is_dispatch_prefetch_address(
    address: int,
    root: int,
    function_start: int,
    prefetch_function_starts: Collection[int],
) -> bool:
    """Identify the pre-root fetch area reached by a handler backedge."""
    return function_start in prefetch_function_starts and function_start <= address < root


def select_width_evidence(
    pc_writes: dict[int, dict], auxiliary: dict[int, dict]
) -> dict[int, dict]:
    if not auxiliary:
        return {units: dict(item) for units, item in pc_writes.items()}

    selected = {units: dict(item) for units, item in auxiliary.items()}
    for units, item in pc_writes.items():
        for selected_units, candidate in selected.items():
            key = "matching_pc_writes" if units == selected_units else "conflicting_pc_writes"
            candidate.setdefault(key, []).append(item)
    return selected


def is_control_flow_mnemonic(mnemonic: str) -> bool:
    value = mnemonic.strip().upper()
    return value in CONTROL_FLOW_MNEMONICS or value.startswith("B.")


def is_load_branch_tail(
    mnemonics: list[str] | tuple[str, ...],
    load_register: str,
    branch_register: str,
    intermediate_destinations: list[str] | tuple[str, ...] = (),
) -> bool:
    normalized = tuple(item.upper() for item in mnemonics)
    if len(normalized) < 2 or normalized[0] != "LDR" or normalized[-1] != "BR":
        return False
    gap = normalized[1:-1]
    if len(gap) > MAX_DISPATCH_GAP or len(intermediate_destinations) != len(gap):
        return False
    target = canonical_register(load_register)
    if target is None or target != canonical_register(branch_register):
        return False
    for mnemonic, destination in zip(gap, intermediate_destinations):
        if is_control_flow_mnemonic(mnemonic):
            return False
        if canonical_register(destination) == target:
            return False
    return True


def is_cmp_dispatch_pattern(
    mnemonics: list[str] | tuple[str, ...],
    load_register: str,
    branch_register: str,
    intermediate_destinations: list[str] | tuple[str, ...] = (),
) -> bool:
    normalized = tuple(item.upper() for item in mnemonics)
    return (
        normalized[:len(CMP_DISPATCH_PREFIX)] == CMP_DISPATCH_PREFIX
        and is_load_branch_tail(
            normalized[len(CMP_DISPATCH_PREFIX) - 1:],
            load_register,
            branch_register,
            intermediate_destinations,
        )
    )


def is_direct_dispatch_pattern(
    mnemonics: list[str] | tuple[str, ...],
    load_register: str,
    branch_register: str,
    intermediate_destinations: list[str] | tuple[str, ...] = (),
) -> bool:
    normalized = tuple(item.upper() for item in mnemonics)
    return (
        normalized[:len(DIRECT_DISPATCH_PREFIX)] == DIRECT_DISPATCH_PREFIX
        and is_load_branch_tail(
            normalized[len(DIRECT_DISPATCH_PREFIX) - 1:],
            load_register,
            branch_register,
            intermediate_destinations,
        )
    )
