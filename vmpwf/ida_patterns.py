"""Pure helpers for recognizing the AArch64 dispatch stubs used by IDA scripts."""

CMP_DISPATCH_MNEMONICS = ("ADRP", "CSET", "ADD", "LDR", "BR")
DIRECT_DISPATCH_MNEMONICS = ("ADRP", "LDR", "BR")


def canonical_register(operand: str) -> str | None:
    value = operand.strip().upper()
    if len(value) < 2 or value[0] not in "WX" or not value[1:].isdigit():
        return None
    return f"X{value[1:]}"


def is_cmp_dispatch_pattern(
    mnemonics: list[str] | tuple[str, ...],
    load_register: str,
    branch_register: str,
) -> bool:
    return (
        tuple(item.upper() for item in mnemonics) == CMP_DISPATCH_MNEMONICS
        and canonical_register(load_register) is not None
        and canonical_register(load_register) == canonical_register(branch_register)
    )


def is_direct_dispatch_pattern(
    mnemonics: list[str] | tuple[str, ...],
    load_register: str,
    branch_register: str,
) -> bool:
    return (
        tuple(item.upper() for item in mnemonics) == DIRECT_DISPATCH_MNEMONICS
        and canonical_register(load_register) is not None
        and canonical_register(load_register) == canonical_register(branch_register)
    )
