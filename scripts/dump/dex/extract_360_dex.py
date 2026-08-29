#!/usr/bin/env python3
"""Pure-static 360 Jiagu DEX extractor reconstructed from static-unpacker APK.

This script extracts and decrypts whole DEX records only. It intentionally does
not parse lm/VMP tables and never patches protected method bodies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import shutil
import struct
import sys
import zlib
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence

MAX_OUTPUT = 128 * 1024 * 1024
KNOWN_SEEDS = (222, 171)
PRGA_VARIANTS = ((2, 1), (1, 0), (1, 1), (2, 0),
                 (3, 1), (4, 1), (3, 0), (4, 0))
NONFREE_MARKERS = {
    "libjiagu_vip.so", "libjiagu_vip_a64.so", "libjiagu_v2.so",
    "libjgcqm.so", "libjgcqm_a64.so", "libjgdtc.so", "libjgdtc_a64.so",
}


class RecoveryError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecoveryError(message)


def checked(data: bytes, offset: int, size: int, label: str) -> bytes:
    require(offset >= 0 and size >= 0 and offset <= len(data)
            and size <= len(data) - offset,
            f"{label} out of range: offset=0x{offset:X} size=0x{size:X} total=0x{len(data):X}")
    return data[offset:offset + size]


def u32(data: bytes, offset: int, label: str = "u32") -> int:
    return struct.unpack_from("<I", checked(data, offset, 4, label))[0]


def align4(value: int) -> int:
    return (value + 3) & ~3


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_zip_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    require(not path.is_absolute() and ".." not in path.parts,
            f"unsafe ZIP path: {name}")
    return path


def valid_dex(data: bytes, strict_integrity: bool = True) -> bool:
    try:
        if len(data) < 0x70 or data[:4] != b"dex\n" or data[7] != 0:
            return False
        if u32(data, 0x20) != len(data) or u32(data, 0x24) != 0x70:
            return False
        if u32(data, 0x28) != 0x12345678:
            return False
        map_off = u32(data, 0x34)
        map_count = u32(data, map_off)
        checked(data, map_off, 4 + map_count * 12, "map_list")
        if strict_integrity:
            if data[12:32] != hashlib.sha1(data[32:]).digest():
                return False
            if u32(data, 8) != (zlib.adler32(data[12:]) & 0xFFFFFFFF):
                return False
        return True
    except (RecoveryError, struct.error):
        return False


def repair_dex(data: bytes) -> bytes:
    require(len(data) >= 0x70, "DEX shorter than 0x70")
    output = bytearray(data)
    output[12:32] = hashlib.sha1(output[32:]).digest()
    struct.pack_into("<I", output, 8, zlib.adler32(output[12:]) & 0xFFFFFFFF)
    result = bytes(output)
    require(valid_dex(result), "recovered DEX failed structural validation")
    return result


def is_shell_dex(data: bytes) -> bool:
    try:
        if len(data) < 0x70 or data[:4] != b"dex\n":
            return False
        map_off = u32(data, 0x34)
        logical_end = align4(map_off + 4 + u32(data, map_off) * 12)
        return checked(data, logical_end, 2, "qh magic") == b"qh"
    except RecoveryError:
        return False


@dataclass(frozen=True)
class Record:
    record_length: int
    encrypted_length: int
    encrypted: bytes
    tail: bytes


@dataclass(frozen=True)
class Container:
    logical_end: int
    payload_length: int
    declared_config: int
    config_mask: int
    raw_config: bytes
    records: tuple[Record, ...]


@dataclass(frozen=True)
class CipherConfig:
    seed: int
    step_i: int
    step_j: int
    i0: int
    j0: int


def value_length(encoded: int) -> int:
    if 0x50 <= encoded <= 0x5F:
        return encoded ^ 0x60
    if 0x60 <= encoded <= 0x6F:
        return encoded ^ 0x40
    if 0x70 <= encoded <= 0x7F:
        return encoded ^ 0x60
    return encoded


def raw_config_end(decoded: bytes) -> int:
    last = -1
    for pos in range(max(0, len(decoded) - 11)):
        if decoded[pos:pos + 4] != b"\x10\x2b\x00\x00":
            continue
        end = pos + 12 + u32(decoded, pos + 4, "config key length")
        end += value_length(u32(decoded, pos + 8, "config value length"))
        if end <= len(decoded):
            last = end
    return last


def detect_qh_mask(shell: bytes, logical_end: int) -> int:
    payload = shell[logical_end + 12:]
    # The APK checks these encoded marker prefixes. 0x52 is retained for its
    # classic model even though classic extraction ultimately reads assets.
    if b"\xd6\xed\xc6\xc6" in payload:
        return 0xC6
    if b"\x22\x39\x52\x52" in payload:
        return 0x52
    # Structural fallback: accept a mask only if it yields a closing config.
    for mask in (0xC6, 0x52, 0x32):
        decoded = bytes(value ^ mask for value in payload)
        if raw_config_end(decoded) >= 0:
            return mask
    return 0


def parse_records(shell: bytes, payload_start: int, config_length: int) -> tuple[Record, ...] | None:
    cursor = payload_start + config_length
    try:
        count = u32(shell, cursor, "DEX record count")
        cursor += 4
        if not 0 < count <= 32:
            return None
        records = []
        for index in range(count):
            record_length = u32(shell, cursor, "record_length")
            encrypted_length = u32(shell, cursor + 4, "encrypted_length")
            cursor += 8
            if record_length < 4 or encrypted_length > record_length - 4:
                return None
            body_length = record_length - 4
            body = checked(shell, cursor, body_length, f"DEX record {index}")
            records.append(Record(record_length, encrypted_length,
                                  body[:encrypted_length], body[encrypted_length:]))
            cursor += body_length
        return tuple(records)
    except RecoveryError:
        return None


def parse_qh_container(shell: bytes) -> Container:
    require(len(shell) >= 0x70 and shell[:4] == b"dex\n", "invalid shell classes.dex")
    map_off = u32(shell, 0x34, "map_off")
    logical_end = align4(map_off + 4 + u32(shell, map_off, "map_count") * 12)
    header = checked(shell, logical_end, 12, "qh header")
    require(header[:2] == b"qh", "no qh container at logical DEX end")
    payload_length, declared_config = u32(header, 4), u32(header, 8)
    payload_start = logical_end + 12
    payload = shell[payload_start:]
    mask = detect_qh_mask(shell, logical_end) or 0xC6
    decoded = bytes(value ^ mask for value in payload)
    marker_end = raw_config_end(decoded)
    candidates = []
    if 0 < declared_config < len(payload):
        candidates.append(declared_config)
    if marker_end >= 0 and marker_end not in candidates:
        candidates.append(marker_end)
    for config_length in candidates:
        records = parse_records(shell, payload_start, config_length)
        if records is not None:
            return Container(logical_end, payload_length, declared_config, mask,
                             checked(shell, payload_start, config_length, "rawConfig"), records)
    if mask in (0x52, 0x32):
        raise RecoveryError("CLASSIC_WHOLE_DEX: classic model stores the real DEX in assets")
    compatibility_mismatch = payload_length != len(shell) - logical_end - 9
    if compatibility_mismatch or declared_config > 0x10000:
        raise RecoveryError("qh payload uses a per-build encrypted record format")
    raise RecoveryError("qh container is not a supported whole-DEX record model")


def make_key(raw: bytes, seed: int, flag: int = 0) -> tuple[bytes, int]:
    key = bytearray(16)
    rolling = 2
    for index, value in enumerate(raw):
        rolling = (rolling * 31 + value) & 0xFF
        key[index % 16] = value
    accumulator = len(raw) * 2
    state = seed
    for index, value in enumerate(raw):
        mix = ((value ^ index) ^ ((accumulator * 5) & 0xFF)) & 0xFF
        slot = index % 16
        old = key[slot]
        low = (old & 0x0F) ^ rolling
        high = ((old >> 4) & 0x0F) ^ rolling
        key[slot] = ((rolling ^ state) ^ (low | high)) & 0xFF
        state ^= (accumulator + rolling + len(raw) + flag) ^ mix
        state &= 0xFFFFFFFF
        accumulator += 1
    return bytes(key), state


def rc4_ksa(key: bytes) -> list[int]:
    require(bool(key), "empty RC4 key")
    state = list(range(256))
    j = 0
    for i in range(256):
        old = state[i]
        j = (j + old + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], old
    return state


def rc4_variant(data: bytes, initial: Sequence[int], i: int, j: int,
                step_i: int, step_j: int) -> bytes:
    state = list(initial)
    output = bytearray(len(data))
    for pos, value in enumerate(data):
        i = (i + step_i) & 0xFF
        old = state[i]
        j = (j + old + step_j) & 0xFF
        state[i], state[j] = state[j], old
        output[pos] = state[(state[i] + old) & 0xFF] ^ value
    return bytes(output)


def rc4_candidate_head(data: bytes, initial: Sequence[int], i: int, j: int,
                       step_i: int, step_j: int) -> bytes:
    # A sparse overlay avoids copying the 256-entry S box for every candidate.
    overlay: dict[int, int] = {}
    output = bytearray(len(data))
    for pos, value in enumerate(data):
        i = (i + step_i) & 0xFF
        old = overlay.get(i, initial[i])
        j = (j + old + step_j) & 0xFF
        at_j = overlay.get(j, initial[j])
        overlay[i], overlay[j] = at_j, old
        new_i = overlay.get(i, initial[i])
        key_byte = overlay.get((new_i + old) & 0xFF, initial[(new_i + old) & 0xFF])
        output[pos] = key_byte ^ value
    return bytes(output)


def is_lzma_envelope(data: bytes, total_length: int | None = None) -> bool:
    if len(data) < 13 or data[0] >= 225:
        return False
    output_length, packed_length = u32(data, 5), u32(data, 9)
    expected = (total_length if total_length is not None else len(data)) - 13
    return 0x70 <= output_length <= MAX_OUTPUT and packed_length == expected


def lzma_filter(prop: int, dictionary: int) -> dict[str, int]:
    require(prop < 225 and dictionary > 0, "invalid raw LZMA properties")
    lc = prop % 9
    rest = prop // 9
    lp, pb = rest % 5, rest // 5
    require(lc + lp <= 4, "invalid raw LZMA lc/lp")
    return {"id": lzma.FILTER_LZMA1, "dict_size": dictionary,
            "lc": lc, "lp": lp, "pb": pb}


def decode_lzma_envelope(data: bytes) -> bytes:
    require(is_lzma_envelope(data), "invalid LZMA envelope")
    output_length, packed_length = u32(data, 5), u32(data, 9)
    decoder = lzma.LZMADecompressor(
        format=lzma.FORMAT_RAW,
        filters=[lzma_filter(data[0], u32(data, 1))],
    )
    try:
        plain = decoder.decompress(checked(data, 13, packed_length, "LZMA payload"),
                                   max_length=output_length)
    except lzma.LZMAError as exc:
        raise RecoveryError(f"raw LZMA decompression failed: {exc}") from exc
    require(len(plain) == output_length, "raw LZMA output length mismatch")
    return plain


def state_order() -> Iterable[tuple[int, int]]:
    yield 3, 5
    for i in range(256):
        for j in range(256):
            if (i, j) != (3, 5):
                yield i, j


def detect_with_seed(raw_config: bytes, encrypted: bytes, seed: int) -> CipherConfig | None:
    key, _ = make_key(raw_config, seed)
    initial = rc4_ksa(key)
    head = encrypted[:13]
    if len(head) < 13:
        return None
    for step_i, step_j in PRGA_VARIANTS:
        for i0, j0 in state_order():
            decoded = rc4_candidate_head(head, initial, i0, j0, step_i, step_j)
            if is_lzma_envelope(decoded, len(encrypted)):
                return CipherConfig(seed, step_i, step_j, i0, j0)
    return None


def detect_cipher_config(raw_config: bytes, encrypted: bytes,
                         scan_all_seeds: bool) -> CipherConfig | None:
    for seed in KNOWN_SEEDS:
        config = detect_with_seed(raw_config, encrypted, seed)
        if config is not None:
            return config
    if not scan_all_seeds:
        return None
    for seed in range(256):
        if seed in KNOWN_SEEDS:
            continue
        key, _ = make_key(raw_config, seed)
        initial = rc4_ksa(key)
        plausible = False
        for step_i, step_j in PRGA_VARIANTS:
            decoded = rc4_candidate_head(encrypted[:13], initial, 3, 5, step_i, step_j)
            if is_lzma_envelope(decoded, len(encrypted)):
                plausible = True
                break
        if plausible:
            config = detect_with_seed(raw_config, encrypted, seed)
            if config is not None:
                return config
    return None


def xor_dex_header(data: bytes, mask: int) -> bytes:
    require(len(data) >= 0x70, "DEX header shorter than 0x70")
    output = bytearray(data)
    for index in range(0x70):
        output[index] ^= mask & 0xFF
    return bytes(output)


def decrypt_string_span(data: bytes, key: bytes) -> bytes:
    try:
        count, table = u32(data, 0x38), u32(data, 0x3C)
        if count < 2:
            return data
        checked(data, table, count * 4, "string_ids")
        first = u32(data, table)
        last = u32(data, table + (count - 1) * 4)
        if last < first:
            return data
        span = checked(data, first, last - first, "string_data span")
        plain = rc4_variant(span, rc4_ksa(key), 3, 5, 2, 1)
        return data[:first] + plain + data[last:]
    except RecoveryError:
        return data


def decrypt_record(record: Record, key: bytes, mask: int,
                   config: CipherConfig | None) -> tuple[bytes, str]:
    standard = rc4_variant(record.encrypted, rc4_ksa(key), 3, 5, 2, 1)
    if is_lzma_envelope(standard):
        return xor_dex_header(decode_lzma_envelope(standard) + record.tail, mask), "RC4(2,1,3,5)+LZMA"
    if config is not None:
        variant = rc4_variant(record.encrypted, rc4_ksa(key), config.i0, config.j0,
                              config.step_i, config.step_j)
        if is_lzma_envelope(variant):
            return xor_dex_header(decode_lzma_envelope(variant) + record.tail, mask), \
                   f"RC4({config.step_i},{config.step_j},{config.i0},{config.j0})+LZMA"
    raw = xor_dex_header(record.encrypted + record.tail, mask)
    return decrypt_string_span(raw, key), "raw+string-RC4"


def classify_variant(names: set[str], has_jgapp: bool) -> str:
    if {"libjgcqm.so", "libjgcqm_a64.so"} & names:
        base = "custom/flagship libjgcqm"
    elif {"libjgdtc.so", "libjgdtc_a64.so"} & names:
        base = "custom/flagship libjgdtc"
    elif {"libjiagu_vip.so", "libjiagu_vip_a64.so"} & names:
        base = "enterprise/VIP libjiagu"
    elif {"libjiagu_v2.so", "libjiagu_a64.so"} & names:
        base = "libjiagu v2/a64"
    elif "libjiagu.so" in names:
        base = "libjiagu free/paid family"
    else:
        base = "classic whole-DEX model"
    return base + (" + .jgapp" if has_jgapp else "")


def inventory_apk(apk: Path) -> tuple[list[tuple[str, bytes]], dict[str, bytes], set[str], list[dict]]:
    root_dexes: list[tuple[str, bytes]] = []
    assets: dict[str, bytes] = {}
    names: set[str] = set()
    inventory = []
    with zipfile.ZipFile(apk, "r") as archive:
        for info in archive.infolist():
            safe_zip_name(info.filename)
            if info.is_dir():
                continue
            leaf = PurePosixPath(info.filename).name
            wanted = ("/" not in info.filename and leaf.startswith("classes") and leaf.endswith(".dex"))
            wanted = wanted or leaf.endswith(".so") or info.filename.startswith("assets/")
            if not wanted:
                continue
            data = archive.read(info)
            inventory.append({"zip_name": info.filename, "size": len(data), "sha256": sha256(data)})
            if "/" not in info.filename and leaf.startswith("classes") and leaf.endswith(".dex"):
                root_dexes.append((info.filename, data))
            elif leaf.endswith(".so"):
                names.add(leaf)
            elif info.filename.startswith("assets/"):
                assets[info.filename[7:]] = data
                names.add(leaf)
    require(bool(root_dexes), "APK contains no root classes*.dex")
    return root_dexes, assets, names, inventory


def find_classic_dex(assets: dict[str, bytes]) -> tuple[str, bytes] | None:
    preferred = ("data", "classes.dex", "app.dex", "real.dex")
    for name in preferred:
        data = assets.get(name)
        if data is not None and valid_dex(data):
            return name, data
    for name, data in assets.items():
        if valid_dex(data):
            return name, data
    return None


def recover(apk: Path, output_dir: Path, allow_nonfree: bool,
            scan_all_seeds: bool) -> dict:
    root_dexes, assets, names, inventory = inventory_apk(apk)
    variant = classify_variant(names, ".jgapp" in assets)
    if not allow_nonfree:
        blocked = sorted(names & NONFREE_MARKERS)
        require(not blocked, f"non-free/custom variant marker(s): {blocked}")
    selected = next(((name, data) for name, data in root_dexes if is_shell_dex(data)), None)
    require(selected is not None, "no root DEX contains a qh container; not a supported 360 whole-DEX shell")
    shell_name, shell = selected
    outputs = []
    cipher_report = None
    try:
        container = parse_qh_container(shell)
        config = detect_cipher_config(container.raw_config, container.records[0].encrypted,
                                      scan_all_seeds)
        seed = config.seed if config else KNOWN_SEEDS[0]
        key, seed_out = make_key(container.raw_config, seed)
        mask = seed_out & 0xFF
        for index, record in enumerate(container.records, 1):
            try:
                plain, mode = decrypt_record(record, key, mask, config)
                memory_sha = sha256(plain)
                restored = repair_dex(plain)
            except RecoveryError as exc:
                raise RecoveryError(f"DEX record {index} could not be restored: {exc}") from exc
            path = output_dir / f"classes{index}_decrypted.dex"
            path.write_bytes(restored)
            outputs.append({"path": str(path.resolve()), "size": len(restored),
                            "sha256": sha256(restored), "memory_sha256": memory_sha,
                            "mode": mode, "record_length": record.record_length,
                            "encrypted_length": record.encrypted_length})
        cipher_report = {
            "config_mask": container.config_mask,
            "raw_config_size": len(container.raw_config),
            "raw_config_sha256": sha256(container.raw_config),
            "seed": seed, "header_mask": mask, "key_sha256": sha256(key),
            "prga": None if config is None else {
                "step_i": config.step_i, "step_j": config.step_j,
                "i0": config.i0, "j0": config.j0,
            },
        }
    except RecoveryError as exc:
        if not str(exc).startswith("CLASSIC_WHOLE_DEX"):
            raise
        classic = find_classic_dex(assets)
        require(classic is not None, "classic model found but assets contain no valid real DEX")
        source, restored = classic
        path = output_dir / "classes1_decrypted.dex"
        path.write_bytes(restored)
        outputs.append({"path": str(path.resolve()), "size": len(restored),
                        "sha256": sha256(restored), "mode": "classic-assets",
                        "source": f"assets/{source}"})
    manifest = {
        "tool": "extract_360_dex.py", "scope": "whole DEX extraction only; no VMP repair",
        "input": {"path": str(apk.resolve()), "size": apk.stat().st_size,
                  "sha256": sha256(apk.read_bytes())},
        "variant": variant, "shell_dex": shell_name, "inventory": inventory,
        "cipher": cipher_report, "outputs": outputs,
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pure-static 360 Jiagu whole-DEX extractor (no VMP repair)")
    parser.add_argument("apk", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--allow-nonfree", action="store_true",
                        help="try unsupported paid/custom markers; validation still fails closed")
    parser.add_argument("--known-seeds-only", action="store_true",
                        help="do not scan seeds other than 222 and 171")
    parser.add_argument("--force", action="store_true",
                        help="replace an existing output directory")
    args = parser.parse_args(argv)
    apk = args.apk.resolve()
    output = (args.output or apk.with_name(apk.name + ".dex-out")).resolve()
    try:
        require(apk.is_file(), f"input not found: {apk}")
        if output.exists() and any(output.iterdir()):
            require(args.force, f"output directory is not empty: {output}; use --force")
            shutil.rmtree(output)
        output.mkdir(parents=True, exist_ok=True)
        manifest = recover(apk, output, args.allow_nonfree, not args.known_seeds_only)
        print(json.dumps({"status": "ok", "output": str(output),
                          "dexes": manifest["outputs"]}, ensure_ascii=False, indent=2))
        return 0
    except (RecoveryError, zipfile.BadZipFile, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
