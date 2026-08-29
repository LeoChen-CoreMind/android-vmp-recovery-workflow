#!/usr/bin/env python3
"""Android 加固样本纯静态一键还原器。

仅解析文件，不连接设备、不加载 SO、不执行恢复代码。默认把 APK 复制到脚本所在
目录的“产物”子目录后再处理。当前实现覆盖经静态验证的保护版本：AArch64 壳 SO 私有 ELF、
qh DEX 容器、lm VMP 记录、100x256 opcode 表，以及已确认 handler 的方法恢复。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import shutil
import struct
import sys
import time
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


MAX_OUTPUT = 128 * 1024 * 1024
PT_LOAD, PF_X = 1, 1
ACC_NATIVE = 0x100


class RecoveryError(RuntimeError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise RecoveryError(message)


def checked(data: bytes, off: int, size: int, name: str) -> bytes:
    require(off >= 0 and size >= 0 and off <= len(data) and size <= len(data) - off,
            f"{name} 越界: off=0x{off:X} size=0x{size:X} total=0x{len(data):X}")
    return data[off:off + size]


def u8(data: bytes, off: int, name: str = "u8") -> int:
    return checked(data, off, 1, name)[0]


def u16(data: bytes, off: int, name: str = "u16") -> int:
    return struct.unpack_from("<H", checked(data, off, 2, name))[0]


def s16(data: bytes, off: int, name: str = "s16") -> int:
    return struct.unpack_from("<h", checked(data, off, 2, name))[0]


def u32(data: bytes, off: int, name: str = "u32") -> int:
    return struct.unpack_from("<I", checked(data, off, 4, name))[0]


def u64(data: bytes, off: int, name: str = "u64") -> int:
    return struct.unpack_from("<Q", checked(data, off, 8, name))[0]


def align4(value: int) -> int:
    return (value + 3) & ~3


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    require(path.stat().st_size == len(data), f"写出长度不符: {path}")


def artifact(path: Path, kind: str, **extra: Any) -> Dict[str, Any]:
    data = path.read_bytes()
    item: Dict[str, Any] = {
        "kind": kind, "path": str(path), "size": len(data), "sha256": sha256(data)
    }
    item.update(extra)
    return item


def safe_zip_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    require(not path.is_absolute() and ".." not in path.parts, f"ZIP 路径不安全: {name}")
    return path


def extract_apk(apk: Path, out_dir: Path) -> Tuple[Path, List[Path], List[Dict[str, Any]]]:
    shell_dex: Optional[Path] = None
    so_paths: List[Path] = []
    inventory: List[Dict[str, Any]] = []
    with zipfile.ZipFile(apk, "r") as zf:
        for info in zf.infolist():
            name = safe_zip_name(info.filename)
            leaf = name.name
            is_dex = len(name.parts) == 1 and leaf.startswith("classes") and leaf.endswith(".dex")
            is_so = leaf.endswith(".so")
            is_identity = info.filename == "assets/.jgapp"
            if not (is_dex or is_so or is_identity) or info.is_dir():
                continue
            data = zf.read(info)
            dest = out_dir.joinpath(*name.parts)
            write_bytes(dest, data)
            inventory.append({"zip_name": info.filename, "path": str(dest), "size": len(data),
                              "sha256": sha256(data)})
            if info.filename == "classes.dex":
                shell_dex = dest
            if is_so:
                so_paths.append(dest)
    require(shell_dex is not None, "APK 中没有根目录 classes.dex")
    require(so_paths, "APK 中没有 SO")
    return shell_dex, so_paths, inventory


# ---------------------------------------------------------------------------
# AArch64 壳 SO -> 真实 ELF
# ---------------------------------------------------------------------------

def parse_elf64_loads(elf: bytes) -> List[Dict[str, int]]:
    require(checked(elf, 0, 4, "ELF magic") == b"\x7fELF", "不是 ELF")
    require(u8(elf, 4) == 2 and u8(elf, 5) == 1, "不是 little-endian ELF64")
    require(u16(elf, 18) == 0xB7, "不是 AArch64 ELF")
    phoff, entsize, count = u64(elf, 32), u16(elf, 54), u16(elf, 56)
    require(entsize >= 56 and 0 < count <= 4096, "ELF 程序头布局异常")
    checked(elf, phoff, entsize * count, "ELF 程序头表")
    result: List[Dict[str, int]] = []
    for idx in range(count):
        p = phoff + idx * entsize
        if u32(elf, p) != PT_LOAD:
            continue
        seg = {"flags": u32(elf, p + 4), "offset": u64(elf, p + 8),
               "vaddr": u64(elf, p + 16), "filesz": u64(elf, p + 32),
               "memsz": u64(elf, p + 40)}
        checked(elf, seg["offset"], seg["filesz"], "PT_LOAD")
        result.append(seg)
    require(result, "ELF 没有 PT_LOAD")
    return result


def va_to_off(loads: Sequence[Dict[str, int]], va: int, size: int = 1) -> int:
    for seg in loads:
        delta = va - seg["vaddr"]
        if delta >= 0 and size >= 0 and delta <= seg["filesz"] - size:
            return seg["offset"] + delta
    raise RecoveryError(f"VA 0x{va:X} 不在文件支持的 PT_LOAD 中")


def is_adrp(insn: int, rd: int) -> bool:
    return (insn & 0x9F00001F) == (0x90000000 | rd)


def decode_adrp(insn: int, pc: int) -> int:
    imm = (((insn >> 5) & 0x7FFFF) << 2) | ((insn >> 29) & 3)
    if imm & 0x100000:
        imm -= 0x200000
    return (pc & ~0xFFF) + (imm << 12)


def is_add_imm64(insn: int, rd: int, rn: int) -> bool:
    return (insn & 0xFF0003FF) == (0x91000000 | (rn << 5) | rd)


def add_imm(insn: int) -> int:
    value = (insn >> 10) & 0xFFF
    return value << 12 if (insn >> 22) & 1 else value


def is_movz_w(insn: int, rd: int) -> bool:
    return (insn & 0x7F80001F) == (0x52800000 | rd)


def is_movk_w(insn: int, rd: int) -> bool:
    return (insn & 0x7F80001F) == (0x72800000 | rd)


def mov_wide(insn: int) -> int:
    return ((insn >> 5) & 0xFFFF) << (((insn >> 21) & 3) * 16)


def apply_movk(old: int, insn: int) -> int:
    shift = ((insn >> 21) & 3) * 16
    mask = 0xFFFF << shift
    return (old & ~mask) | (((insn >> 5) & 0xFFFF) << shift)


def locate_so_carrier(so: bytes, loads: Sequence[Dict[str, int]]) -> Dict[str, int]:
    matches: List[Dict[str, int]] = []
    for seg in loads:
        if not seg["flags"] & PF_X:
            continue
        start, end = seg["offset"], seg["offset"] + seg["filesz"]
        for p in range(start, end - 19, 4):
            a, b, c, d = (u32(so, p + n * 4) for n in range(4))
            if not (is_adrp(a, 8) and is_movz_w(b, 9) and
                    is_add_imm64(c, 8, 8) and is_movk_w(d, 9)):
                continue
            pc = seg["vaddr"] + (p - seg["offset"])
            cipher_va = decode_adrp(a, pc) + add_imm(c)
            cipher_len = apply_movk(mov_wide(b), d)
            if not 6 <= cipher_len <= len(so):
                continue
            for q in range(p + 16, min(end, p + 0x100) - 7, 4):
                qa, qb = u32(so, q), u32(so, q + 4)
                if not (is_adrp(qa, 1) and is_add_imm64(qb, 1, 1)):
                    continue
                qpc = seg["vaddr"] + (q - seg["offset"])
                config_va = decode_adrp(qa, qpc) + add_imm(qb)
                for r in range(q + 8, min(end, q + 0x40) - 3, 4):
                    ri = u32(so, r)
                    if not is_movz_w(ri, 2):
                        continue
                    config_len = mov_wide(ri)
                    try:
                        cipher_off = va_to_off(loads, cipher_va, cipher_len)
                        config_off = va_to_off(loads, config_va, config_len)
                    except RecoveryError:
                        continue
                    if (config_len >= 54 and cipher_off + cipher_len == config_off and
                            checked(so, config_off, 2, "BM") == b"BM" and
                            u32(so, config_off + 2) == config_len):
                        matches.append({"cipher_off": cipher_off, "cipher_len": cipher_len,
                                        "config_off": config_off, "config_len": config_len})
    require(len(matches) == 1, f"SO 解密入口候选应为 1，实际 {len(matches)}")
    return matches[0]


def derive_so_key(config: bytes) -> bytes:
    require(len(config) >= 54 and config[:2] == b"BM" and u32(config, 2) == len(config),
            "BM 配置无效")
    key_count, flag = s16(config, 6), u16(config, 8)
    body = config[14:]
    bits = s16(body, 14)
    table_count = 0 if bits < 0 or bits > 8 else 1 << bits
    if table_count and u32(body, 32):
        table_count = u32(body, 32)
    cursor = 40 + table_count * 16
    key_len = 0 if key_count == 0 else key_count if flag == 0 else key_count - 1
    require(0 < key_len <= 4096 and cursor <= len(body) - key_len * 8, "BM 密钥位表越界")
    key = bytearray()
    for _ in range(key_len):
        value = 0
        for bit in range(7, -1, -1):
            x = body[cursor]
            cursor += 1
            value |= (((x >> 0) ^ (x >> 2) ^ (x >> 4) ^ (x >> 6)) & 1) << bit
        key.append(value)
    return bytes(key)


def rc4_ksa(key: bytes) -> List[int]:
    require(bool(key), "空 RC4 key")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    return state


def rc4x_with_state(data: bytes, initial: Sequence[int], i: int, j: int) -> bytes:
    state = list(initial)
    out = bytearray(data)
    for n, value in enumerate(data):
        i = (i + 2) & 0xFF
        j = (j + state[i] + 1) & 0xFF
        state[i], state[j] = state[j], state[i]
        out[n] = value ^ state[(state[i] + state[j]) & 0xFF]
    return bytes(out)


def decrypt_so_envelope(ciphertext: bytes, key: bytes) -> Tuple[bytes, int, int]:
    initial = rc4_ksa(key)
    for i0 in range(256):
        for j0 in range(256):
            prefix = rc4x_with_state(ciphertext[:6], initial, i0, j0)
            declared = u32(prefix, 0)
            cmf, flg = prefix[4], prefix[5]
            if not (0x1000 < declared <= MAX_OUTPUT and cmf == 0x78 and
                    (((cmf << 8) | flg) % 31 == 0)):
                continue
            envelope = rc4x_with_state(ciphertext, initial, i0, j0)
            try:
                plain = zlib.decompress(envelope[4:])
            except zlib.error:
                continue
            if len(plain) == declared:
                return plain, i0, j0
    raise RecoveryError("未找到通过 zlib 和长度验证的 PRGA 初态")


def restore_private_elf(container: bytes) -> Tuple[bytes, Dict[str, Any]]:
    require(len(container) >= 65, "私有 ELF 容器过短")
    mask, cursor = container[0], 1
    blocks: List[bytes] = []
    while checked(container, cursor, 4, "容器游标") != b"\x7fELF":
        require(len(blocks) < 32, "未在私有容器中找到 ELF")
        size = u32(container, cursor, "私有块长度")
        cursor += 4
        require(size > 0, "私有容器含空块")
        encoded = checked(container, cursor, size, "私有块")
        blocks.append(bytes(v ^ mask for v in encoded))
        cursor += size
    require(bool(blocks), "私有 ELF 缺少抽离块")
    elf = bytearray(container[cursor:])
    require(len(elf) >= 64 and elf[:4] == b"\x7fELF" and elf[4] == 2 and elf[5] == 1,
            "私有容器尾部不是 little-endian ELF64")
    require(u16(elf, 18) == 0xB7, "私有容器尾部不是 AArch64 ELF")
    phoff, entsize, count = u64(elf, 32), u16(elf, 54), u16(elf, 56)
    phsize = entsize * count
    require(len(blocks[0]) == phsize, "抽离程序头块长度不闭合")
    checked(elf, phoff, phsize, "程序头写回")
    elf[phoff:phoff + phsize] = blocks[0]
    parse_elf64_loads(bytes(elf))
    return bytes(elf), {"mask": mask, "block_sizes": [len(v) for v in blocks],
                        "raw_elf_offset": cursor, "phoff": phoff, "phnum": count}


def recover_real_so(so_paths: Sequence[Path], out_dir: Path) -> Tuple[Path, Dict[str, Any]]:
    successes: List[Tuple[Path, bytes, Dict[str, Any]]] = []
    errors: Dict[str, str] = {}
    for path in so_paths:
        data = path.read_bytes()
        try:
            loads = parse_elf64_loads(data)
            carrier = locate_so_carrier(data, loads)
            config = checked(data, carrier["config_off"], carrier["config_len"], "BM config")
            key = derive_so_key(config)
            ciphertext = checked(data, carrier["cipher_off"], carrier["cipher_len"], "SO ciphertext")
            container, i0, j0 = decrypt_so_envelope(ciphertext, key)
            real_elf, details = restore_private_elf(container)
            details.update({"source": str(path), "source_sha256": sha256(data),
                            "cipher_offset": carrier["cipher_off"],
                            "cipher_size": carrier["cipher_len"],
                            "config_offset": carrier["config_off"],
                            "config_size": carrier["config_len"],
                            "derived_key_sha256": sha256(key), "key_size": len(key),
                            "prga_i0": i0, "prga_j0": j0})
            successes.append((path, real_elf, details))
        except RecoveryError as exc:
            errors[str(path)] = str(exc)
    require(len(successes) == 1, f"可恢复的 AArch64 壳 SO 应为 1，实际 {len(successes)}; {errors}")
    source, real_elf, details = successes[0]
    output = out_dir / "real_loader_a64.so"
    write_bytes(output, real_elf)
    details["output_sha256"] = sha256(real_elf)
    details["output_size"] = len(real_elf)
    return output, details


# ---------------------------------------------------------------------------
# 壳 DEX qh 容器 -> 真实 DEX
# ---------------------------------------------------------------------------

def make_key(raw: bytes, seed: int = 222, flag: int = 0) -> Tuple[bytes, int]:
    output = bytearray(16)
    rolling = 2
    for index, value in enumerate(raw):
        rolling = (rolling * 31 + value) & 0xFF
        output[index % 16] = value
    accumulator = 2 * len(raw)
    for index, value in enumerate(raw):
        mix = ((value ^ index) ^ ((accumulator * 5) & 0xFF)) & 0xFF
        slot, old = index % 16, output[index % 16]
        low = (old & 0x0F) ^ rolling
        high = ((old >> 4) & 0x0F) ^ rolling
        output[slot] = ((rolling ^ seed) ^ (low | high)) & 0xFF
        seed = (seed ^ (mix ^ (accumulator + rolling + len(raw) + flag))) & 0xFFFFFFFF
        accumulator += 1
    return bytes(output), seed


def value_length(encoded: int) -> int:
    if 0x60 <= encoded <= 0x6F:
        return encoded ^ 0x40
    if 0x70 <= encoded <= 0x7F:
        return encoded ^ 0x60
    return encoded


def raw_config_end(decoded: bytes) -> int:
    last = -1
    for pos in range(0, max(0, len(decoded) - 11)):
        if decoded[pos:pos + 4] != b"\x10\x2b\x00\x00":
            continue
        key_len = u32(decoded, pos + 4, "config key len")
        val_len = value_length(u32(decoded, pos + 8, "config value len"))
        end = pos + 12 + key_len + val_len
        if end <= len(decoded):
            last = end
    require(last >= 0, "未找到可闭合的 rawConfig")
    return last


def parse_qh_container(shell: bytes) -> Dict[str, Any]:
    require(len(shell) >= 0x70 and shell[:4] == b"dex\n", "壳 classes.dex 无效")
    map_off = u32(shell, 0x34, "map_off")
    map_count = u32(shell, map_off, "map_count")
    logical_end = align4(map_off + 4 + map_count * 12)
    header = checked(shell, logical_end, 12, "qh header")
    require(header[:2] == b"qh", "DEX 逻辑尾部没有 qh 容器")
    payload_length, declared_config = u32(header, 4), u32(header, 8)
    metadata_start = logical_end + 12
    tail = checked(shell, metadata_start, len(shell) - metadata_start, "qh payload")
    decoded = bytes(v ^ 0xC6 for v in tail)
    marker_end = raw_config_end(decoded)
    if declared_config:
        require(declared_config == marker_end,
                f"rawConfig 自报长度 0x{declared_config:X} 与记录边界 0x{marker_end:X} 不一致")
    raw_config = checked(shell, metadata_start, marker_end, "rawConfig 原始字节")
    cursor = metadata_start + marker_end
    block_count = u32(shell, cursor, "DEX block count")
    cursor += 4
    require(0 < block_count <= 32, f"DEX 记录数异常: {block_count}")
    records: List[Dict[str, Any]] = []
    for index in range(block_count):
        record_length = u32(shell, cursor, "record_length")
        encrypted_length = u32(shell, cursor + 4, "encrypted_length")
        cursor += 8
        require(record_length >= 4 and encrypted_length <= record_length - 4,
                f"DEX 记录 {index} 长度无效")
        body_len = record_length - 4
        body = checked(shell, cursor, body_len, f"DEX record {index}")
        records.append({"record_length": record_length,
                        "encrypted_length": encrypted_length,
                        "encrypted": body[:encrypted_length], "tail": body[encrypted_length:]})
        cursor += body_len
    require(payload_length > 0 and cursor <= len(shell), "qh payload 边界无效")
    return {"logical_end": logical_end, "payload_length": payload_length,
            "raw_config": raw_config, "records": records, "parsed_end": cursor}


def rc4x(data: bytes, key: bytes, i0: int = 3, j0: int = 5) -> bytes:
    return rc4x_with_state(data, rc4_ksa(key), i0, j0)


def lzma1_filter(prop: int, dictionary: int) -> Dict[str, int]:
    require(prop < 9 * 5 * 5 and dictionary > 0, "LZMA1 properties 无效")
    lc = prop % 9
    rest = prop // 9
    lp, pb = rest % 5, rest // 5
    require(lc + lp <= 4, "LZMA1 lc+lp 无效")
    return {"id": lzma.FILTER_LZMA1, "dict_size": dictionary, "lc": lc, "lp": lp, "pb": pb}


def is_lzma_envelope(data: bytes) -> bool:
    if len(data) < 13 or data[0] >= 225:
        return False
    output_len, packed_len = u32(data, 5), u32(data, 9)
    return 0x70 <= output_len <= MAX_OUTPUT and packed_len == len(data) - 13


def decode_lzma_envelope(data: bytes) -> bytes:
    require(is_lzma_envelope(data), "LZMA 信封无效")
    prop, dictionary = data[0], u32(data, 1)
    output_len, packed_len = u32(data, 5), u32(data, 9)
    packed = checked(data, 13, packed_len, "LZMA packed data")
    try:
        # 该私有信封给出精确输出长度，raw LZMA1 流不保证携带 EOS marker；
        # 使用增量解码器按自报长度停止，而不是要求标准容器结束标记。
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
                                        filters=[lzma1_filter(prop, dictionary)])
        plain = decoder.decompress(packed, max_length=output_len)
    except lzma.LZMAError as exc:
        raise RecoveryError(f"raw LZMA 解压失败: {exc}") from exc
    require(len(plain) == output_len, "LZMA 输出长度不匹配")
    return plain


def xor_dex_header(data: bytes, mask: int) -> bytes:
    require(len(data) >= 0x70, "DEX 头不足 0x70")
    out = bytearray(data)
    for idx in range(0x70):
        out[idx] ^= mask & 0xFF
    return bytes(out)


def decrypt_string_span(dex: bytes, key: bytes) -> bytes:
    count, table = u32(dex, 0x38), u32(dex, 0x3C)
    if count < 2:
        return dex
    checked(dex, table, count * 4, "string_ids")
    first, last = u32(dex, table), u32(dex, table + 4 * (count - 1))
    require(last >= first, "string_data 偏移逆序")
    plain = rc4x(checked(dex, first, last - first, "string_data span"), key)
    return dex[:first] + plain + dex[last:]


def repair_dex(dex: bytes) -> bytes:
    require(len(dex) >= 0x70, "DEX 过短")
    out = bytearray(dex)
    out[12:32] = hashlib.sha1(out[32:]).digest()
    struct.pack_into("<I", out, 8, zlib.adler32(out[12:]) & 0xFFFFFFFF)
    return bytes(out)


def validate_dex(dex: bytes) -> Dict[str, Any]:
    require(len(dex) >= 0x70 and dex[:4] == b"dex\n" and dex[7] == 0, "DEX magic 无效")
    require(u32(dex, 0x20) == len(dex), "DEX file_size 不匹配")
    require(u32(dex, 0x24) == 0x70 and u32(dex, 0x28) == 0x12345678, "DEX header 无效")
    require(dex[12:32] == hashlib.sha1(dex[32:]).digest(), "DEX SHA-1 不匹配")
    require(u32(dex, 8) == (zlib.adler32(dex[12:]) & 0xFFFFFFFF), "DEX Adler32 不匹配")
    map_off = u32(dex, 0x34)
    map_count = u32(dex, map_off)
    checked(dex, map_off, 4 + map_count * 12, "DEX map_list")
    return {"size": len(dex), "sha256": sha256(dex), "map_count": map_count,
            "signature": dex[12:32].hex(), "adler32": f"{u32(dex, 8):08x}"}


def recover_real_dexes(shell: bytes, out_dir: Path) -> Tuple[List[Path], Dict[str, Any]]:
    container = parse_qh_container(shell)
    key, seed = make_key(container["raw_config"], 222, 0)
    mask = seed & 0xFF
    outputs: List[Path] = []
    records_report: List[Dict[str, Any]] = []
    for index, record in enumerate(container["records"], 1):
        envelope = rc4x(record["encrypted"], key)
        if is_lzma_envelope(envelope):
            plain = decode_lzma_envelope(envelope) + record["tail"]
            plain = xor_dex_header(plain, mask)
            mode = "RC4+LZMA"
        else:
            plain = xor_dex_header(record["encrypted"] + record["tail"], mask)
            plain = decrypt_string_span(plain, key)
            mode = "raw+string-RC4"
        memory_hash = sha256(plain)
        plain = repair_dex(plain)
        validation = validate_dex(plain)
        output = out_dir / f"classes{index}_decrypted.dex"
        write_bytes(output, plain)
        outputs.append(output)
        records_report.append({"id": index, "mode": mode,
                               "record_length": record["record_length"],
                               "encrypted_length": record["encrypted_length"],
                               "memory_sha256": memory_hash, "output": str(output),
                               **validation})
    return outputs, {"qh_logical_end": container["logical_end"],
                     "raw_config_size": len(container["raw_config"]),
                     "raw_config_sha256": sha256(container["raw_config"]),
                     "derived_key_sha256": sha256(key), "header_mask": mask,
                     "records": records_report, "global_key": key,
                     "raw_config": container["raw_config"]}


# ---------------------------------------------------------------------------
# lm VMP 记录、opcode 表和方法 code_item 静态恢复
# ---------------------------------------------------------------------------

def read_uleb(data: bytes, off: int) -> Tuple[int, int]:
    start, value, shift = off, 0, 0
    while True:
        require(off < len(data) and shift < 35, f"ULEB128 无效: 0x{start:X}")
        byte = data[off]
        off += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, off
        shift += 7


def encode_uleb(value: int) -> bytes:
    require(value >= 0, "不能编码负 ULEB128")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def dex_string(dex: bytes, index: int) -> str:
    count, table = u32(dex, 0x38), u32(dex, 0x3C)
    require(0 <= index < count, f"string_idx 越界: {index}")
    off = u32(dex, table + index * 4)
    _, cursor = read_uleb(dex, off)
    end = dex.find(b"\0", cursor)
    require(end >= 0, f"DEX 字符串未终止: {index}")
    return dex[cursor:end].decode("utf-8", "replace")


def type_descriptor(dex: bytes, type_idx: int) -> str:
    count, table = u32(dex, 0x40), u32(dex, 0x44)
    require(0 <= type_idx < count, f"type_idx 越界: {type_idx}")
    return dex_string(dex, u32(dex, table + type_idx * 4))


def method_info(dex: bytes, method_idx: int) -> Dict[str, Any]:
    count, table = u32(dex, 0x58), u32(dex, 0x5C)
    require(0 <= method_idx < count, f"method_idx 越界: {method_idx}")
    off = table + method_idx * 8
    class_idx, proto_idx, name_idx = u16(dex, off), u16(dex, off + 2), u32(dex, off + 4)
    return {"method_idx": method_idx, "class_idx": class_idx, "proto_idx": proto_idx,
            "name_idx": name_idx, "class": type_descriptor(dex, class_idx),
            "name": dex_string(dex, name_idx)}


def proto_register_count(dex: bytes, proto_idx: int) -> Tuple[int, str]:
    count, table = u32(dex, 0x48), u32(dex, 0x4C)
    require(0 <= proto_idx < count, f"proto_idx 越界: {proto_idx}")
    off = table + proto_idx * 12
    return_type, params_off = u32(dex, off + 4), u32(dex, off + 8)
    words = 0
    if params_off:
        size = u32(dex, params_off)
        checked(dex, params_off + 4, size * 2, "type_list")
        for idx in range(size):
            desc = type_descriptor(dex, u16(dex, params_off + 4 + idx * 2))
            words += 2 if desc in ("J", "D") else 1
    return words, type_descriptor(dex, return_type)


def parse_lm(dex: bytes) -> Optional[Dict[str, Any]]:
    lm_off = u32(dex, 0x6C) + u32(dex, 0x68)
    if lm_off + 8 > len(dex) or dex[lm_off:lm_off + 3] != b"lm\0":
        return None
    version = dex[lm_off + 3]
    require(1 <= version <= 3, f"lm version 无效: {version}")
    payload_len = u32(dex, lm_off + 4)
    payload = bytearray(checked(dex, lm_off + 8, payload_len, "lm payload"))
    xor_key = (dex[0x60] + 1) & 0xFF
    for idx in range(len(payload)):
        payload[idx] ^= xor_key
    payload_b = bytes(payload)
    tail_len = u32(payload_b, len(payload_b) - 4, "lm table length")
    require(tail_len > 0 and tail_len % 256 == 0, "lm opcode 表长度无效")
    record_count_off = len(payload_b) - tail_len - 8
    table_off = len(payload_b) - tail_len - 4
    require(record_count_off >= 0, "lm 记录边界无效")
    record_count = u32(payload_b, record_count_off)
    records: List[Dict[str, Any]] = []
    cursor = 0
    method_count = u32(dex, 0x58)
    for index in range(record_count):
        checked(payload_b, cursor, 20, "lm method record")
        method_idx = u32(payload_b, cursor)
        require(method_idx < method_count, "lm method_idx 越界")
        record = {"index": index, "record_offset": cursor, "method_idx": method_idx,
                  "flags": u32(payload_b, cursor + 4), "code_off": u32(payload_b, cursor + 8),
                  "group": u32(payload_b, cursor + 12),
                  "u16_count": u32(payload_b, cursor + 16)}
        cursor += 20 + record["u16_count"] * 2
        require(cursor <= record_count_off, "lm 方法记录越界")
        records.append(record)
    require(cursor == record_count_off, "lm 方法记录区没有精确闭合")
    return {"lm_off": lm_off, "version": version, "payload_len": payload_len,
            "xor_key": xor_key, "records": records,
            "table_cipher": checked(payload_b, table_off, tail_len, "opcode table")}


def fetch_unit(raw: int, key: int, fvp_one: bool) -> int:
    lo, hi, key = raw & 0xFF, (raw >> 8) & 0xFF, key & 0xFF
    if fvp_one:
        hd, ld = (hi - key) & 0xFFFFFFFF, (lo - key) & 0xFFFFFFFF
        h = (hd & 0xFF) ^ (0xE2 if (hd & 0x10) == 0 else 0xE7)
        low = (ld & 0xFF) ^ (0xE2 if (ld & 0x10) == 0 else 0xE7)
    else:
        ha, la = (hi + 0xF0) & 0xFFFFFFFF, (raw + 0xF0) & 0xFFFFFFFF
        h = (ha & 0xFF) ^ (0x2E if (ha & 1) == 0 else 0x7E)
        low = (la & 0xFF) ^ (0x2E if (la & 1) == 0 else 0x7E)
    return (((h ^ key) & 0xFF) << 8) | ((low ^ key) & 0xFF)


def operand_unit(raw: int, key: int, fvp_one: bool) -> int:
    lo, hi, key = raw & 0xFF, (raw >> 8) & 0xFF, key & 0xFF
    if fvp_one:
        hd, ld = (hi - key) & 0xFFFFFFFF, (lo - key) & 0xFFFFFFFF
        h = (hd & 0xFF) ^ (0xD2 if (hd & 0x20) == 0 else 0xD7)
        low = (ld & 0xFF) ^ (0xD2 if (ld & 0x20) == 0 else 0xD7)
    else:
        ha, la = (hi + 0xEE) & 0xFFFFFFFF, (raw + 0xEE) & 0xFFFFFFFF
        h = (ha & 0xFF) ^ (0x2D if (ha & 4) == 0 else 0x7D)
        low = (la & 0xFF) ^ (0x2D if (la & 2) == 0 else 0x7D)
    return (((h ^ key) & 0xFF) << 8) | ((low ^ key) & 0xFF)


def index_unit(raw: int, key: int) -> int:
    lo, hi, key = raw & 0xFF, (raw >> 8) & 0xFF, key & 0xFF
    hd, ld = (hi - key) & 0xFFFFFFFF, (lo - key) & 0xFFFFFFFF
    h = (hd & 0xFF) ^ (0xB2 if (hd & 0x40) == 0 else 0xB7)
    low = (ld & 0xFF) ^ (0xB2 if (ld & 0x40) == 0 else 0xB7)
    return (((h ^ key) & 0xFF) << 8) | ((low ^ key) & 0xFF)


# 这些不是猜测映射，只列入已经由真实 SO handler 数据流确认的语义。
VM_KINDS: Dict[int, Tuple[int, str, int]] = {
    0x9B: (0x71, "invoke-static", 3), 0xDA: (0x6F, "invoke-super", 3),
    0x66: (0x6E, "invoke-virtual", 3), 0x31: (0x70, "invoke-direct", 3),
    0xA6: (0x60, "sget", 2), 0x17: (0x0C, "move-result-object", 1),
    0x4A: (0x1F, "check-cast", 2), 0x8E: (0x5B, "iput-object", 2),
    0xD3: (0x22, "new-instance", 2), 0x59: (0x0E, "return-void", 1),
}


def used_35c_registers(first: int, packed: int) -> List[int]:
    count = (first >> 12) & 0xF
    regs = [packed & 0xF, (packed >> 4) & 0xF, (packed >> 8) & 0xF,
            (packed >> 12) & 0xF, (first >> 8) & 0xF]
    require(count <= 5, "invoke 参数数量超过 5")
    return regs[:count]


def decode_vmp_candidate(dex: bytes, raw_units: Sequence[int], table_row: bytes,
                         key: int, fvp_one: bool, registers_size: int) -> Tuple[List[int], List[Dict[str, Any]]]:
    output: List[int] = []
    trace: List[Dict[str, Any]] = []
    pc = 0
    fields_count, types_count = u32(dex, 0x50), u32(dex, 0x40)
    while pc < len(raw_units):
        decoded = fetch_unit(raw_units[pc], key, fvp_one)
        vm_opcode = table_row[decoded & 0xFF]
        require(vm_opcode in VM_KINDS, f"尚未静态确认的 VM opcode 0x{vm_opcode:02X}")
        dalvik, kind, width = VM_KINDS[vm_opcode]
        require(pc + width <= len(raw_units), f"{kind} 指令越界")
        first = (decoded & 0xFF00) | dalvik
        units = [first]
        item: Dict[str, Any] = {"pc": pc, "vm_opcode": vm_opcode, "kind": kind}
        high = decoded >> 8
        if kind.startswith("invoke-"):
            method_idx = operand_unit(raw_units[pc + 1], key, fvp_one)
            packed = index_unit(raw_units[pc + 2], key)
            info = method_info(dex, method_idx)
            param_words, _ = proto_register_count(dex, info["proto_idx"])
            expected = param_words + (0 if kind == "invoke-static" else 1)
            regs = used_35c_registers(first, packed)
            require(len(regs) == expected and all(v < registers_size for v in regs),
                    f"{kind} 参数/寄存器不闭合")
            units += [method_idx, packed]
            item.update({"method_idx": method_idx, "target": info["class"] + "->" + info["name"],
                         "registers": regs})
        elif kind == "sget":
            field_idx = operand_unit(raw_units[pc + 1], key, fvp_one)
            require(high < registers_size and field_idx < fields_count, "sget 参数越界")
            units.append(field_idx); item.update({"field_idx": field_idx, "dst": high})
        elif kind == "move-result-object":
            require(high < registers_size, "move-result-object 寄存器越界")
            item["dst"] = high
        elif kind == "check-cast":
            type_idx = operand_unit(raw_units[pc + 1], key, fvp_one)
            require(high < registers_size and type_idx < types_count, "check-cast 参数越界")
            units.append(type_idx); item.update({"type_idx": type_idx, "reg": high})
        elif kind == "iput-object":
            field_idx = operand_unit(raw_units[pc + 1], key, fvp_one)
            reg_a, reg_b = high & 0xF, (high >> 4) & 0xF
            require(reg_a < registers_size and reg_b < registers_size and field_idx < fields_count,
                    "iput-object 参数越界")
            units.append(field_idx); item.update({"field_idx": field_idx, "src": reg_a, "obj": reg_b})
        elif kind == "new-instance":
            type_idx = operand_unit(raw_units[pc + 1], key, fvp_one)
            require(high < registers_size and type_idx < types_count, "new-instance 参数越界")
            units.append(type_idx); item.update({"type_idx": type_idx, "dst": high})
        elif kind == "return-void":
            require(high == 0 and pc + 1 == len(raw_units), "return-void 不是合法结尾")
        output.extend(units)
        trace.append(item)
        pc += width
    require(len(output) == len(raw_units), "恢复后的 code unit 数量变化")
    return output, trace


def find_method_field(dex: bytes, method_idx: int, class_idx: int) -> Dict[str, int]:
    class_count, class_table = u32(dex, 0x60), u32(dex, 0x64)
    class_data_off = 0
    for index in range(class_count):
        off = class_table + index * 32
        if u32(dex, off) == class_idx:
            class_data_off = u32(dex, off + 24)
            break
    require(class_data_off != 0, "目标方法 class_data_item 不存在")
    cursor = class_data_off
    sizes: List[int] = []
    for _ in range(4):
        value, cursor = read_uleb(dex, cursor); sizes.append(value)
    for section in range(4):
        last_idx = 0
        for _ in range(sizes[section]):
            diff, cursor = read_uleb(dex, cursor); last_idx += diff
            access_off = cursor
            access, cursor = read_uleb(dex, cursor)
            access_len = cursor - access_off
            if section >= 2:
                code_off_field = cursor
                code_off, cursor = read_uleb(dex, cursor)
                if last_idx == method_idx:
                    return {"access_off": access_off, "access": access,
                            "access_len": access_len, "code_field": code_off_field,
                            "code_off": code_off, "code_len": cursor - code_off_field}
    raise RecoveryError("class_data_item 中找不到目标 method_idx")


def patch_vmp_methods(dex: bytes, global_key: bytes, output: Path,
                      table_dir: Path) -> Optional[Dict[str, Any]]:
    lm = parse_lm(dex)
    if lm is None:
        return None
    table = rc4x(lm["table_cipher"], global_key)
    row_count = len(table) // 256
    permutation_rows = sum(1 for idx in range(row_count)
                           if len(set(table[idx * 256:(idx + 1) * 256])) == 256)
    require(permutation_rows == row_count, "opcode 表不是逐行完整置换")
    write_bytes(table_dir / "opcode_table_all.bin", table)
    patched = bytearray(dex)
    reports: List[Dict[str, Any]] = []
    for record in lm["records"]:
        info = method_info(dex, record["method_idx"])
        code_off = record["code_off"]
        require(code_off > 0 and code_off + 16 <= len(dex), "VMP code_off 无效")
        registers_size, ins_size = u16(dex, code_off), u16(dex, code_off + 2)
        insns_size = u32(dex, code_off + 12)
        code = checked(dex, code_off + 16, insns_size * 2, "VMP code units")
        raw_units = list(struct.unpack("<" + "H" * insns_size, code))
        base_key = (ins_size ^ info["class_idx"] ^ registers_size ^ info["name_idx"] ^ 0x2C) & 0xFF
        candidates: List[Tuple[int, bool, int, List[int], List[Dict[str, Any]]]] = []
        for selector in range(256):
            key = selector ^ base_key
            row = table[(selector % row_count) * 256:(selector % row_count + 1) * 256]
            for fvp_one in (True, False):
                try:
                    units, trace = decode_vmp_candidate(dex, raw_units, row, key, fvp_one, registers_size)
                except RecoveryError:
                    continue
                candidates.append((selector, fvp_one, key, units, trace))
        require(len(candidates) == 1,
                f"{info['class']}->{info['name']} VMP 候选应唯一，实际 {len(candidates)}")
        selector, fvp_one, method_key, units, trace = candidates[0]
        fields = find_method_field(dex, record["method_idx"], info["class_idx"])
        require(fields["access"] & ACC_NATIVE and fields["code_off"] == 0,
                "目标方法不是 native/code_off=0 状态")
        replacement = encode_uleb(fields["access"] & ~ACC_NATIVE) + encode_uleb(code_off)
        old_len = fields["access_len"] + fields["code_len"]
        require(len(replacement) == old_len, "class_data 原地修补长度变化，拒绝移动 DEX")
        patched[fields["access_off"]:fields["access_off"] + old_len] = replacement
        restored_code = struct.pack("<" + "H" * len(units), *units)
        patched[code_off + 16:code_off + 16 + len(restored_code)] = restored_code
        write_bytes(table_dir / f"opcode_row_{selector % row_count:02d}.bin",
                    table[(selector % row_count) * 256:(selector % row_count + 1) * 256])
        reports.append({"record_index": record["index"], "method_idx": record["method_idx"],
                        "class": info["class"], "method": info["name"], "group": record["group"],
                        "code_off": code_off, "selector": selector, "table_row": selector % row_count,
                        "method_key": method_key, "fvp": 1 if fvp_one else 0,
                        "registers_size": registers_size, "ins_size": ins_size,
                        "insns_size": insns_size, "trace": trace})
    final = repair_dex(bytes(patched))
    validation = validate_dex(final)
    output_value: Optional[str] = None
    if reports:
        write_bytes(output, final)
        output_value = str(output)
    return {"lm_offset": lm["lm_off"], "lm_version": lm["version"],
            "lm_xor_key": lm["xor_key"], "table_size": len(table),
            "table_rows": row_count, "permutation_rows": permutation_rows,
            "table_sha256": sha256(table), "methods": reports,
            "output": output_value, **validation}


def markdown_report(manifest: Dict[str, Any]) -> str:
    lines = ["# 一键静态还原结果", "", "> 全流程仅解析文件，没有加载或执行目标代码。", "",
             "## 输入", "", f"- APK：`{manifest['input']['path']}`",
             f"- 大小：`0x{manifest['input']['size']:X}`",
             f"- SHA-256：`{manifest['input']['sha256']}`", "", "## 执行链", "",
             "```text", "APK 安全解压", "  -> AArch64 壳 SO 定位 BM 配置与密文",
             "  -> 位表派生 key -> 修改 RC4 -> zlib -> 私有 ELF 重建",
             "  -> 壳 DEX qh/rawConfig -> makekey -> DEX 记录解密/解压",
             "  -> 真实 DEX lm -> opcode 表解密 -> VMP 方法候选唯一化",
             "  -> 清除 ACC_NATIVE、写回 code_off 和真实 Dalvik code units",
             "  -> 重算 DEX SHA-1/Adler32", "```", "", "## 真实 SO", ""]
    so = manifest["real_so"]
    lines += [f"- 来源：`{so['source']}`", f"- 输出：`{manifest['outputs'][0]['path']}`",
              f"- 输出 SHA-256：`{so['output_sha256']}`",
              f"- 密文/配置长度：`0x{so['cipher_size']:X}` / `0x{so['config_size']:X}`",
              f"- PRGA 初态（静态枚举验证）：`i={so['prga_i0']}, j={so['prga_j0']}`", "",
              "## 真实 DEX", ""]
    for record in manifest["dex"]["records"]:
        lines += [f"- classes{record['id']}：`{record['mode']}`，`0x{record['size']:X}` 字节，"
                  f"SHA-256 `{record['sha256']}`"]
    lines += ["", "## VMP 方法恢复", ""]
    if not manifest["vmp"]:
        lines.append("没有发现 lm VMP 数据块。")
    for item in manifest["vmp"]:
        title = Path(item["output"]).name if item.get("output") else "仅含映射表、没有受保护方法"
        lines += [f"### `{title}`", "",
                  f"- opcode 表：`{item['table_rows']} × 256`，完整置换行 "
                  f"`{item['permutation_rows']}/{item['table_rows']}`",
                  f"- 表 SHA-256：`{item['table_sha256']}`"]
        for method in item["methods"]:
            lines += [f"- `{method['class']}->{method['method']}`：selector `0x{method['selector']:02X}`，"
                      f"row `{method['table_row']}`，key `0x{method['method_key']:02X}`，"
                      f"恢复 `{len(method['trace'])}` 条指令"]
            for insn in method["trace"]:
                target = " " + insn.get("target", "") if insn.get("target") else ""
                lines.append(f"  - PC {insn['pc']:02d}: VM `0x{insn['vm_opcode']:02X}` -> "
                             f"`{insn['kind']}`{target}")
    lines += ["", "## 完整产物", ""]
    for item in manifest["outputs"]:
        lines.append(f"- `{item['kind']}`：`{item['path']}`，SHA-256 `{item['sha256']}`")
    lines += ["", "## 完成边界", "",
              "脚本只恢复已经由真实 SO handler 静态确认的 VM 指令。未来样本出现未知 VM opcode、"
              "非唯一 selector 或结构变体时会失败关闭，不会猜测业务代码。", ""]
    return "\n".join(lines)


def choose_work_dir(requested: Optional[Path], script_dir: Path) -> Path:
    base = requested if requested else script_dir / "产物"
    if not base.exists():
        return base
    return base.with_name(base.name + "_" + time.strftime("%Y%m%d_%H%M%S"))


def main(argv: Optional[Sequence[str]] = None) -> int:
    script_dir = Path(__file__).resolve().parent
    default_apk = script_dir / "demo.apk"
    parser = argparse.ArgumentParser(description="纯静态一键恢复壳 SO、真实 SO、DEX 与已确认 VMP 方法")
    parser.add_argument("apk", nargs="?", type=Path, default=default_apk, help="输入 APK")
    parser.add_argument("-o", "--output", type=Path, help="工作/输出目录；默认使用脚本目录下的“产物”")
    parser.add_argument("--skip-vmp", action="store_true", help="只恢复真实 SO 和 DEX")
    args = parser.parse_args(argv)

    source_apk = args.apk.resolve()
    require(source_apk.is_file(), f"APK 不存在: {source_apk}")
    work = choose_work_dir(args.output.resolve() if args.output else None, script_dir)
    input_dir, extracted_dir = work / "input", work / "extracted"
    recovered_so_dir, recovered_dex_dir = work / "recovered" / "so", work / "recovered" / "dex"
    vmp_dir = work / "recovered" / "vmp"
    for directory in (input_dir, extracted_dir, recovered_so_dir, recovered_dex_dir, vmp_dir, work / "logs"):
        directory.mkdir(parents=True, exist_ok=True)

    processing_apk = input_dir / source_apk.name
    shutil.copy2(source_apk, processing_apk)
    require(sha256(source_apk.read_bytes()) == sha256(processing_apk.read_bytes()), "APK 工作副本哈希不一致")
    shell_path, so_paths, inventory = extract_apk(processing_apk, extracted_dir)
    shell = shell_path.read_bytes()

    real_so_path, so_report = recover_real_so(so_paths, recovered_so_dir)
    dex_paths, dex_internal = recover_real_dexes(shell, recovered_dex_dir)
    global_key = dex_internal.pop("global_key")
    dex_internal.pop("raw_config")

    vmp_reports: List[Dict[str, Any]] = []
    if not args.skip_vmp:
        for index, dex_path in enumerate(dex_paths, 1):
            report = patch_vmp_methods(dex_path.read_bytes(), global_key,
                                       recovered_dex_dir / f"classes{index}_full_restore.dex",
                                       vmp_dir / f"classes{index}")
            if report is not None:
                vmp_reports.append(report)

    outputs = [artifact(real_so_path, "real-so")]
    outputs.extend(artifact(path, "real-dex") for path in dex_paths)
    for report in vmp_reports:
        if report.get("output"):
            outputs.append(artifact(Path(report["output"]), "vmp-restored-dex"))
    all_table_files = sorted(vmp_dir.rglob("*.bin"))
    outputs.extend(artifact(path, "vmp-table") for path in all_table_files)

    manifest: Dict[str, Any] = {
        "tool": "android-packer-static-recovery/one_click_restore.py",
        "static_only": True,
        "input": artifact(processing_apk, "apk", original_path=str(source_apk)),
        "workspace": str(work), "extracted": inventory, "real_so": so_report,
        "dex": dex_internal, "vmp": vmp_reports, "outputs": outputs,
    }
    manifest_path = work / "logs" / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    report_path = work / "静态还原结果.md"
    report_path.write_text(markdown_report(manifest), encoding="utf-8")

    print("[成功] 纯静态一键还原完成")
    print(f"工作目录: {work}")
    print(f"真实 SO : {real_so_path} ({sha256(real_so_path.read_bytes())})")
    for path in dex_paths:
        print(f"真实 DEX: {path} ({sha256(path.read_bytes())})")
    for report in vmp_reports:
        if report.get("output"):
            print(f"VMP DEX : {report['output']} ({report['sha256']})")
    print(f"清单     : {manifest_path}")
    print(f"报告     : {report_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RecoveryError, OSError, zipfile.BadZipFile) as exc:
        print(f"[失败] {exc}", file=sys.stderr)
        raise SystemExit(1)
