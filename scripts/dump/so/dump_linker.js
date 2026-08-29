/*
 * 360 jiagu ARM64 manual-linker dumper.
 *
 * All build-specific offsets and instruction signatures are injected by
 * run_gating.py from the current case. The agent refuses to run without them.
 *
 * Use spawn mode. Attaching with -F is normally too late:
 *   frida -H 192.168.1.4:14725 -f your.package.name -l dump_linker.js
 */

'use strict';

const CONFIG = {
    // null: automatically use /data/user/0/<package>/files
    outputDir: null,

    jiaguNames: [
        'libjiagu_64.so',
        'libjiagu.so',
        'libjiagu_a64.so'
    ],

    manualLoadFunctionOffset: null,
    exactDumpOffset: null,
    handleGlobalOffset: null,
    manualLoaderSignature: null,
    exactDumpInstructionMask: null,
    exactDumpInstructionValue: null,
    dumpOnManualLoaderReturn: false,
    dumpWhenRuntimePointersReady: false,
    runtimePointerPollIntervalMs: 5,
    runtimePointerPollTimeoutMs: 30000,
    requiredNonZeroPointerOffsets: [],
    requiredPointersInsideImage: true,

    // Private soinfo layout used by this 360 build.
    soinfoLoadStartOffset: null,
    soinfoPhdrOffset: null,
    soinfoLoadSizeOffset: null,
    soinfoPhnumOffset: null,
    soinfoDynamicOffset: null,
    soinfoLoadBiasOffset: null,
    soinfoNameOffset: null,

    maxDumpSize: 512 * 1024 * 1024,
};

// The runner injects case-specific values before this script is evaluated.
// Defaults above are reference values only and must be overridden for a new build.
if (globalThis.VMPWF_CONFIG !== undefined && globalThis.VMPWF_CONFIG !== null) {
    Object.assign(CONFIG, globalThis.VMPWF_CONFIG);
}

const ELF_MAGIC = 0x464c457f;
const PT_LOAD = 1;
const PT_DYNAMIC = 2;

let installed = false;
let dumping = false;
let dumped = false;
let lastManualHandle = null;
let installTimer = null;
let runtimePointerTimer = null;

function log(message) {
    console.log('[360-linker-dump] ' + message);
}

function warn(message) {
    console.log('[360-linker-dump][!] ' + message);
}

function u64ToNumber(value, what) {
    const n = Number(value.toString());
    if (!Number.isSafeInteger(n) || n < 0) {
        throw new Error((what || 'u64') + ' is outside the safe JS integer range: ' + value);
    }
    return n;
}

function pointerDelta(high, low) {
    return Number(high.sub(low).toString());
}

function alignDown(value, alignment) {
    return Math.floor(value / alignment) * alignment;
}

function alignUp(value, alignment) {
    return Math.ceil(value / alignment) * alignment;
}

function isElf(address) {
    try {
        return !address.isNull() && address.readU32() === ELF_MAGIC;
    } catch (_) {
        return false;
    }
}

function readCStringSafe(address, maxLength) {
    try {
        if (address.isNull()) return '';
        return address.readCString(maxLength || 256) || '';
    } catch (_) {
        return '';
    }
}

function readInlineAscii(address, maxLength) {
    let result = '';
    try {
        for (let i = 0; i < maxLength; i++) {
            const value = address.add(i).readU8();
            if (value === 0) break;
            if (value < 0x20 || value > 0x7E) break;
            result += String.fromCharCode(value);
        }
    } catch (_) {
    }
    return result;
}

function sanitizeName(name) {
    const clean = (name || 'linker').replace(/[^A-Za-z0-9._-]/g, '_');
    return clean.length > 0 ? clean : 'linker';
}

function getProcessName() {
    try {
        const file = new File('/proc/self/cmdline', 'rb');
        const data = file.readBytes(512);
        file.close();
        const bytes = new Uint8Array(data);
        let result = '';
        for (let i = 0; i < bytes.length && bytes[i] !== 0; i++) {
            result += String.fromCharCode(bytes[i]);
        }
        return result;
    } catch (e) {
        warn('cannot read /proc/self/cmdline: ' + e);
        return '';
    }
}

function packageNameFromProcess() {
    const processName = getProcessName();
    const colon = processName.indexOf(':');
    return colon >= 0 ? processName.substring(0, colon) : processName;
}

function outputDirectories() {
    if (CONFIG.outputDir !== null) return [CONFIG.outputDir];

    const pkg = packageNameFromProcess();
    if (pkg.length === 0) return [];
    return [
        '/data/user/0/' + pkg + '/files',
        '/data/data/' + pkg + '/files',
        '/data/user/0/' + pkg + '/cache',
        '/data/data/' + pkg + '/cache'
    ];
}

function openOutputFile(fileName) {
    const dirs = outputDirectories();
    let lastError = null;
    for (let i = 0; i < dirs.length; i++) {
        const path = dirs[i] + '/' + fileName;
        try {
            return { file: new File(path, 'wb'), path: path };
        } catch (e) {
            lastError = e;
        }
    }
    throw new Error('cannot open output file; set CONFIG.outputDir. Last error: ' + lastError);
}

function findJiaguModule() {
    const modules = Process.enumerateModules();
    for (let i = 0; i < modules.length; i++) {
        const module = modules[i];
        for (let j = 0; j < CONFIG.jiaguNames.length; j++) {
            if (module.name === CONFIG.jiaguNames[j]) return module;
        }
        if (module.name.indexOf('jiagu') !== -1 && module.name.endsWith('.so')) {
            return module;
        }
    }
    return null;
}

function checkManualLoaderSignature(module) {
    try {
        const p = module.base.add(CONFIG.manualLoadFunctionOffset);
        const expected = CONFIG.manualLoaderSignature;
        for (let i = 0; i < expected.length; i++) {
            const value = typeof expected[i] === 'string' ? parseInt(expected[i], 0) : expected[i];
            if (p.add(i * 4).readU32() !== value) return false;
        }
        return true;
    } catch (_) {
        return false;
    }
}

function locateExactDumpPoint(module) {
    const fixed = module.base.add(CONFIG.exactDumpOffset);
    try {
        const mask = Number(CONFIG.exactDumpInstructionMask) >>> 0;
        const expected = Number(CONFIG.exactDumpInstructionValue) >>> 0;
        if (((fixed.readU32() & mask) >>> 0) === expected) {
            return fixed;
        }
    } catch (_) {
    }
    return null;
}

function decodeHandleOffsetAtDumpPoint(hookAddress) {
    try {
        const instruction = hookAddress.readU32();
        if (((instruction & 0xFFC003FF) >>> 0) !== 0xF94002C0) return null;
        const imm12 = (instruction >>> 10) & 0xFFF;
        return imm12 * 8;
    } catch (_) {
        return null;
    }
}

function getSoinfo(handle) {
    if (handle === null || handle.isNull()) throw new Error('null private soinfo');

    const loadStart = handle.add(CONFIG.soinfoLoadStartOffset).readPointer();
    const phdr = handle.add(CONFIG.soinfoPhdrOffset).readPointer();
    const loadSize = u64ToNumber(
        handle.add(CONFIG.soinfoLoadSizeOffset).readU64(),
        'private soinfo load_size'
    );
    const phnum = u64ToNumber(
        handle.add(CONFIG.soinfoPhnumOffset).readU64(),
        'private soinfo phnum'
    );
    const dynamic = handle.add(CONFIG.soinfoDynamicOffset).readPointer();
    const loadBias = handle.add(CONFIG.soinfoLoadBiasOffset).readPointer();
    let name = readInlineAscii(handle.add(CONFIG.soinfoNameOffset), 128);
    if (name === '*.so' || name.length === 0) name = 'linker.so';

    if (loadStart.isNull()) throw new Error('private soinfo load_start is null');
    if (phdr.isNull()) throw new Error('private soinfo phdr is null');
    if (dynamic.isNull()) throw new Error('private soinfo dynamic is null');
    if (loadSize <= 0 || loadSize > CONFIG.maxDumpSize) {
        throw new Error('invalid private soinfo load_size: 0x' + loadSize.toString(16));
    }
    if (phnum <= 0 || phnum > 2048) {
        throw new Error('invalid private soinfo phnum: ' + phnum);
    }

    return {
        handle: handle,
        loadStart: loadStart,
        phdr: phdr,
        loadSize: loadSize,
        phnum: phnum,
        dynamic: dynamic,
        loadBias: loadBias,
        name: name
    };
}

function searchElfHeader(soinfo) {
    const candidates = [soinfo.loadStart, soinfo.loadBias];
    for (let i = 0; i < candidates.length; i++) {
        if (isElf(candidates[i])) return candidates[i];
    }

    const pageSize = Process.pageSize || 4096;
    const searchSize = Math.min(soinfo.loadSize, 32 * 1024 * 1024);
    for (let offset = 0; offset < searchSize; offset += pageSize) {
        const candidate = soinfo.loadStart.add(offset);
        if (isElf(candidate)) return candidate;
    }
    return null;
}

function parseProgramHeaders(phdr, phentsize, phnum) {
    if (phentsize < 56 || phnum === 0 || phnum > 2048) {
        throw new Error('invalid program header table: entsize=' + phentsize + ', num=' + phnum);
    }

    let minVaddr = Number.MAX_SAFE_INTEGER;
    let maxVaddr = 0;
    let dynamicVaddr = null;
    let dynamicMemsz = 0;
    let loadCount = 0;
    const pageSize = Process.pageSize || 4096;

    for (let i = 0; i < phnum; i++) {
        const ph = phdr.add(i * phentsize);
        const type = ph.readU32();
        const vaddr = u64ToNumber(ph.add(0x10).readU64(), 'p_vaddr');
        const memsz = u64ToNumber(ph.add(0x28).readU64(), 'p_memsz');
        if (type === PT_LOAD) {
            loadCount++;
            minVaddr = Math.min(minVaddr, alignDown(vaddr, pageSize));
            maxVaddr = Math.max(maxVaddr, alignUp(vaddr + memsz, pageSize));
        } else if (type === PT_DYNAMIC) {
            dynamicVaddr = vaddr;
            dynamicMemsz = memsz;
        }
    }

    if (loadCount === 0 || minVaddr === Number.MAX_SAFE_INTEGER || maxVaddr <= minVaddr) {
        throw new Error('no valid PT_LOAD span');
    }

    return {
        phentsize: phentsize,
        phnum: phnum,
        loadCount: loadCount,
        minVaddr: minVaddr,
        maxVaddr: maxVaddr,
        imageSpan: maxVaddr - minVaddr,
        dynamicVaddr: dynamicVaddr,
        dynamicMemsz: dynamicMemsz
    };
}

function parseElf64(elfBase) {
    if (!isElf(elfBase)) throw new Error('ELF magic is missing at ' + elfBase);
    if (elfBase.add(4).readU8() !== 2) throw new Error('target is not ELF64');
    if (elfBase.add(5).readU8() !== 1) throw new Error('target is not little-endian');

    const phoff = u64ToNumber(elfBase.add(0x20).readU64(), 'e_phoff');
    const phentsize = elfBase.add(0x36).readU16();
    const phnum = elfBase.add(0x38).readU16();
    const result = parseProgramHeaders(elfBase.add(phoff), phentsize, phnum);
    result.phoff = phoff;
    return result;
}

function pointerInside(address, start, size) {
    return address.compare(start) >= 0 && address.compare(start.add(size)) < 0;
}

function resolveDynamicPointer(rawPointer, soinfo) {
    if (pointerInside(rawPointer, soinfo.loadStart, soinfo.loadSize)) return rawPointer;
    const rawNumber = Number(rawPointer.toString());
    if (Number.isSafeInteger(rawNumber) && rawNumber >= 0 && rawNumber < soinfo.loadSize * 4) {
        return soinfo.loadBias.add(rawNumber);
    }
    return rawPointer;
}

function inspectDynamicTable(soinfo, elf) {
    const result = {
        hasStrtab: false,
        hasSymtab: false,
        hasStrsz: false,
        hasSyment: false,
        hasHash: false,
        hasGnuHash: false,
        symbolCount: null,
        entryCount: 0,
        byteSize: 0
    };
    if (elf.dynamicVaddr === null || elf.dynamicMemsz < 16) return result;

    // 360 removes PT_DYNAMIC from the mapped image and keeps the decrypted
    // Elf64_Dyn array at private soinfo +0x100.
    const dynamicAddress = soinfo.dynamic;
    const maxEntries = Math.min(Math.floor(elf.dynamicMemsz / 16), 65536);
    let sysvHash = null;

    for (let i = 0; i < maxEntries; i++) {
        const entry = dynamicAddress.add(i * 16);
        const tag = u64ToNumber(entry.readU64(), 'dynamic tag');
        result.entryCount = i + 1;
        if (tag === 0) break;
        if (tag === 4) {
            result.hasHash = true;
            sysvHash = entry.add(8).readPointer();
        } else if (tag === 5) {
            result.hasStrtab = true;
        } else if (tag === 6) {
            result.hasSymtab = true;
        } else if (tag === 10) {
            result.hasStrsz = true;
        } else if (tag === 11) {
            result.hasSyment = true;
        } else if (tag === 0x6ffffef5) {
            result.hasGnuHash = true;
        }
    }
    result.byteSize = result.entryCount * 16;

    if (sysvHash !== null) {
        try {
            const hashAddress = resolveDynamicPointer(sysvHash, soinfo);
            if (pointerInside(hashAddress, soinfo.loadStart, soinfo.loadSize)) {
                result.symbolCount = hashAddress.add(4).readU32();
            }
        } catch (_) {
        }
    }
    return result;
}

function inspectRequiredRuntimePointers(soinfo) {
    const result = {};
    const offsets = CONFIG.requiredNonZeroPointerOffsets || [];
    for (let i = 0; i < offsets.length; i++) {
        const offset = typeof offsets[i] === 'string' ? parseInt(offsets[i], 0) : offsets[i];
        if (!Number.isSafeInteger(offset) || offset < 0 || offset + Process.pointerSize > soinfo.loadSize) {
            throw new Error('invalid required runtime pointer offset: ' + offsets[i]);
        }
        const value = soinfo.loadStart.add(offset).readPointer();
        result['0x' + offset.toString(16)] = value.toString();
        if (value.isNull()) {
            throw new Error('required runtime pointer is null at private image +0x' + offset.toString(16));
        }
        if (CONFIG.requiredPointersInsideImage && !pointerInside(value, soinfo.loadStart, soinfo.loadSize)) {
            throw new Error('required runtime pointer is outside private image at +0x' +
                offset.toString(16) + ': ' + value);
        }
    }
    return result;
}

function describeRuntimePointerOwners(runtimePointers) {
    const owners = {};
    Object.keys(runtimePointers).forEach(function (offset) {
        const value = ptr(runtimePointers[offset]);
        let module = null;
        try {
            module = Process.findModuleByAddress(value);
        } catch (_) {
            module = null;
        }
        owners[offset] = module === null ? null : {
            name: module.name,
            base: module.base.toString(),
            size: module.size
        };
    });
    return owners;
}

function waitForRequiredRuntimePointers(handle) {
    if (runtimePointerTimer !== null || dumped || dumping) return;
    const started = Date.now();
    log('waiting for required private-linker runtime pointers');
    runtimePointerTimer = setInterval(function () {
        if (dumped || dumping) {
            clearInterval(runtimePointerTimer);
            runtimePointerTimer = null;
            return;
        }
        try {
            const soinfo = getSoinfo(handle);
            inspectRequiredRuntimePointers(soinfo);
            clearInterval(runtimePointerTimer);
            runtimePointerTimer = null;
            dumpPrivateSoinfo(handle, 'spawn-gated-runtime-pointers-ready');
        } catch (e) {
            if (Date.now() - started >= CONFIG.runtimePointerPollTimeoutMs) {
                clearInterval(runtimePointerTimer);
                runtimePointerTimer = null;
                warn('runtime pointer wait timed out: ' + e);
                send({ event: 'dump-failed', reason: 'runtime-pointer-timeout', error: String(e) });
            }
        }
    }, CONFIG.runtimePointerPollIntervalMs);
}

function buildDynamicOverlay(soinfo, elf, dynamic) {
    if (dynamic.byteSize < 16) throw new Error('private dynamic table has no DT_NULL terminator');
    const offset = elf.dynamicVaddr - elf.minVaddr;
    if (offset < 0 || offset + dynamic.byteSize > soinfo.loadSize) {
        throw new Error('private dynamic table does not fit the PT_LOAD image span');
    }
    const data = soinfo.dynamic.readByteArray(dynamic.byteSize);
    if (data === null) throw new Error('cannot read private dynamic table');
    return {
        name: 'PT_DYNAMIC',
        offset: offset,
        bytes: new Uint8Array(data)
    };
}

function applyOverlay(chunk, chunkOffset, overlay) {
    const chunkEnd = chunkOffset + chunk.length;
    const overlayEnd = overlay.offset + overlay.bytes.length;
    const start = Math.max(chunkOffset, overlay.offset);
    const end = Math.min(chunkEnd, overlayEnd);
    if (start >= end) return;
    const sourceOffset = start - overlay.offset;
    const targetOffset = start - chunkOffset;
    chunk.set(overlay.bytes.subarray(sourceOffset, sourceOffset + (end - start)), targetOffset);
}

function setU64(view, offset, value) {
    const low = value >>> 0;
    const high = Math.floor(value / 0x100000000) >>> 0;
    view.setUint32(offset, low, true);
    view.setUint32(offset + 4, high, true);
}

function synthesizeElf64Header(buffer, soinfo, elf) {
    const bytes = new Uint8Array(buffer);
    const view = new DataView(buffer);
    const phentsize = 56;
    const phoff = 64;
    const phdrSize = soinfo.phnum * phentsize;
    const required = phoff + phdrSize;
    if (required > bytes.length) {
        throw new Error('synthetic ELF header buffer is too small');
    }

    bytes.fill(0, 0, required);
    bytes[0] = 0x7F;
    bytes[1] = 0x45;
    bytes[2] = 0x4C;
    bytes[3] = 0x46;
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // ELFDATA2LSB
    bytes[6] = 1; // EV_CURRENT
    bytes[7] = 0; // System V ABI

    view.setUint16(0x10, 3, true);   // ET_DYN
    view.setUint16(0x12, 183, true); // EM_AARCH64
    view.setUint32(0x14, 1, true);   // EV_CURRENT
    setU64(view, 0x18, 0);           // e_entry
    setU64(view, 0x20, phoff);       // e_phoff
    setU64(view, 0x28, 0);           // e_shoff
    view.setUint32(0x30, 0, true);   // e_flags
    view.setUint16(0x34, 64, true);  // e_ehsize
    view.setUint16(0x36, phentsize, true);
    view.setUint16(0x38, soinfo.phnum, true);
    view.setUint16(0x3A, 64, true);  // Elf64_Shdr size
    view.setUint16(0x3C, 0, true);
    view.setUint16(0x3E, 0, true);

    const phdrBytes = soinfo.phdr.readByteArray(phdrSize);
    if (phdrBytes === null) throw new Error('cannot read private program header table');
    bytes.set(new Uint8Array(phdrBytes), phoff);

    elf.phoff = phoff;
    elf.phentsize = phentsize;
    elf.syntheticHeaderSize = required;
}

function writeZeroFilledMemory(start, size, file, synthetic, overlays) {
    const pageSize = Process.pageSize || 4096;
    let readableBytes = 0;
    let zeroBytes = 0;
    let firstOffset = 0;
    const patchList = overlays || [];

    if (synthetic !== null) {
        const required = 64 + synthetic.soinfo.phnum * 56;
        const prefixSize = alignUp(Math.max(pageSize, required), pageSize);
        if (prefixSize > size) throw new Error('mapping is too small for a synthetic ELF header');

        const prefix = new Uint8Array(prefixSize);
        for (let offset = 0; offset < prefixSize; offset += pageSize) {
            const length = Math.min(pageSize, prefixSize - offset);
            let data = null;
            try {
                data = start.add(offset).readByteArray(length);
            } catch (_) {
                data = null;
            }
            if (data !== null) {
                prefix.set(new Uint8Array(data), offset);
                readableBytes += length;
            } else {
                zeroBytes += length;
            }
        }

        synthesizeElf64Header(prefix.buffer, synthetic.soinfo, synthetic.elf);
        for (let i = 0; i < patchList.length; i++) {
            applyOverlay(prefix, 0, patchList[i]);
        }
        file.write(prefix.buffer);
        firstOffset = prefixSize;
    }

    for (let offset = firstOffset; offset < size; offset += pageSize) {
        const length = Math.min(pageSize, size - offset);
        let data = null;
        try {
            data = start.add(offset).readByteArray(length);
        } catch (_) {
            data = null;
        }

        let chunk = null;
        if (data !== null) {
            chunk = new Uint8Array(data);
            readableBytes += length;
        } else {
            chunk = new Uint8Array(length);
            zeroBytes += length;
        }
        for (let i = 0; i < patchList.length; i++) {
            applyOverlay(chunk, offset, patchList[i]);
        }
        file.write(chunk.buffer);
    }
    return { readableBytes: readableBytes, zeroBytes: zeroBytes };
}

function writeMetadata(path, metadata) {
    try {
        const file = new File(path + '.json', 'wb');
        file.write(JSON.stringify(metadata, null, 2));
        file.flush();
        file.close();
    } catch (e) {
        warn('metadata write failed: ' + e);
    }
}

function dumpPrivateSoinfo(handle, reason) {
    if (dumped || dumping) return;
    dumping = true;

    try {
        const soinfo = getSoinfo(handle);
        log('candidate private soinfo=' + handle +
            ', name="' + soinfo.name + '"' +
            ', load_start=' + soinfo.loadStart +
            ', load_bias=' + soinfo.loadBias +
            ', load_size=0x' + soinfo.loadSize.toString(16) +
            ', phdr=' + soinfo.phdr +
            ', phnum=' + soinfo.phnum +
            ', dynamic=' + soinfo.dynamic);
        let elfBase = searchElfHeader(soinfo);
        let syntheticHeader = false;
        let elf = null;
        if (elfBase === null) {
            // This 360 variant keeps the original Elf64_Phdr array in its
            // private soinfo but deliberately omits the ELF header from the
            // in-place mapping. Rebuild it in the output buffer.
            syntheticHeader = true;
            elfBase = soinfo.loadStart;
            elf = parseProgramHeaders(soinfo.phdr, 56, soinfo.phnum);
            elf.phoff = 64;
            warn('ELF header is intentionally absent; rebuilding it from private soinfo phdr=' +
                soinfo.phdr + ', phnum=' + soinfo.phnum);
        } else {
            try {
                elf = parseElf64(elfBase);
            } catch (e) {
                // Some builds leave an ELF magic/header decoy in the mapping
                // while the authoritative program headers live only in the
                // private soinfo. Fail over to those headers, then synthesize
                // the output header exactly as for a headerless mapping.
                warn('mapped ELF program headers are invalid (' + e +
                    '); rebuilding from private soinfo phdr=' + soinfo.phdr);
                syntheticHeader = true;
                elfBase = soinfo.loadStart;
                elf = parseProgramHeaders(soinfo.phdr, 56, soinfo.phnum);
                elf.phoff = 64;
            }
        }

        const headerOffset = pointerDelta(elfBase, soinfo.loadStart);
        if (headerOffset < 0 || headerOffset >= soinfo.loadSize) {
            throw new Error('ELF header is outside the private load span');
        }

        let dumpSize = soinfo.loadSize - headerOffset;
        if (elf.imageSpan > dumpSize) {
            throw new Error(
                'PT_LOAD span 0x' + elf.imageSpan.toString(16) +
                ' exceeds soinfo span 0x' + dumpSize.toString(16)
            );
        }

        const dynamic = inspectDynamicTable(soinfo, elf);
        if (!dynamic.hasStrtab || !dynamic.hasSymtab || !dynamic.hasStrsz || !dynamic.hasSyment) {
            throw new Error('dynamic symbol metadata is incomplete at the selected dump point');
        }
        if (!dynamic.hasHash && !dynamic.hasGnuHash) {
            throw new Error('both DT_HASH and DT_GNU_HASH are missing');
        }
        const runtimePointers = inspectRequiredRuntimePointers(soinfo);
        const runtimePointerOwners = describeRuntimePointerOwners(runtimePointers);
        const dynamicOverlay = buildDynamicOverlay(soinfo, elf, dynamic);

        const targetName = sanitizeName(soinfo.name || 'linker.so');
        const baseText = elfBase.toString().replace('0x', '');
        const fileName = targetName + '_pid' + Process.id + '_0x' + baseText + '.so';
        const output = openOutputFile(fileName);

        log('exact dump point reached: ' + reason);
        log('private soinfo=' + handle +
            ', load_start=' + soinfo.loadStart +
            ', load_bias=' + soinfo.loadBias +
            ', size=0x' + soinfo.loadSize.toString(16));
        log('ELF=' + elfBase +
            ', synthetic_header=' + syntheticHeader +
            ', PT_LOAD=' + elf.loadCount +
            ', span=0x' + elf.imageSpan.toString(16) +
            ', phnum=' + elf.phnum);
        log('dynamic tables: SYMTAB=' + dynamic.hasSymtab +
            ', STRTAB=' + dynamic.hasStrtab +
            ', HASH=' + dynamic.hasHash +
            ', GNU_HASH=' + dynamic.hasGnuHash +
            ', entries=' + dynamic.entryCount +
            ', symbols=' + (dynamic.symbolCount === null ? 'unknown' : dynamic.symbolCount));

        const stats = writeZeroFilledMemory(
            elfBase,
            dumpSize,
            output.file,
            syntheticHeader ? { soinfo: soinfo, elf: elf } : null,
            [dynamicOverlay]
        );
        output.file.flush();
        output.file.close();

        const metadata = {
            reason: reason,
        jiaguTiming: reason,
            privateSoinfo: handle.toString(),
            targetName: soinfo.name,
            loadStart: soinfo.loadStart.toString(),
            loadBias: soinfo.loadBias.toString(),
            phdr: soinfo.phdr.toString(),
            phnum: soinfo.phnum,
            privateDynamic: soinfo.dynamic.toString(),
            elfBase: elfBase.toString(),
            syntheticHeader: syntheticHeader,
            dynamicOverlayOffset: dynamicOverlay.offset,
            dynamicOverlaySize: dynamicOverlay.bytes.length,
            dumpSize: dumpSize,
            readableBytes: stats.readableBytes,
            zeroFilledBytes: stats.zeroBytes,
            elf: elf,
            dynamic: dynamic,
            runtimePointers: runtimePointers,
            runtimePointerOwners: runtimePointerOwners
        };
        writeMetadata(output.path, metadata);

        dumped = true;
        log('dump complete: ' + output.path);
        log('host repair: SoFixer-Windows-64.exe -s <dump.so> -o <fixed.so>');
        send({ event: 'dumped', path: output.path, loadStart: soinfo.loadStart.toString(), name: soinfo.name, syntheticHeader: syntheticHeader, symbols: dynamic.symbolCount });
    } catch (e) {
        warn('dump failed: ' + e.stack);
        send({ event: 'dump-failed', reason: reason, error: e.stack || String(e) });
    } finally {
        dumping = false;
    }
}

function hookManualLoader(module) {
    if (!checkManualLoaderSignature(module)) {
        warn('manual-loader signature mismatch at +0x' +
            CONFIG.manualLoadFunctionOffset.toString(16) + '; handle capture disabled');
        return;
    }

    Interceptor.attach(module.base.add(CONFIG.manualLoadFunctionOffset), {
        onLeave: function (retval) {
            if (!retval.isNull()) {
                // retval is backed by the invocation context on Frida 16.
                // Clone its numeric value before this callback returns.
                lastManualHandle = ptr(retval.toString());
                log('private linker returned soinfo=' + lastManualHandle +
                    (CONFIG.dumpOnManualLoaderReturn ? ' (dumping at loader return)' :
                        ' (captured; waiting for exact dump point)'));
                if (CONFIG.dumpOnManualLoaderReturn) {
                    // The manual loader has completed and the caller has not yet
                    // begun target symbol lookup/JNI_OnLoad. All private metadata
                    // gates still run inside dumpPrivateSoinfo().
                    dumpPrivateSoinfo(lastManualHandle, 'manual-loader-return-before-target-symbol-lookup');
                } else if (CONFIG.dumpWhenRuntimePointersReady) {
                    waitForRequiredRuntimePointers(lastManualHandle);
                }
            }
        }
    });
}

function hookExactDumpPoint(module) {
    const hookAddress = locateExactDumpPoint(module);
    if (hookAddress === null) {
        throw new Error('cannot locate the pre-JNI_OnLoad dump point');
    }

    // Interceptor replaces/relocates the instruction at hookAddress. Decode
    // the original LDR X0,[X22,#imm] before installing the hook.
    const decodedHandleOffset = decodeHandleOffsetAtDumpPoint(hookAddress);
    const fixedHandleAddress = module.base.add(CONFIG.handleGlobalOffset);

    log('installing exact pre-JNI_OnLoad hook at ' + hookAddress +
        ' (libjiagu+' + hookAddress.sub(module.base) + ')');
    if (decodedHandleOffset !== null) {
        log('pre-decoded private handle operand: X22+0x' + decodedHandleOffset.toString(16));
    }

    Interceptor.attach(hookAddress, {
        onEnter: function () {
            if (dumped || dumping) return;

            let handle = null;
            if (decodedHandleOffset !== null) {
                try {
                    const handleAddress = this.context.x22.add(decodedHandleOffset);
                    handle = handleAddress.readPointer();
                    log('decoded private handle global ' + handleAddress + ' -> ' + handle);
                } catch (_) {
                    handle = null;
                }
            }

            // Exact-build fallback, independent of register decoding.
            if (handle === null || handle.isNull()) {
                try {
                    handle = fixedHandleAddress.readPointer();
                    log('fixed private handle global ' + fixedHandleAddress + ' -> ' + handle);
                } catch (_) {
                    handle = null;
                }
            }

            if ((handle === null || handle.isNull()) && lastManualHandle !== null) {
                handle = ptr(lastManualHandle.toString());
                log('using captured private soinfo -> ' + handle);
            }
            if (handle === null || handle.isNull()) {
                warn('exact point reached but the private soinfo handle is null');
                return;
            }

            // This callback blocks the application thread, so target JNI_OnLoad
            // cannot run until the complete image has been written.
            dumpPrivateSoinfo(handle, 'libjiagu pre-target-JNI_OnLoad');
        }
    });
}

function installForModule(module) {
    if (installed) return;
    installed = true;
    if (installTimer !== null) {
        clearInterval(installTimer);
        installTimer = null;
    }

    log('using ' + module.name + ' @ ' + module.base + ', size=0x' + module.size.toString(16));
    try {
        hookManualLoader(module);
        if (CONFIG.exactDumpOffset !== null && CONFIG.exactDumpOffset !== undefined) {
            hookExactDumpPoint(module);
        } else if (CONFIG.dumpOnManualLoaderReturn || CONFIG.dumpWhenRuntimePointersReady) {
            log('exact dump hook omitted; current-build evidence selected a spawn-gated manual-loader checkpoint');
        } else {
            throw new Error('no exact dump point and manual-loader-return dumping is disabled');
        }
    } catch (e) {
        installed = false;
        warn('hook installation failed: ' + e.stack);
    }
}

function tryInstall() {
    if (installed) return;
    const module = findJiaguModule();
    if (module !== null) installForModule(module);
}

function findGlobalExport(name) {
    try {
        if (typeof Module.findGlobalExportByName === 'function') {
            const p = Module.findGlobalExportByName(name);
            if (p !== null) return p;
        }
    } catch (_) {
    }

    // Frida 16 and older expose the static two-argument API.
    try {
        if (typeof Module.findExportByName === 'function') {
            const p = Module.findExportByName(null, name);
            if (p !== null) return p;
        }
    } catch (_) {
    }

    const modules = Process.enumerateModules();
    for (let i = 0; i < modules.length; i++) {
        try {
            const p = modules[i].findExportByName(name);
            if (p !== null) return p;
        } catch (_) {
        }
    }
    return null;
}

function hookSystemLoader() {
    const names = [
        'android_dlopen_ext',
        '__loader_android_dlopen_ext',
        'dlopen',
        '__loader_dlopen'
    ];
    const hooked = {};
    for (let i = 0; i < names.length; i++) {
        const address = findGlobalExport(names[i]);
        if (address === null || hooked[address.toString()]) continue;
        hooked[address.toString()] = true;
        Interceptor.attach(address, {
            onLeave: function () {
                tryInstall();
            }
        });
    }
}

function main() {
    if (Process.arch !== 'arm64') {
        warn('this script and recovered offsets are ARM64-only; current arch=' + Process.arch);
        return;
    }

    const required = [
        'manualLoadFunctionOffset', 'manualLoaderSignature',
        'soinfoLoadStartOffset', 'soinfoPhdrOffset', 'soinfoLoadSizeOffset',
        'soinfoPhnumOffset', 'soinfoDynamicOffset', 'soinfoLoadBiasOffset',
        'soinfoNameOffset'
    ];
    if (!CONFIG.dumpOnManualLoaderReturn && !CONFIG.dumpWhenRuntimePointersReady) {
        required.push('exactDumpOffset', 'handleGlobalOffset',
            'exactDumpInstructionMask', 'exactDumpInstructionValue');
    }
    const missing = required.filter(name => CONFIG[name] === null || CONFIG[name] === undefined);
    if (missing.length !== 0 || !Array.isArray(CONFIG.manualLoaderSignature) || CONFIG.manualLoaderSignature.length === 0) {
        warn('case-specific dump configuration is incomplete: ' + missing.join(', '));
        send({ event: 'config-error', missing: missing });
        return;
    }

    log('agent started in pid=' + Process.id + '; use -f/spawn mode for the exact timing');
    hookSystemLoader();
    tryInstall();
    if (!installed) installTimer = setInterval(tryInstall, 20);
}

setImmediate(main,3000);
