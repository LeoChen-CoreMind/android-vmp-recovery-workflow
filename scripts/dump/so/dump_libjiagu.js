// dump_libjiagu.js —— frida 17 兼容; libjiagu 一加载(dlopen onLeave)立即 dump
var TARGET = "libjiagu";
var done = false;

function gexp(name) { // 全局导出 (跨旧/新 frida)
    try { if (Module.findGlobalExportByName) return Module.findGlobalExportByName(name); } catch (e) {}
    try { if (Module.getGlobalExportByName) return Module.getGlobalExportByName(name); } catch (e) {}
    try { if (Module.findExportByName) return Module.findExportByName(null, name); } catch (e) {}
    return null;
}
function libc(name) {
    try { return Process.getModuleByName('libc.so').getExportByName(name); } catch (e) {}
    try { if (Module.getExportByName) return Module.getExportByName('libc.so', name); } catch (e) {}
    return null;
}

function self_name() {
    try {
        var open = new NativeFunction(libc('open'), 'int', ['pointer', 'int']);
        var read = new NativeFunction(libc('read'), 'int', ['int', 'pointer', 'int']);
        var close = new NativeFunction(libc('close'), 'int', ['int']);
        var path = Memory.allocUtf8String('/proc/self/cmdline');
        var fd = open(path, 0);
        if (fd != -1) { var b = Memory.alloc(0x1000); read(fd, b, 0x1000); close(fd); return b.readCString(); }
    } catch (e) {}
    return "";
}

function find_jiagu() {
    var r = null;
    Process.enumerateModules().forEach(function (m) {
        if (m.name.toLowerCase().indexOf("jiagu") >= 0) r = m;
    });
    return r;
}

function dump_it(tag) {
    if (done) return;
    var m = find_jiagu();
    if (!m) { console.log("[" + tag + "] jiagu not resolvable yet"); return; }
    done = true;
    console.log("[*] DUMP name=" + m.name + " base=" + m.base + " size=" + ptr(m.size) + " path=" + m.path);
    var out = "/data/data/" + self_name() + "/" + m.name + "_" + m.base + "_" + ptr(m.size) + ".dump.so";
    var f = new File(out, "wb");
    var PAGE = 0x1000, zero = new Uint8Array(PAGE), rd = 0, zf = 0;
    try { Memory.protect(m.base, m.size, 'rwx'); } catch (e) {}
    for (var off = 0; off < m.size; off += PAGE) {
        var n = Math.min(PAGE, m.size - off), chunk = null;
        try { chunk = m.base.add(off).readByteArray(n); } catch (e) { chunk = null; }
        if (chunk && chunk.byteLength === n) { f.write(chunk); rd += n; }
        else { f.write(zero.buffer.slice(0, n)); zf += n; }
    }
    f.flush(); f.close();
    console.log("[+] dumped -> " + out + "  readable=" + rd + " zero=" + zf);
    send({ event: "dumped", path: out, base: m.base.toString(), size: m.size, name: m.name });
}

function hook() {
    ["android_dlopen_ext", "dlopen"].forEach(function (fn) {
        var p = gexp(fn);
        if (!p) { console.log("[!] no export " + fn); return; }
        Interceptor.attach(p, {
            onEnter: function (a) { try { this.nm = a[0].readCString(); } catch (e) { this.nm = ""; } if (this.nm) console.log("[" + fn + "] " + this.nm); },
            onLeave: function (r) { if (!done && this.nm && this.nm.indexOf(TARGET) >= 0) dump_it(fn + "-onLeave"); }
        });
    });
    console.log("[*] hooks armed for '" + TARGET + "'");
    if (find_jiagu()) { console.log("[*] jiagu already loaded, dump now"); dump_it("already-loaded"); }
}
setImmediate(hook);
