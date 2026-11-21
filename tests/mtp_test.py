#!/usr/bin/env python3
"""
Protocol tests for OunceMTP's responder, run on a PC against tests/build/host_mtp.

This is an independent MTP *initiator* written from the PTP/MTP specs. It talks
to the responder through an emulated USB bulk pipe (see host_transport.c) and
is strict about framing: device->host transfers end only at a short packet,
so a missing or extra zero-length packet shows up as a framing failure.

usage: mtp_test.py <host_mtp binary> [mps]
"""
import os, random, shutil, socket, struct, subprocess, sys, tempfile, time

BIN = sys.argv[1]
MPS = int(sys.argv[2]) if len(sys.argv) > 2 else 512

CMD, DATA, RESP = 1, 2, 3
OK = 0x2001
STORAGE = 0x00010001
FAILS = []
CHECKS = 0


def check(cond, msg):
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILS.append(msg)
        print("  FAIL:", msg)


# ---- MTP string / dataset helpers ------------------------------------------
def mtp_str(s):
    if not s:
        return b"\x00"
    u = s.encode("utf-16-le")
    n = len(u) // 2 + 1
    return bytes([n]) + u + b"\x00\x00"


class P:
    def __init__(self, b):
        self.b, self.o = b, 0

    def u8(self):  v = self.b[self.o]; self.o += 1; return v
    def u16(self): v, = struct.unpack_from("<H", self.b, self.o); self.o += 2; return v
    def u32(self): v, = struct.unpack_from("<I", self.b, self.o); self.o += 4; return v
    def u64(self): v, = struct.unpack_from("<Q", self.b, self.o); self.o += 8; return v
    def u128(self): lo = self.u64(); hi = self.u64(); return lo | hi << 64

    def str(self):
        n = self.u8()
        if n == 0:
            return ""
        raw = self.b[self.o:self.o + 2 * n]; self.o += 2 * n
        check(raw[-2:] == b"\x00\x00", "string not NUL terminated")
        return raw[:-2].decode("utf-16-le")

    def arr16(self): return [self.u16() for _ in range(self.u32())]
    def arr32(self): return [self.u32() for _ in range(self.u32())]


def object_info(name, size, fmt=0x3000, parent=0):
    b = struct.pack("<IHHIHIIIIIIIHII", STORAGE, fmt, 0, size if size < 0xFFFFFFFF else 0xFFFFFFFF,
                    0, 0, 0, 0, 0, 0, 0, parent, 1 if fmt == 0x3001 else 0, 0, 0)
    return b + mtp_str(name) + mtp_str("") + mtp_str("") + mtp_str("")


# ---- emulated USB host ------------------------------------------------------
class Host:
    def __init__(self, sock):
        self.s = sock
        self.tid = 0

    def _recvn(self, n):
        out = bytearray()
        while len(out) < n:
            c = self.s.recv(n - len(out))
            if not c:
                raise EOFError
            out += c
        return bytes(out)

    def out_transfer(self, data):           # host -> device, one USB transfer
        self.s.sendall(struct.pack("<I", len(data)) + data)

    def in_transfer(self):                  # device -> host, until short packet
        acc = bytearray()
        while True:
            n, = struct.unpack("<I", self._recvn(4))
            frame = self._recvn(n) if n else b""
            acc += frame
            if n == 0 or n % MPS != 0:
                return bytes(acc)

    def send_data(self, code, payload, mode, unknown_len=False, header_length=None):
        length = 0xFFFFFFFF if unknown_len else 12 + len(payload)
        if header_length is not None:
            length = header_length
        hdr = struct.pack("<IHHI", length, DATA, code, self.tid)
        total = 12 + len(payload)
        if mode == "split":                         # header as its own transfer
            self.out_transfer(hdr)
            self.out_transfer(payload)
            if len(payload) % MPS == 0 and len(payload):
                self.out_transfer(b"")
        else:
            self.out_transfer(hdr + payload)
            if total % MPS == 0 and mode != "nozlp":
                self.out_transfer(b"")              # spec-mandated ZLP

    def op(self, code, params=(), data_out=None, mode="glued", unknown_len=False, expect_data=None, header_length=None):
        self.tid += 1
        cmd = struct.pack("<IHHI", 12 + 4 * len(params), CMD, code, self.tid) + b"".join(struct.pack("<I", p) for p in params)
        self.out_transfer(cmd)
        if data_out is not None:
            self.send_data(code, data_out, mode, unknown_len, header_length)
        t = self.in_transfer()
        data = None
        ln, ty, cd, tid = struct.unpack_from("<IHHI", t)
        if ty == DATA:
            check(cd == code and tid == self.tid, f"data header mismatch op {code:#x}")
            if ln != 0xFFFFFFFF:
                check(ln == len(t), f"op {code:#x}: data container len {ln} but transfer was {len(t)} (ZLP bug?)")
            data = t[12:]
            t = self.in_transfer()
            ln, ty, cd, tid = struct.unpack_from("<IHHI", t)
        check(ty == RESP, f"op {code:#x}: expected response, got type {ty}")
        check(ln == len(t), f"op {code:#x}: response len {ln} vs transfer {len(t)}")
        check(tid == self.tid, f"op {code:#x}: response tid {tid} != {self.tid}")
        rparams = list(struct.unpack_from("<%dI" % ((ln - 12) // 4), t, 12))
        if expect_data is not None:
            check((data is not None) == expect_data, f"op {code:#x}: data phase presence")
        return cd, rparams, data


def run(root, mps_label):
    sockpath = tempfile.mktemp(prefix="mtp", suffix=".sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sockpath); srv.listen(1)
    env = dict(os.environ, MTP_MPS=str(MPS), ASAN_OPTIONS="detect_leaks=1")
    proc = subprocess.Popen([BIN, root, sockpath], env=env, stderr=subprocess.PIPE, text=True)
    srv.settimeout(10)
    try:
        conn, _ = srv.accept()
    except BaseException:
        proc.kill()
        _, err = proc.communicate()
        srv.close(); os.unlink(sockpath)
        print("Responder failed before connecting:\n" + err[-4000:])
        raise
    conn.settimeout(30)
    h = Host(conn)
    rnd = random.Random(1234)

    print(f"[{mps_label}] device info / session")
    rc, _, d = h.op(0x1001, expect_data=True)
    check(rc == OK, "GetDeviceInfo rc")
    p = P(d)
    check(p.u16() == 100, "std version"); p.u32(); p.u16()
    ext = p.str(); check("microsoft.com" in ext and "android.com" in ext, "vendor ext desc")
    p.u16(); ops = p.arr16(); p.arr16(); devprops = p.arr16(); p.arr16(); fmts = p.arr16()
    manu, model, ver, serial = p.str(), p.str(), p.str(), p.str()
    check(p.o == len(d), "DeviceInfo trailing bytes")
    for need in (0x1001, 0x1002, 0x1007, 0x1009, 0x100C, 0x100D, 0x9805, 0x95C1):
        check(need in ops, f"op {need:#x} advertised")
    check(0xD402 in devprops and fmts == [0x3000, 0x3001], "devprops/formats")
    check(manu == "Nintendo" and serial == "TEST0001", "strings")

    rc, _, _ = h.op(0x1004)
    check(rc == 0x2003, "SessionNotOpen before OpenSession")
    # data-out op before session must still have its data phase drained
    rc, _, _ = h.op(0x100C, (STORAGE, 0xFFFFFFFF), data_out=object_info("x", 1))
    check(rc == 0x2003, "SendObjectInfo w/o session -> SessionNotOpen")
    rc, _, _ = h.op(0x1002, (1,)); check(rc == OK, "OpenSession")
    rc, _, _ = h.op(0x1002, (1,)); check(rc == OK, "re-OpenSession tolerated")

    rc, _, d = h.op(0x1004); check(rc == OK and P(d).arr32() == [STORAGE], "GetStorageIDs")
    rc, _, d = h.op(0x1005, (STORAGE,)); p = P(d)
    st_type, fs_type, acc, cap, free = p.u16(), p.u16(), p.u16(), p.u64(), p.u64(); p.u32()
    desc = p.str(); p.str()
    check(rc == OK and cap > 0 and 0 < free <= cap and desc == "SD Card", f"GetStorageInfo cap={cap} free={free}")
    rc, _, _ = h.op(0x1005, (0x12345,)); check(rc == 0x2008, "bad storage id")

    rc, _, d = h.op(0x1014, (0xD402,)); p = P(d); p.u16(); p.u16(); p.u8(); p.str()
    check(rc == OK and p.str() == "Nintendo Switch 2", "friendly name desc")
    rc, _, d = h.op(0x1015, (0xD402,)); check(P(d).str() == "Nintendo Switch 2", "friendly name value")
    rc, _, _ = h.op(0x9999); check(rc == 0x2005, "unknown op -> OperationNotSupported")

    print(f"[{mps_label}] listing")
    rc, _, d = h.op(0x1007, (0xFFFFFFFF, 0, 0xFFFFFFFF)); check(rc == OK, "GetObjectHandles root")
    roots = P(d).arr32()
    names = {}
    for hd in roots:
        rc, _, d = h.op(0x1008, (hd,)); p = P(d)
        sid, fmt, _, csize = p.u32(), p.u16(), p.u16(), p.u32()
        p.u16(); [p.u32() for _ in range(6)]; parent = p.u32(); p.u16(); p.u32(); p.u32()
        nm = p.str(); cdate = p.str(); mdate = p.str(); p.str()
        check(p.o == len(d), "ObjectInfo trailing")
        check(parent == 0 and sid == STORAGE, f"root object parent/storage for {nm}")
        check(len(mdate) == 15 and mdate[8] == "T", f"date format {mdate!r}")
        names[nm] = (hd, fmt, csize)
    disk = sorted(os.listdir(root))
    check(sorted(names) == disk, f"root listing {sorted(names)} vs disk {disk}")
    check(names["games"][1] == 0x3001, "folder format")
    rc, _, d = h.op(0x1006, (STORAGE, 0, 0xFFFFFFFF)); check(d is None and h.op(0x1006, (STORAGE, 0, 0xFFFFFFFF))[1] == [len(disk)], "GetNumObjects")
    rc, _, d = h.op(0x1007, (STORAGE, 0x3001, 0xFFFFFFFF)); check(P(d).arr32() == [names["games"][0]], "format filter")

    # handles are stable across re-listing
    rc, _, d = h.op(0x1007, (0xFFFFFFFF, 0, 0xFFFFFFFF)); check(sorted(P(d).arr32()) == sorted(roots), "stable handles")

    # prop list depth 1 on root, all props
    rc, _, d = h.op(0x9805, (0, 0, 0xFFFFFFFF, 0, 1)); check(rc == OK, "GetObjectPropList root depth1")
    p = P(d); n = p.u32(); props = {}
    for _ in range(n):
        hd, code, dt = p.u32(), p.u16(), p.u16()
        v = {4: p.u16, 6: p.u32, 8: p.u64, 0xA: p.u128, 0xFFFF: p.str}[dt]()
        props.setdefault(hd, {})[code] = v
    check(p.o == len(d), "proplist trailing")
    for nm, (hd, fmt, csize) in names.items():
        check(props[hd][0xDC07] == nm, f"proplist name {nm}")
        if fmt == 0x3000:
            check(props[hd][0xDC04] == os.path.getsize(os.path.join(root, nm)), f"proplist size {nm}")
    rc, _, _ = h.op(0x9805, (0xFFFFFFFF, 0, 0xFFFFFFFF, 0, 0xFFFFFFFF)); check(rc == 0xA808, "depth=all refused")
    hd = names["big.bin"][0]
    rc, _, d = h.op(0x9805, (hd, 0, 0xDC04, 0, 0)); p = P(d)
    check(p.u32() == 1 and p.u32() == hd and p.u16() == 0xDC04 and p.u16() == 8 and p.u64() == os.path.getsize(os.path.join(root, "big.bin")), "proplist single prop")
    rc, _, d = h.op(0x9801, (0x3000,)); check(0xDC07 in P(d).arr16(), "props supported")
    rc, _, d = h.op(0x9802, (0xDC07, 0x3000)); p = P(d); check(p.u16() == 0xDC07 and p.u16() == 0xFFFF and p.u8() == 1, "prop desc filename settable")
    rc, _, d = h.op(0x9803, (hd, 0xDC0B)); check(P(d).u32() == 0, "parent prop of root object = 0")
    rc, _, d = h.op(0x9810, (hd,)); check(rc == OK and P(d).arr32() == [], "GetObjectReferences empty")

    print(f"[{mps_label}] downloads")
    for nm, (hd, fmt, _) in names.items():
        if fmt != 0x3000:
            continue
        want = open(os.path.join(root, nm), "rb").read()
        rc, _, d = h.op(0x1009, (hd,))
        check(rc == OK and d == want, f"GetObject {nm} ({len(want)} B) content")
    # The loop above reuses `hd`; re-fetch big.bin's handle (listing order
    # is filesystem-dependent: alphabetical on NTFS, hash order on ext4).
    hd = names["big.bin"][0]
    want = open(os.path.join(root, "big.bin"), "rb").read()
    rc, rp, d = h.op(0x101B, (hd, 1000, 70000)); check(rc == OK and rp == [70000] and d == want[1000:71000], "GetPartialObject")
    off = len(want) - 100
    rc, rp, d = h.op(0x95C1, (hd, off & 0xFFFFFFFF, off >> 32, 4096)); check(rc == OK and rp == [100] and d == want[off:], "GetPartialObject64 clamps at EOF")
    rc, _, _ = h.op(0x1009, (names["games"][0],)); check(rc == 0x2009, "GetObject on folder rejected")
    rc, _, _ = h.op(0x1009, (0xDEAD,)); check(rc == 0x2009, "GetObject bad handle")

    # nested folder
    gh = names["games"][0]
    rc, _, d = h.op(0x1007, (STORAGE, 0, gh)); sub = P(d).arr32()
    check(len(sub) == len(os.listdir(os.path.join(root, "games"))), "list subfolder")
    for s in sub:
        rc, _, d = h.op(0x9803, (s, 0xDC0B)); check(P(d).u32() == gh, "child parent prop")

    print(f"[{mps_label}] uploads")
    sizes = [0, 1, 500, MPS - 12, MPS, 2 * MPS - 12, (1 << 20) - 12, 1 << 20, (1 << 20) + 1,
             2 * (1 << 20) + MPS - 12, 3 * (1 << 20) + 77]
    modes = ["glued", "split", "nozlp"]
    i = 0
    for sz in sizes:
        for mode in modes:
            name = f"up_{sz}_{mode}.bin"
            payload = rnd.randbytes(sz)
            rc, rp, _ = h.op(0x100C, (STORAGE, 0xFFFFFFFF), data_out=object_info(name, sz))
            check(rc == OK and len(rp) == 3, f"SendObjectInfo {name}")
            rc, _, _ = h.op(0x100D, (), data_out=payload, mode=mode)
            check(rc == OK, f"SendObject {name} rc={rc:#x}")
            ondisk = open(os.path.join(root, name), "rb").read()
            check(ondisk == payload, f"upload content {name} ({len(ondisk)} vs {sz})")
            i += 1
            # the new handle must be immediately usable
            rc, _, d = h.op(0x1009, (rp[2],)); check(d == payload, f"read back {name}")

    # > 4 GiB style: unknown size announced, terminated by short packet
    payload = rnd.randbytes(2 * (1 << 20) + 333)
    rc, rp, _ = h.op(0x100C, (STORAGE, 0xFFFFFFFF), data_out=object_info("unknown_len.bin", 0xFFFFFFFF))
    rc, _, _ = h.op(0x100D, (), data_out=payload, unknown_len=True)
    check(rc == OK and open(os.path.join(root, "unknown_len.bin"), "rb").read() == payload, "unknown-length SendObject")

    # Actual Windows large-upload capture: unknown ObjectInfo size and a data
    # ContainerLength of 11, i.e. (0xFFFFFFFF + 12) modulo 2**32.
    # Small synthetic streams reproduce framing without allocating 25.6 GB.
    for mode, count in (("glued", 2 * (1 << 20) + 333),
                        ("split", 2 * (1 << 20) + 333),
                        ("glued", 2 * (1 << 20) - 12),
                        ("split", 2 * (1 << 20))):
        payload = rnd.randbytes(count)
        name = f"windows_unknown_{mode}_{count}.bin"
        rc, _, _ = h.op(0x100C, (STORAGE, 0xFFFFFFFF), data_out=object_info(name, 0xFFFFFFFF))
        check(rc == OK, "Windows wrapped-length object info")
        rc, _, _ = h.op(0x100D, data_out=payload, mode=mode, header_length=11)
        check(rc == OK and open(os.path.join(root, name), "rb").read() == payload,
              f"Windows wrapped-length {mode} payload={count}")
        rc, _, _ = h.op(0x1004)
        check(rc == OK, "pipe synchronized after Windows wrapped-length upload")

    # SendObjectInfo size disagrees with the data header: the header wins
    for announced, real in ((100, 5000), (3 * (1 << 20), 700), (10, 2 * (1 << 20) + MPS - 12)):
        payload = rnd.randbytes(real)
        nm = f"mismatch_{announced}_{real}.bin"
        h.op(0x100C, (STORAGE, 0xFFFFFFFF), data_out=object_info(nm, announced))
        rc, _, _ = h.op(0x100D, (), data_out=payload, mode="nozlp")
        check(rc == OK and open(os.path.join(root, nm), "rb").read() == payload, f"size mismatch {announced}->{real}")

    # SendObject without SendObjectInfo: rejected, but pipe must stay in sync
    rc, _, _ = h.op(0x100D, (), data_out=rnd.randbytes(5000))
    check(rc == 0x2015, "SendObject without info -> NoValidObjectInfo")
    rc, _, _ = h.op(0x1004); check(rc == OK, "pipe in sync after rejected SendObject")

    # invalid names
    rc, _, _ = h.op(0x100C, (STORAGE, 0xFFFFFFFF), data_out=object_info("..", 3)); check(rc == 0x201D, "'..' rejected")
    rc, rp, _ = h.op(0x100C, (STORAGE, 0xFFFFFFFF), data_out=object_info('bad:na*me?.txt', 3))
    check(rc == OK and os.path.exists(os.path.join(root, "bad_na_me_.txt")), "FAT-illegal chars sanitised")
    h.op(0x100D, (), data_out=b"abc")

    print(f"[{mps_label}] folders / move / rename / copy / delete")
    rc, rp, _ = h.op(0x100C, (STORAGE, 0), data_out=object_info("Nuova cartella 🎮", 0, fmt=0x3001))
    check(rc == OK and os.path.isdir(os.path.join(root, "Nuova cartella 🎮")), "mkdir unicode")
    fh = rp[2]
    rc, rp, _ = h.op(0x100C, (STORAGE, fh), data_out=object_info("inside.txt", 11))
    ih = rp[2]
    h.op(0x100D, (), data_out=b"hello world")
    check(open(os.path.join(root, "Nuova cartella 🎮", "inside.txt"), "rb").read() == b"hello world", "upload into folder")
    rc, _, d = h.op(0x9803, (ih, 0xDC0B)); check(P(d).u32() == fh, "parent of uploaded file")

    rc, _, _ = h.op(0x9804, (ih, 0xDC07), data_out=mtp_str("rinominato.txt"))
    check(rc == OK and os.path.exists(os.path.join(root, "Nuova cartella 🎮", "rinominato.txt")), "rename")
    rc, _, d = h.op(0x9803, (ih, 0xDC07)); check(P(d).str() == "rinominato.txt", "renamed handle keeps identity")
    rc, _, _ = h.op(0x9804, (ih, 0xDC04), data_out=struct.pack("<Q", 5)); check(rc == 0x200F, "size not settable")

    rc, _, _ = h.op(0x1019, (ih, STORAGE, 0xFFFFFFFF))
    check(rc == OK and os.path.exists(os.path.join(root, "rinominato.txt")), "move to root")
    rc, _, d = h.op(0x9803, (ih, 0xDC0B)); check(P(d).u32() == 0, "moved parent")
    rc, _, _ = h.op(0x1019, (fh, STORAGE, fh)); check(rc == 0x201A, "move into itself refused")

    rc, rp, _ = h.op(0x101A, (gh, STORAGE, fh))
    check(rc == OK and len(rp) == 1, "copy folder")
    src_files = sorted(os.listdir(os.path.join(root, "games")))
    check(sorted(os.listdir(os.path.join(root, "Nuova cartella 🎮", "games"))) == src_files, "copied tree")

    rc, _, _ = h.op(0x100B, (fh, 0)); check(rc == OK and not os.path.exists(os.path.join(root, "Nuova cartella 🎮")), "recursive delete")
    rc, _, _ = h.op(0x1008, (fh,)); check(rc == 0x2009, "deleted handle invalid")
    rc, _, _ = h.op(0x100B, (0xFFFFFFFF, 0)); check(rc == 0x200D, "delete-all refused")

    # change on disk behind MTP's back
    os.remove(os.path.join(root, "rinominato.txt"))
    h.op(0x1007, (STORAGE, 0, 0xFFFFFFFF))
    rc, _, _ = h.op(0x1008, (ih,)); check(rc == 0x2009, "vanished file drops its handle on re-list")

    print(f"[{mps_label}] android edit ops")
    hd = names["small.txt"][0]
    rc, _, _ = h.op(0x95C4, (hd,)); check(rc == OK, "BeginEdit")
    rc, rp, _ = h.op(0x95C2, (hd, 2, 0, 3), data_out=b"XYZ"); check(rc == OK and rp == [3], "SendPartialObject")
    rc, _, _ = h.op(0x95C3, (hd, 6, 0)); check(rc == OK, "TruncateObject")
    rc, _, _ = h.op(0x95C5, (hd,)); check(rc == OK, "EndEdit")
    check(open(os.path.join(root, "small.txt"), "rb").read() == b"heXYZ ", "edit result")

    rc, _, _ = h.op(0x1003); check(rc == OK, "CloseSession")
    rc, _, _ = h.op(0x1007, (STORAGE, 0, 0xFFFFFFFF)); check(rc == 0x2003, "closed session")

    conn.close()
    try:
        _, err = proc.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill(); _, err = proc.communicate()
        check(False, "responder did not exit on disconnect")
    srv.close(); os.unlink(sockpath)
    check(proc.returncode == 0, f"responder exit code {proc.returncode}")
    check("ERROR: AddressSanitizer" not in err and "runtime error" not in err, "sanitizers clean")
    check("PC disconnected" in err, "disconnect logged")
    if FAILS:
        print(err[-4000:])
    else:
        print("  responder log tail:\n    " + "\n    ".join(l for l in err.splitlines() if l.startswith(("LOG", "TOTALS")))[-1500:])


def make_fixture():
    root = tempfile.mkdtemp(prefix="sdmc")
    rnd = random.Random(42)
    open(os.path.join(root, "small.txt"), "wb").write(b"hello world")
    open(os.path.join(root, "empty.bin"), "wb").close()
    open(os.path.join(root, "exact_mps.bin"), "wb").write(rnd.randbytes(MPS - 12))   # total == MPS -> ZLP
    open(os.path.join(root, "exact_1m.bin"), "wb").write(rnd.randbytes((1 << 20) - 12))
    open(os.path.join(root, "big.bin"), "wb").write(rnd.randbytes(5 * (1 << 20) + 4321))
    open(os.path.join(root, "città 🎮.txt"), "wb").write("ciao".encode())
    os.mkdir(os.path.join(root, "games"))
    for i in range(30):
        open(os.path.join(root, "games", f"save{i:02}.dat"), "wb").write(rnd.randbytes(rnd.randint(0, 9000)))
    return root


if __name__ == "__main__":
    root = make_fixture()
    t = time.time()
    try:
        run(root, f"mps={MPS}")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print(f"\n{CHECKS - len(FAILS)}/{CHECKS} checks passed in {time.time() - t:.1f}s")
    sys.exit(1 if FAILS else 0)
