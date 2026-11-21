/*
 * OunceMTP - MTP responder (portable C, no libnx dependency).
 * SPDX-License-Identifier: ISC
 *
 * Implements the device side of MTP 1.0 over the USB "Still Image" bulk-only
 * transport (PIMA 15740 + MTP 1.1 spec), plus the Android edit extensions
 * that libmtp/gvfs use for random-access writes. One storage is exposed:
 * the SD card root.
 *
 * Transaction shape (all little-endian):
 *   host -> dev   Command container   [len u32][type=1 u16][code u16][tid u32][params u32 x0..5]
 *   either way    optional Data phase [len u32][type=2 u16][code u16][tid u32][payload ...]
 *   dev  -> host  Response container  [len u32][type=3 u16][code u16][tid u32][params u32 x0..5]
 *
 * Throughput design:
 *   - Two 1 MiB page-aligned buffers are ping-ponged: while USB moves one,
 *     the SD card fills / drains the other (GetObject / SendObject).
 *   - File data is read()/written directly into the USB buffers: zero copy.
 *   - OUT reads are always posted in multiples of wMaxPacketSize, sized to
 *     exactly what the data phase still owes, so we never depend on the host
 *     sending a zero-length packet and never over-read into the next command.
 */
#include "mtp.h"
#include "transport.h"
#include "objdb.h"
#include "dataset.h"
#include "status.h"

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

/* ---- protocol constants ------------------------------------------------- */

enum {
    CT_COMMAND = 1, CT_DATA = 2, CT_RESPONSE = 3, CT_EVENT = 4,
};

enum {
    OP_GetDeviceInfo            = 0x1001,
    OP_OpenSession              = 0x1002,
    OP_CloseSession             = 0x1003,
    OP_GetStorageIDs            = 0x1004,
    OP_GetStorageInfo           = 0x1005,
    OP_GetNumObjects            = 0x1006,
    OP_GetObjectHandles         = 0x1007,
    OP_GetObjectInfo            = 0x1008,
    OP_GetObject                = 0x1009,
    OP_DeleteObject             = 0x100B,
    OP_SendObjectInfo           = 0x100C,
    OP_SendObject               = 0x100D,
    OP_GetDevicePropDesc        = 0x1014,
    OP_GetDevicePropValue       = 0x1015,
    OP_SetDevicePropValue       = 0x1016,
    OP_MoveObject               = 0x1019,
    OP_CopyObject               = 0x101A,
    OP_GetPartialObject         = 0x101B,
    OP_GetObjectPropsSupported  = 0x9801,
    OP_GetObjectPropDesc        = 0x9802,
    OP_GetObjectPropValue       = 0x9803,
    OP_SetObjectPropValue       = 0x9804,
    OP_GetObjectPropList        = 0x9805,
    OP_GetObjectReferences      = 0x9810,
    OP_SetObjectReferences      = 0x9811,
    OP_AndroidGetPartialObject64 = 0x95C1,
    OP_AndroidSendPartialObject  = 0x95C2,
    OP_AndroidTruncateObject     = 0x95C3,
    OP_AndroidBeginEditObject    = 0x95C4,
    OP_AndroidEndEditObject      = 0x95C5,
};

enum {
    RC_OK                       = 0x2001,
    RC_GeneralError             = 0x2002,
    RC_SessionNotOpen           = 0x2003,
    RC_OperationNotSupported    = 0x2005,
    RC_IncompleteTransfer       = 0x2007,
    RC_InvalidStorageID         = 0x2008,
    RC_InvalidObjectHandle      = 0x2009,
    RC_DevicePropNotSupported   = 0x200A,
    RC_InvalidObjectFormatCode  = 0x200B,
    RC_StoreFull                = 0x200C,
    RC_ObjectWriteProtected     = 0x200D,
    RC_AccessDenied             = 0x200F,
    RC_PartialDeletion          = 0x2012,
    RC_NoValidObjectInfo        = 0x2015,
    RC_InvalidParentObject      = 0x201A,
    RC_InvalidParameter         = 0x201D,
    RC_InvalidObjectPropCode    = 0xA801,
    RC_InvalidObjectPropValue   = 0xA803,
    RC_SpecByGroupUnsupported   = 0xA807,
    RC_SpecByDepthUnsupported   = 0xA808,
    RC_ObjectTooLarge           = 0xA809,
    RC_ObjectPropNotSupported   = 0xA80A,
};

enum {
    FMT_Undefined   = 0x3000,
    FMT_Association = 0x3001,   /* folder */
};

enum {
    PROP_StorageID        = 0xDC01,
    PROP_ObjectFormat     = 0xDC02,
    PROP_ProtectionStatus = 0xDC03,
    PROP_ObjectSize       = 0xDC04,
    PROP_ObjectFileName   = 0xDC07,
    PROP_DateCreated      = 0xDC08,
    PROP_DateModified     = 0xDC09,
    PROP_ParentObject     = 0xDC0B,
    PROP_PersistentUID    = 0xDC41,
    PROP_Name             = 0xDC44,
};

enum {
    DT_UINT16 = 0x0004, DT_UINT32 = 0x0006, DT_UINT64 = 0x0008,
    DT_UINT128 = 0x000A, DT_STR = 0xFFFF,
};

#define DEVPROP_FriendlyName 0xD402

#define STORAGE_ID      0x00010001u
#define ALL_HANDLES     0xFFFFFFFFu
#define LEN_UNKNOWN     UINT64_MAX
#define BUF_SZ          (1u << 20)
#define CMD_BUF_SZ      0x1000u
#define XFER_TIMEOUT_MS 20000u
#define DATASET_CAP     (16u << 20)

static const uint16_t k_ops[] = {
    OP_GetDeviceInfo, OP_OpenSession, OP_CloseSession, OP_GetStorageIDs,
    OP_GetStorageInfo, OP_GetNumObjects, OP_GetObjectHandles, OP_GetObjectInfo,
    OP_GetObject, OP_DeleteObject, OP_SendObjectInfo, OP_SendObject,
    OP_GetDevicePropDesc, OP_GetDevicePropValue, OP_SetDevicePropValue,
    OP_MoveObject, OP_CopyObject, OP_GetPartialObject,
    OP_GetObjectPropsSupported, OP_GetObjectPropDesc, OP_GetObjectPropValue,
    OP_SetObjectPropValue, OP_GetObjectPropList, OP_GetObjectReferences,
    OP_SetObjectReferences,
    OP_AndroidGetPartialObject64, OP_AndroidSendPartialObject,
    OP_AndroidTruncateObject, OP_AndroidBeginEditObject, OP_AndroidEndEditObject,
};

static const uint16_t k_props[] = {
    PROP_StorageID, PROP_ObjectFormat, PROP_ProtectionStatus, PROP_ObjectSize,
    PROP_ObjectFileName, PROP_DateCreated, PROP_DateModified, PROP_ParentObject,
    PROP_PersistentUID, PROP_Name,
};

static const uint16_t k_formats[]   = { FMT_Undefined, FMT_Association };
static const uint16_t k_devprops[]  = { DEVPROP_FriendlyName };

#define COUNT(a) ((uint32_t)(sizeof(a) / sizeof((a)[0])))

/* ---- state -------------------------------------------------------------- */

typedef struct {
    uint16_t code;
    uint32_t tid;
    uint32_t p[5];
    int      np;
} req_t;

typedef struct {
    uint16_t code;
    uint32_t p[5];
    int      np;
} resp_t;

static mtp_config_t g_cfg;
static uint8_t     *g_buf[2];
static uint8_t     *g_cmd;
static uint8_t     *g_resp;
static dbuf_t       g_db;

static bool     g_session_open;
static uint32_t g_session_id;

/* SendObjectInfo -> SendObject handoff */
static bool     g_pend_valid;
static uint32_t g_pend_handle;
static uint64_t g_pend_size;

static bool stop_requested(void) { return g_cfg.stop && *g_cfg.stop; }

/* ---- small utils -------------------------------------------------------- */

static void fmt_size(uint64_t n, char *out, size_t sz)
{
    if (n >= (1ull << 30))      snprintf(out, sz, "%.2f GiB", (double)n / (1ull << 30));
    else if (n >= (1ull << 20)) snprintf(out, sz, "%.1f MiB", (double)n / (1ull << 20));
    else if (n >= 1024)         snprintf(out, sz, "%.1f KiB", (double)n / 1024);
    else                        snprintf(out, sz, "%llu B", (unsigned long long)n);
}

static void fmt_date(time_t t, char *out, size_t sz)
{
    struct tm tm;
    if (t <= 0 || !localtime_r(&t, &tm)) { out[0] = 0; return; }
    strftime(out, sz, "%Y%m%dT%H%M%S", &tm);
}

static uint32_t round_up(uint32_t v, uint32_t a) { return (v + a - 1) / a * a; }

/* A host-supplied name becomes a single path component that FAT/exFAT will
 * accept. Returns false for names that can't be made safe. */
static bool sanitize_name(char *name)
{
    if (!name[0] || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return false;
    for (unsigned char *s = (unsigned char *)name; *s; s++) {
        if (*s == '/' || *s == '\\' || *s == ':' || *s == '*' || *s == '?' ||
            *s == '"' || *s == '<' || *s == '>' || *s == '|' || *s < 0x20)
            *s = '_';
    }
    /* FAT silently drops trailing dots/spaces, which would desync names. */
    size_t n = strlen(name);
    while (n > 0 && (name[n - 1] == '.' || name[n - 1] == ' ')) name[--n] = 0;
    return n > 0;
}

/* MTP parent handle -> internal handle. 0 and 0xFFFFFFFF both mean root. */
static uint32_t parent_from_mtp(uint32_t p)
{
    return (p == 0 || p == ALL_HANDLES) ? OBJ_ROOT : p;
}

static uint32_t parent_to_mtp(uint32_t internal)
{
    return internal == OBJ_ROOT ? 0 : internal;
}

/* Recursive delete. Returns 0 on full success. */
static int rm_rf(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    if (!S_ISDIR(st.st_mode)) return unlink(path);

    DIR *d = opendir(path);
    if (!d) return -1;
    int rc = 0;
    struct dirent *e;
    char *child = malloc(OBJ_PATH_MAX);
    if (!child) { closedir(d); return -1; }
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        snprintf(child, OBJ_PATH_MAX, "%s/%s", path, e->d_name);
        if (rm_rf(child) != 0) rc = -1;
    }
    closedir(d);
    free(child);
    if (rmdir(path) != 0) rc = -1;
    return rc;
}

static uint64_t g_copy_done;

static int copy_file(const char *src, const char *dst)
{
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (out < 0) { close(in); return -1; }
    int rc = 0;
    for (;;) {
        ssize_t n = read(in, g_buf[0], BUF_SZ);
        if (n < 0) { rc = -1; break; }
        if (n == 0) break;
        if (write(out, g_buf[0], (size_t)n) != n) { rc = -1; break; }
        g_copy_done += (uint64_t)n;
        status_xfer_progress(g_copy_done);
        if (stop_requested()) { rc = -1; break; }
    }
    close(in);
    if (close(out) != 0) rc = -1;
    if (rc) unlink(dst);
    return rc;
}

static int copy_tree(const char *src, const char *dst)
{
    struct stat st;
    if (stat(src, &st) != 0) return -1;
    if (!S_ISDIR(st.st_mode)) return copy_file(src, dst);
    if (mkdir(dst, 0777) != 0 && errno != EEXIST) return -1;
    DIR *d = opendir(src);
    if (!d) return -1;
    int rc = 0;
    char *a = malloc(OBJ_PATH_MAX), *b = malloc(OBJ_PATH_MAX);
    struct dirent *e;
    while (a && b && (e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        snprintf(a, OBJ_PATH_MAX, "%s/%s", src, e->d_name);
        snprintf(b, OBJ_PATH_MAX, "%s/%s", dst, e->d_name);
        if (copy_tree(a, b) != 0) { rc = -1; break; }
    }
    if (!a || !b) rc = -1;
    free(a); free(b);
    closedir(d);
    return rc;
}

/* ---- data phase: device -> host ---------------------------------------- */

/* Produces exactly `want` bytes into dst; returns <0 on failure. */
typedef int (*src_fn)(void *ctx, uint8_t *dst, uint32_t want);

/*
 * Streams a data container of `payload` bytes. The 12-byte header shares the
 * first buffer with the start of the payload, then every buffer except the
 * last is a full 1 MiB, i.e. a multiple of wMaxPacketSize, so the host sees
 * one continuous transfer. If a source read fails midway the promised length
 * is still honoured (zero padded) to keep the pipe in sync; *src_failed tells
 * the caller to report an error in the response instead.
 */
static int tx_stream(const req_t *rq, uint64_t payload, src_fn src, void *ctx,
                     bool *src_failed, bool track)
{
    const uint64_t total = 12 + payload;
    uint64_t remaining = payload, sent = 0;
    bool first = true, inflight = false;
    int cur = 0, r;
    uint32_t n;

    *src_failed = false;
    while (first || remaining > 0) {
        uint8_t *b = g_buf[cur];
        uint32_t off = 0;
        if (first) {
            /* 0xFFFFFFFF = "length unknown, read to short packet" (> 4 GiB) */
            wr32(b, total >= 0xFFFFFFFFull ? 0xFFFFFFFFu : (uint32_t)total);
            wr16(b + 4, CT_DATA);
            wr16(b + 6, rq->code);
            wr32(b + 8, rq->tid);
            off = 12;
            first = false;
        }
        uint32_t want = (uint32_t)((remaining < BUF_SZ - off) ? remaining : BUF_SZ - off);
        if (want) {
            if (*src_failed || src(ctx, b + off, want) < 0) {
                *src_failed = true;
                memset(b + off, 0, want);
            }
        }
        remaining -= want;
        off += want;

        /* The previous buffer has been on the wire while we filled this one. */
        if (inflight) {
            if ((r = tp_write_end(&n, XFER_TIMEOUT_MS))) return r;
            inflight = false;
        }
        if ((r = tp_write_begin(b, off))) return r;
        inflight = true;
        sent += want;
        if (track) status_xfer_progress(sent);
        cur ^= 1;
        if (stop_requested() && remaining) { tp_abort(); return TP_STOPPED; }
    }
    if (inflight && (r = tp_write_end(&n, XFER_TIMEOUT_MS))) return r;

    /* A transfer that is an exact multiple of the packet size has no short
     * packet to end it; the host would block waiting for more. */
    if (total % tp_max_packet() == 0) {
        if ((r = tp_write(g_buf[0], 0, XFER_TIMEOUT_MS))) return r;
    }
    return TP_OK;
}

typedef struct { const uint8_t *p; } memsrc_t;
static int mem_src(void *ctx, uint8_t *dst, uint32_t want)
{
    memsrc_t *m = ctx;
    memcpy(dst, m->p, want);
    m->p += want;
    return 0;
}

static int send_dataset(const req_t *rq, const dbuf_t *db)
{
    memsrc_t m = { db->data };
    bool failed;
    return tx_stream(rq, db->len, mem_src, &m, &failed, false);
}

typedef struct { int fd; } filesrc_t;
static int file_src(void *ctx, uint8_t *dst, uint32_t want)
{
    filesrc_t *f = ctx;
    while (want) {
        ssize_t n = read(f->fd, dst, want);
        if (n <= 0) return -1;      /* file shrank under us or I/O error */
        dst += n;
        want -= (uint32_t)n;
    }
    return 0;
}

/* ---- data phase: host -> device ---------------------------------------- */

typedef int (*sink_fn)(void *ctx, const uint8_t *data, uint32_t n);

typedef struct {
    uint64_t got;        /* payload bytes received             */
    bool     complete;   /* got == length announced by header   */
    bool     sink_failed;
} rx_result_t;

/*
 * Receives one data container. `hint` is the payload size we expect (from
 * SendObjectInfo) or LEN_UNKNOWN. The container header is authoritative once
 * it arrives. Handles: header in its own transfer or glued to the payload,
 * stray zero-length packets left over from a previous phase, and >4 GiB
 * phases whose header says 0xFFFFFFFF (ended by a short packet).
 *
 * Even when the sink fails (disk full) the whole phase is drained, because
 * the host will not listen for our response until it has sent everything.
 */
static int rx_stream(uint64_t hint, sink_fn sink, void *ctx, rx_result_t *res, bool track, const req_t *request)
{
    const uint32_t mps = tp_max_packet();
    uint8_t  hdr[12];
    uint32_t hdr_have = 0;
    uint64_t expected = LEN_UNKNOWN;
    int cur = 0, r;

    memset(res, 0, sizeof(*res));

    /* First read: exact size if we know it; otherwise one packet, which is
     * enough to learn the length without risking an over-read. */
    uint32_t post = (hint != LEN_UNKNOWN && hint + 12 < BUF_SZ) ? round_up((uint32_t)hint + 12, mps)
                  : (hint != LEN_UNKNOWN ? BUF_SZ : mps);
    if ((r = tp_read_begin(g_buf[cur], post))) return r;

    for (;;) {
        uint32_t n;
        if ((r = tp_read_end(&n, XFER_TIMEOUT_MS))) return r;
        const bool short_pkt = n < post;
        uint8_t *b = g_buf[cur];
        uint32_t pos = 0;
        bool header_only = false;

        if (hdr_have < 12) {
            if (n == 0 && hdr_have == 0) {           /* stray ZLP: ignore */
                if ((r = tp_read_begin(b, post))) return r;
                continue;
            }
            uint32_t take = 12 - hdr_have < n ? 12 - hdr_have : n;
            memcpy(hdr + hdr_have, b, take);
            hdr_have += take;
            pos = take;
            if (hdr_have == 12) {
                uint32_t len = rd32(hdr);
                if (rd16(hdr + 4) != CT_DATA) return TP_ERROR;   /* host skipped the data phase */
                if (request && (rd16(hdr + 6) != request->code || rd32(hdr + 8) != request->tid))
                    return TP_ERROR;
                /* Windows has been observed sending 11 for an unknown-size
                 * upload, consistent with (0xFFFFFFFF + 12) wrapping to u32.
                 * Treat this exact value as unknown only for the matching
                 * pending SendObject, not for datasets or known-size files. */
                if (len == 11 && hint == LEN_UNKNOWN && request && request->code == OP_SendObject)
                    len = 0xFFFFFFFFu;
                if (len != 0xFFFFFFFFu) {
                    if (len < 12) return TP_ERROR;
                    expected = len - 12;
                }
                header_only = (pos == n);
            }
        }

        uint32_t pay = n - pos;
        if (expected != LEN_UNKNOWN && res->got + pay > expected)
            pay = (uint32_t)(expected - res->got);           /* misbehaving host: drop excess */

        bool done;
        if (hdr_have < 12)                                       done = short_pkt;
        else if (expected != LEN_UNKNOWN && res->got + pay >= expected) done = true;
        else if (short_pkt && !header_only)                      done = true;
        else                                                     done = false;

        if (!done) {
            /* Post the next read before touching the disk so USB keeps going. */
            uint32_t next = BUF_SZ;
            if (expected != LEN_UNKNOWN) {
                uint64_t rem = expected - (res->got + pay);
                if (rem < next) next = round_up((uint32_t)rem, mps);
            }
            if ((r = tp_read_begin(g_buf[cur ^ 1], next))) return r;
            post = next;
        }

        if (pay && sink && !res->sink_failed && sink(ctx, b + pos, pay) < 0)
            res->sink_failed = true;
        res->got += pay;
        if (track) status_xfer_progress(res->got);

        if (done) {
            res->complete = (hdr_have == 12) && (expected == LEN_UNKNOWN || res->got == expected);
            return TP_OK;
        }
        cur ^= 1;
        if (stop_requested()) { tp_abort(); return TP_STOPPED; }
    }
}

static int drain_data(void)
{
    rx_result_t res;
    return rx_stream(LEN_UNKNOWN, NULL, NULL, &res, false, NULL);
}

static int dbuf_sink(void *ctx, const uint8_t *data, uint32_t n)
{
    dbuf_t *b = ctx;
    if (b->len + n > DATASET_CAP) return -1;
    dbuf_put(b, data, n);
    return b->oom ? -1 : 0;
}

/* Receives a small dataset into g_db. *ok is false if it was oversize. */
static int recv_dataset(bool *ok)
{
    rx_result_t res;
    dbuf_reset(&g_db);
    int r = rx_stream(LEN_UNKNOWN, dbuf_sink, &g_db, &res, false, NULL);
    *ok = (r == TP_OK) && res.complete && !res.sink_failed;
    return r;
}

typedef struct { int fd; int err; } filesink_t;
static int file_sink(void *ctx, const uint8_t *data, uint32_t n)
{
    filesink_t *f = ctx;
    while (n) {
        ssize_t w = write(f->fd, data, n);
        if (w <= 0) { f->err = w < 0 ? errno : ENOSPC; return -1; }
        data += w;
        n -= (uint32_t)w;
    }
    return 0;
}

/* ---- object properties ---------------------------------------------------- */

typedef struct {
    uint32_t    h;
    const char *name;
    uint32_t    parent;
    bool        is_dir;
    bool        st_ok;
    struct stat st;
} objview_t;

/* Gathers what the property/info encoders need. stat() only once. */
static bool view_object(uint32_t h, objview_t *v)
{
    char path[OBJ_PATH_MAX];
    obj_t *o = objdb_get(h);
    if (!o || h == OBJ_ROOT) return false;
    v->h = h;
    v->name = o->name;
    v->parent = o->parent;
    v->is_dir = o->is_dir;
    v->st_ok = objdb_path(h, path, sizeof(path)) && stat(path, &v->st) == 0;
    if (!v->st_ok) memset(&v->st, 0, sizeof(v->st));
    return true;
}

static uint64_t view_size(const objview_t *v) { return (v->is_dir || !v->st_ok) ? 0 : (uint64_t)v->st.st_size; }

static uint16_t prop_type(uint16_t prop)
{
    switch (prop) {
        case PROP_StorageID:        return DT_UINT32;
        case PROP_ObjectFormat:     return DT_UINT16;
        case PROP_ProtectionStatus: return DT_UINT16;
        case PROP_ObjectSize:       return DT_UINT64;
        case PROP_ObjectFileName:   return DT_STR;
        case PROP_DateCreated:      return DT_STR;
        case PROP_DateModified:     return DT_STR;
        case PROP_ParentObject:     return DT_UINT32;
        case PROP_PersistentUID:    return DT_UINT128;
        case PROP_Name:             return DT_STR;
        default:                    return 0;
    }
}

static void put_prop_value(dbuf_t *b, const objview_t *v, uint16_t prop)
{
    char date[32];
    switch (prop) {
        case PROP_StorageID:        dbuf_u32(b, STORAGE_ID); break;
        case PROP_ObjectFormat:     dbuf_u16(b, v->is_dir ? FMT_Association : FMT_Undefined); break;
        case PROP_ProtectionStatus: dbuf_u16(b, 0); break;
        case PROP_ObjectSize:       dbuf_u64(b, view_size(v)); break;
        case PROP_ObjectFileName:
        case PROP_Name:             dbuf_str(b, v->name); break;
        /* FAT has no reliable creation time through this API; use mtime. */
        case PROP_DateCreated:
        case PROP_DateModified:     fmt_date(v->st_ok ? v->st.st_mtime : 0, date, sizeof(date)); dbuf_str(b, date); break;
        case PROP_ParentObject:     dbuf_u32(b, parent_to_mtp(v->parent)); break;
        case PROP_PersistentUID:    dbuf_u128(b, v->h, 0x4F554E43454D5450ull /* "OUNCEMTP" */); break;
    }
}

static void put_object_info(dbuf_t *b, const objview_t *v)
{
    char date[32];
    uint64_t sz = view_size(v);
    fmt_date(v->st_ok ? v->st.st_mtime : 0, date, sizeof(date));

    dbuf_u32(b, STORAGE_ID);
    dbuf_u16(b, v->is_dir ? FMT_Association : FMT_Undefined);
    dbuf_u16(b, 0);                                   /* protection      */
    dbuf_u32(b, sz >= 0xFFFFFFFFull ? 0xFFFFFFFFu : (uint32_t)sz);
    dbuf_u16(b, 0);                                   /* thumb format    */
    dbuf_u32(b, 0); dbuf_u32(b, 0); dbuf_u32(b, 0);   /* thumb size/w/h  */
    dbuf_u32(b, 0); dbuf_u32(b, 0); dbuf_u32(b, 0);   /* image w/h/depth */
    dbuf_u32(b, parent_to_mtp(v->parent));
    dbuf_u16(b, v->is_dir ? 0x0001 : 0x0000);         /* GenericFolder   */
    dbuf_u32(b, 0);                                   /* assoc desc      */
    dbuf_u32(b, 0);                                   /* sequence        */
    dbuf_str(b, v->name);
    dbuf_str(b, date);                                /* capture date    */
    dbuf_str(b, date);                                /* modified date   */
    dbuf_str(b, NULL);                                /* keywords        */
}

/* ---- operations ----------------------------------------------------------- */

static int op_get_device_info(const req_t *rq, resp_t *rs)
{
    dbuf_reset(&g_db);
    dbuf_u16(&g_db, 100);                          /* standard version 1.00 */
    dbuf_u32(&g_db, 6);                            /* MTP vendor extension  */
    dbuf_u16(&g_db, 100);
    dbuf_str(&g_db, "microsoft.com: 1.0; android.com: 1.0;");
    dbuf_u16(&g_db, 0);                            /* functional mode       */
    dbuf_arr16(&g_db, k_ops, COUNT(k_ops));
    dbuf_arr16(&g_db, NULL, 0);                    /* events                */
    dbuf_arr16(&g_db, k_devprops, COUNT(k_devprops));
    dbuf_arr16(&g_db, NULL, 0);                    /* capture formats       */
    dbuf_arr16(&g_db, k_formats, COUNT(k_formats));
    dbuf_str(&g_db, g_cfg.manufacturer);
    dbuf_str(&g_db, g_cfg.model);
    dbuf_str(&g_db, g_cfg.version);
    dbuf_str(&g_db, g_cfg.serial);
    rs->code = RC_OK;
    return send_dataset(rq, &g_db);
}

static void close_session(void)
{
    g_session_open = false;
    g_pend_valid = false;
    objdb_reset();
}

static int op_open_session(const req_t *rq, resp_t *rs)
{
    if (rq->np < 1 || rq->p[0] == 0) { rs->code = RC_InvalidParameter; return TP_OK; }
    /* Re-opening resets state instead of failing: Windows does this after
     * it lost track of us (sleep, driver restart). */
    close_session();
    g_session_open = true;
    g_session_id = rq->p[0];
    status_set_state(ST_SESSION);
    status_log("Session opened by PC");
    rs->code = RC_OK;
    return TP_OK;
}

static int op_close_session(const req_t *rq, resp_t *rs)
{
    (void)rq;
    close_session();
    status_set_state(ST_CONNECTED);
    status_log("Session closed");
    rs->code = RC_OK;
    return TP_OK;
}

static int op_get_storage_ids(const req_t *rq, resp_t *rs)
{
    const uint32_t ids[] = { STORAGE_ID };
    dbuf_reset(&g_db);
    dbuf_arr32(&g_db, ids, 1);
    rs->code = RC_OK;
    return send_dataset(rq, &g_db);
}

static int op_get_storage_info(const req_t *rq, resp_t *rs)
{
    if (rq->p[0] != STORAGE_ID) { rs->code = RC_InvalidStorageID; return TP_OK; }
    struct statvfs vfs;
    uint64_t total = 0, avail = 0;
    char root[OBJ_PATH_MAX];
    objdb_path(OBJ_ROOT, root, sizeof(root));
    if (statvfs(root, &vfs) == 0) {
        total = (uint64_t)vfs.f_blocks * vfs.f_frsize;
        avail = (uint64_t)vfs.f_bavail * vfs.f_frsize;
    }
    dbuf_reset(&g_db);
    dbuf_u16(&g_db, 0x0004);                 /* RemovableRAM          */
    dbuf_u16(&g_db, 0x0002);                 /* GenericHierarchical   */
    dbuf_u16(&g_db, 0x0000);                 /* read-write            */
    dbuf_u64(&g_db, total);
    dbuf_u64(&g_db, avail);
    dbuf_u32(&g_db, 0xFFFFFFFFu);            /* free objects: n/a     */
    dbuf_str(&g_db, g_cfg.storage_desc);
    dbuf_str(&g_db, NULL);                   /* volume id             */
    rs->code = RC_OK;
    return send_dataset(rq, &g_db);
}

/* Lists the children of an MTP parent handle, filtered by format. */
static int list_children(uint32_t storage, uint32_t format, uint32_t mtp_parent,
                         uint32_t **out, uint16_t *err)
{
    *out = NULL;
    if (storage != STORAGE_ID && storage != ALL_HANDLES) { *err = RC_InvalidStorageID; return -1; }
    uint32_t parent = parent_from_mtp(mtp_parent);
    obj_t *p = objdb_get(parent);
    if (!p || !p->is_dir) { *err = RC_InvalidParentObject; return -1; }
    int n = objdb_list(parent, out);
    if (n < 0) { *err = RC_GeneralError; return -1; }
    if (format != 0 && format != ALL_HANDLES) {
        int k = 0;
        for (int i = 0; i < n; i++) {
            obj_t *o = objdb_get((*out)[i]);
            uint16_t f = o->is_dir ? FMT_Association : FMT_Undefined;
            if (f == format) (*out)[k++] = (*out)[i];
        }
        n = k;
    }
    return n;
}

static int op_get_object_handles(const req_t *rq, resp_t *rs)
{
    uint32_t *hs;
    uint16_t err;
    int n = list_children(rq->p[0], rq->p[1], rq->np >= 3 ? rq->p[2] : 0, &hs, &err);
    if (n < 0) { rs->code = err; return TP_OK; }
    dbuf_reset(&g_db);
    dbuf_arr32(&g_db, hs, (uint32_t)n);
    free(hs);
    rs->code = RC_OK;
    return send_dataset(rq, &g_db);
}

static int op_get_num_objects(const req_t *rq, resp_t *rs)
{
    uint32_t *hs;
    uint16_t err;
    int n = list_children(rq->p[0], rq->p[1], rq->np >= 3 ? rq->p[2] : 0, &hs, &err);
    free(hs);
    if (n < 0) { rs->code = err; return TP_OK; }
    rs->code = RC_OK;
    rs->p[0] = (uint32_t)n;
    rs->np = 1;
    return TP_OK;
}

static int op_get_object_info(const req_t *rq, resp_t *rs)
{
    objview_t v;
    if (!view_object(rq->p[0], &v)) { rs->code = RC_InvalidObjectHandle; return TP_OK; }
    dbuf_reset(&g_db);
    put_object_info(&g_db, &v);
    rs->code = RC_OK;
    return send_dataset(rq, &g_db);
}

/* Shared by GetObject / GetPartialObject / GetPartialObject64. */
static int send_file(const req_t *rq, resp_t *rs, uint64_t offset, uint64_t max_len, bool partial)
{
    char path[OBJ_PATH_MAX], sz[32];
    obj_t *o = objdb_get(rq->p[0]);
    if (!o || rq->p[0] == OBJ_ROOT || o->is_dir) { rs->code = RC_InvalidObjectHandle; return TP_OK; }
    if (!objdb_path(rq->p[0], path, sizeof(path))) { rs->code = RC_GeneralError; return TP_OK; }

    int fd = open(path, O_RDONLY);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0) {
        if (fd >= 0) close(fd);
        rs->code = RC_InvalidObjectHandle;
        return TP_OK;
    }
    uint64_t fsize = (uint64_t)st.st_size;
    if (offset > fsize) offset = fsize;
    uint64_t len = fsize - offset;
    if (len > max_len) len = max_len;
    if (offset && lseek(fd, (off_t)offset, SEEK_SET) < 0) { close(fd); rs->code = RC_GeneralError; return TP_OK; }

    /* Partial reads are how gvfs/Android File Transfer stream: they're
     * usually small and frequent, so keep them out of the UI's history. */
    const bool track = !partial || len >= (8u << 20);
    char name[STATUS_LINE_LEN];
    snprintf(name, sizeof(name), "%s", o->name);   /* o may move on realloc */
    if (track) status_xfer_begin(DIR_TO_PC, name, len);

    filesrc_t f = { fd };
    bool failed;
    int r = tx_stream(rq, len, file_src, &f, &failed, track);
    close(fd);

    if (track) {
        status_xfer_end(r == TP_OK && !failed);
        fmt_size(len, sz, sizeof(sz));
        if (r == TP_OK && !failed) status_log("-> PC   %s (%s)", name, sz);
        else                       status_log("!! PC   %s: transfer aborted", name);
    }
    rs->code = failed ? RC_IncompleteTransfer : RC_OK;
    if (partial) { rs->p[0] = (uint32_t)len; rs->np = 1; }
    return r;
}

static int op_get_object(const req_t *rq, resp_t *rs)
{
    return send_file(rq, rs, 0, UINT64_MAX, false);
}

static int op_get_partial_object(const req_t *rq, resp_t *rs)
{
    if (rq->np < 3) { rs->code = RC_InvalidParameter; return TP_OK; }
    return send_file(rq, rs, rq->p[1], rq->p[2], true);
}

static int op_get_partial_object64(const req_t *rq, resp_t *rs)
{
    if (rq->np < 4) { rs->code = RC_InvalidParameter; return TP_OK; }
    return send_file(rq, rs, (uint64_t)rq->p[1] | (uint64_t)rq->p[2] << 32, rq->p[3], true);
}

static int op_delete_object(const req_t *rq, resp_t *rs)
{
    char path[OBJ_PATH_MAX];
    uint32_t h = rq->p[0];
    if (h == ALL_HANDLES || h == OBJ_ROOT) { rs->code = RC_ObjectWriteProtected; return TP_OK; }
    obj_t *o = objdb_get(h);
    if (!o) { rs->code = RC_InvalidObjectHandle; return TP_OK; }
    if (!objdb_path(h, path, sizeof(path))) { rs->code = RC_GeneralError; return TP_OK; }
    char name[STATUS_LINE_LEN];
    snprintf(name, sizeof(name), "%s", o->name);

    int rc = rm_rf(path);
    struct stat st;
    bool gone = stat(path, &st) != 0;
    if (gone) {
        objdb_remove(h);
    } else if (o->is_dir) {
        /* Partial delete: re-sync so the deleted children lose their handles. */
        uint32_t *tmp = NULL;
        if (objdb_list(h, &tmp) >= 0) free(tmp);
    }

    if (rc == 0 && gone) { status_log("Deleted %s", name); rs->code = RC_OK; }
    else                 { status_log("!! delete %s failed", name); rs->code = gone ? RC_OK : RC_PartialDeletion; }
    return TP_OK;
}

static int op_send_object_info(const req_t *rq, resp_t *rs)
{
    bool ok;
    int r = recv_dataset(&ok);
    if (r) return r;
    g_pend_valid = false;
    if (!ok) { rs->code = RC_InvalidParameter; return TP_OK; }

    if (rq->np >= 1 && rq->p[0] != STORAGE_ID && rq->p[0] != 0) { rs->code = RC_InvalidStorageID; return TP_OK; }
    uint32_t parent = parent_from_mtp(rq->np >= 2 ? rq->p[1] : 0);
    obj_t *po = objdb_get(parent);
    if (!po || !po->is_dir) { rs->code = RC_InvalidParentObject; return TP_OK; }

    dparse_t d;
    dparse_init(&d, g_db.data, g_db.len);
    dparse_u32(&d);                          /* storage           */
    uint16_t format = dparse_u16(&d);
    dparse_u16(&d);                          /* protection        */
    uint32_t csize = dparse_u32(&d);
    dparse_skip(&d, 2 + 4 * 6);              /* thumb/image info  */
    dparse_u32(&d);                          /* parent (use param)*/
    dparse_u16(&d);                          /* association type  */
    dparse_skip(&d, 4 + 4);                  /* assoc desc, seq   */
    char name[512];
    dparse_str(&d, name, sizeof(name));
    if (d.err || !sanitize_name(name)) { rs->code = RC_InvalidParameter; return TP_OK; }

    char path[OBJ_PATH_MAX];
    if (!objdb_child_path(parent, name, path, sizeof(path))) { rs->code = RC_InvalidParameter; return TP_OK; }

    const bool is_dir = (format == FMT_Association);
    struct stat st;
    bool exists = stat(path, &st) == 0;

    if (is_dir) {
        if (exists && !S_ISDIR(st.st_mode)) { rs->code = RC_GeneralError; return TP_OK; }
        if (!exists && mkdir(path, 0777) != 0) { rs->code = RC_AccessDenied; return TP_OK; }
        status_log("New folder %s", name);
    } else {
        if (exists && S_ISDIR(st.st_mode)) { rs->code = RC_GeneralError; return TP_OK; }
        /* Refuse up front if it obviously won't fit. */
        if (csize != 0xFFFFFFFFu) {
            char root[OBJ_PATH_MAX];
            struct statvfs vfs;
            objdb_path(OBJ_ROOT, root, sizeof(root));
            if (statvfs(root, &vfs) == 0 && (uint64_t)vfs.f_bavail * vfs.f_frsize < csize) {
                rs->code = RC_StoreFull;
                return TP_OK;
            }
        }
        /* Create it now so the handle is real even before SendObject. */
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd < 0) { rs->code = RC_AccessDenied; return TP_OK; }
        close(fd);
    }

    uint32_t h = objdb_add(parent, name, is_dir);
    if (h == OBJ_INVALID) { rs->code = RC_GeneralError; return TP_OK; }

    if (!is_dir) {
        g_pend_valid = true;
        g_pend_handle = h;
        g_pend_size = (csize == 0xFFFFFFFFu) ? LEN_UNKNOWN : csize;
    }
    rs->code = RC_OK;
    rs->p[0] = STORAGE_ID;
    rs->p[1] = rq->np >= 2 ? rq->p[1] : 0;   /* echo the host's root convention */
    rs->p[2] = h;
    rs->np = 3;
    return TP_OK;
}

static int op_send_object(const req_t *rq, resp_t *rs)
{
    char path[OBJ_PATH_MAX], sz[32], name[STATUS_LINE_LEN];

    if (!g_pend_valid || !objdb_valid(g_pend_handle) || !objdb_path(g_pend_handle, path, sizeof(path))) {
        int r = drain_data();
        rs->code = RC_NoValidObjectInfo;
        return r;
    }
    const uint32_t h = g_pend_handle;
    const uint64_t hint = g_pend_size;
    g_pend_valid = false;
    snprintf(name, sizeof(name), "%s", objdb_get(h)->name);

    filesink_t f = { open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666), 0 };
    if (f.fd >= 0 && hint != LEN_UNKNOWN && hint > 0) {
        /* Pre-size the file: one FAT cluster-chain allocation instead of
         * thousands, and an early, clean StoreFull. */
        if (ftruncate(f.fd, (off_t)hint) != 0) { f.err = ENOSPC; }
        lseek(f.fd, 0, SEEK_SET);
    }

    status_xfer_begin(DIR_TO_SWITCH, name, hint);
    rx_result_t res;
    int r = rx_stream(hint, (f.fd >= 0 && !f.err) ? file_sink : NULL, &f, &res, true, rq);

    bool ok = (r == TP_OK) && f.fd >= 0 && !f.err && !res.sink_failed && res.complete;
    if (f.fd >= 0) {
        /* Trim the pre-allocation if the host sent less than announced. */
        if (r == TP_OK && !res.sink_failed && res.got != hint && ftruncate(f.fd, (off_t)res.got) != 0) ok = false;
        if (close(f.fd) != 0) ok = false;
    }
    status_xfer_end(ok);

    if (!ok) {
        /* Never leave a truncated file that looks complete. */
        unlink(path);
        objdb_remove(h);
        if (f.fd < 0 || f.err) {
            status_log("!! SD   %s: write failed (%s)", name,
                       f.err == EFBIG ? "file > 4 GiB on FAT32?" : f.err == ENOSPC ? "SD full" : "I/O error");
            rs->code = (f.err == ENOSPC) ? RC_StoreFull : (f.err == EFBIG ? RC_ObjectTooLarge : RC_GeneralError);
        } else {
            status_log("!! SD   %s: transfer incomplete", name);
            rs->code = RC_IncompleteTransfer;
        }
        return r;
    }
    fmt_size(res.got, sz, sizeof(sz));
    status_log("<- PC   %s (%s)", name, sz);
    rs->code = RC_OK;
    return TP_OK;
}

static int op_move_object(const req_t *rq, resp_t *rs)
{
    char from[OBJ_PATH_MAX], to[OBJ_PATH_MAX];
    uint32_t h = rq->p[0];
    obj_t *o = objdb_get(h);
    if (!o || h == OBJ_ROOT) { rs->code = RC_InvalidObjectHandle; return TP_OK; }
    if (rq->np >= 2 && rq->p[1] != STORAGE_ID) { rs->code = RC_InvalidStorageID; return TP_OK; }
    uint32_t np = parent_from_mtp(rq->np >= 3 ? rq->p[2] : 0);
    obj_t *po = objdb_get(np);
    if (!po || !po->is_dir || objdb_is_within(np, h)) { rs->code = RC_InvalidParentObject; return TP_OK; }
    if (!objdb_path(h, from, sizeof(from)) || !objdb_child_path(np, o->name, to, sizeof(to))) {
        rs->code = RC_GeneralError; return TP_OK;
    }
    struct stat st;
    if (stat(to, &st) == 0) { rs->code = RC_GeneralError; return TP_OK; }   /* no silent overwrite */
    if (rename(from, to) != 0) { rs->code = RC_AccessDenied; return TP_OK; }
    objdb_move(h, np);
    status_log("Moved %s", objdb_get(h)->name);
    rs->code = RC_OK;
    return TP_OK;
}

static int op_copy_object(const req_t *rq, resp_t *rs)
{
    char from[OBJ_PATH_MAX], to[OBJ_PATH_MAX], name[STATUS_LINE_LEN];
    uint32_t h = rq->p[0];
    obj_t *o = objdb_get(h);
    if (!o || h == OBJ_ROOT) { rs->code = RC_InvalidObjectHandle; return TP_OK; }
    if (rq->np >= 2 && rq->p[1] != STORAGE_ID) { rs->code = RC_InvalidStorageID; return TP_OK; }
    uint32_t np = parent_from_mtp(rq->np >= 3 ? rq->p[2] : 0);
    obj_t *po = objdb_get(np);
    if (!po || !po->is_dir || objdb_is_within(np, h)) { rs->code = RC_InvalidParentObject; return TP_OK; }
    snprintf(name, sizeof(name), "%s", o->name);
    const bool is_dir = o->is_dir;
    if (!objdb_path(h, from, sizeof(from)) || !objdb_child_path(np, name, to, sizeof(to))) {
        rs->code = RC_GeneralError; return TP_OK;
    }
    struct stat st;
    if (stat(to, &st) == 0) { rs->code = RC_GeneralError; return TP_OK; }
    stat(from, &st);
    status_xfer_begin(DIR_COPY, name, is_dir ? LEN_UNKNOWN : (uint64_t)st.st_size);
    g_copy_done = 0;
    int rc = copy_tree(from, to);
    status_xfer_end(rc == 0);
    if (rc != 0) { rm_rf(to); rs->code = RC_StoreFull; status_log("!! copy %s failed", name); return TP_OK; }
    uint32_t nh = objdb_add(np, name, is_dir);
    status_log("Copied %s", name);
    rs->code = RC_OK;
    rs->p[0] = nh;
    rs->np = 1;
    return TP_OK;
}

static int op_get_object_props_supported(const req_t *rq, resp_t *rs)
{
    (void)rq;
    dbuf_reset(&g_db);
    dbuf_arr16(&g_db, k_props, COUNT(k_props));
    rs->code = RC_OK;
    return send_dataset(rq, &g_db);
}

static int op_get_object_prop_desc(const req_t *rq, resp_t *rs)
{
    uint16_t prop = (uint16_t)rq->p[0];
    uint16_t type = prop_type(prop);
    if (!type) { rs->code = RC_InvalidObjectPropCode; return TP_OK; }

    dbuf_reset(&g_db);
    dbuf_u16(&g_db, prop);
    dbuf_u16(&g_db, type);
    dbuf_u8(&g_db, prop == PROP_ObjectFileName ? 1 : 0);   /* get/set   */
    switch (type) {                                         /* default   */
        case DT_UINT16:  dbuf_u16(&g_db, 0); break;
        case DT_UINT32:  dbuf_u32(&g_db, 0); break;
        case DT_UINT64:  dbuf_u64(&g_db, 0); break;
        case DT_UINT128: dbuf_u128(&g_db, 0, 0); break;
        default:         dbuf_str(&g_db, NULL); break;
    }
    dbuf_u32(&g_db, 0);                                     /* group     */
    dbuf_u8(&g_db, (prop == PROP_DateCreated || prop == PROP_DateModified) ? 0x03 : 0x00); /* form: DateTime / none */
    rs->code = RC_OK;
    return send_dataset(rq, &g_db);
}

static int op_get_object_prop_value(const req_t *rq, resp_t *rs)
{
    objview_t v;
    uint16_t prop = (uint16_t)rq->p[1];
    if (!view_object(rq->p[0], &v)) { rs->code = RC_InvalidObjectHandle; return TP_OK; }
    if (!prop_type(prop)) { rs->code = RC_InvalidObjectPropCode; return TP_OK; }
    dbuf_reset(&g_db);
    put_prop_value(&g_db, &v, prop);
    rs->code = RC_OK;
    return send_dataset(rq, &g_db);
}

static int op_set_object_prop_value(const req_t *rq, resp_t *rs)
{
    bool ok;
    int r = recv_dataset(&ok);
    if (r) return r;
    uint32_t h = rq->p[0];
    uint16_t prop = (uint16_t)rq->p[1];
    obj_t *o = objdb_get(h);
    if (!o || h == OBJ_ROOT) { rs->code = RC_InvalidObjectHandle; return TP_OK; }
    if (!prop_type(prop)) { rs->code = RC_InvalidObjectPropCode; return TP_OK; }
    if (prop != PROP_ObjectFileName) { rs->code = RC_AccessDenied; return TP_OK; }
    if (!ok) { rs->code = RC_InvalidObjectPropValue; return TP_OK; }

    char name[512], from[OBJ_PATH_MAX], to[OBJ_PATH_MAX];
    dparse_t d;
    dparse_init(&d, g_db.data, g_db.len);
    dparse_str(&d, name, sizeof(name));
    if (d.err || !sanitize_name(name)) { rs->code = RC_InvalidObjectPropValue; return TP_OK; }
    if (!objdb_path(h, from, sizeof(from)) || !objdb_child_path(o->parent, name, to, sizeof(to))) {
        rs->code = RC_GeneralError; return TP_OK;
    }
    if (strcmp(from, to) != 0) {
        struct stat st;
        if (stat(to, &st) == 0) { rs->code = RC_GeneralError; return TP_OK; }
        if (rename(from, to) != 0) { rs->code = RC_AccessDenied; return TP_OK; }
        status_log("Renamed %s -> %s", o->name, name);
        objdb_rename(h, name);
    }
    rs->code = RC_OK;
    return TP_OK;
}

static void put_prop_list_entries(dbuf_t *b, const objview_t *v, uint32_t prop, uint32_t *count)
{
    for (uint32_t i = 0; i < COUNT(k_props); i++) {
        if (prop != ALL_HANDLES && prop != k_props[i]) continue;
        dbuf_u32(b, v->h);
        dbuf_u16(b, k_props[i]);
        dbuf_u16(b, prop_type(k_props[i]));
        put_prop_value(b, v, k_props[i]);
        (*count)++;
    }
}

/*
 * GetObjectPropList(handle, format, prop, group, depth). Windows uses it to
 * fill a folder view in one round trip instead of N GetObjectInfo calls.
 * Supported: depth 0 (the object itself) and depth 1 (its children, or the
 * root's children for handle 0/0xFFFFFFFF). "Everything on the device"
 * (depth 0xFFFFFFFF) is refused so libmtp falls back to per-folder listing
 * instead of us walking a 512 GB card.
 */
static int op_get_object_prop_list(const req_t *rq, resp_t *rs)
{
    uint32_t h = rq->p[0], format = rq->p[1], prop = rq->p[2];
    uint32_t group = rq->np >= 4 ? rq->p[3] : 0;
    uint32_t depth = rq->np >= 5 ? rq->p[4] : 0;

    if (prop == 0) { rs->code = group ? RC_SpecByGroupUnsupported : RC_InvalidObjectPropCode; return TP_OK; }
    if (prop != ALL_HANDLES && !prop_type((uint16_t)prop)) { rs->code = RC_ObjectPropNotSupported; return TP_OK; }
    if (depth > 1) { rs->code = RC_SpecByDepthUnsupported; return TP_OK; }

    dbuf_reset(&g_db);
    uint32_t count = 0;
    dbuf_u32(&g_db, 0);   /* patched below */

    if (depth == 0) {
        if (h != 0 && h != ALL_HANDLES) {
            objview_t v;
            if (!view_object(h, &v)) { rs->code = RC_InvalidObjectHandle; return TP_OK; }
            put_prop_list_entries(&g_db, &v, prop, &count);
        }
        /* depth 0 on the root: the root has no properties -> empty list */
    } else if (h != 0 && h != ALL_HANDLES && objdb_get(h) && !objdb_get(h)->is_dir) {
        /* depth 1 below a file: no children, empty list */
    } else {
        uint32_t *hs;
        uint16_t err;
        int n = list_children(STORAGE_ID, format, (h == 0 || h == ALL_HANDLES) ? ALL_HANDLES : h, &hs, &err);
        if (n < 0) { rs->code = (err == RC_InvalidParentObject) ? RC_InvalidObjectHandle : err; return TP_OK; }
        for (int i = 0; i < n; i++) {
            objview_t v;
            if (view_object(hs[i], &v)) put_prop_list_entries(&g_db, &v, prop, &count);
        }
        free(hs);
    }
    dbuf_patch_u32(&g_db, 0, count);
    if (g_db.oom) { rs->code = RC_GeneralError; return TP_OK; }
    rs->code = RC_OK;
    return send_dataset(rq, &g_db);
}

static int op_get_object_references(const req_t *rq, resp_t *rs)
{
    if (!objdb_get(rq->p[0]) || rq->p[0] == OBJ_ROOT) { rs->code = RC_InvalidObjectHandle; return TP_OK; }
    dbuf_reset(&g_db);
    dbuf_arr32(&g_db, NULL, 0);
    rs->code = RC_OK;
    return send_dataset(rq, &g_db);
}

static int op_set_object_references(const req_t *rq, resp_t *rs)
{
    (void)rq;
    int r = drain_data();
    rs->code = RC_OK;   /* we have no playlists; accept and ignore */
    return r;
}

static int op_get_device_prop_desc(const req_t *rq, resp_t *rs)
{
    if (rq->p[0] != DEVPROP_FriendlyName) { rs->code = RC_DevicePropNotSupported; return TP_OK; }
    dbuf_reset(&g_db);
    dbuf_u16(&g_db, DEVPROP_FriendlyName);
    dbuf_u16(&g_db, DT_STR);
    dbuf_u8(&g_db, 0);                         /* get only */
    dbuf_str(&g_db, g_cfg.friendly_name);      /* default  */
    dbuf_str(&g_db, g_cfg.friendly_name);      /* current  */
    dbuf_u8(&g_db, 0);                         /* no form  */
    rs->code = RC_OK;
    return send_dataset(rq, &g_db);
}

static int op_get_device_prop_value(const req_t *rq, resp_t *rs)
{
    if (rq->p[0] != DEVPROP_FriendlyName) { rs->code = RC_DevicePropNotSupported; return TP_OK; }
    dbuf_reset(&g_db);
    dbuf_str(&g_db, g_cfg.friendly_name);
    rs->code = RC_OK;
    return send_dataset(rq, &g_db);
}

static int op_set_device_prop_value(const req_t *rq, resp_t *rs)
{
    int r = drain_data();
    rs->code = rq->p[0] == DEVPROP_FriendlyName ? RC_AccessDenied : RC_DevicePropNotSupported;
    return r;
}

/* Android extensions: in-place edits (gvfs / Android File Transfer). */

static int op_send_partial_object(const req_t *rq, resp_t *rs)
{
    char path[OBJ_PATH_MAX];
    obj_t *o = objdb_get(rq->p[0]);
    if (rq->np < 4 || !o || rq->p[0] == OBJ_ROOT || o->is_dir || !objdb_path(rq->p[0], path, sizeof(path))) {
        int r = drain_data();
        rs->code = rq->np < 4 ? RC_InvalidParameter : RC_InvalidObjectHandle;
        return r;
    }
    uint64_t off = (uint64_t)rq->p[1] | (uint64_t)rq->p[2] << 32;
    filesink_t f = { open(path, O_WRONLY), 0 };
    if (f.fd >= 0 && lseek(f.fd, (off_t)off, SEEK_SET) < 0) { close(f.fd); f.fd = -1; }
    rx_result_t res;
    int r = rx_stream(rq->p[3], f.fd >= 0 ? file_sink : NULL, &f, &res, false, NULL);
    if (f.fd >= 0 && close(f.fd) != 0) f.err = EIO;
    if (r) return r;
    if (f.fd < 0 || f.err || res.sink_failed) rs->code = f.err == ENOSPC ? RC_StoreFull : RC_GeneralError;
    else rs->code = res.complete ? RC_OK : RC_IncompleteTransfer;
    rs->p[0] = (uint32_t)res.got;
    rs->np = 1;
    return TP_OK;
}

static int op_truncate_object(const req_t *rq, resp_t *rs)
{
    char path[OBJ_PATH_MAX];
    obj_t *o = objdb_get(rq->p[0]);
    if (rq->np < 3 || !o || rq->p[0] == OBJ_ROOT || o->is_dir || !objdb_path(rq->p[0], path, sizeof(path))) {
        rs->code = rq->np < 3 ? RC_InvalidParameter : RC_InvalidObjectHandle;
        return TP_OK;
    }
    int fd = open(path, O_WRONLY);
    bool ok = fd >= 0 && ftruncate(fd, (off_t)((uint64_t)rq->p[1] | (uint64_t)rq->p[2] << 32)) == 0;
    if (fd >= 0 && close(fd) != 0) ok = false;
    rs->code = ok ? RC_OK : RC_GeneralError;
    return TP_OK;
}

static int op_edit_object(const req_t *rq, resp_t *rs)
{
    /* Begin/EndEditObject: each partial op opens the file itself, so there is
     * no edit state to keep; just validate the handle. */
    obj_t *o = objdb_get(rq->p[0]);
    rs->code = (!o || rq->p[0] == OBJ_ROOT || o->is_dir) ? RC_InvalidObjectHandle : RC_OK;
    return TP_OK;
}

/* ---- dispatch ------------------------------------------------------------- */

typedef int (*op_fn)(const req_t *, resp_t *);

static op_fn lookup_op(uint16_t code)
{
    switch (code) {
        case OP_GetDeviceInfo:             return op_get_device_info;
        case OP_OpenSession:               return op_open_session;
        case OP_CloseSession:              return op_close_session;
        case OP_GetStorageIDs:             return op_get_storage_ids;
        case OP_GetStorageInfo:            return op_get_storage_info;
        case OP_GetNumObjects:             return op_get_num_objects;
        case OP_GetObjectHandles:          return op_get_object_handles;
        case OP_GetObjectInfo:             return op_get_object_info;
        case OP_GetObject:                 return op_get_object;
        case OP_GetPartialObject:          return op_get_partial_object;
        case OP_DeleteObject:              return op_delete_object;
        case OP_SendObjectInfo:            return op_send_object_info;
        case OP_SendObject:                return op_send_object;
        case OP_GetDevicePropDesc:         return op_get_device_prop_desc;
        case OP_GetDevicePropValue:        return op_get_device_prop_value;
        case OP_SetDevicePropValue:        return op_set_device_prop_value;
        case OP_MoveObject:                return op_move_object;
        case OP_CopyObject:                return op_copy_object;
        case OP_GetObjectPropsSupported:   return op_get_object_props_supported;
        case OP_GetObjectPropDesc:         return op_get_object_prop_desc;
        case OP_GetObjectPropValue:        return op_get_object_prop_value;
        case OP_SetObjectPropValue:        return op_set_object_prop_value;
        case OP_GetObjectPropList:         return op_get_object_prop_list;
        case OP_GetObjectReferences:       return op_get_object_references;
        case OP_SetObjectReferences:       return op_set_object_references;
        case OP_AndroidGetPartialObject64: return op_get_partial_object64;
        case OP_AndroidSendPartialObject:  return op_send_partial_object;
        case OP_AndroidTruncateObject:     return op_truncate_object;
        case OP_AndroidBeginEditObject:    return op_edit_object;
        case OP_AndroidEndEditObject:      return op_edit_object;
        default:                           return NULL;
    }
}

/* Operations whose host->device data phase must be consumed even when we
 * reject them before looking at it (e.g. no session). */
static bool has_data_out(uint16_t code)
{
    return code == OP_SendObjectInfo || code == OP_SendObject || code == OP_SetObjectPropValue ||
           code == OP_SetObjectReferences || code == OP_SetDevicePropValue ||
           code == OP_AndroidSendPartialObject;
}

static int send_response(const req_t *rq, const resp_t *rs)
{
    uint32_t len = 12 + 4u * (uint32_t)rs->np;
    wr32(g_resp, len);
    wr16(g_resp + 4, CT_RESPONSE);
    wr16(g_resp + 6, rs->code);
    wr32(g_resp + 8, rq->tid);
    for (int i = 0; i < rs->np; i++) wr32(g_resp + 12 + 4 * i, rs->p[i]);
    return tp_write(g_resp, len, XFER_TIMEOUT_MS);
}

static void on_disconnect(void)
{
    if (g_session_open) close_session();
    status_set_speed(0);
    status_set_state(ST_WAITING_CABLE);
    status_log("PC disconnected");
}

bool mtp_init(const mtp_config_t *cfg)
{
    g_cfg = *cfg;
    g_buf[0] = aligned_alloc(0x1000, BUF_SZ);
    g_buf[1] = aligned_alloc(0x1000, BUF_SZ);
    g_cmd    = aligned_alloc(0x1000, CMD_BUF_SZ);
    g_resp   = aligned_alloc(0x1000, CMD_BUF_SZ);
    dbuf_init(&g_db);
    if (!g_buf[0] || !g_buf[1] || !g_cmd || !g_resp) return false;
    return objdb_init(cfg->root_path);
}

void mtp_exit(void)
{
    objdb_free();
    dbuf_free(&g_db);
    free(g_buf[0]); free(g_buf[1]); free(g_cmd); free(g_resp);
    g_buf[0] = g_buf[1] = g_cmd = g_resp = NULL;
}

void mtp_run(void)
{
    bool connected = false;
    status_set_state(ST_WAITING_CABLE);

    while (!stop_requested()) {
        int r = tp_wait_configured(250);
        if (r == TP_STOPPED) break;
        if (r != TP_OK) {
            if (connected) { connected = false; on_disconnect(); }
            continue;
        }
        if (!connected) {
            connected = true;
            status_set_speed(tp_max_packet());
            status_set_state(ST_CONNECTED);
            status_log("PC connected (%s)", tp_max_packet() >= 1024 ? "USB 3 SuperSpeed" : "USB 2 High-Speed");
        }

        uint32_t n;
        r = tp_read(g_cmd, CMD_BUF_SZ, &n, TP_NO_TIMEOUT);
        if (r == TP_STOPPED) break;
        if (r == TP_DISCONNECTED) { connected = false; on_disconnect(); continue; }
        if (r != TP_OK) { tp_abort(); continue; }
        if (n < 12) continue;                         /* ZLP or junk */

        const uint32_t clen = rd32(g_cmd);
        if (rd16(g_cmd + 4) != CT_COMMAND || clen < 12 || clen > n) continue;

        req_t rq;
        memset(&rq, 0, sizeof(rq));
        rq.code = rd16(g_cmd + 6);
        rq.tid  = rd32(g_cmd + 8);
        rq.np   = (int)((clen - 12) / 4);
        if (rq.np > 5) rq.np = 5;
        for (int i = 0; i < rq.np; i++) rq.p[i] = rd32(g_cmd + 12 + 4 * i);

        resp_t rs;
        memset(&rs, 0, sizeof(rs));
        op_fn fn = lookup_op(rq.code);

        if (!fn) {
            rs.code = RC_OperationNotSupported;
            r = TP_OK;
        } else if (!g_session_open && rq.code != OP_GetDeviceInfo && rq.code != OP_OpenSession) {
            r = has_data_out(rq.code) ? drain_data() : TP_OK;
            rs.code = RC_SessionNotOpen;
        } else {
            r = fn(&rq, &rs);
        }

        if (r == TP_OK) r = send_response(&rq, &rs);

        if (r == TP_STOPPED) break;
        if (r == TP_DISCONNECTED) { connected = false; on_disconnect(); continue; }
        if (r != TP_OK) {
            /* Stalled or garbled phase: the host has most likely cancelled.
             * Flush our side and wait for its next command. */
            tp_abort();
            status_log("Transfer aborted by host (resync)");
            if (g_session_open) status_set_state(ST_SESSION);
        }
    }
    if (g_session_open) close_session();
}
