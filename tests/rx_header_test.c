/*
 * Exercise the production receive parser with a bounded transport fixture.
 * The compatibility exception must not accept unrelated malformed headers.
 * SPDX-License-Identifier: ISC
 */
#include "../source/mtp.c"
#include <assert.h>

static unsigned char incoming[41];
static void *posted_buffer;
static uint32_t posted_size;
static unsigned received;
static bool simulated_large, simulated_header;
static uint64_t simulated_remaining;
uint32_t tp_max_packet(void) { return 512; }

int tp_read_begin(void *buffer, uint32_t size) {
    assert(size >= sizeof(incoming));
    posted_buffer = buffer;
    posted_size = size;
    return TP_OK;
}

int tp_read_end(uint32_t *n, uint32_t timeout) {
    (void)timeout;
    if (simulated_large) {
        uint32_t header = simulated_header ? 12 : 0;
        uint64_t available = simulated_remaining + header;
        *n = available < posted_size ? (uint32_t)available : posted_size;
        if (header) memcpy(posted_buffer, incoming, 12);
        simulated_remaining -= *n - header;
        simulated_header = false;
        return TP_OK;
    }
    memcpy(posted_buffer, incoming, sizeof(incoming));
    *n = sizeof(incoming);
    return TP_OK;
}

void tp_abort(void) {}
void status_log(const char *fmt, ...) { (void)fmt; }
void status_xfer_progress(uint64_t bytes) { (void)bytes; }

static int consume(void *ctx, const uint8_t *data, uint32_t count) {
    (void)ctx;
    assert(count == 29);
    for (unsigned i = 0; i < count; ++i) assert(data[i] == i);
    received += count;
    return 0;
}

static void test(uint64_t hint, uint32_t length, uint16_t type,
                 uint16_t code, uint32_t tid, const req_t *request, int expected) {
    memset(incoming, 0, sizeof(incoming));
    wr32(incoming, length);
    wr16(incoming + 4, type);
    wr16(incoming + 6, code);
    wr32(incoming + 8, tid);
    for (unsigned i = 0; i < 29; ++i) incoming[12 + i] = i;
    received = 0;
    rx_result_t result;
    assert(rx_stream(hint, consume, NULL, &result, false, request) == expected);
    assert(received == (expected == TP_OK ? 29u : 0u));
    if (expected == TP_OK) assert(result.complete && result.got == 29);
}

int main(void) {
    g_buf[0] = aligned_alloc(4096, BUF_SZ);
    g_buf[1] = aligned_alloc(4096, BUF_SZ);
    assert(g_buf[0] && g_buf[1]);
    const req_t send = {.code = OP_SendObject, .tid = 123};
    const req_t other = {.code = 0x95c2, .tid = 123}; /* Android SendPartialObject */
    test(LEN_UNKNOWN, 11, CT_DATA, send.code, send.tid, &send, TP_OK);
    test(LEN_UNKNOWN, UINT32_MAX, CT_DATA, send.code, send.tid, &send, TP_OK);
    test(29, 41, CT_DATA, send.code, send.tid, &send, TP_OK);
    test(29, 11, CT_DATA, send.code, send.tid, &send, TP_ERROR);
    test(LEN_UNKNOWN, 10, CT_DATA, send.code, send.tid, &send, TP_ERROR);
    test(LEN_UNKNOWN, 0, CT_DATA, send.code, send.tid, &send, TP_ERROR);
    test(LEN_UNKNOWN, 11, CT_COMMAND, send.code, send.tid, &send, TP_ERROR);
    test(LEN_UNKNOWN, 11, CT_DATA, send.code, 124, &send, TP_ERROR);
    test(LEN_UNKNOWN, 11, CT_DATA, other.code, send.tid, &send, TP_ERROR);
    test(LEN_UNKNOWN, 11, CT_DATA, other.code, other.tid, &other, TP_ERROR);
    test(LEN_UNKNOWN, 11, CT_DATA, send.code, send.tid, NULL, TP_ERROR);

    // Exercise the actual 64-bit receive counter beyond the 4 GiB boundary.
    // Transport completions are synthetic; no large allocation/file is made.
    const uint64_t large_size = UINT64_C(24) * 1024 * 1024 * 1024 + 375;
    simulated_large = true;
    simulated_header = true;
    simulated_remaining = large_size;
    rx_result_t result;
    assert(rx_stream(LEN_UNKNOWN, NULL, NULL, &result, false, &send) == TP_OK);
    assert(result.complete && result.got == large_size && simulated_remaining == 0);
    free(g_buf[0]);
    free(g_buf[1]);
    puts("11 header guard cases + simulated 24 GiB receive-counter case passed");
}
