#include "ts-analyzer.h"
#include "utils.h"

#include <memory.h>
#include <bitstream/mpeg/ts.h>

#include <stdio.h>

struct _TsAnalyzer {
    TsAnalyzerClass klass;
    void *cb_userdata;

    /* The accumulated packet data. */
    uint8_t packet_data[256];

    /* The bytes already loaded into packet_data. */
    size_t packet_bytes_read;

    /* Number of bytes read from the whole stream. */
    size_t stream_offset;
    /* Number of bytes in the stream before starting the current packet. */
    size_t packet_offset;

    uint8_t *buffer;
    /* Bytes remaining in the current buffer. */
    size_t remaining;

    size_t packet_length;

    uint32_t error_occured : 1;
};

bool ts_analyzer_handle_packet_fallback(const uint8_t *packet, size_t offset, void *userdata)
{
    return true;
}

TsAnalyzerClass ts_analyzer_class_fallback = {
    .handle_packet = ts_analyzer_handle_packet_fallback,
};

static inline void ts_analyzer_advance_buffer(TsAnalyzer *analyzer, size_t len)
{
    analyzer->buffer += len;
    analyzer->stream_offset += len;
    analyzer->remaining -= len;
}

void ts_analyzer_sync_stream(TsAnalyzer *analyzer)
{
    size_t offset = 0;
    if (!analyzer->packet_length) {
        while (offset < analyzer->remaining) {
            /* FIXME: validate five packets (as below) to avoid error in synchronization. */
            if (ts_validate(&analyzer->buffer[offset])) {
                if (offset + 188 < analyzer->remaining && ts_validate(&analyzer->buffer[offset + 188])) {
                    analyzer->packet_length = 188;
                    break;
                }
                if (offset + 192 < analyzer->remaining && ts_validate(&analyzer->buffer[offset + 192])) {
                    analyzer->packet_length = 192;
                    break;
                }
            }
            ++offset;
        }

        if (!analyzer->packet_length)
            goto err;
    }
    /* return start of first valid sync byte */
    int no_match = 0;
    size_t i;
    while (offset < analyzer->remaining) {
        if (ts_validate(&analyzer->buffer[offset])) { /* possible start */
            no_match = 0;
            /* check if we have the start of a packet (next five packets) */
            for (i = 1; i < 5 && no_match == 0; ++i) {
                if (offset + i * analyzer->packet_length < analyzer->remaining) {
                    if (!ts_validate(&analyzer->buffer[offset + i * analyzer->packet_length]))
                        no_match = 1;
                    break;
                }
                else {
                    goto err;
                }
            }
            if (!no_match) {
                ts_analyzer_advance_buffer(analyzer, offset);
                analyzer->packet_offset = analyzer->stream_offset;
                return;
            }
        }
        ++offset;
    }
err:
    /* drop buffer if not enough bytes in buffer to sync */
    analyzer->stream_offset += analyzer->remaining;
    analyzer->remaining = 0;
}

static inline void ts_analyzer_process_packet(TsAnalyzer *analyzer)
{
    if (ts_validate(analyzer->packet_data)) {
        if (!analyzer->klass.handle_packet(analyzer->packet_data, analyzer->packet_offset, analyzer->cb_userdata))
            analyzer->error_occured = 1;
    }
    else {
        analyzer->packet_bytes_read = 0;
        ts_analyzer_sync_stream(analyzer);
    }
}

static inline void ts_analyzer_read_packet_partial(TsAnalyzer *analyzer)
{
    /* Are there less bytes remaining in the buffer than there are required for a full packet. */
    if (analyzer->remaining < analyzer->packet_length - analyzer->packet_bytes_read) {
        /* Copy all remaining bytes to the packet data. */
        memcpy(&analyzer->packet_data[analyzer->packet_bytes_read], analyzer->buffer, analyzer->remaining);
        analyzer->packet_bytes_read += analyzer->remaining;
        ts_analyzer_advance_buffer(analyzer, analyzer->remaining);
        return;
    }
    else {
        /* Copy all bytes that are required for a full packet. */
        memcpy(&analyzer->packet_data[analyzer->packet_bytes_read], analyzer->buffer, analyzer->packet_length - analyzer->packet_bytes_read);
        ts_analyzer_advance_buffer(analyzer, analyzer->packet_length - analyzer->packet_bytes_read);

        ts_analyzer_process_packet(analyzer);
        analyzer->packet_bytes_read = 0;

        analyzer->packet_offset = analyzer->stream_offset;
    }
}

TsAnalyzer *ts_analyzer_new(TsAnalyzerClass *klass, void *userdata)
{
    TsAnalyzer *analyzer = util_alloc0(sizeof(TsAnalyzer));
    if (!analyzer)
        return NULL;
    if (klass)
        analyzer->klass = *klass;
    else
        analyzer->klass = ts_analyzer_class_fallback;

    if (!analyzer->klass.handle_packet)
        analyzer->klass.handle_packet = ts_analyzer_handle_packet_fallback;

    analyzer->cb_userdata = userdata;

    return analyzer;
}

void ts_analyzer_free(TsAnalyzer *analyzer)
{
    util_free(analyzer);
}

void ts_analyzer_push_buffer(TsAnalyzer *analyzer, const uint8_t *buffer, size_t len)
{
    /* if packet_bytes_read < 188 read min{188-packet_bytes_read,len} bytes from buffer
     * else check if byte 0 valid; if not sync stream */
    analyzer->buffer = (uint8_t *)buffer;
    analyzer->remaining = len;

    if (analyzer->packet_bytes_read == 0 && !ts_validate(analyzer->buffer))
        ts_analyzer_sync_stream(analyzer);

    while (analyzer->remaining && !analyzer->error_occured) {
        ts_analyzer_read_packet_partial(analyzer);
    }
}
