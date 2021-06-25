#include "ts-analyzer.h"
#include "utils.h"

#include <memory.h>
#include <bitstream/mpeg/ts.h>
#include <dvbpsi/dvbpsi.h>
#include <dvbpsi/descriptor.h>
#include <dvbpsi/psi.h>
#include <dvbpsi/pat.h>
#include <dvbpsi/pmt.h>
#include <bitstream/mpeg/pes.h>

typedef struct _DvbPsiProgInfo {
    uint16_t prog_number;
    uint16_t pid;
    dvbpsi_t *handle;
} DvbPsiProgInfo;

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

    uint32_t error_occurred : 1;

    PidInfoManager *pmgr;

    /* dvbpsi handlers */
    dvbpsi_t *pat_handle;
    /* FIXME make this dynamic. */
    DvbPsiProgInfo pmt_handles[64];
    size_t pmt_handle_count;
};

bool ts_analyzer_handle_packet_fallback(PidInfo *pidinfo, const uint8_t *packet, size_t offset, void *userdata)
{
    return true;
}

TsAnalyzerClass ts_analyzer_class_fallback = {
    .handle_packet = ts_analyzer_handle_packet_fallback,
};

static PidInfo *_ts_analyzer_add_pid(TsAnalyzer *analyzer, uint16_t pid, PidType type)
{
    PidInfo *info = pid_info_manager_add_pid(analyzer->pmgr, pid);
    if (info == NULL) /* This should never happen */
        return NULL;
    if (type != PID_TYPE_OTHER)
        info->type = type;

    return info;
}

static DvbPsiProgInfo *ts_analyzer_dvbpsi_add_program(TsAnalyzer *analyzer, uint16_t prog_number, uint16_t pid);

static void ts_analyzer_dvbpsi_message(dvbpsi_t *handle, const dvbpsi_msg_level_t level, const char *msg)
{
}

static void ts_analyzer_dvbpsi_pat_cb(TsAnalyzer *analyzer, dvbpsi_pat_t *pat)
{
    dvbpsi_pat_program_t *prog;

    for (prog = pat->p_first_program; prog; prog = prog->p_next) {
        ts_analyzer_dvbpsi_add_program(analyzer, prog->i_number, prog->i_pid);
    }

    dvbpsi_pat_delete(pat);
}

static void ts_analyzer_dvbpsi_pmt_cb(TsAnalyzer *analyzer, dvbpsi_pmt_t *pmt)
{
    dvbpsi_pmt_es_t *stream;
    PidType type = PID_TYPE_OTHER;
    for (stream = pmt->p_first_es; stream; stream = stream->p_next) {
        switch (stream->i_type) { /* see page 66 (48) of iso 13818-1 */
            case 0x01:
                type = PID_TYPE_VIDEO_11172;
                break;
            case 0x02:
                type = PID_TYPE_VIDEO_13818;
                break;
            case 0x03:
                type = PID_TYPE_AUDIO_11172;
                break;
            case 0x04:
                type = PID_TYPE_AUDIO_13818;
                break;
            case 0x06:
                type = PID_TYPE_TELETEXT;
                break;
            case 0x1b:
                type = PID_TYPE_VIDEO_14496;
                break;
            default:
                type = PID_TYPE_OTHER;
                break;
        }

        PidInfo *info =_ts_analyzer_add_pid(analyzer, stream->i_pid, type);
        if (info) {
            info->stream_type = stream->i_type;
        }
    }
    dvbpsi_pmt_delete(pmt);
}

static DvbPsiProgInfo *ts_analyzer_dvbpsi_add_program(TsAnalyzer *analyzer, uint16_t prog_number, uint16_t pid)
{
    DvbPsiProgInfo *info = NULL;
    size_t j;
    for (j = 0; j < analyzer->pmt_handle_count; ++j) {
        if (analyzer->pmt_handles[j].prog_number == prog_number) {
            info = &analyzer->pmt_handles[j];
            break;
        }
    }
    if (info == NULL) {
        info = &analyzer->pmt_handles[analyzer->pmt_handle_count++];
        info->prog_number = prog_number;
        info->pid = pid;
        info->handle = dvbpsi_new(ts_analyzer_dvbpsi_message, DVBPSI_MSG_ERROR);
        dvbpsi_pmt_attach(info->handle, prog_number, (dvbpsi_pmt_callback)ts_analyzer_dvbpsi_pmt_cb, analyzer);
    }

    _ts_analyzer_add_pid(analyzer, info->pid, PID_TYPE_PMT);

    return info;
}

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

static bool ts_analyzer_handle_packet_internal(TsAnalyzer *analyzer)
{
    /* analyze pid */
    uint16_t pid = ts_get_pid(analyzer->packet_data);
    if (pid == 0) {
        if (analyzer->pat_handle)
            dvbpsi_packet_push(analyzer->pat_handle, analyzer->packet_data);
    }
    else {
        /* check for programs, push packet to handle. */
        size_t j;
        for (j = 0; j < analyzer->pmt_handle_count; ++j) {
            if (analyzer->pmt_handles[j].pid == pid) {
                if (analyzer->pmt_handles[j].handle)
                    dvbpsi_packet_push(analyzer->pmt_handles[j].handle, analyzer->packet_data);
                break;
            }
        }
    }

    PidInfo *info = pid_info_manager_add_pid(analyzer->pmgr, pid);

    /* pass to handler */
    return analyzer->klass.handle_packet(info, analyzer->packet_data, analyzer->packet_offset, analyzer->cb_userdata);
}

static void ts_analyzer_process_packet(TsAnalyzer *analyzer)
{
    if (ts_validate(analyzer->packet_data)) {
        if (!ts_analyzer_handle_packet_internal(analyzer))
            analyzer->error_occurred = 1;
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

    analyzer->pat_handle = dvbpsi_new(ts_analyzer_dvbpsi_message, DVBPSI_MSG_ERROR);
    dvbpsi_pat_attach(analyzer->pat_handle, (dvbpsi_pat_callback)ts_analyzer_dvbpsi_pat_cb, analyzer);

    return analyzer;
}

void ts_analyzer_free(TsAnalyzer *analyzer)
{
    if (analyzer == NULL)
        return;
    if (analyzer->pat_handle) {
        if (analyzer->pat_handle->p_decoder)
            dvbpsi_pat_detach(analyzer->pat_handle);
        dvbpsi_delete(analyzer->pat_handle);
    }
    size_t j;
    for (j = 0; j < analyzer->pmt_handle_count; ++j) {
        if (analyzer->pmt_handles[j].handle) {
            if (analyzer->pmt_handles[j].handle->p_decoder)
                dvbpsi_pmt_detach(analyzer->pmt_handles[j].handle);
            dvbpsi_delete(analyzer->pmt_handles[j].handle);
        }
    }
    util_free(analyzer);
}

void ts_analyzer_set_pid_info_manager(TsAnalyzer *analyzer, PidInfoManager *pmgr)
{
    if (analyzer)
        analyzer->pmgr = pmgr;
}

void ts_analyzer_push_buffer(TsAnalyzer *analyzer, const uint8_t *buffer, size_t len)
{
    /* if packet_bytes_read < 188 read min{188-packet_bytes_read,len} bytes from buffer
     * else check if byte 0 valid; if not sync stream */
    analyzer->buffer = (uint8_t *)buffer;
    analyzer->remaining = len;

    if (analyzer->packet_bytes_read == 0 && !ts_validate(analyzer->buffer))
        ts_analyzer_sync_stream(analyzer);

    while (analyzer->remaining && !analyzer->error_occurred) {
        ts_analyzer_read_packet_partial(analyzer);
    }
}
