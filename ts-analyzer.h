#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "pidinfo.h"

typedef struct _TsAnalyzer TsAnalyzer;

typedef struct _TsAnalyzerClass {
    /* callbacks for packets/tables/… */
    /* Handle a packet.
     * 1. PID info
     * 2. Packet data,
     * 3. Offset (bytes consumed in analyzer),
     * 4. User data
    */
    bool (*handle_packet)(PidInfo *, const uint8_t *, const size_t, void *); /* required */
} TsAnalyzerClass;

TsAnalyzer *ts_analyzer_new(TsAnalyzerClass *klass, void *userdata);
void ts_analyzer_free(TsAnalyzer *analyzer);

void ts_analyzer_set_pid_info_manager(TsAnalyzer *analyzer, PidInfoManager *pmgr);

void ts_analyzer_push_buffer(TsAnalyzer *analyzer, const uint8_t *buffer, size_t len);
