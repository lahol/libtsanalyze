#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct _TsAnalyzer TsAnalyzer;

typedef struct _TsAnalyzerClass {
    /* callbacks for packets/tables/… */
    /* Handle a packet.
     * 1. Packet data,
     * 2. Offset (bytes consumed in analyzer),
     * 3. User data
    */
    bool (*handle_packet)(const uint8_t *, const size_t, void *); /* required */
} TsAnalyzerClass;

TsAnalyzer *ts_analyzer_new(TsAnalyzerClass *klass, void *userdata);
void ts_analyzer_free(TsAnalyzer *analyzer);

void ts_analyzer_push_buffer(TsAnalyzer *analyzer, const uint8_t *buffer, size_t len);
