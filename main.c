#include "ts-analyzer.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

bool ts_analyze_handle_packet(PidInfo *pidinfo, const uint8_t *packet, const size_t offset, void *nil)
{
    fprintf(stderr, "Offset: %zu", offset);
    if (pidinfo) {
        fprintf(stderr, ", pid: %u, type: %u, streamtype: 0x%02x", pidinfo->pid, pidinfo->type, pidinfo->stream_type);
    }
    fprintf(stderr, "\n");
    return true;
}

void ts_analyze_file(const char *filename)
{
    FILE *f;
    struct stat st;
    if (stat(filename, &st) != 0)
        return;

    if ((f = fopen(filename, "r")) == NULL) {
/*        fprintf(stderr, "Could not open file `%s'.\n", argv[1]);*/
        perror("Could not open file");
        return;
    }

    static TsAnalyzerClass tscls = {
        .handle_packet = ts_analyze_handle_packet,
    };
    TsAnalyzer *ts_analyzer = ts_analyzer_new(&tscls, NULL);

    PidInfoManager *pmgr = pid_info_manager_new();
    ts_analyzer_set_pid_info_manager(ts_analyzer, pmgr);

    uint8_t buffer[8*4096];
    size_t bytes_read;

    size_t prog_full = st.st_size;
    size_t prog_current = 0;

    /* read from file */
    while (!feof(f)) {
        bytes_read = fread(buffer, 1, 8*4096, f);
        if (bytes_read == 0) {
            fprintf(stderr, "Error reading buffer.\n");
            break;
        }
        if (bytes_read > 0) {
            ts_analyzer_push_buffer(ts_analyzer, buffer, bytes_read);

            prog_current += bytes_read;
        }
/*        fprintf(stderr, "\rProgress: %6.2f%% [%" G_GUINT64_FORMAT " packets]",
                ((double)prog_current)/((double)prog_full)*100.0f,
                pid_stat->packet_count);*/
    }

/*    fputs("                  \r", stderr);*/

    ts_analyzer_free(ts_analyzer);
    pid_info_manager_free(pmgr);
    fclose(f);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "You must specify a file name.\n");
        exit(1);
    }

    ts_analyze_file(argv[1]);
    return 0;
}
