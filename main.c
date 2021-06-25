#include "ts-analyzer.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>

typedef struct {
    uint64_t packet_count;
    uint32_t client_id;
} TsPidStat;

typedef struct {
    uint64_t count;
} TsPidData;

static char* pid_names[] = {
    "PAT",
    "PMT",
    "EIT",
    "SDT",
    "RST",
    "Video/11172",
    "Video/13818",
    "Video/14496",
    "Audio/11172",
    "Audio/13818",
    "Teletext",
    "Other"
};

bool ts_analyze_handle_packet(PidInfo *pidinfo, const uint8_t *packet, const size_t offset, TsPidStat *stats)
{
    if (!stats || !pidinfo) {
        fprintf(stderr, "Error at %zu\n", offset);
    }

    TsPidData *piddata = pid_info_get_private_data(pidinfo, stats->client_id);
    if (!piddata) {
        piddata = malloc(sizeof(TsPidData));
        memset(piddata, 0, sizeof(TsPidData));
        pid_info_set_private_data(pidinfo, stats->client_id, piddata, (PidInfoPrivateDataFree)free);
    }
    ++piddata->count;
    ++stats->packet_count;

    return true;
}

void ts_analyze_file(const char *filename, TsPidStat *stats, PidInfoManager *pmgr)
{
    FILE *f;
    struct stat st;
    if (stat(filename, &st) != 0)
        return;

    if ((f = fopen(filename, "r")) == NULL) {
        perror("Could not open file");
        return;
    }

    static TsAnalyzerClass tscls = {
        .handle_packet = (TsHandlePacketFunc)ts_analyze_handle_packet,
    };
    TsAnalyzer *ts_analyzer = ts_analyzer_new(&tscls, stats);

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
        fprintf(stderr, "\rProgress: %6.2f%% [%" PRIu64 " packets]",
                ((double)prog_current)/((double)prog_full)*100.0f,
                stats->packet_count);
    }

    fputs("                  \r", stderr);

    ts_analyzer_free(ts_analyzer);
    fclose(f);
}

char *format_size(size_t size)
{
    double dsize = (double)size;
    char suffix[] = {
        ' ',
        'k',
        'M',
        'T',
        0
    };
    size_t j;
    for (j = 0; suffix[j] != 0 && dsize >= 1000.0; ++j) {
        dsize /= 1000.0;
    }
    if (suffix[j] == 0) {
        dsize *= 1000.0;
        --j;
    }
    char *buffer = malloc(64);
    snprintf(buffer, 64, "%.1f %cB", dsize, suffix[j]);
    return buffer;
}

static bool _ts_analyze_print_pid_info(PidInfo *info, TsPidStat *stats)
{
    if (!stats)
        return false;
    TsPidData *data = pid_info_get_private_data(info, stats->client_id);
    if (!data)
        return true;
    char *size_str = format_size(188 * data->count);
    fprintf(stdout, " %4u | %10" PRIu64 " | %6.2f%% | %10s | %14s\n", info->pid,
            data->count, ((double)data->count)/((double)stats->packet_count)*100.0f,
            size_str, pid_names[info->type]);
    free(size_str);
    return true;
}

void ts_analyze_print(TsPidStat *stats, PidInfoManager *pmgr)
{
    /* TODO stort descending */

    fprintf(stdout, "  PID |      count |    rel. |       size |           type \n"
                    "===========================================================\n");

    pid_info_manager_enumerate_pid_infos(pmgr, (PidInfoEnumFunc)_ts_analyze_print_pid_info, stats);

    fprintf(stdout, "===========================================================\n");

    char *size_str = format_size(188 * stats->packet_count);
    fprintf(stdout, "total | %10" PRIu64 " | 100.00%% | %10s | \n",
            stats->packet_count, size_str);
    free(size_str);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "You must specify a file name.\n");
        exit(1);
    }

    TsPidStat stats;
    memset(&stats, 0, sizeof(TsPidStat));
    PidInfoManager *pmgr = pid_info_manager_new();
    stats.client_id = pid_info_manager_register_client(pmgr);

    ts_analyze_file(argv[1], &stats, pmgr);
    ts_analyze_print(&stats, pmgr);

    pid_info_manager_free(pmgr);
    return 0;
}
