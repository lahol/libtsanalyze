#include "pidinfo.h"
#include "utils.h"

#define PID_INFO_CLIENT_MAX 8

typedef struct {
    void *data;
    PidInfoPrivateDataFree destroy;
} PidInfoPrivateData;

typedef struct _PidInfoListEntry {
    PidInfo info;
    PidInfoPrivateData private_data[PID_INFO_CLIENT_MAX];
} PidInfoListEntry;

#define PID_INFO_BLOCK 32

struct _PidInfoManager {
    uint16_t max_client_id;

    size_t pid_count;
    size_t allocated_pid_count;

    PidInfoListEntry **pidlist;
};

/** Add a pid info to the manager
 *  @param[in] pmgr The pid info manager.
 *  @param[in] pid The pid for which to add the info.
 *  @return The newly added info.
 */
PidInfoListEntry *_pid_info_manager_add_pid(PidInfoManager *pmgr, uint16_t pid)
{
    if (!pmgr)
        return NULL;
    if (pmgr->pid_count == pmgr->allocated_pid_count) {
        pmgr->allocated_pid_count += PID_INFO_BLOCK;
        pmgr->pidlist = util_realloc(pmgr->pidlist, pmgr->allocated_pid_count * sizeof(PidInfoListEntry *));
    }
    PidInfoListEntry *entry = util_alloc0(sizeof(PidInfoListEntry));
    pmgr->pidlist[pmgr->pid_count++] = entry;
    entry->info.pid = pid;

    return entry;
}

/** Find the info about a pid.
 *  @param[in] pmgr The pid info manager.
 *  @param[in] pid The pid for which to determine the info.
 *  @param[in] create Whether to create the info if it is not found.
 *  @return The pid info for this pid.
 */
PidInfoListEntry *_pid_info_manager_find_pid(PidInfoManager *pmgr, uint16_t pid, bool create)
{
    if (pmgr == NULL)
        return NULL;
    size_t j;
    for (j = 0; j < pmgr->pid_count; ++j) {
        if (pmgr->pidlist[j]->info.pid == pid) {
            return pmgr->pidlist[j];
        }
    }

    return create ? _pid_info_manager_add_pid(pmgr, pid) : NULL;
}

PidInfoManager *pid_info_manager_new(void)
{
    PidInfoManager *pmgr = util_alloc0(sizeof(PidInfoManager));

    return pmgr;
}

void pid_info_manager_free(PidInfoManager *pmgr)
{
    if (pmgr) {
        size_t j;
        size_t k;
        for (j = 0; j < pmgr->pid_count; ++j) {
            for (k = 0; k < pmgr->max_client_id; ++k) {
                if (pmgr->pidlist[j]->private_data[k].data && pmgr->pidlist[j]->private_data[k].destroy)
                    pmgr->pidlist[j]->private_data[k].destroy(pmgr->pidlist[j]->private_data[k].data);
            }
            util_free(pmgr->pidlist[j]);
        }
        util_free(pmgr->pidlist);
        util_free(pmgr);
    }
}

PidInfo *pid_info_manager_add_pid(PidInfoManager *pmgr, uint16_t pid)
{
    PidInfoListEntry *entry = _pid_info_manager_find_pid(pmgr, pid, true);
    return (PidInfo *)entry;
}

uint16_t pid_info_manager_register_client(PidInfoManager *pmgr)
{
    return pmgr != NULL && pmgr->max_client_id < PID_INFO_CLIENT_MAX ? pmgr->max_client_id++ : PID_INFO_CLIENT_MAX;
}

void pid_info_set_private_data(PidInfo *pinfo, uint16_t client_id, void *data, PidInfoPrivateDataFree destroy_data_func)
{
    if (pinfo == NULL || client_id >= PID_INFO_CLIENT_MAX)
        return;
    ((PidInfoListEntry *)pinfo)->private_data[client_id].data = data;
    ((PidInfoListEntry *)pinfo)->private_data[client_id].destroy = destroy_data_func;
}

void *pid_info_get_private_data(PidInfo *pinfo, uint16_t client_id)
{
    if (pinfo == NULL || client_id >= PID_INFO_CLIENT_MAX)
        return NULL;
    return ((PidInfoListEntry *)pinfo)->private_data[client_id].data;
}

void pid_info_clear_private_data(PidInfo *pinfo, uint16_t client_id)
{
    if (pinfo == NULL || client_id >= PID_INFO_CLIENT_MAX)
        return;
    PidInfoPrivateData *pdata = &((PidInfoListEntry *)pinfo)->private_data[client_id];
    if (pdata->destroy)
        pdata->destroy(pdata->data);
    pdata->data = NULL;
}

void pid_info_manager_set_private_data(PidInfoManager *pmgr, uint16_t pid, uint16_t client_id, void *data, PidInfoPrivateDataFree destroy_data_func)
{
    PidInfoListEntry *entry = _pid_info_manager_find_pid(pmgr, pid, false);
    pid_info_set_private_data((PidInfo *)entry, client_id, data, destroy_data_func);
}

void *pid_info_manager_get_private_data(PidInfoManager *pmgr, uint16_t pid, uint16_t client_id)
{
    PidInfoListEntry *entry = _pid_info_manager_find_pid(pmgr, pid, false);
    return pid_info_get_private_data((PidInfo *)entry, client_id);
}

void pid_info_manager_enumerate_pid_infos(PidInfoManager *pmgr, PidInfoEnumFunc callback, void *userdata)
{
    if (pmgr == NULL || callback == NULL)
        return;
    size_t j;
    for (j = 0; j < pmgr->pid_count; ++j) {
        if (!callback((PidInfo *)pmgr->pidlist[j], userdata))
            return;
    }
}

void pid_info_manager_clear_private_data(PidInfoManager *pmgr, uint16_t client_id)
{
    if (pmgr == NULL || client_id >= PID_INFO_CLIENT_MAX)
        return;
    size_t j;
    for (j = 0; j < pmgr->pid_count; ++j) {
        pid_info_clear_private_data((PidInfo *)pmgr->pidlist[j], client_id);
    }
}

size_t pid_info_manager_get_pid_count(PidInfoManager *pmgr)
{
    return pmgr != NULL ? pmgr->pid_count : 0;
}
