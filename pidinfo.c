#include "pidinfo.h"
#include "utils.h"

typedef struct _PidInfoListEntry {
    PidInfo info;
    void *private_data;
    PidInfoPrivateDataFree destroy_data_func;
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

PidInfoManager *pid_info_manager_new()
{
    PidInfoManager *pmgr = util_alloc0(sizeof(PidInfoManager));

    return pmgr;
}

void pid_info_manager_free(PidInfoManager *pmgr)
{
    if (pmgr) {
        size_t j;
        for (j = 0; j < pmgr->pid_count; ++j) {
            if (pmgr->pidlist[j]->private_data && pmgr->pidlist[j]->destroy_data_func)
                pmgr->pidlist[j]->destroy_data_func(pmgr->pidlist[j]->private_data);
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
    return pmgr != NULL ? ++pmgr->max_client_id : 0;
}

void pid_info_set_private_data(PidInfo *pinfo, uint16_t client_id, void *data, PidInfoPrivateDataFree destroy_data_func)
{
    if (pinfo == NULL)
        return;
    ((PidInfoListEntry *)pinfo)->private_data = data;
    ((PidInfoListEntry *)pinfo)->destroy_data_func = destroy_data_func;
}

void *pid_info_get_private_data(PidInfo *pinfo, uint16_t client_id)
{
    if (pinfo == NULL)
        return NULL;
    return ((PidInfoListEntry *)pinfo)->private_data;
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

