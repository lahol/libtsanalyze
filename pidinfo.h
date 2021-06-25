#pragma once

#include <stdint.h>

typedef enum {
    PID_TYPE_PAT = 0,
    PID_TYPE_PMT,
    PID_TYPE_EIT, /* 18 */
    PID_TYPE_SDT, /* 17 */
    PID_TYPE_RST, /* 19 */
    PID_TYPE_VIDEO_11172,
    PID_TYPE_VIDEO_13818,
    PID_TYPE_VIDEO_14496,
    PID_TYPE_AUDIO_11172,
    PID_TYPE_AUDIO_13818,
    PID_TYPE_TELETEXT,
    PID_TYPE_OTHER
} PidType;

/** Information about a PID, generated from PAT/PMT */
typedef struct _PidInfo {
    uint16_t pid; /**< The PID this information belongs to. */
    PidType type; /**< The type of this pid. */
    uint8_t stream_type; /**< The stream type associated to this pid. */
    uint16_t program; /**< The program this pid belongs toi. */
} PidInfo;

/** Manage Information about pids. */
typedef struct _PidInfoManager PidInfoManager;

/** Callback to free private data. */
typedef void (*PidInfoPrivateDataFree)(void *);

/** Create a new pid info manager.
 *  @return The newly allocated pid info manager.
 */
PidInfoManager *pid_info_manager_new();

/** Free a pid info manager.
 *  @param[in] pmgr The pid info manager to free.
 */
void pid_info_manager_free(PidInfoManager *pmgr);

/** Add a pid to the manager.
 *  @param[in] pmgr The pid info manager.
 *  @param[in] pid The pid to add.
 *  @return The info of the pid, possibly created.
 */
PidInfo *pid_info_manager_add_pid(PidInfoManager *pmgr, uint16_t pid);

/** Register a client with the pid info manager.
 *  @note Currently only one client is supported.
 *  @param[in] pmgr The pid info manager to register the client to.
 *  @return The new, unique client id.
 */
uint16_t pid_info_manager_register_client(PidInfoManager *pmgr);

/** Set private data of the pid info.
 *  @param[in] pinfo The pid info to set private data for.
 *  @param[in] client_id The client id as returned by register_client().
 *  @param[in] data The actual data to be set.
 *  @param[in] destroy_data_func Callback to a function to free the data.
 */
void pid_info_set_private_data(PidInfo *pinfo, uint16_t client_id, void *data, PidInfoPrivateDataFree destroy_data_func);

/** Get private data of the pid info.
 *  @param[in] pinfo The pid info to determine the private data for.
 *  @param[in] client_id The client id as returned by register_client().
 *  @return The private data associated with the client.
 */
void *pid_info_get_private_data(PidInfo *pinfo, uint16_t client_id);

/** Set private data of the pid info given by pid.
 *  @param[in] pmgr The pid manager.
 *  @param[in] pid The pid to set the info for.
 *  @param[in] client_id The client id as returned by register_client().
 *  @param[in] data The actual data to be set.
 *  @param[in] destroy_data_func Callback to a function to free the data.
 */
void pid_info_manager_set_private_data(PidInfoManager *pmgr, uint16_t pid, uint16_t client_id, void *data, PidInfoPrivateDataFree destroy_data_func);

/** Get private data of the pid info given by pid.
 *  @param[in] pmgr The pid manager.
 *  @param[in] pid The pid to get the info for.
 *  @param[in] client_id The client id as returned by register_client().
 *  @return The private data associated with the client.
 */
void *pid_info_manager_get_private_data(PidInfoManager *pmgr, uint16_t pid, uint16_t client_id);
