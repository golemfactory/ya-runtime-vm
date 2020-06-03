#ifndef _PROTO_H
#define _PROTO_H

#include <stdint.h>

#pragma pack(push, 1)

/*
 * Host -> Guest
 *
 * - u64 message ID (non zero),
 * - 1 byte type,
 * - stream of sub-messages ended with `SUB_MSG_END`; each sub-message
 *   consists of 1 byte subtype subtype-specific body (described near each
 *   subtype below) of types:
 * BYTES - unsigned 64bit length, followed by exactly that many bytes;
 * ARRAY - unsigned 64bit number of BYTES objects, that follow immediately
 *         (encoded as described above);
 * u64   - unsigned 64bit number,
 * u32   - unsigned 32bit number.
 *
 * All numbers are encoded in little-endian format.
 */

/*
 * Guest -> Host
 *
 * Guest sends two types of messages - response and asynchronous notification:
 * - u64: message ID matching the request for response, 0 for notification,
 * - 1 byte type, followed by type-specific body.
 */

typedef uint64_t msg_id_t;

struct msg_hdr {
    msg_id_t msg_id;
    uint8_t type;
};

enum MSG_TYPE {
    MSG_QUIT = 1,
    /* Returns ID of spawned process. */
    MSG_RUN_PROCESS,
    MSG_KILL_PROCESS,
    MSG_MOUNT_VOLUME,
    MSG_UPLOAD_FILE,
    /* Returns chunk of process' output as BYTES. */
    MSG_QUERY_OUTPUT,
    MSG_PUT_INPUT,
    MSG_SYNC_FS,
};

enum MSG_SUB_TYPE {
    /* End of sub-messages. */
    SUB_MSG_END = 0,

    /* MSG_RUN_PROCESS */
    /* Binary path. (BYTES) */
    SUB_MSG_RUN_PROCESS_BIN,
    /* Argv. (ARRAY) */
    SUB_MSG_RUN_PROCESS_ARG,
    /* Environment variables. (ARRAY) */
    SUB_MSG_RUN_PROCESS_ENV,
    /* Uid to run as. (u32) */
    SUB_MSG_RUN_PROCESS_UID,
    /* Redirect a fd to the given path. (u32 + REDIRECT_FD_TYPE (1-byte)) */
    SUB_MSG_RUN_PROCESS_RFD,

    /* MSG_KILL_PROCESS */
    /* ID of process. (u64) */
    SUB_MSG_KILL_PROCESS_ID,

    /* MSG_MOUNT_VOLUME */
    /* Path of device to be mounted. (BYTES) */
    SUB_MSG_MOUNT_VOLUME_DEV,
    /* Path to mount at. (BYTES) */
    SUB_MSG_MOUNT_VOLUME_PATH,

    /* MSG_UPLOAD_FILE */
    /* Path of the file. (BYTES) */
    SUB_MSG_UPLOAD_FILE_PATH,
    /* Permissions of the file. (u32) */
    SUB_MSG_UPLOAD_FILE_PERM,
    /* Owner (user) of the file. (u32) */
    SUB_MSG_UPLOAD_FILE_USR,
    /* Owner (group) of the file. (u32) */
    SUB_MSG_UPLOAD_FILE_GRP,
    /* Data to put into file. (BYTES) */
    SUB_MSG_UPLOAD_FILE_DATA,

    /* MSG_QUERY_OUTPUT */
    /* ID of process. (u64) */
    SUB_MSG_QUERY_OUTPUT_ID,
    /* Offset in output. (u64) */
    SUB_MSG_QUERY_OUTPUT_OFF,
    /* Requested length. (u64) */
    SUB_MSG_QUERY_OUTPUT_LEN,

    /* MSG_PUT_INPUT */
    /* ID of process. (u64) */
    SUG_MSG_PUT_INPUT_ID,
    /* Data to put on process' stdin. (BYTES) */
    SUB_MSG_PUT_INPUT_DATA,

    MSG_SUB_TYPE_BOUND,
};
_Static_assert(MSG_SUB_TYPE_BOUND <= 0xff, "MSG_SUB_TYPE overflows 1 byte!");

enum REDIRECT_FD_TYPE {
    /* Path to the file. (BYTES) */
    REDIRECT_FD_FILE,
    /* Buffer size. (u64) */
    REDIRECT_FD_PIPE_BLOCKING,
    /* Buffer size. (u64) */
    REDIRECT_FD_PIPE_CYCLIC,
};

enum RESP_TYPE {
    /* No body. */
    RESP_OK,
    /* Error code. (u32) */
    RESP_ERR,
    /* ID of process and a file descriptor. (u64 + u32) */
    NOTIFY_OUTPUT_AVAILABLE,
    /* ID of process and exit reason. (u64 + u32) */
    NOTIFY_PROCESS_DIED,
};

#pragma pack(pop)

#endif // _PROTO_H
