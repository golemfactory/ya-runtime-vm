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

/* All of the messages can respond with RESP_ERR in addition to what's listed
 * below. */
enum HOST_MSG_TYPE {
    /* Expected response: RESP_OK */
    MSG_QUIT = 1,

    /* Expected response: RESP_OK_U64 - process ID. */
    MSG_RUN_PROCESS,

    /* Expected response: RESP_OK */
    MSG_KILL_PROCESS,

    /* Expected response: RESP_OK */
    MSG_MOUNT_VOLUME,

    /* Expected response: RESP_OK */
    MSG_UPLOAD_FILE,

    /* Expected response: RESP_OK_BYTES - chunk of process' output */
    MSG_QUERY_OUTPUT,

    /* Expected response: RESP_OK */
    MSG_PUT_INPUT,

    /* Expected response: RESP_OK */
    MSG_SYNC_FS,
};

enum SUB_MSG_QUIT_TYPE {
    /* End of sub-messages. */
    SUB_MSG_QUIT_END = 0,
};

/* All options except binary path and argv are optional. */
enum SUB_MSG_RUN_PROCESS_TYPE {
    /* End of sub-messages. */
    SUB_MSG_RUN_PROCESS_END = 0,
    /* Binary path. (BYTES) */
    SUB_MSG_RUN_PROCESS_BIN,
    /* Argv. (ARRAY) */
    SUB_MSG_RUN_PROCESS_ARG,
    /* Environment variables. (ARRAY) */
    SUB_MSG_RUN_PROCESS_ENV,
    /* Uid to run as. (u32) */
    SUB_MSG_RUN_PROCESS_UID,
    /* Gid to run as. (u32) */
    SUB_MSG_RUN_PROCESS_GID,
    /* Redirect a fd to the given path. (u32 + REDIRECT_FD_TYPE (1-byte)
     * + type sepcific data). */
    SUB_MSG_RUN_PROCESS_RFD,
    /* Path to set as current working directory. (BYTES) */
    SUB_MSG_RUN_PROCESS_CWD,
    /* This process is an entrypoint. (No body) */
    SUB_MSG_RUN_PROCESS_ENT,
};

enum SUB_MSG_KILL_PROCESS_TYPE {
    /* End of sub-messages. */
    SUB_MSG_KILL_PROCESS_END = 0,
    /* ID of process. (u64) */
    SUB_MSG_KILL_PROCESS_ID,
};

enum SUB_MSG_MOUNT_VOLUME_TYPE {
    /* End of sub-messages. */
    SUB_MSG_MOUNT_VOLUME_END = 0,
    /* Mount tag. (BYTES) */
    SUB_MSG_MOUNT_VOLUME_TAG,
    /* Path to mount at. (BYTES) */
    SUB_MSG_MOUNT_VOLUME_PATH,
};

enum SUB_MSG_UPLOAD_FILE_TYPE {
    /* End of sub-messages. */
    SUB_MSG_UPLOAD_FILE_END = 0,
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
};

enum SUB_MSG_QUERY_OUTPUT_TYPE {
    /* End of sub-messages. */
    SUB_MSG_QUERY_OUTPUT_END = 0,
    /* ID of process. (u64) */
    SUB_MSG_QUERY_OUTPUT_ID,
    /* File descriptor (u8) */
    SUB_MSG_QUERY_OUTPUT_FD,
    /* Offset in output (default = 0). (u64) */
    SUB_MSG_QUERY_OUTPUT_OFF,
    /* Requested length. (u64) */
    SUB_MSG_QUERY_OUTPUT_LEN,
};

enum SUB_MSG_PUT_INPUT_TYPE {
    /* End of sub-messages. */
    SUB_MSG_PUT_INPUT_END = 0,
    /* ID of process. (u64) */
    SUG_MSG_PUT_INPUT_ID,
    /* Data to put on process' stdin. (BYTES) */
    SUB_MSG_PUT_INPUT_DATA,
};

enum REDIRECT_FD_TYPE {
    /* Invalid type (useful only internally). */
    REDIRECT_FD_INVALID = -1,
    /* Path to the file. (BYTES) */
    REDIRECT_FD_FILE = 0,
    /* Buffer size. (u64) */
    REDIRECT_FD_PIPE_BLOCKING,
    /* Buffer size. (u64) */
    REDIRECT_FD_PIPE_CYCLIC,
};

enum GUEST_MSG_TYPE {
    /* No body. */
    RESP_OK = 0,
    /* Number. (u64) */
    RESP_OK_U64,
    /* Bytes. (BYTES) */
    RESP_OK_BYTES,
    /* Error code. (u32) */
    RESP_ERR,
    /* ID of process and a file descriptor. (u64 + u32) */
    NOTIFY_OUTPUT_AVAILABLE,
    /* ID of process and exit reason (two bytes). (u64 + u8 + u8) */
    NOTIFY_PROCESS_DIED,
};

#pragma pack(pop)

#endif // _PROTO_H
