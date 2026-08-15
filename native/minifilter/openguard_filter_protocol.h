#pragma once

#include <stdint.h>

#define OPENGUARD_FILTER_PROTOCOL_VERSION 1u
#define OPENGUARD_FILTER_MAXIMUM_PATH_CHARS 1024u
#define OPENGUARD_FILTER_REPLY_ALLOW 0u
#define OPENGUARD_FILTER_REPLY_DENY 1u

// Fixed-width, pointer-free messages are the only structures permitted across
// the user/kernel boundary. Every receiver must validate version and size.
typedef struct OPENGUARD_FILE_EVENT {
    uint32_t version;
    uint32_t size;
    uint64_t sequence;
    uint64_t process_id;
    uint32_t desired_access;
    uint32_t operation;
    uint16_t path[OPENGUARD_FILTER_MAXIMUM_PATH_CHARS];
} OPENGUARD_FILE_EVENT;

typedef struct OPENGUARD_FILE_REPLY {
    uint32_t version;
    uint32_t size;
    uint64_t sequence;
    uint32_t decision;
    uint32_t reserved;
} OPENGUARD_FILE_REPLY;
