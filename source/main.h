#ifndef __FSCC_90DNS_NX2_H
#define __FSCC_90DNS_NX2_H
#include <stdio.h>
#include <stdbool.h>
#include <switch.h>
typedef enum {
    DNS_BLOCKED = 0,
    DNS_RESOLVED,
    DNS_UNRESOLVED,
    DNS_TIMEOUT,
    DNS_OFFLINE,
    DNS_ERROR,
    DNS_EVENT_WAIT,
    DNS_NA
} RESOLVER_STATUS;
typedef struct {
    u8 major, minor, micro, rev_major, rev_minor;
    bool real_from_setsys, via_kaihen_fallback, is_kaihen;
    Result setsys_rc;
} FwInfo;
void detectRealFirmware(FwInfo *out);
RESOLVER_STATUS resolveHostnameLegacy(const char *hostname);
RESOLVER_STATUS resolveHostnameAsync(const char *hostname, FILE *log, Result *out_probe_rc);
void runHttpFsccChecks(FILE *log);
#endif
