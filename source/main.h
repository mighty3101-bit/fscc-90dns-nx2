#ifndef __90DNS_TESTER_NX2_H
#define __90DNS_TESTER_NX2_H
#include <stdio.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <switch.h>
#define APP_VERSION_STR "1.2.0"
#define LOG_FILE_PATH "sdmc:/90dns-tester-nx2.log"
#define MAX_DOMAINS 55
#define MAX_HTTP_TARGETS 5
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
typedef struct {
    const char *host;
    const char *expected_org;
    int state;
    int http_code;
    int gai_err;
    char ip[INET_ADDRSTRLEN];
    char org[64];
} HttpCheckResult;
void detectRealFirmware(FwInfo *out);
RESOLVER_STATUS resolveHostnameLegacy(const char *hostname);
RESOLVER_STATUS resolveHostnameAsync(Service *resolver, const char *hostname, FILE *log, Result *out_probe_rc);
void runHttpConnectivityChecks(HttpCheckResult *results, size_t max_results, size_t *out_count, FILE *log);
#endif
