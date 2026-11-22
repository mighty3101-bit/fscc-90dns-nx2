#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <switch.h>
#include "main.h"
static PrintConsole *console;
static const char *statusNames[] = { "blocked", "unblocked", "unresolved", "timeout", "offline", "error", "event-wait", "N/A" };
static const char *hostnames[] = {
    "nintendo.com", "nintendo.net", "nintendo.jp", "nintendo.co.jp",
    "nintendo.co.uk", "nintendo-europe.com", "nintendowifi.net", "nintendo.fr",
    "nintendo.de", "nintendo.es", "nintendo.it", "nintendo.co.kr",
    "nintendo.tw", "nintendo.com.hk", "nintendo.com.au", "nintendoswitch.com",
    "nintendoswitch.cn", "nintendocdn.com", "sun.hac.lp1.d4c.nintendo.net",
    "bcat-data-lp1.cdn.nintendo.net", "aauth-lp1.ndas.srv.nintendo.net",
    "dauth-lp1.ndas.srv.nintendo.net", "receive-lp1.dg.srv.nintendo.net",
    "nega-lp1-upload.s3.us-east-1.amazonaws.com", "scsi-upload-lp1.s3.us-west-2.amazonaws.com"
};
static void printStatus(RESOLVER_STATUS st) {
    const char *col = (st == DNS_BLOCKED) ? CONSOLE_GREEN : ((st == DNS_RESOLVED) ? CONSOLE_RED : CONSOLE_YELLOW);
    printf("%s%-10s" CONSOLE_RESET, col, statusNames[st]);
}
static void fmtIp(u32 ip_val, char *buf, size_t sz) {
    if (ip_val == 0) { snprintf(buf, sz, "-"); return; }
    struct in_addr a; a.s_addr = ip_val; inet_ntop(AF_INET, &a, buf, (socklen_t)sz);
}
RESOLVER_STATUS resolveHostnameLegacy(const char *hostname) {
    struct hostent *he; struct in_addr a; errno = 0;
    he = gethostbyname(hostname);
    if (he) {
        RESOLVER_STATUS result = DNS_UNRESOLVED;
        if (he->h_addrtype != AF_INET || he->h_length != sizeof(a) || !he->h_addr_list) { freehostent(he); return DNS_UNRESOLVED; }
        for (char **address = he->h_addr_list; *address; address++) {
            memcpy(&a, *address, sizeof(a));
            if (a.s_addr != htonl(INADDR_LOOPBACK) && a.s_addr != htonl(INADDR_ANY)) { result = DNS_RESOLVED; break; }
            result = DNS_BLOCKED;
        }
        freehostent(he); return result;
    }
    return (errno == ETIMEDOUT) ? DNS_TIMEOUT : DNS_UNRESOLVED;
}
static void runAllTests(void) {
    const char *logPath = "sdmc:/fscc-90dns-nx2-log.txt";
    FwInfo fw; detectRealFirmware(&fw);
    u32 ip = 0, mask = 0, gw = 0, dns1 = 0, dns2 = 0;
    Result net_rc = nifmGetCurrentIpConfigInfo(&ip, &mask, &gw, &dns1, &dns2);
    if (R_FAILED(net_rc)) net_rc = nifmGetCurrentIpAddress(&ip);
    char s_ip[24], s_gw[24], s_d1[24], s_d2[24];
    fmtIp(ip, s_ip, sizeof(s_ip)); fmtIp(gw, s_gw, sizeof(s_gw)); fmtIp(dns1, s_d1, sizeof(s_d1)); fmtIp(dns2, s_d2, sizeof(s_d2));
    bool offline = R_FAILED(net_rc) || ip == 0;
    printf(CONSOLE_CYAN "FSCC + 90DNS Tester NX2 v1.0.0" CONSOLE_RESET "  |  B: Exit   X: Retry\n");
    printf("FW %u.%u.%u (rev %u.%u) [%s]  |  kaiHEN: %s\n", fw.major, fw.minor, fw.micro, fw.rev_major, fw.rev_minor, fw.real_from_setsys ? "set:sys OK" : (fw.via_kaihen_fallback ? "kaiHEN set:sys" : "hbloader"), fw.is_kaihen ? "OUI" : "NON");
    printf("IP: %s  |  GW: %s  |  DNS1: %s  DNS2: %s\n", s_ip, s_gw, s_d1, s_d2);
    if (offline) printf(CONSOLE_YELLOW "Reseau indisponible : blocage non verifiable." CONSOLE_RESET "\n");
    printf("%-43s %-10s %-10s\n", "Domaine", "Legacy", "Async");
    FILE *log = fopen(logPath, "a");
    if (log) {
        time_t now = time(NULL); struct tm *ts = localtime(&now); char d[32];
        fprintf(log, "\n=== FSCC + 90DNS Tester NX2 v1.0.0 ===\n");
        if (ts && strftime(d, sizeof(d), "%Y-%m-%d %H:%M:%S", ts)) fprintf(log, "Time: %s\n", d);
        fprintf(log, "FW %u.%u.%u (rev %u.%u) kaiHEN=%d setsys=%d/%d rc=0x%08X\n", fw.major, fw.minor, fw.micro, fw.rev_major, fw.rev_minor, fw.is_kaihen?1:0, fw.real_from_setsys?1:0, fw.via_kaihen_fallback?1:0, fw.setsys_rc);
        fprintf(log, "IP=%s GW=%s DNS1=%s DNS2=%s\n", s_ip, s_gw, s_d1, s_d2);
    }
    unsigned int total = (unsigned int)(sizeof(hostnames) / sizeof(hostnames[0]));
    unsigned int legacyBlocked = 0, asyncBlocked = 0, asyncUnblocked = 0, asyncNa = 0;
    for (unsigned int i = 0; i < total; i++) {
        RESOLVER_STATUS legacy = offline ? DNS_OFFLINE : resolveHostnameLegacy(hostnames[i]);
        Result probe_rc = 0;
        RESOLVER_STATUS async = offline ? DNS_OFFLINE : resolveHostnameAsync(hostnames[i], log, &probe_rc);
        if (legacy == DNS_BLOCKED) legacyBlocked++;
        if (async == DNS_BLOCKED) asyncBlocked++;
        else if (async == DNS_RESOLVED) asyncUnblocked++;
        else if (async == DNS_NA) asyncNa++;
        printf("%-43s ", hostnames[i]); printStatus(legacy); printf(" "); printStatus(async); printf("\n"); consoleUpdate(console);
        if (log) fprintf(log, "%-43s %-10s %-10s (rc=0x%08X)\n", hostnames[i], statusNames[legacy], statusNames[async], probe_rc);
    }
    printf("Resume -> Legacy: %u/%u bloq | Async: %u bloq, %u fuite, %u N/A\n", legacyBlocked, total, asyncBlocked, asyncUnblocked, asyncNa);
    if (!offline) runHttpFsccChecks(log);
    if (log) { fclose(log); printf("Log: %s\n", logPath); }
    consoleUpdate(console);
}
int main(int argc, char **argv) {
    (void)argc; (void)argv;
    console = consoleGetDefault(); consoleInit(console);
    PadState pad; padConfigureInput(1, HidNpadStyleSet_NpadFullCtrl); padInitializeAny(&pad);
    socketInitializeDefault(); nifmInitialize(NifmServiceType_User);
    runAllTests();
    while (appletMainLoop()) {
        padUpdate(&pad); u64 kDown = padGetButtonsDown(&pad);
        if (kDown & HidNpadButton_B) break;
        if (kDown & HidNpadButton_X) { consoleClear(); runAllTests(); }
    }
    nifmExit(); socketExit(); consoleExit(console); return 0;
}
