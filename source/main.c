#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <switch.h>
#include "main.h"
typedef struct { const char *host; int group; } DomainDef;
typedef struct { const char *host; int group; RESOLVER_STATUS legacy; RESOLVER_STATUS async; Result probe_rc; } DomainResult;
static const DomainDef domainDefs[] = {
    {"nintendo.com", 0},
    {"nintendo.net", 0},
    {"nintendo.jp", 0},
    {"nintendo.co.jp", 0},
    {"nintendo.co.uk", 0},
    {"nintendo-europe.com", 0},
    {"nintendowifi.net", 0},
    {"nintendo.es", 0},
    {"nintendo.co.kr", 0},
    {"nintendo.tw", 0},
    {"nintendo.com.hk", 0},
    {"nintendo.com.au", 0},
    {"nintendo.co.nz", 0},
    {"nintendo.at", 0},
    {"nintendo.be", 0},
    {"nintendods.cz", 0},
    {"nintendo.dk", 0},
    {"nintendo.de", 0},
    {"nintendo.fi", 0},
    {"nintendo.fr", 0},
    {"nintendo.gr", 0},
    {"nintendo.hu", 0},
    {"nintendo.it", 0},
    {"nintendo.nl", 0},
    {"nintendo.no", 0},
    {"nintendo.pt", 0},
    {"nintendo.ru", 0},
    {"nintendo.se", 0},
    {"nintendo.co.za", 0},
    {"nintendo.ch", 0},
    {"nintendo.pl", 0},
    {"nintendoswitch.cn", 0},
    {"nintendoswitch.com.cn", 0},
    {"nintendoswitch.com", 0},
    {"sun.hac.lp1.d4c.nintendo.net", 0},
    {"bcat-data-lp1.cdn.nintendo.net", 0},
    {"aauth-lp1.ndas.srv.nintendo.net", 0},
    {"dauth-lp1.ndas.srv.nintendo.net", 0},
    {"receive-lp1.dg.srv.nintendo.net", 0},
    {"receive-lp1.er.srv.nintendo.net", 0},
    {"accounts.nintendo.com", 0},
    {"e0d67c509fb203858ebcb2fe3f88c2aa.baas.nintendo.com", 0},
    {"nega-lp1-upload.s3.us-east-1.amazonaws.com", 0},
    {"scsi-upload-lp1.s3.us-west-2.amazonaws.com", 0},
    {"nintendocdn.com", 1},
    {"nintendo.co.il", 1},
    {"nintendo.com.br", 1},
    {"nintendo.com.mx", 1},
    {"nintendo.co.th", 1},
    {"nintendo.sg", 1},
    {"nintendo.ph", 1},
    {"nintendo.my", 1},
    {"dns.google", 2},
    {"cloudflare-dns.com", 2},
    {"dns.quad9.net", 2},
};
static PrintConsole *console;
static const char *statusNames[] = { "blocked", "unblocked", "unresolved", "timeout", "offline", "error", "event-wait", "N/A" };
static FwInfo g_fw;
static char g_ip[24], g_gw[24], g_d1[24], g_d2[24];
static bool g_offline = false;
static DomainResult g_results[MAX_DOMAINS];
static size_t g_total_domains = 0;
static HttpCheckResult g_http[MAX_HTTP_TARGETS];
static size_t g_http_count = 0;
static unsigned int g_core_total = 0, g_core_leg_blk = 0, g_core_asy_blk = 0, g_core_leg_leak = 0, g_core_asy_leak = 0, g_asy_na = 0;
static unsigned int g_ext_total = 0, g_ext_leg_blk = 0, g_ext_asy_blk = 0;
static bool g_90dns_test_ok = false;
static void printStatus(RESOLVER_STATUS st) {
    const char *col = (st == DNS_BLOCKED) ? CONSOLE_GREEN : ((st == DNS_RESOLVED) ? CONSOLE_RED : CONSOLE_YELLOW);
    printf("%s%-10s" CONSOLE_RESET, col, statusNames[st]);
}
static void fmtIp(u32 ip_val, char *buf, size_t sz) {
    if (ip_val == 0) { snprintf(buf, sz, "-"); return; }
    struct in_addr a; a.s_addr = ip_val; inet_ntop(AF_INET, &a, buf, (socklen_t)sz);
}
static bool isSafeProxyOr90DnsIp(const char *ip_str) {
    struct in_addr a;
    if (inet_pton(AF_INET, ip_str, &a) != 1) return false;
    u32 ip = ntohl(a.s_addr);
    u8 b1 = (u8)((ip >> 24) & 0xFF);
    u8 b2 = (u8)((ip >> 16) & 0xFF);
    if (b1 == 127 || b1 == 10 || b1 == 0) return true;
    if (b1 == 192 && b2 == 168) return true;
    if (b1 == 172 && b2 >= 16 && b2 <= 31) return true;
    if (b1 == 100 && b2 >= 64 && b2 <= 127) return true;
    if (strcmp(ip_str, "95.216.149.205") == 0) return true;
    if (strcmp(ip_str, "163.172.141.219") == 0) return true;
    if (strcmp(ip_str, "207.246.121.77") == 0) return true;
    return false;
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
static void printHeader(int page) {
    printf(CONSOLE_CYAN "90DNS Tester NX2 v" APP_VERSION_STR CONSOLE_RESET "  |  L/R: Page (%d/4)   X: Retest   B: Exit\n", page + 1);
    printf("FW %u.%u.%u (rev %u.%u) [%s]  |  kaiHEN: %s\n", g_fw.major, g_fw.minor, g_fw.micro, g_fw.rev_major, g_fw.rev_minor, g_fw.real_from_setsys ? "set:sys OK" : (g_fw.via_kaihen_fallback ? "kaiHEN set:sys" : "hbloader"), g_fw.is_kaihen ? "YES" : "NO");
    printf("IP: %s | GW: %s | DNS: %s, %s\n", g_ip, g_gw, g_d1, g_d2);
    if (g_offline) printf(CONSOLE_YELLOW "Network offline: DNS blocking cannot be verified.\n");
    else printf("\n");
}
static void printSummaryFooter(void) {
    bool coreSafe = (!g_offline && g_core_leg_leak == 0 && g_core_asy_leak == 0 && g_core_leg_blk == g_core_total);
    const char *verdictCol = g_offline ? CONSOLE_YELLOW : (coreSafe ? CONSOLE_GREEN : CONSOLE_RED);
    const char *verdictTxt = g_offline ? "OFFLINE" : (coreSafe ? "SAFE (Core Blocked)" : ((g_core_leg_leak > 0 || g_core_asy_leak > 0) ? "WARNING: LEAK DETECTED" : "INCOMPLETE BLOCK"));
    printf("\nCore 90DNS (%u): Legacy %u/%u blk (%u leak) | Async %u/%u blk (%u leak, %u N/A)\n", g_core_total, g_core_leg_blk, g_core_total, g_core_leg_leak, g_core_asy_blk, g_core_total, g_core_asy_leak, g_asy_na);
    printf("Ext+DoH (%u): Legacy %u/%u blk | Async %u/%u blk  ->  %s%s" CONSOLE_RESET "\n", g_ext_total, g_ext_leg_blk, g_ext_total, g_ext_asy_blk, g_ext_total, verdictCol, verdictTxt);
}
static void renderPage(int page) {
    consoleClear();
    printHeader(page);
    if (page == 0 || page == 1) {
        size_t start = (page == 0) ? 0 : 22;
        size_t end = (page == 0) ? 22 : 44;
        if (end > g_total_domains) end = g_total_domains;
        printf(CONSOLE_CYAN "Core Nintendo & Telemetry Domains (%zu-%zu of %u):" CONSOLE_RESET "\n", start + 1, end, g_core_total);
        printf("%-51s %-10s %-10s\n", "Domain", "Legacy", "Async");
        for (size_t i = start; i < end; i++) {
            printf("%-51s ", g_results[i].host);
            printStatus(g_results[i].legacy); printf(" "); printStatus(g_results[i].async); printf("\n");
        }
    } else if (page == 2) {
        printf(CONSOLE_CYAN "Extended Regional & DoH Domains (Optional / Strict Blockers):" CONSOLE_RESET "\n");
        printf("%-51s %-10s %-10s %s\n", "Domain", "Legacy", "Async", "Type");
        for (size_t i = 44; i < g_total_domains; i++) {
            const char *tag = (g_results[i].group == 2) ? "DoH" : "Ext";
            printf("%-51s ", g_results[i].host);
            printStatus(g_results[i].legacy); printf(" "); printStatus(g_results[i].async); printf(" %s\n", tag);
        }
        printf("\n" CONSOLE_YELLOW "Note: Public 90DNS does not list these 11 domains by default;\n");
        printf("unblocked here is normal unless using a strict/custom DNS blocker." CONSOLE_RESET "\n");
    } else {
        printf(CONSOLE_CYAN "Connectivity & 90DNS HTTP Check (Port 80 + X-Organization):" CONSOLE_RESET "\n");
        if (g_offline) {
            printf(CONSOLE_YELLOW "  Skipped (network offline)." CONSOLE_RESET "\n");
        } else {
            for (size_t i = 0; i < g_http_count; i++) {
                HttpCheckResult *r = &g_http[i];
                if (r->state == -1) {
                    printf("  %-34s " CONSOLE_YELLOW "DNS FAIL (%d)" CONSOLE_RESET "\n", r->host, r->gai_err);
                } else if (r->state == -2) {
                    printf("  %-34s " CONSOLE_YELLOW "TCP ERR (%s)" CONSOLE_RESET "\n", r->host, r->ip);
                } else {
                    bool orgOk = (r->http_code == 200 && strcasecmp(r->org, r->expected_org) == 0);
                    bool is90Test = (strcmp(r->host, "90dns.test") == 0);
                    bool noLeaks = (g_core_leg_leak == 0 && g_core_asy_leak == 0);
                    const char *note = "";
                    const char *col = CONSOLE_RED;
                    if (orgOk && is90Test) { col = CONSOLE_GREEN; note = " [90DNS]"; }
                    else if (orgOk && noLeaks && (g_90dns_test_ok || isSafeProxyOr90DnsIp(r->ip))) { col = CONSOLE_GREEN; note = " [OK]"; }
                    else if (orgOk && !noLeaks) { col = CONSOLE_RED; note = " [LEAK!]"; }
                    else if (r->http_code == 200) { col = CONSOLE_YELLOW; note = " [ChkIP]"; }
                    printf("  %-34s %s%d [%s] %s%s" CONSOLE_RESET "\n", r->host, col, r->http_code, r->org[0] ? r->org : "none", r->ip, note);
                }
            }
        }
        printf("\n" CONSOLE_CYAN "How to interpret:" CONSOLE_RESET "\n");
        printf("  - 90DNS / Proxy: 90dns.test->200 [LavaTech], conntest->200 [Nintendo]\n");
        printf("  - DNS-MITM (0.0.0.0/127.0.0.1) w/o HTTP server: DNS/TCP ERR is normal\n");
        printf("  - Status: blocked=0.0.0.0/127.0.0.1 | unblocked=real IP | N/A=no Async\n");
        printf("  - Log saved to: " LOG_FILE_PATH "\n");
    }
    printSummaryFooter();
    consoleUpdate(console);
}
static void runAllTests(void) {
    detectRealFirmware(&g_fw);
    u32 ip = 0, mask = 0, gw = 0, dns1 = 0, dns2 = 0;
    Result net_rc = nifmGetCurrentIpConfigInfo(&ip, &mask, &gw, &dns1, &dns2);
    if (R_FAILED(net_rc)) net_rc = nifmGetCurrentIpAddress(&ip);
    fmtIp(ip, g_ip, sizeof(g_ip)); fmtIp(gw, g_gw, sizeof(g_gw)); fmtIp(dns1, g_d1, sizeof(g_d1)); fmtIp(dns2, g_d2, sizeof(g_d2));
    g_offline = R_FAILED(net_rc) || ip == 0;
    g_total_domains = sizeof(domainDefs) / sizeof(domainDefs[0]);
    if (g_total_domains > MAX_DOMAINS) g_total_domains = MAX_DOMAINS;
    g_core_total = 0; g_core_leg_blk = 0; g_core_asy_blk = 0; g_core_leg_leak = 0; g_core_asy_leak = 0; g_asy_na = 0;
    g_ext_total = 0; g_ext_leg_blk = 0; g_ext_asy_blk = 0; g_90dns_test_ok = false;
    consoleClear();
    printHeader(0);
    printf(CONSOLE_CYAN "Running DNS & Connectivity checks..." CONSOLE_RESET "\n");
    consoleUpdate(console);
    FILE *log = fopen(LOG_FILE_PATH, "w");
    if (log) {
        time_t now = time(NULL); struct tm *ts = localtime(&now); char d[32];
        fprintf(log, "=== 90DNS Tester NX2 v" APP_VERSION_STR " ===\n");
        if (ts && strftime(d, sizeof(d), "%Y-%m-%d %H:%M:%S", ts)) fprintf(log, "Time: %s\n", d);
        fprintf(log, "FW %u.%u.%u (rev %u.%u) kaiHEN=%d setsys=%d/%d rc=0x%08X\n", g_fw.major, g_fw.minor, g_fw.micro, g_fw.rev_major, g_fw.rev_minor, g_fw.is_kaihen?1:0, g_fw.real_from_setsys?1:0, g_fw.via_kaihen_fallback?1:0, g_fw.setsys_rc);
        fprintf(log, "IP=%s GW=%s DNS1=%s DNS2=%s\n", g_ip, g_gw, g_d1, g_d2);
    }
    Service resolver = {0};
    Result sm_rc = 0;
    if (!g_offline) {
        sm_rc = smGetService(&resolver, "sfdnsres");
        if (R_FAILED(sm_rc) && log) fprintf(log, "smGetService(sfdnsres) failed: rc=0x%08X\n", sm_rc);
    }
    for (size_t i = 0; i < g_total_domains; i++) {
        g_results[i].host = domainDefs[i].host;
        g_results[i].group = domainDefs[i].group;
        g_results[i].legacy = g_offline ? DNS_OFFLINE : resolveHostnameLegacy(domainDefs[i].host);
        g_results[i].probe_rc = R_FAILED(sm_rc) ? sm_rc : 0;
        g_results[i].async = g_offline ? DNS_OFFLINE : resolveHostnameAsync(&resolver, domainDefs[i].host, log, &g_results[i].probe_rc);
        if (domainDefs[i].group == 0) {
            g_core_total++;
            if (g_results[i].legacy == DNS_BLOCKED) g_core_leg_blk++;
            else if (g_results[i].legacy == DNS_RESOLVED) g_core_leg_leak++;
            if (g_results[i].async == DNS_BLOCKED) g_core_asy_blk++;
            else if (g_results[i].async == DNS_RESOLVED) g_core_asy_leak++;
            else if (g_results[i].async == DNS_NA) g_asy_na++;
        } else {
            g_ext_total++;
            if (g_results[i].legacy == DNS_BLOCKED) g_ext_leg_blk++;
            if (g_results[i].async == DNS_BLOCKED) g_ext_asy_blk++;
        }
        if (log) fprintf(log, "%-51s %-10s %-10s [grp=%d rc=0x%08X]\n", g_results[i].host, statusNames[g_results[i].legacy], statusNames[g_results[i].async], g_results[i].group, g_results[i].probe_rc);
        if (i % 5 == 0 || i + 1 == g_total_domains) {
            printf("  Testing DNS: %zu / %zu ...\r", i + 1, g_total_domains);
            consoleUpdate(console);
        }
    }
    if (serviceIsActive(&resolver)) serviceClose(&resolver);
    printf("\n  Testing Port 80 HTTP Connectivity...\n");
    consoleUpdate(console);
    if (!g_offline) {
        runHttpConnectivityChecks(g_http, MAX_HTTP_TARGETS, &g_http_count, log);
        for (size_t i = 0; i < g_http_count; i++) {
            if (strcmp(g_http[i].host, "90dns.test") == 0 && g_http[i].state == 0 && g_http[i].http_code == 200 && strcasecmp(g_http[i].org, "LavaTech") == 0) {
                g_90dns_test_ok = true;
            }
        }
    }
    if (log) fclose(log);
    renderPage(0);
}
int main(int argc, char **argv) {
    (void)argc; (void)argv;
    console = consoleGetDefault(); consoleInit(console);
    PadState pad; padConfigureInput(1, HidNpadStyleSet_NpadFullCtrl); padInitializeAny(&pad);
    socketInitializeDefault(); nifmInitialize(NifmServiceType_User);
    int page = 0;
    runAllTests();
    while (appletMainLoop()) {
        padUpdate(&pad); u64 kDown = padGetButtonsDown(&pad);
        if (kDown & HidNpadButton_B) break;
        if (kDown & HidNpadButton_X) { page = 0; runAllTests(); }
        if (kDown & (HidNpadButton_R | HidNpadButton_Right)) { page = (page + 1) % 4; renderPage(page); }
        if (kDown & (HidNpadButton_L | HidNpadButton_Left)) { page = (page + 3) % 4; renderPage(page); }
    }
    nifmExit(); socketExit(); consoleExit(console); return 0;
}
