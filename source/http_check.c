#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <switch.h>
#include "main.h"
typedef struct { const char *host; const char *path; const char *expected_org; } HttpTestTarget;
static const HttpTestTarget httpTargets[] = {
    {"conntest.nintendowifi.net", "/", "Nintendo"},
    {"ctest.cdn.nintendo.net", "/", "Nintendo"},
    {"ctest.p01.ctest.srv.nintendo.net", "/", "Nintendo"},
    {"api.p01.lp1.ctest.srv.nintendo.net", "/", "Nintendo"},
    {"90dns.test", "/", "LavaTech"}
};
static int connectWithTimeout(const struct addrinfo *ai, int timeout_sec) {
    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) return -1;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (rc < 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (rc != 0) {
        fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
        struct timeval tv = {timeout_sec, 0};
        rc = select(fd + 1, NULL, &wfds, NULL, &tv);
        if (rc <= 0) { close(fd); return -1; }
        int so_err = 0; socklen_t len = sizeof(so_err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &len) < 0 || so_err != 0) { close(fd); return -1; }
    }
    if (flags >= 0) fcntl(fd, F_SETFL, flags);
    struct timeval tv = {timeout_sec, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return fd;
}
static void extractHeaderValue(const char *resp, const char *header_name, char *out, size_t out_sz) {
    out[0] = 0;
    const char *p = resp;
    size_t hlen = strlen(header_name);
    while (*p) {
        const char *eol = strstr(p, "\r\n");
        size_t line_len = eol ? (size_t)(eol - p) : strlen(p);
        if (line_len == 0) break;
        if (line_len > hlen && strncasecmp(p, header_name, hlen) == 0 && p[hlen] == 58) {
            const char *val = p + hlen + 1;
            while (*val == 32 || *val == 9) val++;
            size_t vlen = (size_t)(p + line_len - val);
            if (vlen >= out_sz) vlen = out_sz - 1;
            memcpy(out, val, vlen); out[vlen] = 0; return;
        }
        if (!eol) break;
        p = eol + 2;
    }
}
void runHttpConnectivityChecks(HttpCheckResult *results, size_t max_results, size_t *out_count, FILE *log) {
    size_t count = sizeof(httpTargets) / sizeof(httpTargets[0]);
    if (count > max_results) count = max_results;
    if (out_count) *out_count = count;
    if (log) fprintf(log, "\n=== Connectivity & 90DNS HTTP Check (Port 80) ===\n");
    for (size_t i = 0; i < count; i++) {
        const HttpTestTarget *t = &httpTargets[i];
        HttpCheckResult *r = &results[i];
        memset(r, 0, sizeof(*r));
        r->host = t->host;
        r->expected_org = t->expected_org;
        snprintf(r->ip, sizeof(r->ip), "-");
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        int gai = getaddrinfo(t->host, "80", &hints, &res);
        if (gai != 0 || !res) {
            r->state = -1; r->gai_err = gai;
            if (log) fprintf(log, "  %s -> DNS FAIL (%d)\n", t->host, gai);
            continue;
        }
        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &sin->sin_addr, r->ip, sizeof(r->ip));
        int fd = connectWithTimeout(res, 2);
        freeaddrinfo(res);
        if (fd < 0) {
            r->state = -2;
            if (log) fprintf(log, "  %s -> %s TCP ERR\n", t->host, r->ip);
            continue;
        }
        char req[256];
        int req_len = snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Nintendo NX\r\nConnection: close\r\n\r\n", t->path, t->host);
        send(fd, req, (size_t)req_len, 0);
        char resp[1024]; size_t total = 0;
        while (total + 1 < sizeof(resp)) {
            ssize_t n = recv(fd, resp + total, sizeof(resp) - 1 - total, 0);
            if (n <= 0) break;
            total += (size_t)n;
        }
        resp[total] = 0; close(fd);
        if (strncmp(resp, "HTTP/", 5) == 0) { const char *sp = strchr(resp, 32); if (sp) r->http_code = atoi(sp + 1); }
        extractHeaderValue(resp, "X-Organization", r->org, sizeof(r->org));
        r->state = 0;
        if (log) fprintf(log, "  %s -> %s HTTP %d X-Org=%s\n", t->host, r->ip, r->http_code, r->org[0] ? r->org : "none");
    }
}
