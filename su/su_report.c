/*
 * su_report.c
 *
 * Helper functions to send a small JSON to the report daemon.
 */

#include "su_report.h"
#include "su_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

/* same socket path as daemon */
#define SOCKET_PATH "/dev/socket/report_daemon"
#define BUF_MAX 4096

/* Escape minimal JSON characters in-place into new malloc'd buffer.
 * Escapes: backslash, double-quote, newline, tab, carriage return.
 */
char* json_escape(const char* in) {
    if (!in) return strdup("");
    size_t len = strlen(in);
    /* worst-case every char expands to 2 (e.g. backslash), reserve more */
    size_t max_out = len * 6 + 1;
    char* out = (char*)malloc(max_out);
    if (!out) return NULL;
    char* p = out;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = in[i];
        switch (c) {
            case '\\': *p++ = '\\'; *p++ = '\\'; break;
            case '"':  *p++ = '\\'; *p++ = '"';  break;
            case '\n': *p++ = '\\'; *p++ = 'n';  break;
            case '\r': *p++ = '\\'; *p++ = 'r';  break;
            case '\t': *p++ = '\\'; *p++ = 't';  break;
            default:
                if (c < 0x20) { // control chars -> escape as \u00XX
                    static const char hex[] = "0123456789ABCDEF";
                    *p++ = '\\'; *p++ = 'u'; *p++ = '0'; *p++ = '0';
                    *p++ = hex[(c >> 4) & 0xF];
                    *p++ = hex[c & 0xF];
                } else {
                    *p++ = c;
                }
        }
    }
    *p = '\0';
    return out;
}

/* Join argv into one string, separated by spaces. Caller frees. */
char* join_argv(int argc, char** argv) {
    if (!argv || argc <= 0) return strdup("");
    /* reserve some space */
    size_t total = 0;
    for (int i = 0; i < argc; ++i) {
        if (argv[i]) total += strlen(argv[i]) + 1;
    }
    if (total == 0) return strdup("");
    char* out = (char*)malloc(total + 1);
    if (!out) return strdup("");
    out[0] = '\0';
    for (int i = 0; i < argc; ++i) {
        if (argv[i]) {
            if (i) strcat(out, " ");
            strcat(out, argv[i]);
        }
    }
    return out;
}

/* Send JSON to daemon via UNIX datagram socket. Non-blocking-ish.
 * Builds JSON: {"cmd":"...","uid":1234,"execDir":"...","pkg":"...","pkgSha256":"...","sysUpSec":"..."}
 */
void report_su_denied(const char* cmd, uid_t uid, const char* pkg, const char* cwd,
                      const char* pkg_sha, const char* uptime) {
    int sock = -1;
    struct sockaddr_un addr;
    char buf[BUF_MAX];

    /* build JSON with escaped values */
    char* esc_cmd = json_escape(cmd ? cmd : "");
    char uid_buf[32];
    snprintf(uid_buf, sizeof(uid_buf), "%u", (unsigned)uid);
    char* esc_pkg = json_escape(pkg ? pkg : "");
    char* esc_cwd = json_escape(cwd ? cwd : "");
    char* esc_pkg_sha = json_escape(pkg_sha ? pkg_sha : "");
    char* esc_uptime = json_escape(uptime ? uptime : "");

    int ret = snprintf(buf, sizeof(buf),
                       "{\"cmd\":\"%s\",\"uid\":%s,\"execDir\":\"%s\",\"pkg\":\"%s\",\"pkgSha256\":\"%s\",\"sysUpSec\":\"%s\"}",
                       esc_cmd, uid_buf, esc_cwd, esc_pkg, esc_pkg_sha, esc_uptime);

    free(esc_cmd);
    free(esc_pkg);
    free(esc_cwd);
    free(esc_pkg_sha);
    free(esc_uptime);

    if (ret < 0 || ret >= (int)sizeof(buf)) return;

    /* create unix datagram socket */
    sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        /* cannot create socket, give up */
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    /* sendto -- this won't require server accept; it's fast in the common case */
    ssize_t w = sendto(sock, buf, strlen(buf), 0, (struct sockaddr*)&addr, sizeof(addr));
    if (w < 0) {
        warnx("DEBUG: report_su_denied, sendto failed, error: %d", errno);
    }
    warnx("DEBUG: report_su_denied, sent %zd bytes", w);
    (void)w; /* ignore result; nothing we can do if daemon isn't present */

    close(sock);
}
