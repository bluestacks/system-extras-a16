/*
 * su_report.h
 *
 * Small helper interface that su can call to report denied events to the daemon.
 */

#ifndef SU_REPORT_H
#define SU_REPORT_H

#include <sys/types.h>

/* Build a JSON-like detail and send it to report_daemon via UNIX datagram socket.
 * Parameters:
 *   cmd      - command string (will be included as JSON string)
 *   uid      - caller uid
 *   pkg      - package name (nullable, pass NULL if unknown)
 *   cwd      - current working directory (nullable)
 *   pkg_sha  - SHA-256 of package signature (nullable)
 *   uptime   - system uptime in seconds (nullable string)
 *
 * This function is non-blocking in the sense it uses a UNIX datagram sendto()
 * and returns quickly in the common case. It does not wait for network upload.
 */
void report_su_denied(const char* cmd, uid_t uid, const char* pkg, const char* cwd,
                      const char* pkg_sha, const char* uptime);

/* Join argv[] into a single whitespace-separated commandline.
 * Caller must free returned string. Returns strdup("") on empty.
 */
char* join_argv(int argc, char** argv);

/* Escape string for JSON value (returns malloc'd string; caller frees) */
char* json_escape(const char* in);

#endif /* SU_REPORT_H */
