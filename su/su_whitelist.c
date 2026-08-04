#include "su_whitelist.h"
#include "su_utils.h"
#include "su_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <private/android_filesystem_config.h>

// System (read-only) paths, for bundled whitelist, swl means su whitelist
#define WL_CONFIG_PATH_SYS        "/system/etc/.swl.cfg"
#define WL_CONFIG_SIG_PATH_SYS    "/system/etc/.swl.cfg.sig"

// Data (override) paths, for OTA whitelist override, swl means su whitelist
#define WL_VENDOR_DIR             "/data/downloads/.swl"
#define WL_CONFIG_PATH_DATA       WL_VENDOR_DIR "/.swl.cfg"
#define WL_CONFIG_SIG_PATH_DATA   WL_VENDOR_DIR "/.swl.cfg.sig"

// Safety limit to avoid oversized input
#ifndef WL_CFG_MAX_SIZE
#define WL_CFG_MAX_SIZE (256 * 1024)
#endif

// Debug option
#ifndef SKIP_SIGNATURE_VERIFICATION
#define SKIP_SIGNATURE_VERIFICATION 0
#endif

// Default allowed execution directories
static const char* DEFAULT_EXEC_DIRS[] = {
    /* e.g. "/system/xbin/bstk" */
};

/* Public key for whitelist signature verification */
static const char* WHITELIST_PUBKEY_PEM =
"-----BEGIN PUBLIC KEY-----\n"
"MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAw02SuZKC2DkOGXQti8OC\n"
"/Sr0i3+j7jx88hJl5StX5YbveeClR/C3nmkYNwI4PLUhUItEghGkmW0Nd8Z/eIUT\n"
"+QOmflv477rD/yTfY7HcZwEcG7fUIm6HdgshMff7XuTQsL5xvxf4Yfc5n/EfKFwd\n"
"60GsefdGcAzR7sMtthNmZ5ji01DskI4eeAM0nbTOC8Qn9ILJew/s2sWWFZ36CpHv\n"
"NcfPK1k98PwlJBzGvu2deKfTFNqog16s+IfQ001Ya2YPWXYgr9515llQLsnsDaws\n"
"e9NL+umbZc6QkAIIVD94Q+vd6EsCPK5LAMp/RvwtXbsa1nFJDPG0ZOwblKASMchp\n"
"q2CN32bj38Og6wI4Cx5tCh56W7hdRCGhrMruKLmjpHb7mh5EYA/nRijqxDojJGQ3\n"
"peQ+a2U8v+wa8R9B3V/MH6Eh/n9ANV5wYxIE38PKUwvjMFNiWiZQNHqb0JnWzByh\n"
"9liRvcMhYuuwsdyIGLUnkytCFzPjFan9B1NuzjtaJoHZAgMBAAE=\n"
"-----END PUBLIC KEY-----\n";

static int       g_wl_uids[MAX_WL_UIDS];
static size_t    g_wl_uids_cnt = 0;

static wl_pkg_t  g_wl_pkgs[MAX_WL_PKGS];
static size_t    g_wl_pkgs_cnt = 0;

static char      g_wl_execdirs[MAX_WL_DIRS][PATH_MAX];
static size_t    g_wl_execdirs_cnt = 0;

static char      g_wl_cmds[MAX_WL_CMDS][PATH_MAX];
static size_t    g_wl_cmds_cnt = 0;

// Add an execution directory
static void add_execdir(const char* dir) {
    if (!dir) return;
    if (g_wl_execdirs_cnt >= MAX_WL_DIRS) return;
    snprintf(g_wl_execdirs[g_wl_execdirs_cnt], PATH_MAX, "%s", dir);
    size_t n = strlen(g_wl_execdirs[g_wl_execdirs_cnt]);
    while (n && g_wl_execdirs[g_wl_execdirs_cnt][n-1]=='/')
        g_wl_execdirs[g_wl_execdirs_cnt][--n]=0;
    g_wl_execdirs_cnt++;
}

// Add a specific command string
static void add_command(const char* cmd) {
    if (!cmd) return;
    if (g_wl_cmds_cnt >= MAX_WL_CMDS) return;

    snprintf(g_wl_cmds[g_wl_cmds_cnt], PATH_MAX, "%s", cmd);
    trim(g_wl_cmds[g_wl_cmds_cnt]);
    if (!g_wl_cmds[g_wl_cmds_cnt][0]) {
        g_wl_cmds[g_wl_cmds_cnt][0] = '\0';
        return;
    }

    for (size_t i = 0; i < g_wl_cmds_cnt; ++i) {
        if (strcmp(g_wl_cmds[i], g_wl_cmds[g_wl_cmds_cnt]) == 0) {
            g_wl_cmds[g_wl_cmds_cnt][0] = '\0';
            return;
        }
    }

    g_wl_cmds_cnt++;
}

// Initialize default configuration
static void wl_init_defaults(void) {
    for (size_t i=0;i<sizeof(DEFAULT_EXEC_DIRS)/sizeof(DEFAULT_EXEC_DIRS[0]);++i) {
        add_execdir(DEFAULT_EXEC_DIRS[i]);
    }
}

// Generic verify: caller specifies sig file path
static bool verify_whitelist_signature(const unsigned char* data, size_t datalen,
                                          const char* sig_path) {
    warnx("DEBUG: WL verify (sig=%s)", sig_path ? sig_path : "(null)");

    if (SKIP_SIGNATURE_VERIFICATION) {
        warnx("WARNING: Signature verification SKIPPED (debug)");
        return true;
    }
    if (!data || datalen == 0 || datalen > WL_CFG_MAX_SIZE) {
        warnx("ERROR: invalid cfg size: %zu", datalen);
        return false;
    }
    if (!sig_path) {
        warnx("ERROR: sig_path is NULL");
        return false;
    }

    unsigned char* sig = NULL; size_t siglen = 0;
    if (!read_file_all(sig_path, &sig, &siglen)) {
        warnx("ERROR: missing sig: %s (errno=%d:%s)", sig_path, errno, strerror(errno));
        return false;
    }

    void* pk = load_pubkey_from_pem(WHITELIST_PUBKEY_PEM);
    if (!pk) {
        free(sig);
        warnx("ERROR: load pubkey failed");
        return false;
    }

    bool ok = verify_signature_sha256(data, datalen, sig, siglen, pk);
    if (!ok) warnx("ERROR: whitelist signature FAILED for %s", sig_path);
    else     warnx("DEBUG: whitelist signature OK for %s", sig_path);

    free_pubkey(pk);
    free(sig);
    return ok;
}

static void wl_parse_and_apply(const unsigned char* buf, size_t len) {
    if (!buf || !len) return;
    char* tmp = (char*)malloc(len+1);
    if (!tmp) return;
    memcpy(tmp, buf, len); tmp[len]=0;

    char* saveptr = NULL;
    char* line = strtok_r(tmp, "\n", &saveptr);
    while (line) {
        trim(line);
        if (!line[0] || line[0] == '#') {
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
        }

        if (starts_with(line, "uid:")) {
            if (g_wl_uids_cnt < MAX_WL_UIDS) {
                int uid = atoi(line+4);
                g_wl_uids[g_wl_uids_cnt++] = uid;
            }
        } else if (starts_with(line, "pkg:")) {
            if (g_wl_pkgs_cnt < MAX_WL_PKGS) {
                wl_pkg_t* e = &g_wl_pkgs[g_wl_pkgs_cnt];
                memset(e, 0, sizeof(*e));
                const char* p = line+4;
                const char* sp = strstr(p, " sha256:");
                if (sp) {
                    size_t n = (size_t)(sp - p);
                    if (n > sizeof(e->pkg)-1) n = sizeof(e->pkg)-1;
                    memcpy(e->pkg, p, n); e->pkg[n]=0;

                    const char* h = sp + 8;
                    while (*h && isspace((unsigned char)*h)) h++;
                    strncpy(e->sha256_hex, h, 64);
                    e->sha256_hex[64] = 0;
                    to_lower_inplace(e->sha256_hex);
                } else {
                    strncpy(e->pkg, p, sizeof(e->pkg)-1);
                    e->pkg[sizeof(e->pkg)-1] = 0;
                    e->sha256_hex[0] = 0;
                }
                g_wl_pkgs_cnt++;
            }
        } else if (starts_with(line, "execdir:")) {
            add_execdir(line+8);
        } else if (starts_with(line, "cmd:")) {
            add_command(line+4);
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
    free(tmp);
}

// Try load+verify+apply from given cfg/sig
static bool wl_try_load_from(const char* cfg_path, const char* sig_path) {
    if (!cfg_path || !sig_path) return false;

    unsigned char* buf = NULL; size_t blen = 0;
    if (!read_file_all(cfg_path, &buf, &blen)) {
        // Not present → silently allow caller to try next candidate
        return false;
    }
    if (blen == 0 || blen > WL_CFG_MAX_SIZE) {
        warnx("ERROR: cfg invalid size: %s (size=%zu)", cfg_path, blen);
        free(buf);
        return false;
    }

    if (!verify_whitelist_signature(buf, blen, sig_path)) {
        warnx("ERROR: signature verify failed for %s", cfg_path);
        free(buf);
        return false;
    }

    wl_parse_and_apply(buf, blen);
    free(buf);
    warnx("INFO: Whitelist loaded: %s (sig=%s)", cfg_path, sig_path);
    return true;
}

void load_whitelist_or_die(void) {
    wl_init_defaults();

    // Priority: /data/vendor/su → /system/etc
    struct {
        const char* cfg;
        const char* sig;
    } cand[] = {
        { WL_CONFIG_PATH_DATA, WL_CONFIG_SIG_PATH_DATA },
        { WL_CONFIG_PATH_SYS,  WL_CONFIG_SIG_PATH_SYS  },
    };

    for (size_t i = 0; i < sizeof(cand)/sizeof(cand[0]); ++i) {
        if (wl_try_load_from(cand[i].cfg, cand[i].sig)) {
            return; // success
        }
    }

    // Fallback: use defaults only
    warnx("WARNING: No valid whitelist in %s or %s; using defaults only.", WL_CONFIG_PATH_DATA, WL_CONFIG_PATH_SYS);
}

// Check if a UID is in the whitelist
bool uid_in_whitelist(int uid) {
    for (size_t i=0;i<g_wl_uids_cnt;++i) {
        if (g_wl_uids[i] == uid) {
            return true;
        }
    }
    return false;
}

// Check if a package name and signature are allowed
bool is_pkg_allowed_by_name_and_sig(const char* pkg, const char* sha256_hex) {
    for (size_t i=0;i<g_wl_pkgs_cnt;++i) {
        if (strcmp(g_wl_pkgs[i].pkg, pkg) == 0) {
            if (g_wl_pkgs[i].sha256_hex[0] == 0) {
                // Name-only allow (not recommended)
                return true;
            }
            if (sha256_hex && strcmp(g_wl_pkgs[i].sha256_hex, sha256_hex) == 0) {
                return true;
            }
        }
    }
    return false;
}

// Check if any package of a UID is whitelisted
bool any_pkg_of_uid_whitelisted(int uid) {
    extern size_t get_packages_for_uid(int uid, char pkgs[][256], size_t max_pkgs);
    extern int get_pkg_sha256_from_packages_xml_indexed(const char* pkg, char out_hex[65]); // legacy helper function for package signature retrieval

    char pkgs[8][256];
    size_t n = get_packages_for_uid(uid, pkgs, 8);
    if (n == 0) return false;

    for (size_t i=0;i<n;++i) {
        char sha[65] = {0};
        bool has_sig = (get_pkg_sha256_from_packages_xml_indexed(pkgs[i], sha) > -1);
        if (!has_sig) {
            if (is_pkg_allowed_by_name_and_sig(pkgs[i], NULL)) return true;
        } else {
            if (is_pkg_allowed_by_name_and_sig(pkgs[i], sha)) return true;
        }
    }
    return false;
}

bool command_in_whitelist(const char* cmd) {
    if (!cmd) return false;

    char normalized[PATH_MAX];
    snprintf(normalized, sizeof(normalized), "%s", cmd);
    trim(normalized);
    if (!normalized[0]) return false;

    for (size_t i = 0; i < g_wl_cmds_cnt; ++i) {
        if (strcmp(g_wl_cmds[i], normalized) == 0) {
            return true;
        }
    }
    return false;
}

bool has_command_whitelist(void) {
    return g_wl_cmds_cnt > 0;
}

// Check if a path is under the allowed execution directories
bool path_under_allowed_execdirs(const char* abspath) {
    for (size_t i=0;i<g_wl_execdirs_cnt;++i) {
        size_t L = strlen(g_wl_execdirs[i]);
        if (strncmp(abspath, g_wl_execdirs[i], L) == 0 &&
            (abspath[L] == '/' || abspath[L] == 0)) {
            return true;
        }
    }
    return false;
}

// Resolve a command path in allowed directories
bool resolve_in_allowed_dirs(const char* cmd, char out[]) {
    if (!cmd || !out) return false;
    if (cmd[0] == '/') {
        snprintf(out, PATH_MAX, "%s", cmd);
        return path_under_allowed_execdirs(out);
    }
    for (size_t i=0;i<g_wl_execdirs_cnt;++i) {
        char cand[PATH_MAX];
        snprintf(cand, sizeof(cand), "%s/%s", g_wl_execdirs[i], cmd);
        if (access(cand, X_OK) == 0) {
            snprintf(out, PATH_MAX, "%s", cand);
            return true;
        }
    }
    return false;
}

// Check if a command string contains disallowed absolute paths
bool command_string_contains_disallowed_abs(const char* s) {
    if (!s) return false;
    const char* bad[] = { "/data/", "/sdcard/", "/storage/", "/mnt/sdcard/" };
    for (size_t i=0;i<sizeof(bad)/sizeof(bad[0]);++i) {
        if (strstr(s, bad[i])) return true;
    }
    return false;
}
