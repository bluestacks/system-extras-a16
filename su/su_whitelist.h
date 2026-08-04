#ifndef SU_WHITELIST_H
#define SU_WHITELIST_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Whitelist related constants and structures
#define MAX_WL_UIDS        256
#define MAX_WL_PKGS        256
#define MAX_WL_DIRS         32
#define MAX_WL_CMDS        1024

typedef struct {
    char pkg[256];
    char sha256_hex[65]; // lowercase hex, 64 chars + '\0'
} wl_pkg_t;

// Whitelist management functions
void load_whitelist_or_die(void);

bool uid_in_whitelist(int uid);

bool is_pkg_allowed_by_name_and_sig(const char* pkg, const char* sha256_hex);

bool any_pkg_of_uid_whitelisted(int uid);

bool path_under_allowed_execdirs(const char* abspath);

bool resolve_in_allowed_dirs(const char* cmd, char out[]);

bool command_in_whitelist(const char* cmd);

bool has_command_whitelist(void);

bool command_string_contains_disallowed_abs(const char* s);

#ifdef __cplusplus
}
#endif

#endif // SU_WHITELIST_H
