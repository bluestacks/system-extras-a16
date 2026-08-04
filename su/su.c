/*
**
** Copyright 2008, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#define LOG_TAG "su"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <unistd.h>
#include <pwd.h>
#include <android/log.h>
#include <sys/sysinfo.h>

#include "su_utils.h"
#include "su_packages.h"
#include "su_whitelist.h"
#include "su_hcall_wrapper.h"
#include "su_report.h"

// Special process check function (unchanged)
int is_special_process()
{
    char *x = 0;
    FILE *fp;
    char data[1024];
    char proc[64] = "mpi";
    pid_t pid = getppid();

    sprintf(data, "/proc/%d/cmdline", pid);
    fp = fopen(data, "r");
    if(fp) {
        x = fgets(data, 1024, fp);
        fclose(fp);
    }

    //fprintf(stderr,"su: process name(%d): %s\n", pid, x);
    if (x && !strcmp(x, strcat(proc,".v23")))
    {
        //fprintf(stderr,"su: %s(%d) is a special process and allowed to use su\n", x, pid);
        return 1;
    }

    return 0;
}

int is_special_su()
{
    char	buf[1024] = {0};
    char	path[1024];
    sprintf(path, "/%s/%d/%s", "proc", getpid(), "exe");
    readlink(path, buf, sizeof(buf));
    if (strcmp(buf, "/system/xbin/su") == 0)
        return 0;
    return 1;
}

/*
 * SU can be given a specific command to exec. UID _must_ be
 * specified for this (ie argc => 3).
 *
 * Usage:
 * su 1000
 * su 1000 ls -l
 */
int main(int argc, char** argv)
{
    init_debug_log();

    load_whitelist_or_die();

    struct passwd *pw = NULL;
    int uid = 0, gid = 0;
    int argi = 1;

    if (argc >= 2) {
        pw = getpwnam(argv[argi]);
        if (!pw) {
            uid = gid = atoi(argv[argi]);
        } else {
            uid = pw->pw_uid;
            gid = pw->pw_gid;
        }
        argi++;
    } else {
        uid = gid = 0;
    }


    int myuid = getuid();
    bool allowed = false;

    char* cmd = join_argv(argc, argv);
    char cmdline[PATH_MAX] = {0};
    snprintf(cmdline, sizeof(cmdline), "%s", cmd);
    if (cmd) free(cmd);

    warnx("DEBUG: Checking permission for uid %d, target uid: %d, gid: %d, cmd: %s, argc: %d", myuid, uid, gid, cmdline, argc);
    log_debug("Checking permission for uid %d, target uid: %d, gid: %d, cmd: %s, argc: %d", myuid, uid, gid, cmdline, argc);

    char caller_path[PATH_MAX];
    if (get_caller_path(caller_path, sizeof(caller_path))) {
        log_debug("the su caller path is: %s", caller_path);
    }

    char su_path_resolved[PATH_MAX] = {0};
    char su_self_path[PATH_MAX] = {0};
    bool su_path_allowed = false;

    ssize_t su_self_len = readlink("/proc/self/exe", su_self_path, sizeof(su_self_path) - 1);
    if (su_self_len >= 0) {
        su_self_path[su_self_len] = '\0';
        warnx("DEBUG: su self path: %s", su_self_path);
        log_debug("su self path: %s", su_self_path);
        if (path_under_allowed_execdirs(su_self_path)) {
            su_path_allowed = true;
            snprintf(su_path_resolved, sizeof(su_path_resolved), "%s", su_self_path);
        }
    } else {
        warnx("DEBUG: Failed to readlink /proc/self/exe");
        log_debug("Failed to readlink /proc/self/exe");
    }

    if (!su_path_allowed && argv[0]) {
        if (resolve_in_allowed_dirs(argv[0], su_path_resolved)) {
            warnx("DEBUG: su binary resolved path: %s", su_path_resolved);
            log_debug("su binary resolved path: %s", su_path_resolved);
            su_path_allowed = true;
        } else {
            warnx("DEBUG: Failed to resolve su binary path: %s", argv[0]);
            log_debug("Failed to resolve su binary path: %s", argv[0]);
        }
    }

    if (!su_path_allowed) {
        const char* attempt = su_self_len >= 0 ? su_self_path : (argv[0] ? argv[0] : "(null)");
        warnx("DEBUG: Permission denied - su binary not in allowed dirs: %s", attempt);
        log_debug("Permission denied - su binary not in allowed dirs: %s", attempt);
    } else {
        warnx("DEBUG: su binary resolved path: %s", su_path_resolved);
        log_debug("su binary resolved path: %s", su_path_resolved);

        bool command_allowed = false;
        if (has_command_whitelist()) {
            const char* candidate_cmds[3];
            size_t candidate_cmds_cnt = 0;
            char* joined_cmd = NULL;

            if (argc >= 3 && argv[2]) {
                candidate_cmds[candidate_cmds_cnt++] = argv[2];
            }

            if (argc > 3) {
                joined_cmd = join_argv(argc - 2, &argv[2]);
            } else if (argc == 3 && argv[2]) {
                joined_cmd = strdup(argv[2]);
            }

            if (joined_cmd && joined_cmd[0] && candidate_cmds_cnt < sizeof(candidate_cmds) / sizeof(candidate_cmds[0])) {
                candidate_cmds[candidate_cmds_cnt++] = joined_cmd;
            }

            if (argc <= 3 && candidate_cmds_cnt < sizeof(candidate_cmds) / sizeof(candidate_cmds[0])) {
                candidate_cmds[candidate_cmds_cnt++] = "/system/bin/sh";
            }

            for (size_t i = 0; i < candidate_cmds_cnt; ++i) {
                const char* candidate = candidate_cmds[i];
                if (!candidate || !candidate[0]) {
                    continue;
                }
                if (command_in_whitelist(candidate)) {
                    command_allowed = true;
                    warnx("DEBUG: Command matched whitelist: %s", candidate);
                    log_debug("Command matched whitelist: %s", candidate);
                    break;
                }
            }

            if (joined_cmd) {
                free(joined_cmd);
            }

            if (!command_allowed) {
                warnx("DEBUG: Permission denied - command not in whitelist");
                log_debug("Permission denied - command not in whitelist");
            }
        }

        if (command_allowed) {
            allowed = true;
        }
        else if (uid_in_whitelist(myuid)) {
            warnx("DEBUG: Permission granted - uid %d is in whitelist", myuid);
            log_debug("Permission granted - uid %d is in whitelist", myuid);
            allowed = true;
        } else if (any_pkg_of_uid_whitelisted(myuid)) {
            warnx("DEBUG: Permission granted - uid %d has package in whitelist", myuid);
            log_debug("Permission granted - uid %d has package in whitelist", myuid);
            allowed = true;
        }
    }

    if (!allowed) {
        // fprintf(stderr, "su: uid %d not allowed to su\n", myuid);
        log_debug("su: uid %d not allowed to su", myuid);

        bool hcall_result = isDeveloperMode();
        warnx("DEBUG: Hcall wrapper function returned: %d", hcall_result ? 1 : 0);
        if (!hcall_result) {
            // fprintf(stderr, "su: hcall_verify failed, error %d\n", hcall_result);
            char* cwd = getcwd(NULL, 0);
            const char* pkgname = NULL;
            const char* pkg_sha_ptr = NULL;
            char pkg_sha[65] = {0};
            const char* uptime_ptr = NULL;
            char uptime_buf[32] = {0};

            char pkgs[8][256];
            size_t n = get_packages_for_uid(myuid, pkgs, 8);
            if (n > 0) {
                pkgname = pkgs[0];
                if (get_pkg_sha256_from_packages_xml_indexed(pkgname, pkg_sha) > -1) {
                    pkg_sha_ptr = pkg_sha;
                }
            }

            struct sysinfo si;
            if (sysinfo(&si) == 0) {
                snprintf(uptime_buf, sizeof(uptime_buf), "%ld", (long)si.uptime);
                uptime_ptr = uptime_buf;
            }

            warnx("DEBUG: report_su_denied, cmdline: %s, uid: %d, pkgname: %s, pkgsha: %s, uptime: %s, cwd: %s",
                cmdline, myuid, pkgname ? pkgname : "(null)", pkg_sha_ptr ? pkg_sha_ptr : "(null)", uptime_ptr ? uptime_ptr : "(null)", cwd ? cwd : "(null)");
            report_su_denied(cmdline, myuid, pkgname, cwd, pkg_sha_ptr, uptime_ptr);

            free(cwd);
            return 1;
        }
    } else {
        warnx("DEBUG: Permission check passed for uid %d", myuid);
        log_debug("Permission check passed for uid %d", myuid);
    }

#if 0
    if (is_special_su() && !is_special_process()) {
        fprintf(stderr, "su: permission denied as this process is not allowed.\n");
        return 1;
    }
#endif

    if (setgid(gid) || setuid(uid)) {
        fprintf(stderr,"su: permission denied\n");
        return 1;
    }

    /* User specified command for exec. */
    if (argc == 3 ) {
        // BS4-9390 com.userjoy.sgc macro issue. The macro-tool is not passing the argument list correctly when executing
        // commands using su. The space separated commands are being sent in a single argv parameter resulting in execvp failing
        // with -ENOENT as the file name does not exist.
        // ex. '/data/local/tmp/i -n com.userjoy.sgc -l /data/local/tmp/l -s /data/local/tmp/s' == > should actually be broken as
        // '/data/local/tmp/i', '-n', etc.
        // Hence starting sh process in exec call as the new process so that the above command exexcutes correctly.
        char *shell = "/system/bin/sh";
        char *sh = "sh";
        char *switchcmd = "-c";
        char *exec_args[4];
        exec_args[0] = sh;
        exec_args[1] = switchcmd;
        exec_args[2] = argv[2];
        exec_args[3] = NULL;
        warnx("DEBUG: argc == 3, execvp %s %s %s", shell, switchcmd, argv[2]);
        if (execvp(shell, exec_args) < 0) {
            int saved_errno = errno;
            fprintf(stderr, "su: exec failed for %s Error:%s\n", argv[2],
                    strerror(errno));
            warnx("DEBUG: execvp failed for %s, error: %s", argv[2], strerror(saved_errno));
            return -saved_errno;
        }
    } else if (argc > 3) {
        /* Copy the rest of the args from main. */
        char *exec_args[argc - 1];
        memset(exec_args, 0, sizeof(exec_args));
        memcpy(exec_args, &argv[2], sizeof(exec_args));
        warnx("DEBUG: argc > 3, execvp %s %s", argv[2], exec_args[0]);
        if (execvp(argv[2], exec_args) < 0) {
            int saved_errno = errno;
            fprintf(stderr, "su: exec failed for %s Error:%s\n", argv[2],
                    strerror(errno));
            warnx("DEBUG: execvp failed for %s, error: %s", argv[2], strerror(saved_errno));
            return -saved_errno;
        }
    }

    /* Default exec shell. */
    execlp("/system/bin/sh", "sh", NULL);

    fprintf(stderr, "su: exec failed\n");
    return 1;
}
