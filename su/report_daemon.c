/*
 * report_daemon.c
 *
 * Daemon that listens on a UNIX datagram socket for messages from su.
 * For each received message, a worker thread will POST it to the cloud.
 *
 * Dependencies:
 *  - libcurl (for HTTP POST)
 *  - cutils/properties.h (Android property_get)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>

#include <cutils/properties.h> // property_get
#include <curl/curl.h>         // libcurl

#include "su_utils.h"

#define SOCKET_PATH "/dev/socket/report_daemon"
#define BUF_SIZE 4096

static void get_prop(const char *key, char *out, const char *def, size_t out_size) {
    if (property_get(key, out, def) <= 0) {
        strncpy(out, def, out_size - 1);
        out[out_size - 1] = '\0';
    }
}

/* Worker thread: do the HTTP POST to cloud using libcurl.
 * arg is a malloc'd char* containing the message (JSON). Worker must free it.
 */
static void* send_report(void* arg) {
    char* msg = (char*)arg;
    CURL *curl = NULL;
    CURLcode res;
    char host[PROP_VALUE_MAX];
    char image_name[PROP_VALUE_MAX];
    char cloudUrl[512];
    char *escaped_arg2 = NULL;
    char postdata[8192];

    property_get("bst.bluestacks_cloud_url", host, "https://cloud.bluestacks.com");
    property_get("bst.android_image", image_name, "");

    snprintf(cloudUrl, sizeof(cloudUrl), "%s/app_player/debug_stats", host);

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "report_daemon: curl_easy_init failed\n");
        warnx("DEBUG: report_daemon, send_report, curl_easy_init failed");
        free(msg);
        return NULL;
    }

    /* Escape arg2 (the JSON detail) so it is safe in application/x-www-form-urlencoded */
    escaped_arg2 = curl_easy_escape(curl, msg, 0);
    if (!escaped_arg2) escaped_arg2 = strdup("");

    // collect all properties
    char android_id[PROP_VALUE_MAX]; get_prop("bst.android_id", android_id, "", sizeof(android_id));
    char android_image[PROP_VALUE_MAX]; get_prop("bst.android_image", android_image, "", sizeof(android_image));
    char account_id[PROP_VALUE_MAX]; get_prop("bst.bluestacks_account_id", account_id, "", sizeof(account_id));
    char campaign_hash[PROP_VALUE_MAX]; get_prop("bst.campaign_hash", campaign_hash, "", sizeof(campaign_hash));
    char country[PROP_VALUE_MAX]; get_prop("bst.country", country, "", sizeof(country));
    char guid[PROP_VALUE_MAX]; get_prop("bst.guid", guid, "", sizeof(guid));
    char hypervisor[PROP_VALUE_MAX]; get_prop("bst.status.hypervisor", hypervisor, "", sizeof(hypervisor));
    char install_id[PROP_VALUE_MAX]; get_prop("bst.install_id", install_id, "", sizeof(install_id));
    char instance[PROP_VALUE_MAX]; get_prop("bst.instance", instance, "", sizeof(instance));
    char locale[PROP_VALUE_MAX]; get_prop("bst.locale", locale, "", sizeof(locale));
    char machine_id[PROP_VALUE_MAX]; get_prop("bst.machine_id", machine_id, "", sizeof(machine_id));
    char oem[PROP_VALUE_MAX]; get_prop("bst.oem", oem, "", sizeof(oem));
    char player_version[PROP_VALUE_MAX]; get_prop("bst.version", player_version, "", sizeof(player_version));
    char session_id[PROP_VALUE_MAX]; get_prop("bst.status.session_id", session_id, "", sizeof(session_id));
    char version_machine_id[PROP_VALUE_MAX]; get_prop("bst.version_machine_id", version_machine_id, "", sizeof(version_machine_id));

    // build POST data (application/x-www-form-urlencoded style)
    snprintf(postdata, sizeof(postdata),
        "event=%s&arg1=%s&arg2=%s"
        "&image_name=%s"
        "&android_id=%s"
        "&android_image=%s"
        "&bluestacks_account_id=%s"
        "&campaign_hash=%s"
        "&country=%s"
        "&guid=%s"
        "&hypervisor=%s"
        "&install_id=%s"
        "&instance=%s"
        "&locale=%s"
        "&machine_id=%s"
        "&oem=%s"
        "&player_version=%s"
        "&session_id=%s"
        "&version_machine_id=%s",
        "security", "su_denied", escaped_arg2,
        android_image,
        android_id,
        android_image,
        account_id,
        campaign_hash,
        country,
        guid,
        hypervisor,
        install_id,
        instance,
        locale,
        machine_id,
        oem,
        player_version,
        session_id,
        version_machine_id
    );

    log_debug("DEBUG: report_daemon, send_report, postdata: %s", postdata);

    curl_easy_setopt(curl, CURLOPT_URL, cloudUrl);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);         // 5 seconds timeout
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);        // avoid SIGALRM issues on Android
    curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1L);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "report_daemon: curl_easy_perform failed: %s\n", curl_easy_strerror(res));
    } else {
        long response_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        log_debug("DEBUG: report_daemon, send_report, curl_easy_perform, response_code: %ld", response_code);
        (void)response_code;
    }

    /* cleanup */
    curl_free(escaped_arg2);
    curl_easy_cleanup(curl);
    free(msg);
    return NULL;
}

/**
 * Check if "security" is enabled in bst.feature.enable_debug_info
 *
 * @return 1 if enabled, 0 otherwise
 */
int is_debug_security_enabled(void) {
    char prop[PROP_VALUE_MAX] = {0};

    property_get("bst.feature.enable_debug_info", prop, "");

    if (strlen(prop) == 0) {
        warnx("DEBUG: report_daemon, is_debug_security_enabled, property not set");
        return 0;
    }

    char *saveptr;
    char *token = strtok_r(prop, ",", &saveptr);
    while (token) {
        if (strcmp(token, "security") == 0) {
            warnx("DEBUG: report_daemon, is_debug_security_enabled, found security in property");
            return 1;
        }
        token = strtok_r(NULL, ",", &saveptr);
    }

    warnx("DEBUG: report_daemon, is_debug_security_enabled, did not find security in property");
    return 0;
}

/* Signal handler: attempt to remove socket file and exit gracefully */
static void handle_signal(int sig) {
    fprintf(stderr, "report_daemon: caught signal %d, exiting\n", sig);
    unlink(SOCKET_PATH);
    _exit(0);
}

int main(int argc, char** argv) {
    init_debug_log();
    (void)argc;  // mark unused
    (void)argv;  // mark unused
    int fd = -1;
    struct sockaddr_un addr;
    char buf[BUF_SIZE];

    /* install signals */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* remove previous socket file if any */
    unlink(SOCKET_PATH);

    /* create unix datagram socket */
    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("report_daemon: socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    /* bind to path */
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("report_daemon: bind");
        close(fd);
        return 1;
    }

    /* make the socket file writable so su (non-root in some builds) can send */
    chmod(SOCKET_PATH, 0666);

    fprintf(stderr, "report_daemon: started, listening at %s\n", SOCKET_PATH);
    warnx("DEBUG: report_daemon, main, started, listening at %s", SOCKET_PATH);

    /* initialize libcurl globally (thread-safe init) */
    curl_global_init(CURL_GLOBAL_ALL);

    /* main loop: receive datagrams and spawn thread to handle them */
    while (1) {
        ssize_t r = recv(fd, buf, sizeof(buf) - 1, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("report_daemon: recv");
            break;
        }
        if (r == 0) continue;

        buf[r] = '\0';
        
        if (!is_debug_security_enabled()) {
            warnx("DEBUG: report_daemon, check, debug security not enabled, not sending report");
            continue;
        }

        /* duplicate message and spawn worker */
        char* msg_dup = strdup(buf);
        if (!msg_dup) {
            fprintf(stderr, "report_daemon: strdup failed\n");
            warnx("DEBUG: report_daemon, main, recv, strdup failed");
            continue;
        }

        pthread_t tid;
        int rc = pthread_create(&tid, NULL, send_report, msg_dup);
        if (rc != 0) {
            fprintf(stderr, "report_daemon: pthread_create failed: %d\n", rc);
            warnx("DEBUG: report_daemon, main, recv, pthread_create failed: %d", rc);
            free(msg_dup);
            continue;
        }
        pthread_detach(tid);
    }

    close(fd);
    unlink(SOCKET_PATH);
    curl_global_cleanup();
    return 0;
}
