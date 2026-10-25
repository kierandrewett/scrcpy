#include "linux_server.h"

#include <errno.h>
#include <libavutil/mem.h>
#include <libavutil/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
# include <direct.h>
#else
# include <sys/stat.h>
#endif

#include "config.h"
#include "util/env.h"
#include "util/file.h"
#include "util/log.h"
#include "util/process.h"

#define SC_LINUX_SERVER_FILENAME "scrcpy-server-linux-aarch64"
#define SC_LINUX_SERVER_SHA256_LEN 64

static bool
is_valid_sha256(const char *s) {
    if (strlen(s) != SC_LINUX_SERVER_SHA256_LEN) {
        return false;
    }
    // Lowercase hex only, so that the comparison below is exact
    for (const char *p = s; *p; ++p) {
        bool digit = *p >= '0' && *p <= '9';
        bool hex = *p >= 'a' && *p <= 'f';
        if (!digit && !hex) {
            return false;
        }
    }
    return true;
}

static char *
get_installed_path(void) {
#ifndef PORTABLE
    char *path = strdup(PREFIX "/share/scrcpy/" SC_LINUX_SERVER_FILENAME);
    if (!path) {
        LOG_OOM();
        return NULL;
    }
#else
    char *path = sc_file_get_local_path(SC_LINUX_SERVER_FILENAME);
    if (!path) {
        return NULL;
    }
#endif
    if (!sc_file_is_regular(path)) {
        free(path);
        return NULL;
    }
    return path;
}

static int
make_dir(const char *path) {
#ifdef _WIN32
    return _mkdir(path);
#else
    return mkdir(path, 0700);
#endif
}

static bool
make_dirs(const char *dir) {
    char *copy = strdup(dir);
    if (!copy) {
        LOG_OOM();
        return false;
    }
    // Create each missing parent component (ignore errors: an existing
    // component or a missing drive root is not a failure here)
    for (char *p = copy + 1; *p; ++p) {
        if (*p == '/' || *p == '\\') {
            char c = *p;
            *p = '\0';
            make_dir(copy);
            *p = c;
        }
    }
    bool ok = make_dir(copy) == 0 || errno == EEXIST;
    free(copy);
    return ok;
}

// Returns the directory "$XDG_CACHE_HOME/scrcpy" (or "$HOME/.cache/scrcpy")
static char *
get_cache_dir(void) {
    char *base = sc_get_env("XDG_CACHE_HOME");
    if (!base || !base[0]) {
        free(base);
        char *home = sc_get_env("HOME");
        if (!home || !home[0]) {
            free(home);
            LOGE("Could not determine the cache directory "
                 "(XDG_CACHE_HOME and HOME are unset)");
            return NULL;
        }
        base = sc_file_build_path(home, ".cache");
        free(home);
        if (!base) {
            return NULL;
        }
    }

    char *dir = sc_file_build_path(base, "scrcpy");
    free(base);
    return dir;
}

static bool
file_sha256_matches(const char *path, const char *expected) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        LOGE("Could not open '%s'", path);
        return false;
    }

    struct AVSHA *ctx = av_sha_alloc();
    if (!ctx) {
        fclose(f);
        LOG_OOM();
        return false;
    }
    if (av_sha_init(ctx, 256) < 0) {
        av_free(ctx);
        fclose(f);
        LOGE("Could not initialize SHA-256");
        return false;
    }

    uint8_t buf[64 * 1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        av_sha_update(ctx, buf, (unsigned) n);
    }
    bool read_error = ferror(f);
    fclose(f);

    uint8_t digest[32];
    av_sha_final(ctx, digest);
    av_free(ctx);

    if (read_error) {
        LOGE("Could not read '%s'", path);
        return false;
    }

    char hex[SC_LINUX_SERVER_SHA256_LEN + 1];
    for (unsigned i = 0; i < sizeof(digest); ++i) {
        snprintf(&hex[2 * i], 3, "%02x", digest[i]);
    }
    return !strcmp(hex, expected);
}

static bool
download(struct sc_intr *intr, const char *url, const char *dest) {
    // Only HTTPS, also after redirects (GitHub redirects release assets)
    const char *const argv[] = {
        "curl", "--fail", "--silent", "--show-error", "--location",
        "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
        "--connect-timeout", "30", "--output", dest, url, NULL,
    };

    sc_pid pid;
    enum sc_process_result r =
        sc_process_execute(argv, &pid, SC_PROCESS_NO_STDOUT);
    if (r != SC_PROCESS_SUCCESS) {
        LOGE("Could not execute curl to download the Linux server: install "
             "curl, or download %s manually and set SCRCPY_LINUX_SERVER_PATH",
             url);
        return false;
    }

    if (intr && !sc_intr_set_process(intr, pid)) {
        // Already interrupted
        sc_process_terminate(pid);
        sc_process_wait(pid, true);
        return false;
    }

    sc_exit_code code = sc_process_wait(pid, false);

    if (intr) {
        sc_intr_set_process(intr, SC_PROCESS_NONE);
    }
    sc_process_close(pid);

    if (code) {
        LOGE("Could not download %s (curl exit code %" SC_PRIexitcode ")",
             url, code);
        return false;
    }
    return true;
}

static char *
get_downloaded_path(struct sc_intr *intr) {
    if (!is_valid_sha256(LINUX_SERVER_SHA256)) {
        LOGE("No Linux server available: set SCRCPY_LINUX_SERVER_PATH, or "
             "build the client with -Dlinux_server_prebuilt=<file>");
        return NULL;
    }

    char *dir = get_cache_dir();
    if (!dir) {
        return NULL;
    }
    if (!make_dirs(dir)) {
        LOGE("Could not create cache directory '%s'", dir);
        free(dir);
        return NULL;
    }

    // The file name embeds the expected hash, so that a new client release
    // never reuses an older cached server
    char *name;
    if (asprintf(&name, SC_LINUX_SERVER_FILENAME "-%s",
                 LINUX_SERVER_SHA256) == -1) {
        LOG_OOM();
        free(dir);
        return NULL;
    }
    char *path = sc_file_build_path(dir, name);
    free(name);
    free(dir);
    if (!path) {
        return NULL;
    }

    if (sc_file_is_regular(path)) {
        if (file_sha256_matches(path, LINUX_SERVER_SHA256)) {
            LOGD("Using cached Linux server: %s", path);
            return path;
        }
        LOGW("Cached Linux server '%s' does not match the expected SHA-256, "
             "downloading again", path);
        remove(path);
    }

    char *part;
    if (asprintf(&part, "%s.part", path) == -1) {
        LOG_OOM();
        free(path);
        return NULL;
    }

    LOGI("Downloading Linux server from %s", LINUX_SERVER_URL);
    if (!download(intr, LINUX_SERVER_URL, part)) {
        remove(part);
        free(part);
        free(path);
        return NULL;
    }

    if (!file_sha256_matches(part, LINUX_SERVER_SHA256)) {
        LOGE("SHA-256 of the downloaded Linux server does not match the "
             "expected value, refusing to use it");
        remove(part);
        free(part);
        free(path);
        return NULL;
    }

    // rename() does not replace an existing file on Windows
    remove(path);
    if (rename(part, path) != 0) {
        LOGE("Could not move '%s' to '%s'", part, path);
        remove(part);
        free(part);
        free(path);
        return NULL;
    }
    free(part);

    LOGI("Linux server cached: %s", path);
    return path;
}

char *
sc_linux_server_get_path(struct sc_intr *intr) {
    char *path = sc_get_env("SCRCPY_LINUX_SERVER_PATH");
    if (path) {
        if (!sc_file_is_regular(path)) {
            LOGE("SCRCPY_LINUX_SERVER_PATH '%s' does not exist or is not a "
                 "regular file", path);
            free(path);
            return NULL;
        }
        LOGD("Using SCRCPY_LINUX_SERVER_PATH: %s", path);
        return path;
    }

    path = get_installed_path();
    if (path) {
        LOGD("Using Linux server: %s", path);
        return path;
    }

    return get_downloaded_path(intr);
}
