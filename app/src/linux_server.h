#ifndef SC_LINUX_SERVER_H
#define SC_LINUX_SERVER_H

#include "common.h"

#include "util/intr.h"

/**
 * Return the path of the native server used for Linux (non-Android) devices
 *
 * The first available source is used, in this order:
 *  1. the SCRCPY_LINUX_SERVER_PATH environment variable,
 *  2. the copy installed next to the client (meson option linux_server_prebuilt),
 *  3. a cached download, whose SHA-256 must match the value compiled into the
 *     client (LINUX_SERVER_SHA256); if it is missing, the server is downloaded
 *     from LINUX_SERVER_URL and verified before being cached.
 *
 * The result must be freed by the caller using free(). It may return NULL on
 * error.
 */
char *
sc_linux_server_get_path(struct sc_intr *intr);

#endif
