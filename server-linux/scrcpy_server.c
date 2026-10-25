/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * scrcpy-compatible server for postmarketOS (Linux, no Android app_process).
 *
 * Implements the subset of the scrcpy 4.x server protocol the stock client
 * needs for video mirroring and control:
 *   - reverse (default) and tunnel_forward sockets: video, audio, control
 *   - device name, H.264 codec id, session and framed media packets
 *   - audio is reported as explicitly disabled (codec id 0)
 *   - control: keycode, text, touch (MT type B via uinput), back, video reset
 *
 * Capture: wlr-screencopy (shm) from the running Wayland compositor (phoc).
 * Encode: libx264 ultrafast/zerolatency, baseline profile, ABR.
 *
 * Launched by the PC client through /usr/bin/app_process (shim script).
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <wayland-client.h>
#include <x264.h>

#include <wayland-client-protocol.h>
#include "wlr-screencopy-unstable-v1-client-protocol.h"

#define PANEL_W 1080
#define PANEL_H 2340
#define DEFAULT_MAX_SIZE 1170
#define DEFAULT_FPS 30
#define DEFAULT_BITRATE 8000000
#define MAX_TOUCH 10
#define WL_TIMEOUT_MS 2000
#define MAX_CTRL_STRING (1 << 18)

#define PKT_FLAG_CONFIG (UINT64_C(1) << 62)
#define PKT_FLAG_KEY (UINT64_C(1) << 61)

static void logf_(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fputs("scrcpy-server: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}
#define LOG(...) logf_(__VA_ARGS__)

static void die(const char *msg) {
    LOG("fatal: %s", msg);
    exit(1);
}

static int64_t mono_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static int64_t mono_ms(void) {
    return mono_us() / 1000;
}

/* ---------- options ---------- */

struct opts {
    uint32_t scid;
    int max_size; /* long side cap */
    int fps;
    int bitrate;  /* bit/s */
    bool audio;
    bool control;
    bool forward;
    int threads;
};

static void parse_args(int argc, char **argv, struct opts *o) {
    o->scid = 0;
    o->max_size = 0;
    o->fps = DEFAULT_FPS;
    o->bitrate = DEFAULT_BITRATE;
    o->audio = true;
    o->control = true;
    o->forward = false;
    o->threads = 4;
    const char *t = getenv("SCRCPY_X264_THREADS");
    if (t && atoi(t) > 0)
        o->threads = atoi(t);

    for (int i = 1; i < argc; i++) {
        char *eq = strchr(argv[i], '=');
        if (!eq)
            continue; /* version string, class name, "/" */
        *eq = '\0';
        const char *k = argv[i], *v = eq + 1;
        if (!strcmp(k, "scid"))
            o->scid = (uint32_t)strtoul(v, NULL, 16);
        else if (!strcmp(k, "max_size"))
            o->max_size = atoi(v);
        else if (!strcmp(k, "max_fps")) {
            int f = (int)(strtod(v, NULL) + 0.5);
            if (f > 0)
                o->fps = f;
        } else if (!strcmp(k, "video_bit_rate")) {
            int b = atoi(v);
            if (b > 0)
                o->bitrate = b;
        } else if (!strcmp(k, "video_codec")) {
            if (strcmp(v, "h264"))
                die("only video_codec=h264 is supported");
        } else if (!strcmp(k, "video")) {
            if (!strcmp(v, "false"))
                die("video=false is not supported");
        } else if (!strcmp(k, "audio"))
            o->audio = strcmp(v, "false") != 0;
        else if (!strcmp(k, "control"))
            o->control = strcmp(v, "false") != 0;
        else if (!strcmp(k, "tunnel_forward"))
            o->forward = !strcmp(v, "true");
        *eq = '=';
    }
    if (o->max_size <= 0)
        o->max_size = DEFAULT_MAX_SIZE;
    if (o->fps <= 0)
        o->fps = DEFAULT_FPS;
}

/* ---------- byte helpers ---------- */

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

static void put_be64(uint8_t *p, uint64_t v) {
    put_be32(p, (uint32_t)(v >> 32));
    put_be32(p + 4, (uint32_t)v);
}

static uint16_t get_be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t get_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t get_be64(const uint8_t *p) {
    return ((uint64_t)get_be32(p) << 32) | get_be32(p + 4);
}

static int write_all(int fd, const void *buf, size_t n) {
    const uint8_t *p = buf;
    while (n > 0) {
        ssize_t r = write(fd, p, n);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t n) {
    uint8_t *p = buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            return -1;
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

/* ---------- sockets (abstract namespace, as scrcpy uses) ---------- */

static socklen_t abstract_addr(const char *name, struct sockaddr_un *a) {
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    size_t n = strlen(name);
    if (n > sizeof(a->sun_path) - 2)
        die("socket name too long");
    memcpy(a->sun_path + 1, name, n);
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
}

/* reverse tunnel: the client listens, we connect */
static int sock_connect(const char *name) {
    struct sockaddr_un a;
    socklen_t len = abstract_addr(name, &a);
    for (int t = 0; t < 400; t++) {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
            die("socket");
        if (connect(fd, (struct sockaddr *)&a, len) == 0)
            return fd;
        close(fd);
        usleep(50000);
    }
    return -1;
}

/* forward tunnel: we listen once and accept each client socket in turn
 * (video, then control), like scrcpy; closing between accepts would let a
 * client's connect race with the rebind and be refused. */
static int sock_listen(const char *name) {
    struct sockaddr_un a;
    socklen_t len = abstract_addr(name, &a);
    int l = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (l < 0)
        die("socket");
    if (bind(l, (struct sockaddr *)&a, len) < 0)
        die("bind");
    if (listen(l, 4) < 0)
        die("listen");
    return l;
}

static int sock_accept_on(int l) {
    return accept4(l, NULL, NULL, SOCK_CLOEXEC);
}

/* ---------- uinput ---------- */

static int ui_touch = -1;
static int ui_keys = -1;

static void emit(int fd, uint16_t type, uint16_t code, int32_t value) {
    struct input_event ev;
    memset(&ev, 0, sizeof ev);
    ev.type = type;
    ev.code = code;
    ev.value = value;
    if (write(fd, &ev, sizeof ev) < 0)
        LOG("uinput write failed: %s", strerror(errno));
}

static void syn(int fd) {
    emit(fd, EV_SYN, SYN_REPORT, 0);
}

static int uinput_open(void) {
    int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        LOG("cannot open /dev/uinput: %s (control disabled)", strerror(errno));
    return fd;
}

static void abs_setup(int fd, uint16_t code, int32_t max, int32_t res) {
    struct uinput_abs_setup a;
    memset(&a, 0, sizeof a);
    a.code = code;
    a.absinfo.minimum = 0;
    a.absinfo.maximum = max;
    a.absinfo.resolution = res;
    ioctl(fd, UI_SET_ABSBIT, code);
    if (ioctl(fd, UI_ABS_SETUP, &a) < 0)
        LOG("UI_ABS_SETUP %u: %s", code, strerror(errno));
}

static int touch_create(void) {
    int fd = uinput_open();
    if (fd < 0)
        return -1;
    ioctl(fd, UI_SET_EVBIT, EV_KEY);
    ioctl(fd, UI_SET_KEYBIT, BTN_TOUCH);
    ioctl(fd, UI_SET_EVBIT, EV_ABS);
    ioctl(fd, UI_SET_PROPBIT, INPUT_PROP_DIRECT);
    abs_setup(fd, ABS_X, PANEL_W - 1, 15);
    abs_setup(fd, ABS_Y, PANEL_H - 1, 15);
    abs_setup(fd, ABS_MT_SLOT, MAX_TOUCH - 1, 0);
    abs_setup(fd, ABS_MT_POSITION_X, PANEL_W - 1, 15);
    abs_setup(fd, ABS_MT_POSITION_Y, PANEL_H - 1, 15);
    abs_setup(fd, ABS_MT_TRACKING_ID, 65535, 0);
    struct uinput_setup us;
    memset(&us, 0, sizeof us);
    us.id.bustype = BUS_VIRTUAL;
    us.id.vendor = 0x1234;
    us.id.product = 0x5680;
    us.id.version = 1;
    snprintf(us.name, sizeof us.name, "scrcpy-server-touch");
    if (ioctl(fd, UI_DEV_SETUP, &us) < 0 || ioctl(fd, UI_DEV_CREATE) < 0) {
        LOG("touch device create failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static int keys_create(void) {
    int fd = uinput_open();
    if (fd < 0)
        return -1;
    ioctl(fd, UI_SET_EVBIT, EV_KEY);
    for (int k = 1; k < 256; k++)
        ioctl(fd, UI_SET_KEYBIT, k);
    ioctl(fd, UI_SET_KEYBIT, KEY_APPSELECT);
    ioctl(fd, UI_SET_KEYBIT, KEY_BACK);
    ioctl(fd, UI_SET_KEYBIT, KEY_HOMEPAGE);
    ioctl(fd, UI_SET_KEYBIT, KEY_POWER);
    ioctl(fd, UI_SET_KEYBIT, KEY_VOLUMEUP);
    ioctl(fd, UI_SET_KEYBIT, KEY_VOLUMEDOWN);
    struct uinput_setup us;
    memset(&us, 0, sizeof us);
    us.id.bustype = BUS_VIRTUAL;
    us.id.vendor = 0x1234;
    us.id.product = 0x5681;
    us.id.version = 1;
    snprintf(us.name, sizeof us.name, "scrcpy-server-keys");
    if (ioctl(fd, UI_DEV_SETUP, &us) < 0 || ioctl(fd, UI_DEV_CREATE) < 0) {
        LOG("keyboard device create failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

/* ---------- key maps ---------- */

/* Android KEYCODE_* -> Linux KEY_* (0 = unmapped) */
static int android_to_linux_key(uint32_t kc) {
    static const uint16_t letters[26] = {
        30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38, 50,   /* a..m */
        49, 24, 25, 16, 19, 31, 20, 22, 47, 17, 45, 21, 44,   /* n..z */
    };
    if (kc >= 29 && kc <= 54)
        return letters[kc - 29];
    if (kc == 7)
        return KEY_0;
    if (kc >= 8 && kc <= 16)
        return (int)kc - 6; /* KEYCODE_1..9 -> KEY_1..9 */
    if (kc >= 131 && kc <= 140)
        return (int)kc - 131 + KEY_F1; /* F1..F10 */
    switch (kc) {
    case 3: return KEY_HOMEPAGE;
    case 4: return KEY_BACK;
    case 19: return KEY_UP;
    case 20: return KEY_DOWN;
    case 21: return KEY_LEFT;
    case 22: return KEY_RIGHT;
    case 24: return KEY_VOLUMEUP;
    case 25: return KEY_VOLUMEDOWN;
    case 26: return KEY_POWER;
    case 27: return KEY_CAMERA;
    case 55: return KEY_COMMA;
    case 56: return KEY_DOT;
    case 57: return KEY_LEFTALT;
    case 58: return KEY_RIGHTALT;
    case 59: return KEY_LEFTSHIFT;
    case 60: return KEY_RIGHTSHIFT;
    case 61: return KEY_TAB;
    case 62: return KEY_SPACE;
    case 66: return KEY_ENTER;
    case 67: return KEY_BACKSPACE;
    case 68: return KEY_GRAVE;
    case 69: return KEY_MINUS;
    case 70: return KEY_EQUAL;
    case 71: return KEY_LEFTBRACE;
    case 72: return KEY_RIGHTBRACE;
    case 73: return KEY_BACKSLASH;
    case 74: return KEY_SEMICOLON;
    case 75: return KEY_APOSTROPHE;
    case 76: return KEY_SLASH;
    case 82: return KEY_MENU;
    case 84: return KEY_SEARCH;
    case 85: return KEY_PLAYPAUSE;
    case 86: return KEY_STOPCD;
    case 87: return KEY_NEXTSONG;
    case 88: return KEY_PREVIOUSSONG;
    case 92: return KEY_PAGEUP;
    case 93: return KEY_PAGEDOWN;
    case 111: return KEY_ESC;
    case 112: return KEY_DELETE;
    case 113: return KEY_LEFTCTRL;
    case 114: return KEY_RIGHTCTRL;
    case 117: return KEY_LEFTMETA;
    case 118: return KEY_RIGHTMETA;
    case 122: return KEY_HOME;
    case 123: return KEY_END;
    case 141: return KEY_F11;
    case 142: return KEY_F12;
    case 160: return KEY_KPENTER;
    case 164: return KEY_MUTE;
    case 187: return KEY_APPSELECT;
    case 220: return KEY_BRIGHTNESSDOWN;
    case 221: return KEY_BRIGHTNESSUP;
    default: return 0;
    }
}

/* ASCII -> Linux key plus shift flag (US layout). Returns false if unmapped. */
static bool ascii_to_key(int c, int *key, bool *shift) {
    *shift = false;
    if (c >= 'a' && c <= 'z') {
        *key = android_to_linux_key(29 + (c - 'a'));
        return *key != 0;
    }
    if (c >= 'A' && c <= 'Z') {
        *shift = true;
        *key = android_to_linux_key(29 + (c - 'A'));
        return *key != 0;
    }
    if (c >= '1' && c <= '9') { *key = KEY_1 + (c - '1'); return true; }
    if (c == '0') { *key = KEY_0; return true; }
    switch (c) {
    case '!': *shift = true; *key = KEY_1; return true;
    case '@': *shift = true; *key = KEY_2; return true;
    case '#': *shift = true; *key = KEY_3; return true;
    case '$': *shift = true; *key = KEY_4; return true;
    case '%': *shift = true; *key = KEY_5; return true;
    case '^': *shift = true; *key = KEY_6; return true;
    case '&': *shift = true; *key = KEY_7; return true;
    case '*': *shift = true; *key = KEY_8; return true;
    case '(': *shift = true; *key = KEY_9; return true;
    case ')': *shift = true; *key = KEY_0; return true;
    case ' ': *key = KEY_SPACE; return true;
    case '\n': *key = KEY_ENTER; return true;
    case '\t': *key = KEY_TAB; return true;
    case '-': *key = KEY_MINUS; return true;
    case '_': *shift = true; *key = KEY_MINUS; return true;
    case '=': *key = KEY_EQUAL; return true;
    case '+': *shift = true; *key = KEY_EQUAL; return true;
    case '[': *key = KEY_LEFTBRACE; return true;
    case '{': *shift = true; *key = KEY_LEFTBRACE; return true;
    case ']': *key = KEY_RIGHTBRACE; return true;
    case '}': *shift = true; *key = KEY_RIGHTBRACE; return true;
    case '\\': *key = KEY_BACKSLASH; return true;
    case '|': *shift = true; *key = KEY_BACKSLASH; return true;
    case ';': *key = KEY_SEMICOLON; return true;
    case ':': *shift = true; *key = KEY_SEMICOLON; return true;
    case '\'': *key = KEY_APOSTROPHE; return true;
    case '"': *shift = true; *key = KEY_APOSTROPHE; return true;
    case '`': *key = KEY_GRAVE; return true;
    case '~': *shift = true; *key = KEY_GRAVE; return true;
    case ',': *key = KEY_COMMA; return true;
    case '<': *shift = true; *key = KEY_COMMA; return true;
    case '.': *key = KEY_DOT; return true;
    case '>': *shift = true; *key = KEY_DOT; return true;
    case '/': *key = KEY_SLASH; return true;
    case '?': *shift = true; *key = KEY_SLASH; return true;
    default: return false;
    }
}

static void key_tap(int key) {
    if (ui_keys < 0 || !key)
        return;
    emit(ui_keys, EV_KEY, key, 1);
    syn(ui_keys);
    emit(ui_keys, EV_KEY, key, 0);
    syn(ui_keys);
}

static void inject_keycode(uint8_t action, uint32_t keycode) {
    if (ui_keys < 0 || (action != 0 && action != 1))
        return;
    int key = android_to_linux_key(keycode);
    if (!key) {
        LOG("unmapped keycode %u", keycode);
        return;
    }
    emit(ui_keys, EV_KEY, key, action == 0 ? 1 : 0);
    syn(ui_keys);
}

static void inject_text(const char *text, size_t len) {
    if (ui_keys < 0)
        return;
    for (size_t i = 0; i < len; i++) {
        int c = (unsigned char)text[i];
        int key;
        bool shift;
        if (c >= 0x80)
            continue; /* no keymap for non-ASCII */
        if (!ascii_to_key(c, &key, &shift)) {
            LOG("text: no key for 0x%02x", c);
            continue;
        }
        if (shift) {
            emit(ui_keys, EV_KEY, KEY_LEFTSHIFT, 1);
            syn(ui_keys);
        }
        key_tap(key);
        if (shift) {
            emit(ui_keys, EV_KEY, KEY_LEFTSHIFT, 0);
            syn(ui_keys);
        }
    }
}

/* ---------- multi-touch (type B) ---------- */

struct slot {
    bool used;
    int64_t id;
};
static struct slot slots[MAX_TOUCH];
static int active_touches;
static int32_t next_tracking = 1;

static void touch_pos(int slot, int px, int py) {
    emit(ui_touch, EV_ABS, ABS_MT_SLOT, slot);
    emit(ui_touch, EV_ABS, ABS_MT_POSITION_X, px);
    emit(ui_touch, EV_ABS, ABS_MT_POSITION_Y, py);
    emit(ui_touch, EV_ABS, ABS_X, px);
    emit(ui_touch, EV_ABS, ABS_Y, py);
}

static void inject_touch(uint8_t action, int64_t pid, int32_t x, int32_t y, uint16_t sw, uint16_t sh) {
    if (ui_touch < 0 || sw == 0 || sh == 0)
        return;
    int64_t px64 = (int64_t)x * PANEL_W / sw;
    int64_t py64 = (int64_t)y * PANEL_H / sh;
    int px = (int)(px64 < 0 ? 0 : px64 >= PANEL_W ? PANEL_W - 1 : px64);
    int py = (int)(py64 < 0 ? 0 : py64 >= PANEL_H ? PANEL_H - 1 : py64);

    int idx = -1;
    for (int i = 0; i < MAX_TOUCH; i++)
        if (slots[i].used && slots[i].id == pid)
            idx = i;

    switch (action) {
    case 0: /* ACTION_DOWN */
        if (idx >= 0) { /* already down: treat as move */
            touch_pos(idx, px, py);
            syn(ui_touch);
            return;
        }
        for (int i = 0; i < MAX_TOUCH && idx < 0; i++)
            if (!slots[i].used)
                idx = i;
        if (idx < 0)
            return;
        slots[idx].used = true;
        slots[idx].id = pid;
        emit(ui_touch, EV_ABS, ABS_MT_SLOT, idx);
        emit(ui_touch, EV_ABS, ABS_MT_TRACKING_ID, next_tracking);
        next_tracking = next_tracking >= 65535 ? 1 : next_tracking + 1;
        touch_pos(idx, px, py);
        if (active_touches == 0)
            emit(ui_touch, EV_KEY, BTN_TOUCH, 1);
        active_touches++;
        syn(ui_touch);
        break;
    case 2: /* ACTION_MOVE */
        if (idx < 0)
            return;
        touch_pos(idx, px, py);
        syn(ui_touch);
        break;
    case 1: /* ACTION_UP */
    case 3: /* ACTION_CANCEL */
        if (idx < 0)
            return;
        touch_pos(idx, px, py);
        emit(ui_touch, EV_ABS, ABS_MT_SLOT, idx);
        emit(ui_touch, EV_ABS, ABS_MT_TRACKING_ID, -1);
        slots[idx].used = false;
        active_touches--;
        if (active_touches == 0)
            emit(ui_touch, EV_KEY, BTN_TOUCH, 0);
        syn(ui_touch);
        break;
    default:
        break;
    }
}

/* ---------- control channel ---------- */

enum {
    CTL_KEYCODE = 0,
    CTL_TEXT = 1,
    CTL_TOUCH = 2,
    CTL_SCROLL = 3,
    CTL_BACK_OR_SCREEN_ON = 4,
    CTL_EXPAND_NOTIFICATION = 5,
    CTL_EXPAND_SETTINGS = 6,
    CTL_COLLAPSE_PANELS = 7,
    CTL_GET_CLIPBOARD = 8,
    CTL_SET_CLIPBOARD = 9,
    CTL_SET_DISPLAY_POWER = 10,
    CTL_ROTATE_DEVICE = 11,
    CTL_UHID_CREATE = 12,
    CTL_UHID_INPUT = 13,
    CTL_UHID_DESTROY = 14,
    CTL_OPEN_HARD_KEYBOARD_SETTINGS = 15,
    CTL_START_APP = 16,
    CTL_RESET_VIDEO = 17,
    CTL_CAMERA_SET_TORCH = 18,
    CTL_CAMERA_ZOOM_IN = 19,
    CTL_CAMERA_ZOOM_OUT = 20,
    CTL_RESIZE_DISPLAY = 21,
    CTL_SCAN_FILE = 22,
};

static volatile int force_idr;

/* Read and discard a length-prefixed field (len u32 at buf[0..3] already read). */
static int skip_bytes(int fd, uint32_t len) {
    if (len > MAX_CTRL_STRING)
        return -1;
    uint8_t *tmp = malloc(len ? len : 1);
    if (!tmp)
        return -1;
    int r = read_all(fd, tmp, len);
    free(tmp);
    return r;
}

static void *control_thread(void *arg) {
    int fd = *(int *)arg;
    free(arg);
    uint8_t b[64];
    for (;;) {
        uint8_t type;
        if (read_all(fd, &type, 1) < 0)
            break;
        switch (type) {
        case CTL_KEYCODE: /* action u8, keycode i32, repeat i32, meta i32 */
            if (read_all(fd, b, 13) < 0) goto done;
            inject_keycode(b[0], get_be32(b + 1));
            break;
        case CTL_TEXT: /* len u32, utf8 */
            if (read_all(fd, b, 4) < 0) goto done;
            {
                uint32_t len = get_be32(b);
                if (len > MAX_CTRL_STRING) goto done;
                char *text = malloc(len + 1);
                if (!text) goto done;
                if (read_all(fd, text, len) < 0) { free(text); goto done; }
                text[len] = '\0';
                inject_text(text, len);
                free(text);
            }
            break;
        case CTL_TOUCH: /* action u8, pointerId i64, x i32, y i32, w u16, h u16, pressure u16, button i32, buttons i32 */
            if (read_all(fd, b, 31) < 0) goto done;
            inject_touch(b[0], (int64_t)get_be64(b + 1), (int32_t)get_be32(b + 9),
                         (int32_t)get_be32(b + 13), get_be16(b + 17), get_be16(b + 19));
            break;
        case CTL_SCROLL: /* position 12 bytes, hscroll i16, vscroll i16, buttons i32 */
            if (read_all(fd, b, 20) < 0) goto done;
            break;
        case CTL_BACK_OR_SCREEN_ON: /* action u8 */
            if (read_all(fd, b, 1) < 0) goto done;
            if (b[0] == 0)
                key_tap(KEY_BACK);
            break;
        case CTL_EXPAND_NOTIFICATION:
        case CTL_EXPAND_SETTINGS:
        case CTL_COLLAPSE_PANELS:
        case CTL_ROTATE_DEVICE:
        case CTL_OPEN_HARD_KEYBOARD_SETTINGS:
        case CTL_CAMERA_ZOOM_IN:
        case CTL_CAMERA_ZOOM_OUT:
            break;
        case CTL_RESET_VIDEO:
            __atomic_store_n(&force_idr, 1, __ATOMIC_RELAXED);
            break;
        case CTL_GET_CLIPBOARD:
        case CTL_SET_DISPLAY_POWER:
        case CTL_CAMERA_SET_TORCH:
            if (read_all(fd, b, 1) < 0) goto done;
            break;
        case CTL_SET_CLIPBOARD: /* seq i64, paste u8, len u32, text */
            if (read_all(fd, b, 13) < 0) goto done;
            if (skip_bytes(fd, get_be32(b + 9)) < 0) goto done;
            break;
        case CTL_UHID_CREATE: /* id u16, vid u16, pid u16, name len u8 + bytes, data len u16 + bytes */
            if (read_all(fd, b, 7) < 0) goto done;
            if (skip_bytes(fd, b[6]) < 0) goto done;
            if (read_all(fd, b, 2) < 0) goto done;
            if (skip_bytes(fd, get_be16(b)) < 0) goto done;
            break;
        case CTL_UHID_INPUT: /* id u16, len u16, data */
            if (read_all(fd, b, 4) < 0) goto done;
            if (skip_bytes(fd, get_be16(b + 2)) < 0) goto done;
            break;
        case CTL_UHID_DESTROY: /* id u16 */
            if (read_all(fd, b, 2) < 0) goto done;
            break;
        case CTL_START_APP: /* len u8 + name */
            if (read_all(fd, b, 1) < 0) goto done;
            if (skip_bytes(fd, b[0]) < 0) goto done;
            break;
        case CTL_RESIZE_DISPLAY: /* w u16, h u16 */
            if (read_all(fd, b, 4) < 0) goto done;
            break;
        case CTL_SCAN_FILE: /* len u32 + path */
            if (read_all(fd, b, 4) < 0) goto done;
            if (skip_bytes(fd, get_be32(b)) < 0) goto done;
            break;
        default:
            LOG("unknown control message type %u, closing control", type);
            goto done;
        }
    }
done:
    LOG("control channel closed");
    close(fd);
    return NULL;
}

/* ---------- wayland / wlr-screencopy ---------- */

struct wl {
    struct wl_display *dpy;
    struct wl_registry *reg;
    struct wl_shm *shm;
    struct wl_output *out;
    struct zwlr_screencopy_manager_v1 *mgr;
    uint32_t mgr_ver;
    int mode_w, mode_h;

    /* per-frame state, set by frame events */
    bool have_buffer, buf_done, copy_ready, copy_failed, y_invert;
    uint32_t fmt, fw, fh, fstride;

    /* shm buffer currently attached */
    struct wl_buffer *buf;
    void *map;
    size_t map_size;
    int memfd;
    uint32_t bfmt, bw, bh, bstride;
};

static void out_mode(void *d, struct wl_output *o, uint32_t flags, int32_t w, int32_t h, int32_t refresh) {
    struct wl *s = d;
    (void)o; (void)refresh;
    if (flags & WL_OUTPUT_MODE_CURRENT) {
        s->mode_w = w;
        s->mode_h = h;
    }
}

static void out_geometry(void *d, struct wl_output *o, int32_t x, int32_t y, int32_t pw, int32_t ph,
                         int32_t subpixel, const char *make, const char *model, int32_t transform) {
    (void)d; (void)o; (void)x; (void)y; (void)pw; (void)ph;
    (void)subpixel; (void)make; (void)model; (void)transform;
}

static void out_done(void *d, struct wl_output *o) {
    (void)d; (void)o;
}

static void out_scale(void *d, struct wl_output *o, int32_t factor) {
    (void)d; (void)o; (void)factor;
}

static const struct wl_output_listener out_listener = {
    .geometry = out_geometry,
    .mode = out_mode,
    .done = out_done,
    .scale = out_scale,
};

static void reg_global(void *data, struct wl_registry *r, uint32_t name, const char *iface, uint32_t version) {
    struct wl *s = data;
    if (!strcmp(iface, wl_shm_interface.name)) {
        s->shm = wl_registry_bind(r, name, &wl_shm_interface, 1);
    } else if (!strcmp(iface, wl_output_interface.name) && !s->out) {
        s->out = wl_registry_bind(r, name, &wl_output_interface, version < 2 ? version : 2);
        wl_output_add_listener(s->out, &out_listener, s);
    } else if (!strcmp(iface, zwlr_screencopy_manager_v1_interface.name)) {
        s->mgr_ver = version > 3 ? 3 : version;
        s->mgr = wl_registry_bind(r, name, &zwlr_screencopy_manager_v1_interface, s->mgr_ver);
    }
}

static void reg_global_remove(void *data, struct wl_registry *r, uint32_t name) {
    (void)data; (void)r; (void)name;
}

static const struct wl_registry_listener reg_listener = {
    .global = reg_global,
    .global_remove = reg_global_remove,
};

static void fr_buffer(void *d, struct zwlr_screencopy_frame_v1 *f, uint32_t fmt, uint32_t w, uint32_t h, uint32_t stride) {
    struct wl *s = d;
    (void)f;
    s->fmt = fmt;
    s->fw = w;
    s->fh = h;
    s->fstride = stride;
    s->have_buffer = true;
}

static void fr_flags(void *d, struct zwlr_screencopy_frame_v1 *f, uint32_t flags) {
    struct wl *s = d;
    (void)f;
    s->y_invert = (flags & ZWLR_SCREENCOPY_FRAME_V1_FLAGS_Y_INVERT) != 0;
}

static void fr_ready(void *d, struct zwlr_screencopy_frame_v1 *f, uint32_t hi, uint32_t lo, uint32_t ns) {
    struct wl *s = d;
    (void)f; (void)hi; (void)lo; (void)ns;
    s->copy_ready = true;
}

static void fr_failed(void *d, struct zwlr_screencopy_frame_v1 *f) {
    struct wl *s = d;
    (void)f;
    s->copy_failed = true;
}

static void fr_damage(void *d, struct zwlr_screencopy_frame_v1 *f, uint32_t x, uint32_t y, uint32_t w, uint32_t h) {
    (void)d; (void)f; (void)x; (void)y; (void)w; (void)h;
}

static void fr_linux_dmabuf(void *d, struct zwlr_screencopy_frame_v1 *f, uint32_t fmt, uint32_t w, uint32_t h) {
    (void)d; (void)f; (void)fmt; (void)w; (void)h;
}

static void fr_buffer_done(void *d, struct zwlr_screencopy_frame_v1 *f) {
    struct wl *s = d;
    (void)f;
    s->buf_done = true;
}

static const struct zwlr_screencopy_frame_v1_listener frame_listener = {
    .buffer = fr_buffer,
    .flags = fr_flags,
    .ready = fr_ready,
    .failed = fr_failed,
    .damage = fr_damage,
    .linux_dmabuf = fr_linux_dmabuf,
    .buffer_done = fr_buffer_done,
};

static void free_buffer(struct wl *s) {
    if (s->buf) {
        wl_buffer_destroy(s->buf);
        s->buf = NULL;
    }
    if (s->map) {
        munmap(s->map, s->map_size);
        s->map = NULL;
    }
    if (s->memfd >= 0) {
        close(s->memfd);
        s->memfd = -1;
    }
}

static int ensure_buffer(struct wl *s) {
    if (s->buf && s->bfmt == s->fmt && s->bw == s->fw && s->bh == s->fh && s->bstride == s->fstride)
        return 0;
    free_buffer(s);
    size_t size = (size_t)s->fstride * s->fh;
    int fd = memfd_create("scrcpy-shm", MFD_CLOEXEC);
    if (fd < 0)
        return -1;
    if (ftruncate(fd, (off_t)size) < 0) {
        close(fd);
        return -1;
    }
    void *m = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) {
        close(fd);
        return -1;
    }
    struct wl_shm_pool *pool = wl_shm_create_pool(s->shm, fd, (int32_t)size);
    s->buf = wl_shm_pool_create_buffer(pool, 0, (int32_t)s->fw, (int32_t)s->fh, (int32_t)s->fstride, s->fmt);
    wl_shm_pool_destroy(pool);
    s->map = m;
    s->map_size = size;
    s->memfd = fd;
    s->bfmt = s->fmt;
    s->bw = s->fw;
    s->bh = s->fh;
    s->bstride = s->fstride;
    return 0;
}

/* stage 0: frame offered its buffer parameters; stage 1: copy finished */
static bool stage_done(const struct wl *s, int stage) {
    if (stage == 0)
        return s->copy_failed || (s->mgr_ver >= 3 ? s->buf_done : s->have_buffer);
    return s->copy_ready || s->copy_failed;
}

/* Dispatch Wayland events until the stage completes or the timeout expires. */
static int wl_wait(struct wl *s, int stage, int timeout_ms) {
    int64_t deadline = mono_ms() + timeout_ms;
    while (!stage_done(s, stage)) {
        while (wl_display_prepare_read(s->dpy) != 0)
            wl_display_dispatch_pending(s->dpy);
        if (wl_display_flush(s->dpy) < 0 && errno != EAGAIN) {
            wl_display_cancel_read(s->dpy);
            return -1;
        }
        int64_t left = deadline - mono_ms();
        if (left < 0)
            left = 0;
        struct pollfd p = { .fd = wl_display_get_fd(s->dpy), .events = POLLIN };
        int r = poll(&p, 1, (int)left);
        if (r <= 0) {
            wl_display_cancel_read(s->dpy);
            return -1;
        }
        if (wl_display_read_events(s->dpy) < 0)
            return -1;
        wl_display_dispatch_pending(s->dpy);
    }
    return 0;
}

/* Connect to the compositor, filling in WAYLAND_DISPLAY/XDG_RUNTIME_DIR if unset. */
static int wl_connect_env(struct wl *s) {
    memset(s, 0, sizeof *s);
    s->memfd = -1;
    if (!getenv("XDG_RUNTIME_DIR")) {
        char p[64];
        snprintf(p, sizeof p, "/run/user/%d", (int)getuid());
        setenv("XDG_RUNTIME_DIR", p, 1);
    }
    if (!getenv("WAYLAND_DISPLAY")) {
        const char *dir = getenv("XDG_RUNTIME_DIR");
        DIR *d = dir ? opendir(dir) : NULL;
        if (d) {
            struct dirent *e;
            while ((e = readdir(d))) {
                if (!strncmp(e->d_name, "wayland-", 8) && !strstr(e->d_name, ".lock")) {
                    setenv("WAYLAND_DISPLAY", e->d_name, 1);
                    break;
                }
            }
            closedir(d);
        }
    }
    s->dpy = wl_display_connect(NULL);
    if (!s->dpy)
        return -1;
    s->reg = wl_display_get_registry(s->dpy);
    wl_registry_add_listener(s->reg, &reg_listener, s);
    wl_display_roundtrip(s->dpy);
    wl_display_roundtrip(s->dpy);
    if (!s->mgr || !s->shm || !s->out) {
        LOG("compositor lacks zwlr_screencopy_manager_v1, wl_shm or wl_output");
        wl_display_disconnect(s->dpy);
        s->dpy = NULL;
        return -1;
    }
    return 0;
}

static int capture(struct wl *s) {
    s->have_buffer = s->buf_done = s->copy_ready = s->copy_failed = false;
    struct zwlr_screencopy_frame_v1 *f = zwlr_screencopy_manager_v1_capture_output(s->mgr, 0, s->out);
    zwlr_screencopy_frame_v1_add_listener(f, &frame_listener, s);
    int ret = -1;
    int step = 0;
    if (wl_wait(s, 0, WL_TIMEOUT_MS) < 0 || s->copy_failed || !s->have_buffer) {
        step = 1;
        goto out;
    }
    if (ensure_buffer(s) < 0) {
        step = 2;
        goto out;
    }
    zwlr_screencopy_frame_v1_copy(f, s->buf);
    if (wl_wait(s, 1, WL_TIMEOUT_MS) < 0 || !s->copy_ready) {
        step = 3;
        goto out;
    }
    ret = 0;
out:
    if (ret != 0) {
        static int nlog;
        if (nlog++ < 5)
            LOG("capture failed at step %d (have_buffer=%d buf_done=%d copy_failed=%d)", step, s->have_buffer, s->buf_done, s->copy_failed);
    }
    zwlr_screencopy_frame_v1_destroy(f);
    wl_display_flush(s->dpy);
    return ret;
}

/* ---------- conversion: screencopy XRGB -> scaled I420 ---------- */

struct conv {
    int sw, sh, dw, dh;
    int *xr0, *xr1, *yr0, *yr1;
    uint8_t *rgb; /* dw*dh*3 */
};

static int conv_init(struct conv *c, int sw, int sh, int dw, int dh) {
    memset(c, 0, sizeof *c);
    c->sw = sw;
    c->sh = sh;
    c->dw = dw;
    c->dh = dh;
    c->xr0 = malloc(sizeof(int) * dw);
    c->xr1 = malloc(sizeof(int) * dw);
    c->yr0 = malloc(sizeof(int) * dh);
    c->yr1 = malloc(sizeof(int) * dh);
    c->rgb = malloc((size_t)dw * dh * 3);
    if (!c->xr0 || !c->xr1 || !c->yr0 || !c->yr1 || !c->rgb)
        return -1;
    for (int x = 0; x < dw; x++) {
        c->xr0[x] = (int)((int64_t)x * sw / dw);
        c->xr1[x] = (int)((int64_t)(x + 1) * sw / dw);
        if (c->xr1[x] <= c->xr0[x]) c->xr1[x] = c->xr0[x] + 1;
        if (c->xr1[x] > sw) c->xr1[x] = sw;
    }
    for (int y = 0; y < dh; y++) {
        c->yr0[y] = (int)((int64_t)y * sh / dh);
        c->yr1[y] = (int)((int64_t)(y + 1) * sh / dh);
        if (c->yr1[y] <= c->yr0[y]) c->yr1[y] = c->yr0[y] + 1;
        if (c->yr1[y] > sh) c->yr1[y] = sh;
    }
    return 0;
}

static void conv_free(struct conv *c) {
    free(c->xr0);
    free(c->xr1);
    free(c->yr0);
    free(c->yr1);
    free(c->rgb);
    memset(c, 0, sizeof *c);
}

/* Box-filter the screencopy buffer into RGB, then write Y/U/V planes of the x264 picture. */
static int convert_frame(struct conv *c, const struct wl *s, const uint8_t *src, x264_picture_t *pic) {
    int ro, bo;
    switch (s->fmt) {
    case WL_SHM_FORMAT_ARGB8888:
    case WL_SHM_FORMAT_XRGB8888:
        bo = 0; ro = 2; /* B,G,R,X in memory */
        break;
    case WL_SHM_FORMAT_ABGR8888:
    case WL_SHM_FORMAT_XBGR8888:
        bo = 2; ro = 0; /* R,G,B,X in memory */
        break;
    default:
        LOG("unsupported screencopy format 0x%08x", s->fmt);
        return -1;
    }
    for (int dy = 0; dy < c->dh; dy++) {
        int y0 = c->yr0[dy], y1 = c->yr1[dy];
        for (int dx = 0; dx < c->dw; dx++) {
            int x0 = c->xr0[dx], x1 = c->xr1[dx];
            uint32_t r = 0, g = 0, b = 0, n = 0;
            for (int sy = y0; sy < y1; sy++) {
                int ey = s->y_invert ? (c->sh - 1 - sy) : sy;
                const uint8_t *row = src + (size_t)ey * s->fstride;
                for (int sx = x0; sx < x1; sx++) {
                    const uint8_t *p = row + (size_t)sx * 4;
                    r += p[ro];
                    g += p[1];
                    b += p[bo];
                    n++;
                }
            }
            uint8_t *o = c->rgb + ((size_t)dy * c->dw + dx) * 3;
            o[0] = (uint8_t)(r / n);
            o[1] = (uint8_t)(g / n);
            o[2] = (uint8_t)(b / n);
        }
    }
    /* Y plane (BT.601 limited range) */
    for (int y = 0; y < c->dh; y++) {
        uint8_t *yp = pic->img.plane[0] + (size_t)y * pic->img.i_stride[0];
        const uint8_t *in = c->rgb + (size_t)y * c->dw * 3;
        for (int x = 0; x < c->dw; x++) {
            int R = in[x * 3], G = in[x * 3 + 1], B = in[x * 3 + 2];
            int Y = ((66 * R + 129 * G + 25 * B + 128) >> 8) + 16;
            yp[x] = (uint8_t)(Y < 0 ? 0 : Y > 255 ? 255 : Y);
        }
    }
    /* U/V planes, 2x2 averaged */
    for (int y = 0; y < c->dh / 2; y++) {
        uint8_t *up = pic->img.plane[1] + (size_t)y * pic->img.i_stride[1];
        uint8_t *vp = pic->img.plane[2] + (size_t)y * pic->img.i_stride[2];
        const uint8_t *r0 = c->rgb + (size_t)(2 * y) * c->dw * 3;
        const uint8_t *r1 = r0 + (size_t)c->dw * 3;
        for (int x = 0; x < c->dw / 2; x++) {
            int R = 0, G = 0, B = 0;
            for (int k = 0; k < 2; k++) {
                const uint8_t *a = (k ? r1 : r0) + (size_t)(2 * x) * 3;
                R += a[0] + a[3];
                G += a[1] + a[4];
                B += a[2] + a[5];
            }
            R >>= 2; G >>= 2; B >>= 2;
            int U = ((-38 * R - 74 * G + 112 * B + 128) >> 8) + 128;
            int V = ((112 * R - 94 * G - 18 * B + 128) >> 8) + 128;
            up[x] = (uint8_t)(U < 0 ? 0 : U > 255 ? 255 : U);
            vp[x] = (uint8_t)(V < 0 ? 0 : V > 255 ? 255 : V);
        }
    }
    return 0;
}

/* ---------- encoder ---------- */

struct enc {
    x264_t *x;
    x264_picture_t pic;
    int w, h;
    int64_t frame;
};

static int enc_open(struct enc *e, int w, int h, const struct opts *o) {
    x264_param_t p;
    if (x264_param_default_preset(&p, "ultrafast", "zerolatency") < 0)
        return -1;
    p.i_width = w;
    p.i_height = h;
    p.i_csp = X264_CSP_I420;
    p.i_fps_num = o->fps;
    p.i_fps_den = 1;
    p.b_vfr_input = 0;
    p.b_repeat_headers = 1;
    p.b_annexb = 1;
    p.i_keyint_max = o->fps * 2;
    p.i_threads = o->threads;
    p.rc.i_rc_method = X264_RC_ABR;
    p.rc.i_bitrate = o->bitrate / 1000;
    p.rc.i_vbv_max_bitrate = o->bitrate / 1000;
    p.rc.i_vbv_buffer_size = o->bitrate / 1000;
    p.i_log_level = X264_LOG_WARNING;
    if (x264_param_apply_profile(&p, "baseline") < 0)
        return -1;
    e->x = x264_encoder_open(&p);
    if (!e->x)
        return -1;
    if (x264_picture_alloc(&e->pic, X264_CSP_I420, w, h) < 0) {
        x264_encoder_close(e->x);
        e->x = NULL;
        return -1;
    }
    e->w = w;
    e->h = h;
    e->frame = 0;
    return 0;
}

static void enc_close(struct enc *e) {
    if (!e->x)
        return;
    x264_picture_clean(&e->pic);
    x264_encoder_close(e->x);
    e->x = NULL;
}

/* ---------- video stream output (scrcpy framing) ---------- */

static int send_session(int fd, uint32_t w, uint32_t h) {
    uint8_t hdr[12] = { 0 };
    hdr[0] = 0x80; /* session packet flag */
    put_be32(hdr + 4, w);
    put_be32(hdr + 8, h);
    return write_all(fd, hdr, sizeof hdr);
}

static int send_media(int fd, uint64_t flags_pts, const uint8_t *data, uint32_t len) {
    uint8_t hdr[12];
    put_be64(hdr, flags_pts);
    put_be32(hdr + 8, len);
    if (write_all(fd, hdr, sizeof hdr) < 0)
        return -1;
    return write_all(fd, data, len);
}

/* ---------- main ---------- */

static void on_sigterm(int sig) {
    (void)sig;
    _exit(0);
}

int main(int argc, char **argv) {
    struct opts o;
    parse_args(argc, argv, &o);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, on_sigterm);
    signal(SIGINT, on_sigterm);

    char name[32];
    snprintf(name, sizeof name, "scrcpy_%08x", o.scid);

    /* Socket order matches scrcpy: video, then audio (if enabled), then control. */
    int vfd, afd = -1, cfd = -1;
    if (o.forward) {
        int l = sock_listen(name);
        vfd = sock_accept_on(l);
        if (vfd < 0) die("accept video");
        uint8_t dummy = 0;
        if (write_all(vfd, &dummy, 1) < 0) die("dummy byte");
        if (o.audio) afd = sock_accept_on(l);
        if (o.control) cfd = sock_accept_on(l);
        close(l);
    } else {
        vfd = sock_connect(name);
        if (vfd < 0) die("connect video");
        if (o.audio) afd = sock_connect(name);
        if (o.control) cfd = sock_connect(name);
    }
    if (afd >= 0) {
        /* codec id 0 = audio explicitly disabled; the client continues
         * video-only. Keep the socket open until the session ends: closing
         * it at once lets the adb tunnel drop the four bytes, and the client
         * then reports a connection error and quits. */
        uint8_t zero[4] = { 0, 0, 0, 0 };
        write_all(afd, zero, sizeof zero);
    }

    const char *devname = getenv("SCRCPY_DEVICE_NAME");
    if (!devname || !*devname)
        devname = "postmarketOS bramble";
    uint8_t devbuf[64] = { 0 };
    strncpy((char *)devbuf, devname, 63);
    if (write_all(vfd, devbuf, sizeof devbuf) < 0) die("device name");

    /* Wait for the compositor before announcing the codec. */
    struct wl w;
    int wl_ok = -1;
    for (int t = 0; t < 120 && wl_ok < 0; t++) {
        wl_ok = wl_connect_env(&w);
        if (wl_ok < 0)
            sleep(1);
    }
    if (wl_ok < 0)
        die("cannot connect to Wayland compositor");
    LOG("wayland %s, screencopy v%u, mode %dx%d", getenv("WAYLAND_DISPLAY"), w.mgr_ver, w.mode_w, w.mode_h);

    if (cfd >= 0) {
        ui_touch = touch_create();
        ui_keys = keys_create();
        int *p = malloc(sizeof(int));
        *p = cfd;
        pthread_t th;
        if (pthread_create(&th, NULL, control_thread, p) != 0)
            die("control thread");
        pthread_detach(th);
    }

    struct enc enc;
    memset(&enc, 0, sizeof enc);
    struct conv conv;
    memset(&conv, 0, sizeof conv);
    int cw = 0, ch = 0; /* source dims the converter was built for */
    bool started = false;
    int64_t t_start = mono_us();
    int period_us = 1000000 / o.fps;

    for (;;) {
        int64_t t0 = mono_us();
        if (capture(&w) != 0) {
            /* screen off or no frame yet: keep retrying, do not end the stream */
            usleep(200000);
            continue;
        }
        int sw = (int)w.fw, sh = (int)w.fh;
        int dw = sw, dh = sh;
        int longside = sw > sh ? sw : sh;
        if (longside > o.max_size) {
            dw = (int)((int64_t)sw * o.max_size / longside);
            dh = (int)((int64_t)sh * o.max_size / longside);
        }
        dw &= ~1;
        dh &= ~1;
        if (dw < 2) dw = 2;
        if (dh < 2) dh = 2;

        if (!enc.x || dw != enc.w || dh != enc.h || sw != cw || sh != ch) {
            enc_close(&enc);
            conv_free(&conv);
            if (conv_init(&conv, sw, sh, dw, dh) < 0 || enc_open(&enc, dw, dh, &o) < 0)
                die("encoder setup");
            cw = sw;
            ch = sh;
            if (!started) {
                /* codec id "h264" */
                uint8_t codec[4] = { 0x68, 0x32, 0x36, 0x34 };
                if (write_all(vfd, codec, sizeof codec) < 0) die("codec id");
                started = true;
            }
            if (send_session(vfd, (uint32_t)dw, (uint32_t)dh) < 0) die("session");
            x264_nal_t *hn;
            int hcount;
            int hs = x264_encoder_headers(enc.x, &hn, &hcount);
            if (hs < 0) die("x264 headers");
            if (send_media(vfd, PKT_FLAG_CONFIG, hn[0].p_payload, (uint32_t)hs) < 0) die("config");
            __atomic_store_n(&force_idr, 1, __ATOMIC_RELAXED);
            LOG("stream %dx%d from %dx%d", dw, dh, sw, sh);
        }

        if (convert_frame(&conv, &w, w.map, &enc.pic) < 0) die("convert");

        int idr = __atomic_exchange_n(&force_idr, 0, __ATOMIC_RELAXED);
        enc.pic.i_pts = enc.frame++;
        enc.pic.i_type = idr ? X264_TYPE_IDR : X264_TYPE_AUTO;
        x264_nal_t *nals;
        int nn;
        x264_picture_t pout;
        int sz = x264_encoder_encode(enc.x, &nals, &nn, &enc.pic, &pout);
        if (sz < 0) die("x264 encode");
        if (sz > 0) {
            uint64_t pts = (uint64_t)(mono_us() - t_start);
            uint64_t flags = pts | (pout.b_keyframe ? PKT_FLAG_KEY : 0);
            if (send_media(vfd, flags, nals[0].p_payload, (uint32_t)sz) < 0) {
                LOG("video socket closed");
                break;
            }
        }

        int64_t el = mono_us() - t0;
        if (el < period_us)
            usleep((useconds_t)(period_us - el));
    }

    enc_close(&enc);
    conv_free(&conv);
    free_buffer(&w);
    return 0;
}
