/*
 * Copyright (C) 2026 Sehannnnn
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stddef.h>
#include <time.h>
#include <poll.h>

#define DEFAULT_SOCK_PATH "/data/local/tmp/coredaemon/run/coredaemon.sock"
#define ABSTRACT_NAME "coredaemon"
#define CTRL_ABSTRACT_NAME "coredaemon-ctrl"
#define CTRL_SOCK_PATH "/data/local/tmp/coredaemon/run/coredaemon-ctrl.sock"
#define RECV_BUF 4096

static int force_abstract = 0;
static const char* forced_path = NULL;
static int one_shot = 0;
static int quiet = 0;
static int reconnect = 0;
static int filter_open = 0;
static int filter_close = 0;
static int filter_fg = 0;
static int json_output = 0;
static char filter_pkg[256] = {0};
static char filter_type[64] = {0};
static char filter_fg_pkg[256] = {0};
static const char* control_cmd = NULL;
static const char* forced_ctrl_path = NULL;

static int send_all(int fd, const void* data, size_t len) {
    const char* p = (const char*)data;
    while (len > 0) {
        ssize_t n = send(fd, p, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static char* recv_all_timeout(int fd, const char* delim, size_t max_bytes, int timeout_ms) {
    char* response = NULL;
    size_t resp_len = 0;
    char buf[RECV_BUF];

    struct timeval start;
    gettimeofday(&start, NULL);

    while (resp_len < max_bytes) {
        struct timeval now;
        gettimeofday(&now, NULL);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 +
                       (now.tv_usec - start.tv_usec) / 1000;
        int remaining = timeout_ms - (int)elapsed;
        if (remaining <= 0) {
            free(response);
            return NULL;
        }

        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int ready = poll(&pfd, 1, remaining);
        if (ready < 0) {
            if (errno == EINTR) continue;
            free(response);
            return NULL;
        }
        if (ready == 0) {
            free(response);
            return NULL;
        }

        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(response);
            return NULL;
        }
        if (n == 0) {
            free(response);
            return NULL;
        }

        size_t chunk = (size_t)n;
        if (resp_len + chunk > max_bytes)
            chunk = max_bytes - resp_len;
        if (chunk == 0) {
            free(response);
            return NULL;
        }

        char* tmp = realloc(response, resp_len + chunk + 1);
        if (!tmp) {
            free(response);
            return NULL;
        }
        response = tmp;
        memcpy(response + resp_len, buf, chunk);
        resp_len += chunk;
        response[resp_len] = '\0';
        
        if (strstr(response, delim))
            return response;
    }

    free(response);
    return NULL;
}

static int connect_abstract(const char* name) {
    size_t name_len = strlen(name);
    if (name_len >= sizeof(((struct sockaddr_un*)0)->sun_path) - 1) {
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    memcpy(addr.sun_path + 1, name, name_len);

    socklen_t len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + name_len);
    if (connect(fd, (struct sockaddr*)&addr, len) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int connect_filesystem(const char* path) {
    size_t path_len = strlen(path);
    if (path_len >= sizeof(((struct sockaddr_un*)0)->sun_path)) {
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path, path_len + 1);

    socklen_t len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_len + 1);

    if (connect(fd, (struct sockaddr*)&addr, len) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int connect_event_socket(void) {
    int fd = -1;
    if (force_abstract) {
        fd = connect_abstract(ABSTRACT_NAME);
    } else if (forced_path) {
        fd = connect_filesystem(forced_path);
    } else {
        fd = connect_abstract(ABSTRACT_NAME);
        if (fd < 0) fd = connect_filesystem(DEFAULT_SOCK_PATH);
    }
    return fd;
}

static int connect_control_socket(void) {
    if (forced_ctrl_path) {
        return connect_filesystem(forced_ctrl_path);
    }
    if (force_abstract) {
        return connect_abstract(CTRL_ABSTRACT_NAME);
    }
    int fd = connect_abstract(CTRL_ABSTRACT_NAME);
    if (fd < 0) fd = connect_filesystem(CTRL_SOCK_PATH);
    return fd;
}

static void usage(const char* prog) {
    fprintf(stderr,
        "cored_client\n\n"
        "Usage: %s [options]\n"
        "  -a                Force abstract socket\n"
        "  -s <path>         Force filesystem socket\n"
        "  -S <path>         Force control socket path\n"
        "  -1                Exit after first event\n"
        "  -q                Quiet\n"
        "  -R                Reconnect\n"
        "  -o                OPENED only\n"
        "  -c                CLOSED only\n"
        "  -p <pkg>          Package filter\n"
        "  -t <type>         Type filter\n"
        "  -g [pkg]          FOREGROUND filter (opt. package)\n"
        "  -j                JSON output\n"
        "  -C <cmd>         Control command\n"
        "  --version\n"
        "  --help\n",
        prog);
}

static int event_matches(const char* line) {
    const char* p = line;
    p = strchr(p, '|');
    if (!p) return 0;
    p++;

    const char* type_start = p;
    p = strchr(p, '|');
    if (!p) return 0;
    size_t type_len = p - type_start;
    p++;

    const char* pkg_start = p;
    p = strchr(p, '|');
    if (!p) return 0;
    size_t pkg_len = p - pkg_start;

    if (filter_fg) {
        if (type_len != 10 || strncmp(type_start, "FOREGROUND", 10) != 0)
            return 0;

        if (filter_fg_pkg[0]) {
            if (pkg_len != strlen(filter_fg_pkg) ||
                strncmp(pkg_start, filter_fg_pkg, pkg_len) != 0)
                return 0;
            return 1;
        }

        const char* extra = strchr(p + 1, '|');
        if (!extra) return 0;
        extra++;
        if (strncmp(extra, "monitored=1", 11) == 0)
            return 1;
        return 0;
    }

    if (filter_open && (type_len != 6 || strncmp(type_start, "OPENED", 6) != 0))
        return 0;
    if (filter_close && (type_len != 6 || strncmp(type_start, "CLOSED", 6) != 0))
        return 0;
    if (filter_type[0] && (type_len != strlen(filter_type) ||
                           strncmp(type_start, filter_type, type_len) != 0))
        return 0;
    if (filter_pkg[0] && (pkg_len != strlen(filter_pkg) ||
                          strncmp(pkg_start, filter_pkg, pkg_len) != 0))
        return 0;

    return 1;
}

static void json_escape(const char* s) {
    putchar('"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\b': fputs("\\b", stdout);  break;
        case '\f': fputs("\\f", stdout);  break;
        case '\n': fputs("\\n", stdout);  break;
        case '\r': fputs("\\r", stdout);  break;
        case '\t': fputs("\\t", stdout);  break;
        default:
            if (c < 0x20)
                fprintf(stdout, "\\u%04x", c);
            else
                putchar(c);
        }
    }
    putchar('"');
}

static void print_json(const char* line) {
    const char* p = line;
    char ts[32] = "";
    char type[32] = "";
    char pkg[256] = "";
    int pid = 0;
    char extra[512] = "";
    const char* start = p;
    p = strchr(p, '|');
    if (p) {
        size_t len = p - start;
        if (len >= sizeof(ts)) len = sizeof(ts) - 1;
        memcpy(ts, start, len);
        ts[len] = '\0';
        p++;
    }

    start = p;
    p = strchr(p, '|');
    if (p) {
        size_t len = p - start;
        if (len >= sizeof(type)) len = sizeof(type) - 1;
        memcpy(type, start, len);
        type[len] = '\0';
        p++;
    }

    start = p;
    p = strchr(p, '|');
    if (p) {
        size_t len = p - start;
        if (len >= sizeof(pkg)) len = sizeof(pkg) - 1;
        memcpy(pkg, start, len);
        pkg[len] = '\0';
        p++;
    }

    start = p;
    p = strchr(p, '|');
    if (p) {
        size_t len = p - start;
        char pid_str[16];
        if (len >= sizeof(pid_str)) len = sizeof(pid_str) - 1;
        memcpy(pid_str, start, len);
        pid_str[len] = '\0';
        pid = atoi(pid_str);
        p++;
        if (*p && *p != '\n') {
            size_t elen = strlen(p);
            if (elen > sizeof(extra) - 1) elen = sizeof(extra) - 1;
            memcpy(extra, p, elen);
            extra[elen] = '\0';
            if (elen > 0 && extra[elen - 1] == '\n')
                extra[elen - 1] = '\0';
        }
    }

    printf("{\"timestamp\":");
    json_escape(ts);
    printf(",\"type\":");
    json_escape(type);
    printf(",\"package\":");
    json_escape(pkg);
    printf(",\"pid\":%d", pid);
    if (extra[0]) {
        printf(",\"extra\":");
        json_escape(extra);
    }
    printf("}\n");
}

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0) {
            force_abstract = 1;
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            forced_path = argv[++i];
        } else if (strcmp(argv[i], "-1") == 0) {
            one_shot = 1;
        } else if (strcmp(argv[i], "-q") == 0) {
            quiet = 1;
        } else if (strcmp(argv[i], "-R") == 0) {
            reconnect = 1;
        } else if (strcmp(argv[i], "-o") == 0) {
            filter_open = 1;
        } else if (strcmp(argv[i], "-c") == 0) {
            filter_close = 1;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            size_t len = strlen(argv[i+1]);
            if (len >= sizeof(filter_pkg)) len = sizeof(filter_pkg) - 1;
            memcpy(filter_pkg, argv[++i], len);
            filter_pkg[len] = '\0';
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            size_t len = strlen(argv[i+1]);
            if (len >= sizeof(filter_type)) len = sizeof(filter_type) - 1;
            memcpy(filter_type, argv[++i], len);
            filter_type[len] = '\0';
        } else if (strcmp(argv[i], "-g") == 0) {
            filter_fg = 1;
            if (i + 1 < argc && argv[i+1][0] != '-') {
                size_t len = strlen(argv[i+1]);
                if (len >= sizeof(filter_fg_pkg)) len = sizeof(filter_fg_pkg) - 1;
                memcpy(filter_fg_pkg, argv[++i], len);
                filter_fg_pkg[len] = '\0';
            }
        } else if (strcmp(argv[i], "-j") == 0) {
            json_output = 1;
        } else if (strcmp(argv[i], "-C") == 0 && i + 1 < argc) {
            control_cmd = argv[++i];
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("cored_client v1.0\n");
            return 0;
        } else if (strcmp(argv[i], "-S") == 0 && i + 1 < argc) {
            forced_ctrl_path = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "cored_client: unknown option: %s\n\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }
    
    if (filter_open && filter_close) {
        fprintf(stderr, "cored_client: -o and -c cannot be used together\n");
        return 1;
    }

    if (control_cmd) {
    int fd = connect_control_socket();
    if (fd < 0) {
        fprintf(stderr, "cored_client: cannot connect to control socket\n");
        return 2;
    }

    if (send_all(fd, control_cmd, strlen(control_cmd)) != 0 ||
        send_all(fd, "\n", 1) != 0) {
        fprintf(stderr, "cored_client: send failed\n");
        close(fd);
        return 3;
    }

    char* response = recv_all_timeout(fd, "CRON_END", 65536, 3000);
    if (!response) {
        fprintf(stderr, "cored_client: protocol error (timeout or no CRON_END)\n");
        close(fd);
        return 3;
    }

    fputs(response, stdout);
    free(response);
    close(fd);
    return 0;
}

    int first_connect = 1;
    int event_received = 0;

    while (1) {
        int fd = connect_event_socket();
        if (fd < 0) {
            if (!quiet || first_connect) {
                fprintf(stderr, "cored_client: cannot connect to event socket\n");
            }
            if (!reconnect) return 2;
            sleep(1);
            first_connect = 0;
            continue;
        }

        if (!quiet && first_connect) {
            fprintf(stderr, "Connected to CoreDaemon event stream.\n");
            fflush(stderr);
        }
        first_connect = 0;

        char buf[RECV_BUF];
        char line[RECV_BUF * 2];
        int line_len = 0;
        int should_exit = 0;

        while (!should_exit) {
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            if (n <= 0) {
                if (n == 0) {
                    if (!quiet) fprintf(stderr, "Daemon closed connection.\n");
                } else {
                    if (errno != EINTR && !quiet)
                        fprintf(stderr, "recv error: %s\n", strerror(errno));
                }
                break;
            }

            for (ssize_t i = 0; i < n; i++) {
                char c = buf[i];
                if (line_len < (int)sizeof(line) - 1) {
                line[line_len++] = c;
            } else {
                while (i < n && buf[i] != '\n') i++;
                line_len = 0;
                if (!quiet)
                    fprintf(stderr, "cored_client: oversized line discarded\n");
                if (i < n) i--;
                continue;
            }

                if (c == '\n') {
                    line[line_len] = '\0';
                    if (event_matches(line)) {
                        if (json_output) {
                            print_json(line);
                        } else {
                            fputs(line, stdout);
                        }
                        fflush(stdout);
                        event_received = 1;
                        if (one_shot) {
                            should_exit = 1;
                            break;
                        }
                    }
                    line_len = 0;
                }
            }
        }

        close(fd);
        if (should_exit) break;
        if (!reconnect) break;
        if (!quiet) fprintf(stderr, "Reconnecting in 1 second...\n");
        sleep(1);
    }

    if (one_shot && !event_received) {
        return 1;
    }
    return 0;
}