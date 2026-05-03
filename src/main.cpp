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

#include <csignal>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <pthread.h>

#include "daemon_core.h"
#include "utils.h"

static const char* kVersion = "CoreDaemon v1.0";
static int g_pid_fd = -1;

static void write_str(int fd, const char* s) {
    size_t len = strlen(s);
    while (len > 0) {
        ssize_t n = write(fd, s, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        s += n;
        len -= (size_t)n;
    }
}

static bool write_all(int fd, const char* data, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, data, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        data += n;
        len  -= (size_t)n;
    }
    return true;
}

static bool send_all(int fd, const void* data, size_t len) {
    const char* p = static_cast<const char*>(data);
    while (len > 0) {
        ssize_t n = ::send(fd, p, len, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        p += n;
        len -= (size_t)n;
    }
    return true;
}

static ssize_t recv_all_timeout(int fd, char* out, size_t max_bytes,
                                const char* delim, int timeout_ms,
                                bool* truncated) {
    const size_t delim_len = strlen(delim);
    *truncated = false;

    auto now_ms = []() -> int64_t {
        struct timespec ts{};
        ::clock_gettime(CLOCK_MONOTONIC, &ts);
        return (int64_t)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
    };
    int64_t deadline = now_ms() + timeout_ms;
    size_t total = 0;
    char buf[1024];

    while (total < max_bytes) {
        int64_t remaining = deadline - now_ms();
        if (remaining <= 0) return -1;

        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        int ready = ::poll(&pfd, 1, (int)remaining);
        if (ready < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (ready == 0) return -1;

        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;

        size_t take = (total + (size_t)n <= max_bytes) ? (size_t)n
                                                       : (max_bytes - total);
        if (take > 0) {
            memcpy(out + total, buf, take);
            total += take;

            size_t search_start = (total >= take + delim_len)
                                      ? total - take - delim_len + 1
                                      : 0;
            void* found = memmem(out + search_start, total - search_start,
                                 delim, delim_len);
            if (found) return (ssize_t)total;
        }

        if (total == max_bytes) {
            *truncated = true;
            return (ssize_t)total;
        }
    }
    return -1;
}

static bool ctrl_send(bool has_root, const std::string& cmd) {
    struct Endpoint {
        const char* path;
        bool        abstract;
    };

    static const Endpoint preferred[] = {
        { cfg::kCtrlSockPath,     false },
        { cfg::kCtrlSockAbstract, true  }
    };
    static const Endpoint fallback[] = {
        { cfg::kCtrlSockAbstract, true  },
        { cfg::kCtrlSockPath,     false }
    };

    const Endpoint* order = has_root ? preferred : fallback;
    static const Endpoint* last_good = nullptr;
    Fd fd;

    if (last_good) {
        fd = sock::connect_unix(last_good->path, last_good->abstract,
                                cfg::kDefaultCtrlTimeoutMs);
        if (fd.get() < 0) last_good = nullptr;
    }
    if (!last_good) {
        for (int attempt = 0; attempt < 2; ++attempt) {
            fd = sock::connect_unix(order[attempt].path, order[attempt].abstract,
                                    cfg::kDefaultCtrlTimeoutMs);
            if (fd.get() >= 0) {
                last_good = &order[attempt];
                break;
            }
        }
    }

    if (fd.get() < 0) {
        last_good = nullptr;
        char msg[256];
        snprintf(msg, sizeof(msg), "coredaemon: cannot connect to control socket (%s)\n",
                 errno_str("connect").c_str());
        write_str(STDERR_FILENO, msg);
        return false;
    }

    if (!send_all(fd.get(), cmd.data(), cmd.size()) ||
        !send_all(fd.get(), "\n", 1)) {
        char msg[256];
        snprintf(msg, sizeof(msg), "coredaemon: send failed (%s)\n",
                 errno_str("send").c_str());
        write_str(STDERR_FILENO, msg);
        return false;
    }

    char response[65536];
    bool truncated = false;
    ssize_t len = recv_all_timeout(fd.get(), response, sizeof(response),
                                   "CRON_END", cfg::kDefaultCtrlTimeoutMs,
                                   &truncated);
    if (len < 0 || truncated) {
        if (truncated) {
            write_str(STDERR_FILENO, "coredaemon: response too large (truncated)\n");
        } else {
            write_str(STDERR_FILENO, "coredaemon: protocol error (no CRON_END)\n");
        }
        return false;
    }

    if (write_all(STDOUT_FILENO, response, (size_t)len)) {
        return true;
    }
    write_str(STDERR_FILENO, "coredaemon: partial write to stdout\n");
    return false;
}

static bool become_daemon() {
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid > 0) _exit(0);
    if (setsid() < 0) return false;
    pid = fork();
    if (pid < 0) return false;
    if (pid > 0) _exit(0);
    chdir("/"); umask(0);

    int dn = open("/dev/null", O_RDWR);
    if (dn >= 0) {
        dup2(dn, STDIN_FILENO);
        dup2(dn, STDOUT_FILENO);
        dup2(dn, STDERR_FILENO);
        if (dn > STDERR_FILENO) close(dn);
    }
    return true;
}

static void print_usage(const char* prog) {
    write_str(STDOUT_FILENO, kVersion);
    write_str(STDOUT_FILENO, "\n\nUsage: ");
    write_str(STDOUT_FILENO, prog);
    write_str(STDOUT_FILENO,
        " [options]\n\n"
        "Daemon:\n"
        "  -c <file>   Config file\n"
        "  -l <file>   Log file\n"
        "  -s <path>   Socket path (or --socket)\n"
        "  -f          Foreground\n"
        "  -v          Verbose logging\n"
        "  --version   Print version and exit\n"
        "  --help      This help\n\n"
        "Client:\n"
        "  -r          RELOAD_CONFIG\n"
        "  -R          REFRESH_PACKAGES\n"
        "  --add <job> CRON_ADD\n"
        "  --remove <id> CRON_REMOVE\n"
        "  --list [own]  CRON_LIST\n"
        "  --exec <cmd>  Raw control command\n");
}

int main(int argc, char* argv[]) {
    std::string config_path = cfg::kDefaultConfigFile;
    std::string log_path    = cfg::kDefaultLogFile;
    std::string socket_path = cfg::kEventSockDefault;
    bool foreground = false, verbose = false;
    bool do_reload  = false, do_refresh = false;
    bool do_add     = false;
    bool do_remove  = false;
    bool do_list    = false;
    bool do_exec    = false;
    std::string add_spec;
    std::string remove_id;
    std::string list_owner;
    std::string exec_cmd;
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (a[0] == '-') {
            switch (a[1]) {
            case 'c': if (i+1<argc) config_path = argv[++i]; break;
            case 'l': if (i+1<argc) log_path    = argv[++i]; break;
            case 's': if (i+1<argc) socket_path = argv[++i]; break;
            case 'f': foreground = true; break;
            case 'v': verbose = true; break;
            case 'h': print_usage(argv[0]); return 0;
            case 'r': do_reload = true; break;
            case 'R': do_refresh = true; break;
            case '-': {
                const char* opt = a;
                if (strcmp(opt, "--version") == 0) { write_str(STDOUT_FILENO, kVersion); write_str(STDOUT_FILENO, "\n"); return 0; }
                if (strcmp(opt, "--help") == 0)    { print_usage(argv[0]); return 0; }
                if (strcmp(opt, "--add") == 0 && i+1<argc) { do_add = true; add_spec = argv[++i]; }
                else if (strcmp(opt, "--remove") == 0 && i+1<argc) { do_remove = true; remove_id = argv[++i]; }
                else if (strcmp(opt, "--list") == 0) {
                    do_list = true;
                    if (i+1<argc && argv[i+1][0]!='-') list_owner = argv[++i];
                }
                else if (strcmp(opt, "--exec") == 0 && i+1<argc) { do_exec = true; exec_cmd = argv[++i]; }
                else {
                    write_str(STDERR_FILENO, "coredaemon: unknown option: ");
                    write_str(STDERR_FILENO, opt);
                    write_str(STDERR_FILENO, "\n");
                    print_usage(argv[0]);
                    return 1;
                }
                break;
            }
            default:
                write_str(STDERR_FILENO, "coredaemon: unknown option: ");
                write_str(STDERR_FILENO, a);
                write_str(STDERR_FILENO, "\n");
                print_usage(argv[0]);
                return 1;
            }
        } else {
            write_str(STDERR_FILENO, "coredaemon: unexpected argument: ");
            write_str(STDERR_FILENO, a);
            write_str(STDERR_FILENO, "\n");
            print_usage(argv[0]);
            return 1;
        }
    }

    bool has_root = utils::check_root();
    if (do_reload)  return ctrl_send(has_root, "RELOAD_CONFIG") ? 0 : 2;
    if (do_refresh) return ctrl_send(has_root, "REFRESH_PACKAGES") ? 0 : 2;
    if (do_add) {
        std::string full_cmd = "CRON_ADD ";
        size_t first_space = add_spec.find(' ');
        std::string first_token = (first_space == std::string::npos) ? add_spec : add_spec.substr(0, first_space);
        bool looks_like_trigger = (!first_token.empty() && 
            (first_token[0] == '@' || 
             first_token.find_first_of("0123456789*") != std::string::npos));
        if (looks_like_trigger) {
            full_cmd += "cli " + add_spec;
        } else {
            full_cmd += add_spec;
        }
        return ctrl_send(has_root, full_cmd) ? 0 : 2;
    }
    if (do_remove)  return ctrl_send(has_root, "CRON_REMOVE " + remove_id) ? 0 : 2;
    if (do_list)    return ctrl_send(has_root, "CRON_LIST" + (list_owner.empty()?"":" "+list_owner)) ? 0 : 2;
    if (do_exec)    return ctrl_send(has_root, exec_cmd) ? 0 : 2;
    g_pid_fd = open(cfg::kPidFile, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
    if (g_pid_fd < 0) {
        write_str(STDERR_FILENO, "coredaemon: cannot open PID file\n");
        return 1;
    }
    if (flock(g_pid_fd, LOCK_EX | LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK) {
            char buf[32];
            ssize_t n = read(g_pid_fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                write_str(STDERR_FILENO, "coredaemon: already running (PID ");
                write_str(STDERR_FILENO, buf);
                write_str(STDERR_FILENO, "). Use -r to reload.\n");
            } else {
                write_str(STDERR_FILENO, "coredaemon: already running (unknown PID).\n");
            }
        } else {
            write_str(STDERR_FILENO, "coredaemon: cannot lock PID file\n");
        }
        close(g_pid_fd);
        g_pid_fd = -1;
        return 0;
    }

    struct sigaction sa{};
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGPIPE, &sa, nullptr);
    sigaction(SIGHUP,  &sa, nullptr);

    if (!foreground && !become_daemon()) {
        write_str(STDERR_FILENO, "coredaemon: failed to daemonize\n");
        flock(g_pid_fd, LOCK_UN);
        close(g_pid_fd); unlink(cfg::kPidFile);
        return 1;
    }

    if (ftruncate(g_pid_fd, 0) < 0 ||
        lseek(g_pid_fd, 0, SEEK_SET) < 0) {
        write_str(STDERR_FILENO, "coredaemon: cannot prepare PID file\n");
        flock(g_pid_fd, LOCK_UN);
        close(g_pid_fd); unlink(cfg::kPidFile);
        return 1;
    }
    std::string pid_str = std::to_string(getpid());
    if (!write_all(g_pid_fd, pid_str.c_str(), pid_str.size())) {
        write_str(STDERR_FILENO, "coredaemon: cannot write PID to file\n");
        flock(g_pid_fd, LOCK_UN);
        close(g_pid_fd); unlink(cfg::kPidFile);
        return 1;
    }

    if (!utils::init_logger(log_path, verbose)) return 1;

    LOG_INFO("CoreDaemon starting [UID=%d, root=%s, cgroup_v2=%s]",
             getuid(),
             has_root ? "yes" : "no",
             utils::detect_cgroup_v2() ? "yes" : "no");
    LOG_INFO("Config: %s | Log: %s", config_path.c_str(), log_path.c_str());

    CoreDaemon daemon(config_path, socket_path, has_root);
    if (!daemon.initialize()) {
        LOG_ERROR("Init failed");
        utils::close_logger();
        unlink(cfg::kPidFile);
        return 1;
    }
    
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    int rc = pthread_sigmask(SIG_BLOCK, &mask, nullptr);
    if (rc != 0) {
        LOG_ERROR("pthread_sigmask: %s", strerror(rc));
        utils::close_logger();
        return 1;
    }

    int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (sfd == -1) {
        LOG_ERROR("signalfd: %s", strerror(errno));
        utils::close_logger();
        return 1;
    }
    daemon.set_signalfd(sfd);

    daemon.run();
    if (g_pid_fd >= 0) {
        flock(g_pid_fd, LOCK_UN);
        close(g_pid_fd);
        g_pid_fd = -1;
    }
    unlink(cfg::kPidFile);
    utils::close_logger();
    return 0;
}
