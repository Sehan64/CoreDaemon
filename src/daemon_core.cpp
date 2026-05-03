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

#include "daemon_core.h"
#include "event_emitter.h"
#include "scheduler.h"
#include "cgroup_watcher.h"
#include "uid_mapper.h"
#include "utils.h"
#include "proc_monitor.h"
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <cstdio>
#include <algorithm>

static void safe_close(int& fd) { if(fd>=0){close(fd);fd=-1;} }
static void drain_timerfd(int fd) {
    uint64_t v;
    ssize_t ret;
    while ((ret = read(fd, &v, sizeof(v))) > 0 || (ret < 0 && errno == EINTR)) {}
}

static int64_t mono_ms() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return (int64_t)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static std::string dirname_of(const std::string& p) {
    size_t s=p.rfind('/'); return s==std::string::npos?".":p.substr(0,s);
}

static bool write_file_atomic(const char* path, const char* content, size_t len) {
    std::string tmp = std::string(path) + ".tmp";
    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return false;
    const char* p = content;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n < 0) { if (errno == EINTR) continue; close(fd); unlink(tmp.c_str()); return false; }
        p += n; remaining -= (size_t)n;
    }
    close(fd);
    if (rename(tmp.c_str(), path) != 0) { unlink(tmp.c_str()); return false; }
    return true;
}

CoreDaemon::CoreDaemon(const std::string& cfg, const std::string& sock, bool root)
    : m_config_path(cfg), m_socket_path(sock), m_has_root(root) {}

CoreDaemon::~CoreDaemon() { stop(); }

bool CoreDaemon::epoll_add(int fd, uint64_t tag, uint32_t events) {
    struct epoll_event ev{};
    ev.events   = events | EPOLLET;
    ev.data.u64 = tag;
    if (epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        LOG_ERROR("epoll_add fd=%d tag=%llu: %s", fd, (unsigned long long)tag, strerror(errno));
        return false;
    }
    return true;
}

bool CoreDaemon::epoll_del(int fd) {
    return epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, fd, nullptr) == 0;
}

int CoreDaemon::register_inotify_watch(const std::string& path, uint32_t mask) {
    return inotify_add_watch(m_inotify_shared, path.c_str(), mask);
}

void CoreDaemon::apply_monitor_mode() {
    const std::string& mode = m_monitor_mode;
    bool app = false, fg = false;
    if (mode == "auto" || mode.empty()) {
        app = true; fg = true;
    } else if (mode == "cgroup.events") {
        app = true;
    } else if (mode == "cgroup.procs") {
        fg = true;
    } else if (mode == "cgroup.events,cgroup.procs" ||
               mode == "cgroup.procs,cgroup.events" ||
               mode == "cgroup.events;cgroup.procs" ||
               mode == "cgroup.procs;cgroup.events") {
        app = true; fg = true;
    } else {
        LOG_WARN("Unknown monitor_mode '%s', using auto", mode.c_str());
        app = true; fg = true;
    }
    m_app_monitoring = app;
    m_foreground_detection = fg;
}

bool CoreDaemon::initialize() {
    load_config();

    m_emitter = std::make_unique<EventEmitter>(m_socket_path, m_has_root);
    if (m_emitter->initialize() < 0) {
        LOG_ERROR("EventEmitter init failed");
        return false;
    }

    m_inotify_shared = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (m_inotify_shared < 0) {
        LOG_ERROR("inotify_init1: %s", strerror(errno));
        return false;
    }

    m_uid_mapper = std::make_unique<UidMapper>(m_has_root);
    m_uid_mapper->set_inotify_fd(m_inotify_shared);

    m_scheduler = std::make_unique<Scheduler>(m_has_root, m_emitter.get(), this);

    if (m_app_monitoring) {
        m_watcher = std::make_unique<CgroupWatcher>();
        m_watcher->set_mapper(m_uid_mapper.get());
        m_watcher->set_inotify_fd(m_inotify_shared);
        m_watcher->set_app_filter([this](const std::string& pkg) {
            return is_app_in_list(pkg);
        });
        m_watcher->set_debounce_ms(m_debounce_ms);
    }

    if (!m_crontab_file.empty())
        m_scheduler->load(m_crontab_file, m_rules_dir);

    return setup_epoll();
}

bool CoreDaemon::setup_epoll() {
    m_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (m_epoll_fd < 0) {
        LOG_ERROR("epoll_create1: %s", strerror(errno));
        return false;
    }

    epoll_add(m_inotify_shared, TAG_SHARED_INOTIFY, EPOLLIN);

    int uid_fd = m_uid_mapper->setup();
    if (uid_fd >= 0) {
        m_pkgmap_wd = m_uid_mapper->watch_wd();
    }

    rebuild_fast_uid_set();

    setup_inotify_watches();

    if (m_watcher) {
        auto wmode = m_watcher->setup(m_has_root);
        const char* mode_str =
           wmode == CgroupWatcher::Mode::CGROUP_V2 ? "cgroup_v2_EPOLLPRI" :
           "proc_timer_500ms";
        LOG_INFO("CoreDaemon: monitoring mode = %s", mode_str);

        for (const auto& e : m_watcher->drain_new_entries())
            epoll_add(e.fd, e.tag, e.events);

        m_cgroup_inotify_wd = m_watcher->cgroup_inotify_wd();
    } else {
        LOG_INFO("CoreDaemon: app monitoring disabled");
    }

    setup_cron_timer();
    epoll_add(m_emitter->server_fd(), TAG_EVENT_SERVER, EPOLLIN);
    setup_ctrl_socket();

    return true;
}

void CoreDaemon::setup_inotify_watches() {
    if (!m_crontab_file.empty()) {
        int wd = register_inotify_watch(m_crontab_dir.c_str(), IN_CLOSE_WRITE | IN_MOVED_TO);
        if (wd >= 0) m_config_wds.insert(wd);
        wd = register_inotify_watch(m_crontab_file.c_str(), IN_CLOSE_WRITE);
        if (wd >= 0) m_config_wds.insert(wd);
    }
    if (!m_rules_dir.empty()) {
        struct stat st{};
        if (stat(m_rules_dir.c_str(), &st) != 0) mkdir(m_rules_dir.c_str(), 0755);
        int wd = register_inotify_watch(m_rules_dir,
                                        IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_DELETE);
        if (wd >= 0) m_config_wds.insert(wd);
    }

    if (m_foreground_detection && m_cpuctl_wd < 0) {
        static const char* kTopAppPaths[] = {
            "/dev/cpuset/top-app/cgroup.procs",
            "/dev/cpuctl/top-app/cgroup.procs",
        };

        for (const char* candidate : kTopAppPaths) {
            int fd = open(candidate, O_RDONLY | O_CLOEXEC);
            if (fd >= 0) {
                close(fd);
                m_topapp_path = candidate;
                break;
            }
        }

        if (!m_topapp_path.empty()) {
            m_cpuctl_wd = inotify_add_watch(m_inotify_shared,
                                m_topapp_path.c_str(),
                                IN_CLOSE_WRITE | IN_MODIFY |
                                IN_DELETE_SELF | IN_MOVE_SELF);
            if (m_cpuctl_wd >= 0) {
                LOG_INFO("Foreground: detection via %s", m_topapp_path.c_str());
            }
        } else {
            LOG_WARN("Foreground: no top-app cgroup path accessible");
        }
    }
}

bool CoreDaemon::setup_cron_timer() {
    m_timer_cron = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK | TFD_CLOEXEC);
    if (m_timer_cron < 0) return false;
    update_cron_timer();
    epoll_add(m_timer_cron, TAG_CRON_TIMER, EPOLLIN);
    return true;
}

void CoreDaemon::update_cron_timer() {
    if (!m_scheduler || m_timer_cron < 0) return;
    time_t now = time(nullptr);
    time_t next = m_scheduler->next_cron_time();
    struct itimerspec its{};
    if (next > now) {
        its.it_value.tv_sec = next;
        timerfd_settime(m_timer_cron, TFD_TIMER_ABSTIME, &its, nullptr);
    } else {
        its.it_value.tv_sec = 0;
        timerfd_settime(m_timer_cron, TFD_TIMER_ABSTIME, &its, nullptr);
    }
}

bool CoreDaemon::setup_ctrl_socket() {
    m_ctrl_server = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (m_ctrl_server < 0) return false;

    if (m_has_root) {
        const char* path = cfg::kCtrlSockPath;
        size_t len = strlen(path);
        struct sockaddr_un addr{};
        if (len >= sizeof(addr.sun_path)) {
            LOG_ERROR("ctrl bind: path too long");
            safe_close(m_ctrl_server); return false;
        }
        m_ctrl_sock_path = path;
        unlink(path);
        addr.sun_family = AF_UNIX;
        memcpy(addr.sun_path, path, len + 1);
        socklen_t socklen = (socklen_t)(offsetof(sockaddr_un, sun_path) + len + 1);
        if (bind(m_ctrl_server, (sockaddr*)&addr, socklen) < 0) {
            LOG_ERROR("ctrl bind: %s", strerror(errno));
            safe_close(m_ctrl_server); return false;
        }
        chmod(path, 0600);
    } else {
        const char* name = cfg::kCtrlSockAbstract;
        size_t name_len = strlen(name);
        struct sockaddr_un addr{};
        if (name_len >= sizeof(addr.sun_path) - 1) {
            LOG_ERROR("ctrl abstract bind: name too long");
            safe_close(m_ctrl_server); return false;
        }
        addr.sun_family = AF_UNIX;
        addr.sun_path[0] = '\0';
        memcpy(addr.sun_path + 1, name, name_len);
        socklen_t socklen = (socklen_t)(offsetof(sockaddr_un, sun_path) + 1 + name_len);
        if (bind(m_ctrl_server, (sockaddr*)&addr, socklen) < 0) {
            LOG_ERROR("ctrl abstract bind: %s", strerror(errno));
            safe_close(m_ctrl_server); return false;
        }
    }
    listen(m_ctrl_server, 8);
    epoll_add(m_ctrl_server, TAG_CTRL_SERVER, EPOLLIN);
    return true;
}

void CoreDaemon::run() {
    if (m_signalfd >= 0) epoll_add(m_signalfd, TAG_SIGNAL, EPOLLIN);
    m_running = true;
    startup_scan();
    m_scheduler->fire_reboot_jobs();
    daemon_loop();
    LOG_INFO("CoreDaemon shutting down...");
    stop();
}

void CoreDaemon::stop() {
    if (!m_running.exchange(false)) return;
    safe_close(m_epoll_fd);
    safe_close(m_inotify_shared);
    safe_close(m_timer_cron);
    safe_close(m_signalfd);
    if (m_ctrl_server >= 0) {
        safe_close(m_ctrl_server);
        if (!m_ctrl_sock_path.empty()) {
            unlink(m_ctrl_sock_path.c_str());
            m_ctrl_sock_path.clear();
        }
    }
    if (m_emitter) m_emitter->shutdown();
}

void CoreDaemon::daemon_loop() {
    alignas(64) struct epoll_event evs[32];
    while (m_running) {
        int n = epoll_wait(m_epoll_fd, evs, 32, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("epoll_wait: %s", strerror(errno));
            break;
        }
        for (int i = 0; i < n && m_running; ++i) {
            uint64_t tag = evs[i].data.u64;
            if (tag == TAG_SIGNAL) {
                struct signalfd_siginfo siginfo;
                ssize_t sz = read(m_signalfd, &siginfo, sizeof(siginfo));
                if (sz == sizeof(siginfo)) {
                    LOG_INFO("CoreDaemon: received signal %d", siginfo.ssi_signo);
                    m_running = false;
                }
                continue;
            } else if (tag == TAG_SHARED_INOTIFY) {
                on_shared_inotify();
            } else if (tag == TAG_CRON_TIMER) {
                on_cron_timer();
            } else if (tag == TAG_EVENT_SERVER) {
                on_event_server();
            } else if (tag == TAG_CTRL_SERVER) {
                on_ctrl_server();
            } else if ((tag & TAG_CTRL_CLI_BASE) == TAG_CTRL_CLI_BASE) {
                on_ctrl_client((int)(tag & 0x0FFFFFFF));
            } else if ((tag & TAG_CLIENT_BASE) == TAG_CLIENT_BASE) {
                if (evs[i].events & (EPOLLHUP | EPOLLERR))
                    on_client_hup((int)(tag & 0x0FFFFFFF));
            } else {
                on_watcher_event(tag);
            }
        }
    }
}

void CoreDaemon::rebuild_fast_uid_set() {
    m_fast_monitored.reset();
    for (const auto& pkg : m_app_list) {
        uint32_t uid = m_uid_mapper->reverse_lookup(pkg);
        if (uid >= kAppUidStart && uid <= kAppUidEnd)
            m_fast_monitored.set(uid - kAppUidStart);
    }
}

bool CoreDaemon::is_uid_monitored_fast(uint32_t uid) const {
    if (__builtin_expect(uid >= kAppUidStart && uid <= kAppUidEnd, 1))
        return m_fast_monitored[uid - kAppUidStart];
    std::string pkg = m_uid_mapper->lookup(uid);
    return !pkg.empty() && is_app_in_list(pkg);
}

bool CoreDaemon::read_top_app_pid_uid(int& pid, uint32_t& uid) {
    if (m_topapp_path.empty()) return false;

    Fd fd(open(m_topapp_path.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd.get() < 0) return false;

    char buf[128];
    ssize_t n = read(fd.get(), buf, sizeof(buf) - 1);
    if (n <= 0) return false;
    buf[n] = '\0';

    const char* p = buf;
    while (*p == ' ' || *p == '\n') ++p;

    bool first_match = true;
    for (size_t i = 0; i < m_pid_cache.len; ++i) {
        if (p[i] != m_pid_cache.str[i]) { first_match = false; break; }
    }
    if (first_match && (p[m_pid_cache.len] == ' ' || p[m_pid_cache.len] == '\n' || p[m_pid_cache.len] == '\0')) {
        pid = m_pid_cache.pid;
        uid = m_pid_cache.uid;
        return true;
    }

    int last_pid = -1;
    uint32_t last_uid = 0xFFFFFFFF;
    for (int i = 0; i < 8; ++i) {
        while (*p == ' ' || *p == '\n') ++p;
        if (*p < '0' || *p > '9') break;
        char* end;
        long pval = strtol(p, &end, 10);
        if (pval <= 0) break;
        int candidate = (int)pval;
        uint32_t candidate_uid = CgroupWatcher::get_pid_uid(candidate);
        if (candidate_uid >= 10000) {
            last_pid = candidate;
            last_uid = candidate_uid;
            break;
        }
        p = end;
    }

    if (last_pid != -1) {
        pid = last_pid;
        uid = last_uid;
        m_pid_cache.pid = last_pid;
        m_pid_cache.uid = last_uid;
        int len = snprintf(m_pid_cache.str, sizeof(m_pid_cache.str), "%d", last_pid);
        if (len > 0 && len < (int)sizeof(m_pid_cache.str)) {
            m_pid_cache.len = (size_t)len;
        }
        return true;
    }
    return false;
}

void CoreDaemon::on_shared_inotify() {
    alignas(struct inotify_event) char buf[4096];
    int config_event_count = 0;
    static time_t last_reload = 0;
    static int last_fg_pid = -1;
    static int64_t last_fg_time_ms = 0;
    bool v2_overflow = false;

    for (;;) {
        ssize_t n = read(m_inotify_shared, buf, sizeof(buf));
        if (n <= 0) {
            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                LOG_ERROR("shared inotify: %s", strerror(errno));
            break;
        }
        ssize_t pos = 0;
        while (pos < n) {
            const auto* ev = reinterpret_cast<const struct inotify_event*>(buf + pos);
            pos += (ssize_t)(sizeof(struct inotify_event) + ev->len);
            if (ev->mask & IN_Q_OVERFLOW) {
                v2_overflow = true;
                continue;
            }

            if (m_config_wds.count(ev->wd)) {
                ++config_event_count;
            } else if (ev->wd == m_pkgmap_wd) {
                m_uid_mapper->handle_inotify();
                rebuild_fast_uid_set();
            } else if (ev->wd == m_cgroup_inotify_wd && m_watcher && ev->len > 0) {
                auto evs = m_watcher->handle_cg_inotify_event(*ev, *m_uid_mapper);
                for (const auto& e : evs) {
                    if (e.is_open) on_app_opened(e.uid, e.pid, e.cgroup_path);
                    else           on_app_closed(e.uid, e.pid);
                }
                if (m_watcher->has_new_entries()) {
                    for (const auto& entry : m_watcher->drain_new_entries())
                        epoll_add(entry.fd, entry.tag, entry.events);
                }
            } else if (m_cpuctl_wd >= 0 && ev->wd == m_cpuctl_wd) {
                if (ev->mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED)) {
                    inotify_rm_watch(m_inotify_shared, static_cast<uint32_t>(m_cpuctl_wd));
                    m_cpuctl_wd = inotify_add_watch(
                        m_inotify_shared, m_topapp_path.c_str(),
                        IN_CLOSE_WRITE | IN_MODIFY |
                        IN_DELETE_SELF | IN_MOVE_SELF);
                    if (m_cpuctl_wd >= 0) {
                        LOG_DEBUG("Foreground watch re‑established on %s",
                                  m_topapp_path.c_str());
                    } else {
                        LOG_WARN("Foreground watch lost and could not be re‑added");
                    }
                    continue;
                }

                if (m_fg_cooldown_ms > 0) {
                    int64_t now = mono_ms();
                    if (now - last_fg_time_ms < m_fg_cooldown_ms)
                        continue;
                    last_fg_time_ms = now;
                }

                int pid = -1;
                uint32_t uid = 0xFFFFFFFF;
                if (!read_top_app_pid_uid(pid, uid)) continue;

                if (pid == last_fg_pid) continue;
                last_fg_pid = pid;

                std::string pkg;
                bool monitored = is_uid_monitored_fast(uid);
                if (monitored && uid != 0xFFFFFFFF && uid > 0) {
                    pkg = m_uid_mapper->lookup(uid);
                }

                report_foreground(pkg, monitored, pid);
                if (m_scheduler)
                    m_scheduler->on_foreground_event(pkg, monitored);
            }
        }
    }
    
    if (v2_overflow && m_watcher) {
        LOG_WARN("CgroupWatcher: inotify queue overflow – forcing rescan");
        auto evs = m_watcher->startup_scan(*m_uid_mapper);
        for (const auto& e : evs) {
            if (e.is_open) on_app_opened(e.uid, e.pid, e.cgroup_path);
            else           on_app_closed(e.uid, e.pid);
        }
        while (m_watcher->has_new_entries()) {
            for (const auto& entry : m_watcher->drain_new_entries())
                epoll_add(entry.fd, entry.tag, entry.events);
        }
    }

    if (config_event_count > 0) {
        time_t now = time(nullptr);
        if (now - last_reload >= 2) {
            LOG_INFO("Config change – hot-reload");
            reload_config();
            last_reload = now;
        }
    }
}

void CoreDaemon::report_foreground(const std::string& pkg, bool is_monitored, int pid) {
    if (__builtin_expect(!is_monitored && !m_foreground_file && !m_foreground_prop, 0))
        return;

    if (m_foreground_file) {
        const char* fg_path = cfg::kFgStatusFile;
        static int last_fg_val = -1;
        int fg_val = is_monitored ? 1 : 0;
        if (fg_val != last_fg_val) {
            char val = static_cast<char>('0' + fg_val);
            write_file_atomic(fg_path, &val, 1);
            last_fg_val = fg_val;
        }
    }

    if (m_foreground_prop) {
        const char* new_val = (is_monitored && !pkg.empty()) ? pkg.c_str() : "none";
        if (m_last_setprop_value != new_val) {
            if (__system_property_set("debug.cored.app", new_val) != 0) {
                LOG_WARN("Failed to set debug.cored.app property");
            }
            m_last_setprop_value = new_val;
        }
    }

    if (m_emitter && is_monitored)
        m_emitter->emit("FOREGROUND", pkg, pid, "monitored=1");
}

void CoreDaemon::on_app_opened(uint32_t uid, int pid, const std::string& cgroup) {
    if (!is_uid_monitored_fast(uid)) {
        if (uid >= 10000 && m_pending_refresh_uids.find(uid) == m_pending_refresh_uids.end()) {
            m_pending_refresh_uids.insert(uid);
            m_uid_mapper->async_refresh();
        }
        return;
    }

    std::string pkg = m_uid_mapper->lookup(uid);
    if (pkg.empty()) {
        if (uid >= 10000 && m_pending_refresh_uids.find(uid) == m_pending_refresh_uids.end()) {
            m_pending_refresh_uids.insert(uid);
            m_uid_mapper->async_refresh();
        }
        return;
    }
    m_pending_refresh_uids.erase(uid);
    if (!is_app_in_list(pkg)) return;

    bool already = m_active.count(uid) && m_active[uid].open;
    if (!already) m_active[uid] = {pkg, true};
    if (already) return;

    if (pid > 0 && !cgroup.empty())
        LOG_EVENT("OPENED %s PID=%d CGROUP=%s", pkg.c_str(), pid, cgroup.c_str());
    else if (pid > 0)
        LOG_EVENT("OPENED %s PID=%d", pkg.c_str(), pid);
    else if (!cgroup.empty())
        LOG_EVENT("OPENED %s CGROUP=%s", pkg.c_str(), cgroup.c_str());
    else
        LOG_EVENT("OPENED %s", pkg.c_str());

    if (m_emitter) m_emitter->emit("OPENED", pkg, pid, cgroup);
    if (m_scheduler) m_scheduler->on_app_event(true, pkg, pid);
}

void CoreDaemon::on_app_closed(uint32_t uid, int pid) {
    auto it = m_active.find(uid);
    if (it == m_active.end() || !it->second.open) return;
    std::string pkg = it->second.pkg;
    it->second.open = false;

    if (pid > 0) LOG_EVENT("CLOSED %s PID=%d", pkg.c_str(), pid);
    else         LOG_EVENT("CLOSED %s", pkg.c_str());
    if (m_emitter) m_emitter->emit("CLOSED", pkg, pid, "");
    if (m_scheduler) m_scheduler->on_app_event(false, pkg, pid);
}

void CoreDaemon::on_cron_timer() {
    drain_timerfd(m_timer_cron);
    time_t now = time(nullptr);
    struct tm t{};
    localtime_r(&now, &t);
    if (m_scheduler) m_scheduler->tick(t);
    update_cron_timer();
}

void CoreDaemon::on_event_server() {
    for (;;) {
        int cfd = m_emitter->accept_one();
        if (cfd < 0) break;
        m_emitter->add_client(cfd);
        struct epoll_event cev{};
        cev.events   = EPOLLHUP | EPOLLERR;
        cev.data.u64 = TAG_CLIENT_BASE | (uint64_t)cfd;
        epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, cfd, &cev);
    }
}

void CoreDaemon::on_ctrl_server() {
    for (;;) {
        int cfd = accept4(m_ctrl_server, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0) break;
        struct epoll_event cev{};
        cev.events   = EPOLLIN | EPOLLONESHOT;
        cev.data.u64 = TAG_CTRL_CLI_BASE | (uint64_t)cfd;
        epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, cfd, &cev);
    }
}

void CoreDaemon::on_ctrl_client(int fd) {
    char buf[2048]{};
    std::string request;
    ssize_t n;
    while ((n = recv(fd, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = '\0';
        request += buf;
        if (request.size() > 4096) {
            LOG_WARN("Ctrl: request too long, disconnecting");
            close(fd);
            return;
        }
        if (request.find('\n') != std::string::npos) break;
    }
    epoll_del(fd);
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        LOG_ERROR("ctrl recv: %s", strerror(errno));
        close(fd);
        return;
    }
    while (!request.empty() && (request.back() == '\n' || request.back() == '\r'))
        request.pop_back();
    if (request.empty()) { LOG_WARN("Ctrl: empty request"); close(fd); return; }

    std::string cmd = request;
    std::string resp;
    if (cmd == "RELOAD_CONFIG") { reload_config(); resp = "RELOAD_ACK ok\nCRON_END\n"; }
    else if (cmd == "REFRESH_PACKAGES") { m_uid_mapper->async_refresh(); resp = "REFRESH_ACK queued\nCRON_END\n"; }
    else if (m_scheduler) resp = m_scheduler->handle_ctrl(cmd);
    else resp = "CRON_ERR no_scheduler\nCRON_END\n";
    send(fd, resp.c_str(), resp.size(), MSG_NOSIGNAL);
    close(fd);
}

void CoreDaemon::on_client_hup(int fd) {
    epoll_del(fd);
    m_emitter->remove_client(fd);
}

void CoreDaemon::on_watcher_event(uint64_t tag) {
    if (!m_watcher) return;
    std::vector<AppEvent> evs;
    if (tag == CgroupWatcher::TAG_PROC_TIMER) {
        evs = m_watcher->scan_proc_tick(*m_uid_mapper);
    } else {
        evs = m_watcher->handle(tag, *m_uid_mapper);
        if (m_watcher->has_new_entries()) {
            for (const auto& e : m_watcher->drain_new_entries())
                epoll_add(e.fd, e.tag, e.events);
        }
    }
    for (const auto& e : evs) {
        if (e.is_open) on_app_opened(e.uid, e.pid, e.cgroup_path);
        else           on_app_closed(e.uid, e.pid);
    }
}

void CoreDaemon::startup_scan() {
    if (m_watcher) {
        auto evs = m_watcher->startup_scan(*m_uid_mapper);
        for (const auto& e : evs) on_app_opened(e.uid, e.pid, e.cgroup_path);
    }

    if (m_cpuctl_wd >= 0) {
        int pid = -1;
        uint32_t uid = 0xFFFFFFFF;
        if (read_top_app_pid_uid(pid, uid)) {
            bool monitored = is_uid_monitored_fast(uid);
            std::string pkg = monitored ? m_uid_mapper->lookup(uid) : "";
            report_foreground(pkg, monitored, pid);
            if (m_scheduler)
                m_scheduler->on_foreground_event(pkg, monitored);
        }
    }

    std::vector<std::string> pkgs(m_app_list.begin(), m_app_list.end());
    std::unordered_set<int> all_pids;
    if (m_watcher && m_watcher->mode() != CgroupWatcher::Mode::CGROUP_V2) {
        all_pids = ProcMonitor::scan_pids();
    }
    for (const auto& pkg : pkgs) {
        uint32_t uid = m_uid_mapper->reverse_lookup(pkg);
        if (uid == 0) continue;
        bool already_open = m_active.count(uid) && m_active[uid].open;
        if (already_open) continue;
        for (int pid : all_pids) {
            std::string pcmd = ProcMonitor::read_cmdline(pid);
            if (pcmd == pkg) {
                on_app_opened(uid, pid,
                    "/uid_" + std::to_string(uid) + "/pid_" + std::to_string(pid));
                break;
            }
        }
    }
}

void CoreDaemon::emit_event(const std::string& type, const std::string& pkg,
                             int pid, const std::string& extra) {
    if (m_emitter) m_emitter->emit(type, pkg, pid, extra);
}

bool CoreDaemon::is_app_in_list(std::string_view pkg) const {
    if (m_monitor_all) return true;
    if (m_app_list.count(std::string(pkg))) return true;
    for (const auto& w : m_wildcards) {
        if (!w.empty() && w.back() == '*') {
            std::string_view pre(w.data(), w.size() - 1);
            if (pkg.substr(0, pre.size()) == pre) return true;
        }
    }
    return false;
}

void CoreDaemon::reload_config() {
    load_config();
    for (int wd : m_config_wds) inotify_rm_watch(m_inotify_shared, static_cast<uint32_t>(wd));
    m_config_wds.clear();
    setup_inotify_watches();

    if (m_watcher) m_watcher->set_debounce_ms(m_debounce_ms);
    if (m_scheduler && !m_crontab_file.empty())
        m_scheduler->load(m_crontab_file, m_rules_dir);
    LOG_INFO("CoreDaemon: config reloaded");
}

void CoreDaemon::load_config() {
    m_monitor_all = false;
    m_monitor_mode = "auto";
    m_foreground_file = false;
    m_foreground_prop = false;
    m_fg_cooldown_ms = 0;

    auto trim = [](const std::string& s) -> std::string {
        size_t start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        size_t end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    };

    std::ifstream f(m_config_path);
    if (!f.is_open()) {
        LOG_WARN("Config not found: %s -> monitoring ALL", m_config_path.c_str());
        m_monitor_all = true;
        apply_monitor_mode();
        return;
    }

    std::string line, app_list_path;
    while (std::getline(f, line)) {
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        if (!line.empty()) line.erase(line.find_last_not_of(" \t\r\n") + 1);
        if (line.empty() || line[0] == '#') continue;

        if (line.rfind("app_list_file=", 0) == 0) {
            app_list_path = trim(line.substr(14));
        } else if (line.rfind("monitor_all=", 0) == 0) {
            auto v = trim(line.substr(12));
            m_monitor_all = (v == "true" || v == "1" || v == "yes");
        } else if (line.rfind("crontab_file=", 0) == 0) {
            m_crontab_file = trim(line.substr(13));
            m_crontab_dir = dirname_of(m_crontab_file);
        } else if (line.rfind("rules_dir=", 0) == 0) {
            m_rules_dir = trim(line.substr(10));
        } else if (line.rfind("log=", 0) == 0) {
            utils::set_log_levels(trim(line.substr(4)));
        } else if (line.rfind("debounce_ms=", 0) == 0) {
            std::string val = trim(line.substr(12));
            char* endptr;
            long ms = strtol(val.c_str(), &endptr, 10);
            if (endptr != val.c_str() && *endptr == '\0' && ms >= 0 && ms <= 10000)
                m_debounce_ms = static_cast<int>(ms);
            else LOG_WARN("Invalid debounce_ms value: %s", val.c_str());
        } else if (line.rfind("monitor_mode=", 0) == 0) {
            m_monitor_mode = trim(line.substr(13));
        } else if (line.rfind("foreground_file=", 0) == 0) {
            auto v = trim(line.substr(16));
            m_foreground_file = (v == "true" || v == "1" || v == "yes");
        } else if (line.rfind("foreground_prop=", 0) == 0) {
            auto v = trim(line.substr(16));
            m_foreground_prop = (v == "true" || v == "1" || v == "yes");
        } else if (line.rfind("foreground_cooldown_ms=", 0) == 0) {
            std::string val = trim(line.substr(23));
            char* endptr;
            long ms = strtol(val.c_str(), &endptr, 10);
            if (endptr != val.c_str() && *endptr == '\0' && ms >= 0 && ms <= 10000)
                m_fg_cooldown_ms = static_cast<int>(ms);
            else LOG_WARN("Invalid foreground_cooldown_ms value: %s", val.c_str());
        }
    }

    if (!app_list_path.empty()) {
        std::ifstream af(app_list_path);
        if (af.is_open()) {
            m_app_list.clear();
            m_wildcards.clear();
            std::string pkg;
            while (std::getline(af, pkg)) {
                pkg.erase(0, pkg.find_first_not_of(" \t\r\n"));
                if (!pkg.empty()) pkg.erase(pkg.find_last_not_of(" \t\r\n") + 1);
                if (pkg.empty() || pkg[0] == '#') continue;
                (pkg.find('*') != std::string::npos ? m_wildcards : m_app_list).insert(pkg);
            }
        } else {
            LOG_WARN("app_list_file not found: %s", app_list_path.c_str());
        }
    }

    apply_monitor_mode();

    if (m_uid_mapper) rebuild_fast_uid_set();

    LOG_INFO("Config: %zu apps%s%s%s%s",
             m_app_list.size(),
             m_monitor_all ? " (all)" : "",
             m_crontab_file.empty() ? "" : " crontab=",
             m_crontab_file.empty() ? "" : m_crontab_file.c_str(),
             m_rules_dir.empty() ? "" : (" rules=" + m_rules_dir).c_str());
}