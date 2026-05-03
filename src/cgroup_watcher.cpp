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

#include "cgroup_watcher.h"
#include "uid_mapper.h"
#include "proc_monitor.h"
#include "utils.h"
#include <sys/inotify.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cerrno>
#include <cstdio>

static int64_t mono_ms() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return (int64_t)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static int get_pid_max() {
    int fd = open("/proc/sys/kernel/pid_max", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 32768;
    char buf[16];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 32768;
    buf[n] = '\0';
    char* end;
    long max = strtol(buf, &end, 10);
    if (end == buf || max < 4 || max > (1 << 22))
        return 32768;
    return (int)max;
}

static inline bool pid_known(const std::vector<uint16_t>& gen, int pid,
                             uint16_t current_gen) {
    if (pid <= 0 || (size_t)pid >= gen.size()) return false;
    return gen[(size_t)pid] == current_gen;
}
static inline void mark_pid_known(std::vector<uint16_t>& gen, int pid,
                                  uint16_t current_gen) {
    if (pid > 0 && (size_t)pid < gen.size())
        gen[(size_t)pid] = current_gen;
}

static int fast_utoa(unsigned int n, char* out) {
    if (n == 0) { out[0] = '0'; return 1; }
    char tmp[10];
    int pos = 0;
    while (n > 0) { tmp[pos++] = '0' + (n % 10); n /= 10; }
    for (int i = 0; i < pos; ++i) out[i] = tmp[pos - 1 - i];
    return pos;
}

uint32_t CgroupWatcher::get_pid_uid(int pid) {
    char path[32];
    memcpy(path, "/proc/", 6);
    int len = fast_utoa((unsigned int)pid, path + 6);
    path[6 + len] = '\0';
    struct stat st;
    if (stat(path, &st) == 0) return static_cast<uint32_t>(st.st_uid);
    return 0xFFFFFFFF;
}

static int parse_populated(int fd) {
    if (lseek(fd, 0, SEEK_SET) < 0) return -1;
    char buf[128]{};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) return -1;
    buf[n] = '\0';
    const char* found = (const char*)memmem(buf, (size_t)n, "populated ", 10);
    if (found) {
        char c = found[10];
        if (c == '0') return 0;
        if (c == '1') return 1;
    }
    return -1;
}

static std::string uid_pid_path(uint32_t uid, int pid) {
    char buf[64];
    char* p = buf;
    memcpy(p, "/uid_", 5); p += 5;
    p += fast_utoa(uid, p);
    memcpy(p, "/pid_", 5); p += 5;
    p += fast_utoa((unsigned int)pid, p);
    return {buf, (size_t)(p - buf)};
}

int CgroupWatcher::get_pid_from_uid_dir(const std::string& uid_dir) const {
    DIR* d = opendir(uid_dir.c_str());
    if (!d) return 0;
    struct dirent* ent;
    while ((ent = readdir(d)) != nullptr) {
        if (strncmp(ent->d_name, "pid_", 4) != 0) continue;
        char* ep;
        long lpid = strtol(ent->d_name + 4, &ep, 10);
        if (*ep == '\0' && lpid > 0 && lpid < INT_MAX) {
            closedir(d);
            return (int)lpid;
        }
    }
    closedir(d);
    return 0;
}

void CgroupWatcher::build_uid_paths() {
    char buf[32];
    for (uint32_t uid = kUidMin; uid <= kUidMax; ++uid) {
        char* p = buf;
        memcpy(p, "/uid_", 5); p += 5;
        p += fast_utoa(uid, p);
        m_uid_paths[uid - kUidMin].assign(buf, (size_t)(p - buf));
    }
}

const std::string& CgroupWatcher::uid_path(uint32_t uid) const {
    if (uid >= kUidMin && uid <= kUidMax)
        return m_uid_paths[uid - kUidMin];
    static std::string fallback;
    fallback = "/uid_" + std::to_string(uid);
    return fallback;
}

CgroupWatcher::~CgroupWatcher() {
    for (auto& [fd, uid] : m_fd_to_uid) close(fd);
    if (m_debounce_fd   >= 0) close(m_debounce_fd);
    if (m_proc_timer_fd >= 0) close(m_proc_timer_fd);
}

int CgroupWatcher::read_populated(uint32_t uid) const {
    auto it = m_uid_to_fd.find(uid);
    if (it == m_uid_to_fd.end()) return -1;
    return parse_populated(it->second);
}

CgroupWatcher::Mode CgroupWatcher::setup(bool has_root) {
    m_has_root = has_root;
    build_uid_paths();
    if (setup_cgroup_v2()) {
        m_mode = Mode::CGROUP_V2;
        LOG_INFO("CgroupWatcher: cgroup v2 EPOLLPRI (%s)", has_root ? "root" : "non-root");
    } else {
        setup_proc_timer();
        m_mode = Mode::PROC_TIMER;
        LOG_INFO("CgroupWatcher: Using 500ms timerfd+getdents64 fallback");
    }
    return m_mode;
}

std::vector<CgroupWatcher::EpollEntry> CgroupWatcher::drain_new_entries() {
    std::vector<EpollEntry> out;
    out.swap(m_new_entries);
    return out;
}

std::vector<AppEvent> CgroupWatcher::startup_scan(UidMapper& mapper) {
    std::vector<AppEvent> out;
    out.reserve(16);
    if (m_mode != Mode::CGROUP_V2) return out;

    int total_populated = 0;
    for (auto& [uid, fd] : m_uid_to_fd) {
        int pop = read_populated(uid);
        if (pop != 1) continue;

        m_uid_populated[uid] = 1;
        total_populated++;

        char uid_dir[128];
        snprintf(uid_dir, sizeof(uid_dir), "%s/uid_%u", m_cgroup_root.c_str(), uid);
        int pid = get_pid_from_uid_dir(uid_dir);
        if (pid == 0) {
            char path[128];
            snprintf(path, sizeof(path), "%s/uid_%u/cgroup.procs",
                     m_cgroup_root.c_str(), uid);
            int ffd = open(path, O_RDONLY | O_CLOEXEC);
            if (ffd >= 0) {
                char pbuf[32];
                ssize_t r = read(ffd, pbuf, sizeof(pbuf) - 1);
                if (r > 0) {
                    pbuf[r] = '\0';
                    char* endptr;
                    long lpid = strtol(pbuf, &endptr, 10);
                    if (endptr != pbuf && *endptr == '\0' && lpid > 0 && lpid < INT_MAX)
                        pid = static_cast<int>(lpid);
                }
                close(ffd);
            }
        }

        out.push_back({true, uid, pid, uid_path(uid)});
    }
    LOG_INFO("CgroupWatcher: startup scan completed, %d UIDs already populated", total_populated);
    return out;
}

bool CgroupWatcher::setup_cgroup_v2() {
    int fd = open("/proc/mounts", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOG_INFO("CgroupWatcher: cannot open /proc/mounts");
        return false;
    }

    char buf[8192];
    size_t buflen = 0;
    while (buflen < sizeof(buf) - 1) {
        ssize_t n = read(fd, buf + buflen, sizeof(buf) - 1 - buflen);
        if (n <= 0) break;
        buflen += (size_t)n;
    }
    close(fd);
    if (buflen == 0) {
        LOG_INFO("CgroupWatcher: /proc/mounts empty");
        return false;
    }
    buf[buflen] = '\0';

    const char* p = buf;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n') ++p;
        if (!*p) break;

        while (*p && *p != ' ' && *p != '\t') ++p;
        if (!*p) break;
        while (*p == ' ' || *p == '\t') ++p;
        if (!*p) break;

        const char* mp_start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') ++p;
        size_t mp_len = (size_t)(p - mp_start);
        if (!*p) break;
        while (*p == ' ' || *p == '\t') ++p;
        if (!*p) break;

        const char* fs_start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n') ++p;
        size_t fs_len = (size_t)(p - fs_start);

        if (fs_len == 7 && memcmp(fs_start, "cgroup2", 7) == 0) {
            m_cgroup_root.assign(mp_start, mp_len);
            break;
        }

        while (*p && *p != '\n') ++p;
        if (*p == '\n') ++p;
    }

    if (m_cgroup_root.empty()) {
        LOG_INFO("CgroupWatcher: cgroup2 not in /proc/mounts");
        return false;
    }

    std::string uid_root = m_cgroup_root;
    DIR* d = opendir(uid_root.c_str());
    if (!d) {
        LOG_INFO("CgroupWatcher: cannot open %s", uid_root.c_str());
        m_cgroup_root.clear();
        return false;
    }
    struct dirent* e;
    bool found_uid = false;
    while ((e = readdir(d)) != nullptr) {
        if (strncmp(e->d_name, "uid_", 4) == 0) {
            found_uid = true;
            break;
        }
    }
    closedir(d);

    if (!found_uid) {
        std::string alt = m_cgroup_root + "/apps";
        d = opendir(alt.c_str());
        if (d) {
            while ((e = readdir(d)) != nullptr) {
                if (strncmp(e->d_name, "uid_", 4) == 0) { found_uid = true; break; }
            }
            closedir(d);
            if (found_uid) uid_root = alt;
        }
    }

    if (!found_uid) {
        LOG_INFO("CgroupWatcher: no uid_* directories found (cgroup2)");
        m_cgroup_root.clear();
        return false;
    }

    m_cgroup_root = uid_root;

    d = opendir(uid_root.c_str());
    if (!d) {
        LOG_INFO("CgroupWatcher: cannot open %s", uid_root.c_str());
        m_cgroup_root.clear();
        return false;
    }

    int uid_count = 0;
    while ((e = readdir(d)) != nullptr) {
        if (strncmp(e->d_name, "uid_", 4) != 0) continue;
        char* ep;
        long uid_raw = strtol(e->d_name + 4, &ep, 10);
        if (*ep != '\0' || uid_raw <= 0) continue;
        uint32_t uid = static_cast<uint32_t>(uid_raw);

        if (uid >= 10000) {
            if (m_mapper) {
                std::string pkg = std::string(m_mapper->lookup(uid));
                if (!pkg.empty() && is_tracked_package(pkg)) {
                    add_uid_cgroup(uid, uid_root + "/" + e->d_name);
                    ++uid_count;
                }
            }
        }
    }
    closedir(d);

    if (m_cg_inotify_fd >= 0) {
        m_cg_inotify_wd = inotify_add_watch(m_cg_inotify_fd, uid_root.c_str(),
                                            IN_CREATE | IN_DELETE | IN_ONLYDIR);
    }

    m_debounce_fd = timerfd_create(CLOCK_MONOTONIC_COARSE, TFD_NONBLOCK | TFD_CLOEXEC);
    if (m_debounce_fd >= 0)
        m_new_entries.push_back({m_debounce_fd, EPOLLIN, TAG_CG_DEBOUNCE});

    LOG_INFO("CgroupWatcher: cgroup v2 at %s, %d uid(s) at startup",
             uid_root.c_str(), uid_count);
    return true;
}

void CgroupWatcher::add_uid_cgroup(uint32_t uid, const std::string& uid_dir) {
    if (m_uid_to_fd.count(uid)) return;
    int fd = open((uid_dir + "/cgroup.events").c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    m_fd_to_uid[fd] = uid;
    m_uid_to_fd[uid] = fd;
    m_uid_populated[uid] = -1;
    m_new_entries.push_back({fd, EPOLLPRI, TAG_CG_EVENTS_BASE | ((uint64_t)uid << 8)});
}

void CgroupWatcher::remove_uid_cgroup(uint32_t uid) {
    auto it = m_uid_to_fd.find(uid);
    if (it == m_uid_to_fd.end()) return;
    int fd = it->second;
    m_fd_to_uid.erase(fd);
    m_uid_to_fd.erase(it);
    m_uid_populated.erase(uid);
    m_pending_close.erase(uid);
    close(fd);
}

std::vector<AppEvent> CgroupWatcher::handle_cg_inotify_event(const struct inotify_event& ev,
                                                              UidMapper& mapper) {
    std::vector<AppEvent> out;
    out.reserve(16);
    if (ev.len == 0 || strncmp(ev.name, "uid_", 4) != 0) return out;
    char* ep;
    long uid_raw = strtol(ev.name + 4, &ep, 10);
    if (*ep != '\0' || uid_raw <= 0) return out;
    uint32_t uid = static_cast<uint32_t>(uid_raw);

    if (ev.mask & IN_CREATE) {
        if (uid >= 10000) {
            std::string pkg = std::string(mapper.lookup(uid));
            if (!pkg.empty() && is_tracked_package(pkg)) {
                std::string uid_dir = m_cgroup_root + "/" + ev.name;
                add_uid_cgroup(uid, uid_dir);
                if (read_populated(uid) == 1) {
                    m_uid_populated[uid] = 1;
                    int pid = get_pid_from_uid_dir(uid_dir);
                    out.push_back({true, uid, pid, uid_path(uid)});
                }
            }
        }
    } else if (ev.mask & IN_DELETE) {
        remove_uid_cgroup(uid);
    }
    return out;
}

bool CgroupWatcher::setup_proc_timer() {
    m_proc_timer_fd = timerfd_create(CLOCK_MONOTONIC_COARSE, TFD_NONBLOCK | TFD_CLOEXEC);
    if (m_proc_timer_fd < 0) return false;
    struct itimerspec its{};
    its.it_value.tv_nsec = its.it_interval.tv_nsec = 500000000L;
    timerfd_settime(m_proc_timer_fd, 0, &its, nullptr);

    m_pid_max = get_pid_max();
    m_pid_gen.assign((size_t)m_pid_max + 1, 0);
    m_proc_gen = 1;
    m_retry_count.assign((size_t)m_pid_max + 1, 0);

    auto pids = ProcMonitor::scan_pids();
    for (int pid : pids)
        mark_pid_known(m_pid_gen, pid, m_proc_gen);

    m_new_entries.push_back({m_proc_timer_fd, EPOLLIN, TAG_PROC_TIMER});
    return true;
}

std::vector<AppEvent> CgroupWatcher::handle(uint64_t tag, UidMapper& mapper) {
    if (tag == TAG_CG_DEBOUNCE) return handle_debounce();
    if ((tag & 0xFF) == TAG_CG_EVENTS_BASE) {
        uint32_t uid = static_cast<uint32_t>(tag >> 8);
        auto it = m_uid_to_fd.find(uid);
        if (it != m_uid_to_fd.end()) return handle_cg_events_fd(it->second);
    }
    return {};
}

std::vector<AppEvent> CgroupWatcher::handle_cg_events_fd(int fd) {
    std::vector<AppEvent> out;
    out.reserve(16);
    int populated = parse_populated(fd);
    if (populated < 0) return out;

    auto uid_it = m_fd_to_uid.find(fd);
    if (uid_it == m_fd_to_uid.end()) return out;
    uint32_t uid = uid_it->second;

    auto pop_it = m_uid_populated.find(uid);
    int last = (pop_it != m_uid_populated.end()) ? pop_it->second : -1;
    m_uid_populated[uid] = populated;

    if (populated == 1 && last != 1) {
        if (m_pending_close.erase(uid) > 0 && m_pending_close.empty()) {
            struct itimerspec its{};
            timerfd_settime(m_debounce_fd, 0, &its, nullptr);
            m_last_debounce_expiry = 0;
        }
        out.push_back({true, uid, 0, uid_path(uid)});

    } else if (populated == 0 && last != 0 && last != -1) {
        if (m_debounce_ms == 0) {
            out.push_back({false, uid, 0, uid_path(uid)});
        } else {
            int64_t now = mono_ms();
            int64_t deadline = now + m_debounce_ms;
            m_pending_close[uid] = deadline;

            if (m_debounce_fd >= 0) {
                if (deadline != m_last_debounce_expiry) {
                    int64_t rem = deadline - now;
                    if (rem <= 0) rem = 1;
                    struct itimerspec its{};
                    its.it_value.tv_sec  = rem / 1000;
                    its.it_value.tv_nsec = (rem % 1000) * 1000000L;
                    timerfd_settime(m_debounce_fd, 0, &its, nullptr);
                    m_last_debounce_expiry = deadline;
                }
            }
        }
    }
    return out;
}

std::vector<AppEvent> CgroupWatcher::handle_debounce() {
    std::vector<AppEvent> out;
    out.reserve(16);

    {
        uint64_t v;
        ssize_t ret;
        while ((ret = read(m_debounce_fd, &v, sizeof(v))) > 0 ||
               (ret < 0 && errno == EINTR)) {}
    }

    int64_t now = mono_ms();
    int64_t min_deadline = 0;

    for (auto it = m_pending_close.begin(); it != m_pending_close.end(); ) {
        if (now < it->second) {
            if (min_deadline == 0 || it->second < min_deadline)
                min_deadline = it->second;
            ++it;
            continue;
        }
        uint32_t uid = it->first;
        if (read_populated(uid) == 0)
            out.push_back({false, uid, 0, uid_path(uid)});
        it = m_pending_close.erase(it);
    }

    if (min_deadline > 0) {
        if (min_deadline != m_last_debounce_expiry) {
            int64_t rem = min_deadline - now;
            if (rem <= 0) rem = 1;
            struct itimerspec its{};
            its.it_value.tv_sec  = rem / 1000;
            its.it_value.tv_nsec = (rem % 1000) * 1000000L;
            timerfd_settime(m_debounce_fd, 0, &its, nullptr);
            m_last_debounce_expiry = min_deadline;
        }
    } else {
        if (m_last_debounce_expiry != 0) {
            struct itimerspec its{};
            timerfd_settime(m_debounce_fd, 0, &its, nullptr);
            m_last_debounce_expiry = 0;
        }
    }

    return out;
}

std::vector<AppEvent> CgroupWatcher::scan_proc_tick(UidMapper& mapper) {
    std::vector<AppEvent> out;
    out.reserve(16);

    if (++m_proc_gen == 0) {
        std::fill(m_pid_gen.begin(), m_pid_gen.end(), 0);
        m_proc_gen = 1;
    }

    ProcMonitor::scan_pids_into(m_current_pids);

    for (int pid : m_current_pids) {
        if (pid_known(m_pid_gen, pid, m_proc_gen)) continue;

        char cmdbuf[256];
        if (ProcMonitor::read_cmdline_into(pid, cmdbuf, sizeof(cmdbuf))) {
            uint32_t uid = get_pid_uid(pid);
            if (uid > 0) {
                if (mapper.lookup(uid).empty()) mapper.async_refresh();
                out.push_back({true, uid, pid, uid_pid_path(uid, pid)});
            }
            mark_pid_known(m_pid_gen, pid, m_proc_gen);
            if (pid <= m_pid_max) m_retry_count[(size_t)pid] = 0;
        } else {
            if (pid <= m_pid_max) {
                uint8_t& retries = m_retry_count[(size_t)pid];
                if (++retries >= ProcMonitor::MAX_PENDING_RETRIES) {
                    mark_pid_known(m_pid_gen, pid, m_proc_gen);
                    retries = 0;
                }
            }
        }
    }

    uint64_t v;
    ssize_t r;
    while ((r = read(m_proc_timer_fd, &v, sizeof(v))) > 0 ||
           (r < 0 && errno == EINTR)) {}

    return out;
}