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

#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <functional>

class UidMapper;
struct AppEvent {
    bool is_open;
    uint32_t uid;
    int pid;
    std::string cgroup_path;
};

#ifndef COREDAEMON_DEBOUNCE_MS
#define COREDAEMON_DEBOUNCE_MS 200
#endif

class CgroupWatcher {
public:
    enum class Mode { CGROUP_V2, PROC_TIMER };

    struct EpollEntry {
        int fd;
        uint32_t events;
        uint64_t tag;
    };

    static constexpr uint64_t TAG_CG_DEBOUNCE  = 0x30;
    static constexpr uint64_t TAG_PROC_TIMER   = 0x50;
    static constexpr uint64_t TAG_CG_EVENTS_BASE = 0x20;

    CgroupWatcher() = default;
    ~CgroupWatcher();

    Mode setup(bool has_root);
    std::vector<EpollEntry> drain_new_entries();
    std::vector<AppEvent> startup_scan(UidMapper& mapper);
    std::vector<AppEvent> handle(uint64_t tag, UidMapper& mapper);
    std::vector<AppEvent> scan_proc_tick(UidMapper& mapper);

    Mode mode() const { return m_mode; }
    const std::string& cgroup_root() const { return m_cgroup_root; }

    void set_mapper(UidMapper* mapper) { m_mapper = mapper; }
    void set_debounce_ms(int ms) { m_debounce_ms = ms; }

    using AppListFilter = std::function<bool(const std::string& pkg)>;
    void set_app_filter(AppListFilter filter) { m_filter = std::move(filter); }
    bool has_new_entries() const { return !m_new_entries.empty(); }

    void set_inotify_fd(int fd) { m_cg_inotify_fd = fd; }
    std::vector<AppEvent> handle_cg_inotify_event(const struct inotify_event& ev, UidMapper& mapper);
    int  cgroup_inotify_wd() const { return m_cg_inotify_wd; }

    static uint32_t get_pid_uid(int pid);

private:
    bool setup_cgroup_v2();
    bool setup_proc_timer();
    void add_uid_cgroup(uint32_t uid, const std::string& uid_dir);
    void remove_uid_cgroup(uint32_t uid);
    int read_populated(uint32_t uid) const;
    std::vector<AppEvent> handle_cg_events_fd(int fd);
    std::vector<AppEvent> handle_debounce();

    int get_pid_from_uid_dir(const std::string& uid_dir) const;

    Mode m_mode = Mode::PROC_TIMER;
    bool m_has_root = false;
    std::string m_cgroup_root;

    std::unordered_map<int, uint32_t> m_fd_to_uid;
    std::unordered_map<uint32_t, int> m_uid_to_fd;
    std::unordered_map<uint32_t, int> m_uid_populated;
    std::unordered_map<uint32_t, int64_t> m_pending_close;

    int m_cg_inotify_fd = -1;
    int m_cg_inotify_wd = -1;
    int m_debounce_fd = -1;
    int64_t m_last_debounce_expiry = 0;

    int m_proc_timer_fd = -1;
    int m_pid_max = 0;
    std::vector<uint16_t> m_pid_gen;
    uint16_t m_proc_gen = 1;
    std::vector<uint8_t> m_retry_count;
    std::unordered_set<int> m_current_pids;

    std::vector<EpollEntry> m_new_entries;
    UidMapper* m_mapper = nullptr;
    int m_debounce_ms = COREDAEMON_DEBOUNCE_MS;
    AppListFilter m_filter;

    bool is_tracked_package(const std::string& pkg) const {
        return m_filter && m_filter(pkg);
    }

    static constexpr uint32_t kUidMin = 10000;
    static constexpr uint32_t kUidMax = 19999;
    std::array<std::string, kUidMax - kUidMin + 1> m_uid_paths;
    void build_uid_paths();
    const std::string& uid_path(uint32_t uid) const;
};