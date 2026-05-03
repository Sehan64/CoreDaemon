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
#include <string_view>
#include <atomic>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <bitset>
#include <sys/inotify.h>

#ifndef COREDAEMON_DEBOUNCE_MS
#define COREDAEMON_DEBOUNCE_MS 200
#endif

class EventEmitter;
class Scheduler;
class CgroupWatcher;
class UidMapper;

class alignas(64) CoreDaemon {
public:
    CoreDaemon(const std::string& config_path,
               const std::string& socket_path,
               bool has_root);
    ~CoreDaemon();

    bool initialize();
    void run();
    void stop();
    bool is_running() const { return m_running.load(); }

    void reload_config();
    void emit_event(const std::string& type, const std::string& pkg,
                    int pid, const std::string& extra);
    bool is_app_in_list(std::string_view pkg) const;
    void update_cron_timer();
    void set_signalfd(int fd) { m_signalfd = fd; }

    int register_inotify_watch(const std::string& path, uint32_t mask);

private:
    static constexpr uint64_t TAG_SHARED_INOTIFY = 0x07;
    static constexpr uint64_t TAG_CRON_TIMER = 0x04;
    static constexpr uint64_t TAG_EVENT_SERVER = 0x05;
    static constexpr uint64_t TAG_CTRL_SERVER = 0x06;
    static constexpr uint64_t TAG_SIGNAL = 0x08;
    static constexpr uint64_t TAG_CLIENT_BASE = 0x8000000000000000ULL;
    static constexpr uint64_t TAG_CTRL_CLI_BASE = 0x4000000000000000ULL;

    bool setup_epoll();
    void setup_inotify_watches();
    bool setup_cron_timer();
    bool setup_ctrl_socket();
    bool epoll_add(int fd, uint64_t tag, uint32_t events);
    bool epoll_del(int fd);

    void daemon_loop();
    void on_shared_inotify();
    void on_cron_timer();
    void on_event_server();
    void on_ctrl_server();
    void on_ctrl_client(int fd);
    void on_client_hup(int fd);
    void on_watcher_event(uint64_t tag);
    void on_app_opened(uint32_t uid, int pid, const std::string& cgroup);
    void on_app_closed(uint32_t uid, int pid);
    void report_foreground(const std::string& pkg, bool is_monitored, int pid);
    void startup_scan();
    void load_config();
    void apply_monitor_mode();
    bool read_top_app_pid_uid(int& pid, uint32_t& uid);

    bool is_uid_monitored_fast(uint32_t uid) const;
    void rebuild_fast_uid_set();

    std::string m_config_path;
    std::string m_socket_path;
    bool m_has_root;
    std::string m_ctrl_sock_path;

    int m_epoll_fd = -1;
    int m_inotify_shared = -1;
    int m_timer_cron = -1;
    int m_ctrl_server = -1;
    int m_signalfd = -1;

    std::unordered_set<int> m_config_wds;
    int m_pkgmap_wd = -1;
    int m_cgroup_inotify_wd = -1;
    int m_cpuctl_wd = -1;

    std::atomic<bool> m_running{false};

    std::unique_ptr<EventEmitter> m_emitter;
    std::unique_ptr<Scheduler> m_scheduler;
    std::unique_ptr<CgroupWatcher> m_watcher;
    std::unique_ptr<UidMapper> m_uid_mapper;

    std::unordered_set<std::string> m_app_list;
    std::unordered_set<std::string> m_wildcards;
    bool m_monitor_all = false;
    std::string m_crontab_file;
    std::string m_rules_dir;
    std::string m_crontab_dir;

    struct AppState { std::string pkg; bool open = false; };
    std::unordered_map<uint32_t, AppState> m_active;

    std::unordered_set<uint32_t> m_pending_refresh_uids;
    int m_debounce_ms = COREDAEMON_DEBOUNCE_MS;

    std::string m_monitor_mode = "auto";
    bool m_app_monitoring = true;
    bool m_foreground_detection = false;
    bool m_foreground_file = false;
    bool m_foreground_prop = false;
    int  m_fg_cooldown_ms = 0;
    std::string m_last_setprop_value = "\xFF";

    static constexpr uint32_t kAppUidStart = 10000;
    static constexpr uint32_t kAppUidEnd   = 19999;
    std::bitset<kAppUidEnd - kAppUidStart + 1> m_fast_monitored;
    std::string m_topapp_path;
    struct PidCache {
        int pid = -1;
        uint32_t uid = 0xFFFFFFFF;
        char str[12] = {0};
        size_t len = 0;
    };
    PidCache m_pid_cache;
};