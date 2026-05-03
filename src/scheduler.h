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
#include <atomic>
#include <memory>
#include <pthread.h>
#include <ctime>
#include <unordered_map>

class EventEmitter;
class CoreDaemon;

struct CronField {
    bool matched[64]{};
    bool is_star = false;
    std::string raw_text;

    bool parse(const std::string& token, int vmin, int vmax);
    bool matches(int v) const { return v>=0&&v<64&&matched[v]; }
private:
    bool parse_element(const std::string& e, int vmin, int vmax);
};

enum class TriggerType { CRON, REBOOT, APP_OPEN, APP_CLOSE, APP_FG, APP_FG_EXIT };
enum class ActionType { SHELL, BUILTIN, PLUGIN_EVENT };
enum class OverlapPolicy { SKIP, ALLOW, KILL };

struct ScheduledJob {
    std::string id;
    std::string owner;
    TriggerType trigger_type = TriggerType::CRON;
    std::string trigger_pkg;
    CronField minute, hour, dom, month, dow;
    std::string context_str;
    ActionType action_type = ActionType::SHELL;
    std::string action;
    int timeout_sec = 30;
    OverlapPolicy overlap = OverlapPolicy::SKIP;
    bool emit_event = false;

    std::shared_ptr<std::atomic<bool>> running{std::make_shared<std::atomic<bool>>(false)};
    std::shared_ptr<std::atomic<int>> running_pid{std::make_shared<std::atomic<int>>(-1)};

    bool matches_time(const struct tm& t) const;
    bool is_allowed(bool has_root) const;

    std::unordered_map<std::string, std::string> env;
    time_t next_trigger(time_t from) const;
};

class Scheduler {
public:
    Scheduler(bool has_root, EventEmitter* emitter, CoreDaemon* daemon);
    ~Scheduler();
    void load(const std::string& crontab_path, const std::string& rules_dir);
    void tick(const struct tm& t);
    void on_app_event(bool is_open, const std::string& package, int pid);
    void on_foreground_event(const std::string& pkg, bool is_monitored);
    std::string handle_ctrl(const std::string& cmd);
    void fire_reboot_jobs();
    int  job_count() const;
    time_t next_cron_time() const;
private:
    void dispatch(const ScheduledJob& job, const std::string& trigger);
    static void* job_runner(void* arg);
    void run_builtin(const std::string& cmd, const std::string& id);
    bool parse_line(const std::string& raw, int lineno, const std::string& default_owner,
                    const std::unordered_map<std::string, std::string>& env,
                    ScheduledJob& out);
    std::string unique_id(const std::string& hint);
    void dispatch_by_trigger(const std::string& pkg, TriggerType type);

    bool m_has_root;
    EventEmitter* m_emitter;
    CoreDaemon* m_daemon;

    mutable pthread_mutex_t m_mutex = PTHREAD_MUTEX_INITIALIZER;
    std::shared_ptr<const std::vector<ScheduledJob>> m_jobs{
    std::make_shared<std::vector<ScheduledJob>>()};
    std::atomic<unsigned> m_id_seq{1};
    std::atomic<int> m_inflight{0};
    pthread_cond_t m_inflight_cond = PTHREAD_COND_INITIALIZER;
    std::string m_last_fg_pkg;
};