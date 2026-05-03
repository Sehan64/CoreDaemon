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

#include "scheduler.h"
#include "event_emitter.h"
#include "daemon_core.h"
#include "utils.h"
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <fstream>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <algorithm>
#include <unordered_map>
#include <cstdlib>
#include <ctime>
#include <string_view>
#include <atomic>
#include <spawn.h>

static bool safe_atoi(const char* s, int* out) {
    if (!s || !*s) return false;
    char* e; long v = strtol(s, &e, 10);
    if (e == s || *e != '\0') return false;
    *out = (int)v; return true;
}

static long long mono_ms() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static constexpr size_t MAX_TOKENS = 32;

static size_t tokenize(std::string_view s, std::string_view (&tokens)[MAX_TOKENS]) {
    size_t count = 0;
    const char* start = nullptr;
    char quote = 0;
    bool escape = false;

    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (quote) {
            if (escape) { escape = false; continue; }
            if (c == '\\' && i + 1 < s.size() && s[i + 1] == quote) { escape = true; continue; }
            if (c == quote) {
                tokens[count++] = std::string_view(start, (size_t)(s.data() + i - start));
                quote = 0; start = nullptr;
            }
        } else {
            if (c == '\'' || c == '"') { quote = c; start = s.data() + i + 1; }
            else if (c == '\\' && i + 1 < s.size()) { ++i; }
            else if (c == ' ' || c == '\t') {
                if (start) { tokens[count++] = std::string_view(start, (size_t)(s.data() + i - start)); start = nullptr; }
            } else { if (!start) start = s.data() + i; }
        }
        if (count >= MAX_TOKENS) break;
    }

    if (start && count < MAX_TOKENS) {
        if (quote) {
            LOG_SCHED("Scheduler: unclosed quote in token: %.*s", (int)s.size(), s.data());
        } else {
            tokens[count++] = std::string_view(start, (size_t)(s.data() + s.size() - start));
        }
    }
    return count;
}

static std::vector<std::string> split_comma(const std::string& s) {
    std::vector<std::string> v;
    size_t b = 0;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == ',') {
            if (i > b) v.push_back(s.substr(b, i - b));
            b = i + 1;
        }
    }
    return v;
}

static int parse_month_name(std::string_view s) {
    static constexpr std::pair<std::string_view, int> months[] = {
        {"jan",1}, {"feb",2}, {"mar",3}, {"apr",4}, {"may",5}, {"jun",6},
        {"jul",7}, {"aug",8}, {"sep",9}, {"oct",10}, {"nov",11}, {"dec",12}
    };
    for (const auto& [name, val] : months) {
        if (s.size() == name.size() && 
            std::equal(s.begin(), s.end(), name.begin(),
                       [](char a, char b) { return ::tolower(a) == ::tolower(b); })) {
            return val;
        }
    }
    return -1;
}

static int parse_weekday_name(std::string_view s) {
    static constexpr std::pair<std::string_view, int> wdays[] = {
        {"sun",0}, {"mon",1}, {"tue",2}, {"wed",3}, {"thu",4}, {"fri",5}, {"sat",6}
    };
    for (const auto& [name, val] : wdays) {
        if (s.size() == name.size() && 
            std::equal(s.begin(), s.end(), name.begin(),
                       [](char a, char b) { return ::tolower(a) == ::tolower(b); })) {
            return val;
        }
    }
    return -1;
}

bool CronField::parse_element(const std::string& e, int vmin, int vmax) {
    size_t sl = e.find('/');
    std::string rng = (sl != std::string::npos) ? e.substr(0, sl) : e;
    int step = 1;
    if (sl != std::string::npos && (!safe_atoi(e.c_str() + sl + 1, &step) || step <= 0))
        return false;
    int lo, hi;
    if (rng == "*") { lo = vmin; hi = vmax; }
    else {
        size_t d = rng.find('-');
        if (d != std::string::npos) {
            if (!safe_atoi(rng.substr(0, d).c_str(), &lo) ||
                !safe_atoi(rng.substr(d + 1).c_str(), &hi))
                return false;
        } else {
            if (!safe_atoi(rng.c_str(), &lo)) return false;
            hi = lo;
        }
    }
    if (lo < vmin || hi > vmax || lo > hi) return false;
    for (int v = lo; v <= hi; v += step)
        if (v >= 0 && v < 64) matched[v] = true;
    return true;
}

bool CronField::parse(const std::string& tok, int vmin, int vmax) {
    raw_text = tok;
    memset(matched, 0, sizeof(matched));
    is_star = (tok == "*");
    for (auto& p : split_comma(tok))
        if (!parse_element(p, vmin, vmax)) return false;
    return true;
}

bool ScheduledJob::matches_time(const struct tm& t) const {
    if (!minute.matches(t.tm_min)) return false;
    if (!hour.matches(t.tm_hour))   return false;
    if (!month.matches(t.tm_mon+1)) return false;
    if (dom.is_star && dow.is_star) return true;
    if (dom.is_star) return dow.matches(t.tm_wday);
    if (dow.is_star) return dom.matches(t.tm_mday);
    return dom.matches(t.tm_mday) || dow.matches(t.tm_wday);
}

bool ScheduledJob::is_allowed(bool has_root) const {
    if (context_str == "root")    return has_root;
    if (context_str == "nonroot") return !has_root;
    return true;
}

time_t ScheduledJob::next_trigger(time_t from) const {
    if (trigger_type != TriggerType::CRON) return 0;
    struct tm tm_buf;
    localtime_r(&from, &tm_buf);
    tm_buf.tm_sec = 0;
    time_t candidate = mktime(&tm_buf);
    if (candidate <= from) candidate += 60;
    const time_t max_search = from + 730 * 24 * 3600;

    while (candidate <= max_search) {
        localtime_r(&candidate, &tm_buf);
        if (!month.matches(tm_buf.tm_mon + 1)) {
            tm_buf.tm_mday = 1;
            tm_buf.tm_mon++;
            if (tm_buf.tm_mon > 11) { tm_buf.tm_mon = 0; tm_buf.tm_year++; }
            tm_buf.tm_hour = 0;
            tm_buf.tm_min  = 0;
            candidate = mktime(&tm_buf);
            continue;
        }
        {
            bool dom_match = dom.matches(tm_buf.tm_mday);
            bool dow_match = dow.matches(tm_buf.tm_wday);

            bool need_advance = false;
            if (!dom.is_star && !dow.is_star) {
                if (!(dom_match || dow_match)) need_advance = true;
            } else if (!dom.is_star) {
                if (!dom_match) need_advance = true;
            } else if (!dow.is_star) {
                if (!dow_match) need_advance = true;
            }

            if (need_advance) {
                tm_buf.tm_mday++;
                tm_buf.tm_hour = 0;
                tm_buf.tm_min  = 0;
                candidate = mktime(&tm_buf);
                continue;
            }
        }

        if (!hour.matches(tm_buf.tm_hour)) {
            int next_h = tm_buf.tm_hour + 1;
            while (next_h <= 23 && !hour.matches(next_h)) ++next_h;
            if (next_h > 23) {
                tm_buf.tm_mday++;
                tm_buf.tm_hour = 0;
                tm_buf.tm_min  = 0;
            } else {
                tm_buf.tm_hour = next_h;
                tm_buf.tm_min  = 0;
            }
            candidate = mktime(&tm_buf);
            continue;
        }

        if (!minute.matches(tm_buf.tm_min)) {
            int next_m = tm_buf.tm_min + 1;
            while (next_m <= 59 && !minute.matches(next_m)) ++next_m;
            if (next_m > 59) {
                tm_buf.tm_hour++;
                tm_buf.tm_min = 0;
            } else {
                tm_buf.tm_min = next_m;
            }
            candidate = mktime(&tm_buf);
            continue;
        }

        return candidate;
    }
    return 0;
}

Scheduler::Scheduler(bool hr, EventEmitter* e, CoreDaemon* d)
    : m_has_root(hr), m_emitter(e), m_daemon(d) {
    pthread_mutex_init(&m_mutex, nullptr);
}

Scheduler::~Scheduler() {
    pthread_mutex_lock(&m_mutex);
    while (m_inflight.load() > 0) {
        pthread_cond_wait(&m_inflight_cond, &m_mutex);
    }
    pthread_mutex_unlock(&m_mutex);
    pthread_cond_destroy(&m_inflight_cond);
    pthread_mutex_destroy(&m_mutex);
}

int Scheduler::job_count() const {
    auto sp = std::atomic_load_explicit(&m_jobs, std::memory_order_acquire);
    return (int)(*sp).size();
}

std::string Scheduler::unique_id(const std::string& hint) {
    return hint + std::to_string(m_id_seq.fetch_add(1));
}

void Scheduler::load(const std::string& crontab_path, const std::string& rules_dir) {
    tzset();
    std::vector<ScheduledJob> new_jobs;
    {
        auto sp = std::atomic_load_explicit(&m_jobs, std::memory_order_acquire);
        for (const auto& j : *sp)
            if (j.owner != "core" && !j.owner.empty())
                new_jobs.push_back(j);
    }

    auto load_file = [&](const std::string& path, const std::string& owner) {
        std::ifstream f(path);
        if (!f.is_open()) return;
        std::string line; int lineno = 0, errors = 0;
        std::unordered_map<std::string, std::string> current_env;

        while (std::getline(f, line)) {
            ++lineno;
            if (!line.empty() && line.back() == '\r') line.pop_back();
            size_t s = line.find_first_not_of(" \t");
            if (s == std::string::npos || line[s] == '#') continue;

            std::string trimmed = line.substr(s);
            size_t eq = trimmed.find('=');
            if (eq != std::string::npos && eq > 0 && eq < trimmed.size() - 1) {
                std::string key = trimmed.substr(0, eq);
                std::string val = trimmed.substr(eq + 1);
                bool valid = !key.empty() && (isalpha(key[0]) || key[0] == '_');
                for (char c : key) if (!isalnum(c) && c != '_') { valid = false; break; }
                if (valid) { current_env[key] = val; continue; }
            }

            ScheduledJob job;
            if (parse_line(trimmed, lineno, owner, current_env, job))
                new_jobs.push_back(std::move(job));
            else
                ++errors;
        }
        if (errors)
            LOG_SCHED("Scheduler: %s: %d line(s) skipped", path.c_str(), errors);
    };

    load_file(crontab_path, "core");

    if (!rules_dir.empty()) {
        DIR* d = opendir(rules_dir.c_str());
        if (d) {
            std::vector<std::string> files;
            struct dirent* e;
            while ((e = readdir(d)) != nullptr) {
                const char* nm = e->d_name;
                size_t nlen = strlen(nm);
                if (nlen >= 5 && strcmp(nm + nlen - 5, ".cron") == 0)
                    files.push_back(nm);
            }
            closedir(d);
            std::sort(files.begin(), files.end());
            for (const auto& nm : files) {
                std::string owner(nm, 0, nm.size() - 5);
                load_file(rules_dir + "/" + nm, owner);
            }
        }
    }
    
    pthread_mutex_lock(&m_mutex);
    auto final_vec = std::make_shared<std::vector<ScheduledJob>>(std::move(new_jobs));
    auto const_vec = std::shared_ptr<const std::vector<ScheduledJob>>(final_vec);
    std::atomic_store_explicit(&m_jobs, const_vec, std::memory_order_release);
    int cnt = (int)final_vec->size();
    pthread_mutex_unlock(&m_mutex);

    LOG_SCHED("Scheduler: loaded %d job(s) from %s%s",
              cnt, crontab_path.c_str(),
              !rules_dir.empty() ? " + rules/*.cron" : "");

    if (m_daemon) m_daemon->update_cron_timer();
}

void Scheduler::tick(const struct tm& t) {
    auto sp = std::atomic_load_explicit(&m_jobs, std::memory_order_acquire);
    const auto& jobs = *sp;
    std::vector<ScheduledJob> to_run;
    for (const auto& j : jobs)
        if (j.trigger_type == TriggerType::CRON && j.matches_time(t) && j.is_allowed(m_has_root))
            to_run.push_back(j);

    if (to_run.empty()) return;

    char tbuf[20];
    strftime(tbuf, sizeof(tbuf), "%H:%M", &t);
    LOG_SCHED("Scheduler: cron tick %s -> %zu job(s)", tbuf, to_run.size());

    for (auto& j : to_run) dispatch(j, "cron@" + std::string(tbuf));
}

void Scheduler::on_app_event(bool is_open, const std::string& package, int pid) {
    TriggerType want = is_open ? TriggerType::APP_OPEN : TriggerType::APP_CLOSE;
    auto sp = std::atomic_load_explicit(&m_jobs, std::memory_order_acquire);
    const auto& jobs = *sp;
    std::vector<ScheduledJob> matching;
    for (const auto& j : jobs)
        if (j.trigger_type == want && j.trigger_pkg == package && j.is_allowed(m_has_root))
            matching.push_back(j);

    std::string desc = (is_open ? "@app_open:" : "@app_close:") + package;
    for (auto& j : matching) dispatch(j, desc);
    (void)pid;
}

void Scheduler::on_foreground_event(const std::string& new_pkg, bool is_monitored) {
    std::string old_pkg;
    {
        pthread_mutex_lock(&m_mutex);
        old_pkg = m_last_fg_pkg;
        pthread_mutex_unlock(&m_mutex);
    }

    if (new_pkg != old_pkg) {
        if (!old_pkg.empty())
            dispatch_by_trigger(old_pkg, TriggerType::APP_FG_EXIT);
        if (!new_pkg.empty())
            dispatch_by_trigger(new_pkg, TriggerType::APP_FG);
        pthread_mutex_lock(&m_mutex);
        m_last_fg_pkg = new_pkg;
        pthread_mutex_unlock(&m_mutex);
    }
}

void Scheduler::dispatch_by_trigger(const std::string& pkg, TriggerType type) {
    auto sp = std::atomic_load_explicit(&m_jobs, std::memory_order_acquire);
    const auto& jobs = *sp;
    std::vector<ScheduledJob> matching;
    for (const auto& j : jobs)
        if (j.trigger_type == type && j.trigger_pkg == pkg && j.is_allowed(m_has_root))
            matching.push_back(j);

    std::string desc = (type == TriggerType::APP_FG) ? "@app_fg:"+pkg : "@app_fg_exit:"+pkg;
    for (auto& j : matching) dispatch(j, desc);
}

void Scheduler::fire_reboot_jobs() {
    auto sp = std::atomic_load_explicit(&m_jobs, std::memory_order_acquire);
    const auto& jobs = *sp;
    std::vector<ScheduledJob> rj;
    for (const auto& j : jobs)
        if (j.trigger_type == TriggerType::REBOOT && j.is_allowed(m_has_root))
            rj.push_back(j);
    for (auto& j : rj) dispatch(j, "@reboot");
}

std::string Scheduler::handle_ctrl(const std::string& raw) {
    std::string_view tokens[MAX_TOKENS];
    size_t token_count = tokenize(raw, tokens);
    if (token_count == 0) return "CRON_ERR empty_command\nCRON_END\n";
    const std::string cmd(tokens[0]);

    if (cmd == "CRON_LIST") {
        std::string filter = (token_count > 1) ? std::string(tokens[1]) : "";
        std::string resp;
        auto sp = std::atomic_load_explicit(&m_jobs, std::memory_order_acquire);
        for (const auto& j : *sp) {
            if (!filter.empty() && j.owner != filter) continue;

            std::string trig;
            switch (j.trigger_type) {
                case TriggerType::REBOOT:    trig = "@reboot"; break;
                case TriggerType::APP_OPEN:  trig = "@app_open:" + j.trigger_pkg; break;
                case TriggerType::APP_CLOSE: trig = "@app_close:" + j.trigger_pkg; break;
                case TriggerType::APP_FG:    trig = "@app_fg:" + j.trigger_pkg; break;
                case TriggerType::APP_FG_EXIT: trig = "@app_fg_exit:" + j.trigger_pkg; break;
                case TriggerType::CRON:
                    trig = j.minute.raw_text + " " + j.hour.raw_text + " "
                         + j.dom.raw_text + " " + j.month.raw_text + " "
                         + j.dow.raw_text;
                    break;
                default:
                trig = "cron";
                break;
            }

            resp += "CRON_JOB id=" + j.id
                 + " owner=" + (j.owner.empty() ? "core" : j.owner)
                 + " context=" + j.context_str
                 + " trigger=" + trig
                 + " action=[" + j.action + "]\n";
        }
        return (resp.empty() ? "CRON_JOB (none)\n" : resp) + "CRON_END\n";
    }

    if (cmd == "CRON_REMOVE" && token_count >= 2) {
        const std::string jid(tokens[1]);
        bool found = false;
        pthread_mutex_lock(&m_mutex);
        auto sp = std::atomic_load_explicit(&m_jobs, std::memory_order_acquire);
        auto new_vec = std::make_shared<std::vector<ScheduledJob>>(*sp);
        for (auto it = new_vec->begin(); it != new_vec->end(); ++it) {
            if (it->id == jid) { new_vec->erase(it); found = true; break; }
        }
        if (found) {
            auto const_vec = std::shared_ptr<const std::vector<ScheduledJob>>(new_vec);
            std::atomic_store_explicit(&m_jobs, const_vec, std::memory_order_release);
            if (m_daemon) m_daemon->update_cron_timer();
        }
        pthread_mutex_unlock(&m_mutex);
        return (found ? "CRON_ACK removed=" + jid : "CRON_ERR not_found=" + jid) + "\nCRON_END\n";
    }

    if (cmd == "CRON_ADD" && token_count >= 4) {
        std::string owner(tokens[1]);
        std::string line;
        for (size_t i = 2; i < token_count; ++i) {
            if (i > 2) line += ' ';
            line += tokens[i];
        }
        ScheduledJob job;
        std::unordered_map<std::string, std::string> empty_env;
        if (!parse_line(line, -1, owner, empty_env, job))
            return "CRON_ERR parse_failed\nCRON_END\n";
        job.owner = owner;
        pthread_mutex_lock(&m_mutex);
        auto sp = std::atomic_load_explicit(&m_jobs, std::memory_order_acquire);
        auto new_vec = std::make_shared<std::vector<ScheduledJob>>(*sp);
        new_vec->push_back(std::move(job));
        std::string assigned = new_vec->back().id;
        auto const_vec = std::shared_ptr<const std::vector<ScheduledJob>>(new_vec);
        std::atomic_store_explicit(&m_jobs, const_vec, std::memory_order_release);
        pthread_mutex_unlock(&m_mutex);
        LOG_SCHED("Scheduler: dynamic job '%s' added by %s", assigned.c_str(), owner.c_str());
        if (m_daemon) m_daemon->update_cron_timer();
        return "CRON_ACK id=" + assigned + "\nCRON_END\n";
    }

    return "CRON_ERR unknown=" + cmd + "\nCRON_END\n";
}

bool Scheduler::parse_line(const std::string& raw, int lineno,
                           const std::string& default_owner,
                           const std::unordered_map<std::string, std::string>& env,
                           ScheduledJob& out) {
    auto warn = [&](const std::string& m) {
        std::string loc = lineno >= 0 ? "line " + std::to_string(lineno) + ": " : "";
        LOG_SCHED("Scheduler: %s%s -> skipped", loc.c_str(), m.c_str());
        return false;
    };

    std::string_view tokens[MAX_TOKENS];
    size_t token_count = tokenize(raw, tokens);
    if (token_count == 0) return false;
    size_t ti = 0;

    auto set_cron_macro = [&](int min, int hr, int dom_v, int mon, int dow_v) {
        out.trigger_type = TriggerType::CRON;
        char tmp[8];
        snprintf(tmp, sizeof(tmp), "%d", min);   out.minute.parse(min < 0 ? "*" : tmp, 0, 59);
        snprintf(tmp, sizeof(tmp), "%d", hr);    out.hour.parse(hr < 0 ? "*" : tmp, 0, 23);
        snprintf(tmp, sizeof(tmp), "%d", dom_v); out.dom.parse(dom_v < 0 ? "*" : tmp, 1, 31);
        snprintf(tmp, sizeof(tmp), "%d", mon);   out.month.parse(mon < 0 ? "*" : tmp, 1, 12);
        snprintf(tmp, sizeof(tmp), "%d", dow_v); out.dow.parse(dow_v < 0 ? "*" : tmp, 0, 6);
    };

    const std::string_view first = tokens[ti];
    if      (first == "@reboot")   { out.trigger_type = TriggerType::REBOOT; ++ti; }
    else if (first == "@hourly")   { set_cron_macro(0, -1, -1, -1, -1); ++ti; }
    else if (first == "@daily" || first == "@midnight") { set_cron_macro(0, 0, -1, -1, -1); ++ti; }
    else if (first == "@weekly")   { set_cron_macro(0, 0, -1, -1, 0); ++ti; }
    else if (first == "@monthly")  { set_cron_macro(0, 0, 1, -1, -1); ++ti; }
    else if (first == "@yearly" || first == "@annually") { set_cron_macro(0, 0, 1, 1, -1); ++ti; }
    else if (first.size() >= 10 && first.substr(0, 10) == "@app_open:") {
        out.trigger_type = TriggerType::APP_OPEN;
        out.trigger_pkg = first.substr(10);
        if (out.trigger_pkg.empty()) return warn("@app_open: missing package");
        ++ti;
    }
    else if (first.size() >= 11 && first.substr(0, 11) == "@app_close:") {
        out.trigger_type = TriggerType::APP_CLOSE;
        out.trigger_pkg = first.substr(11);
        if (out.trigger_pkg.empty()) return warn("@app_close: missing package");
        ++ti;
    }
    else if (first.size() >= 8 && first.substr(0, 8) == "@app_fg:") {
        out.trigger_type = TriggerType::APP_FG;
        out.trigger_pkg = first.substr(8);
        if (out.trigger_pkg.empty()) return warn("@app_fg: missing package");
        ++ti;
    }
    else if (first.size() >= 12 && first.substr(0, 12) == "@app_fg_exit:") {
        out.trigger_type = TriggerType::APP_FG_EXIT;
        out.trigger_pkg = first.substr(12);
        if (out.trigger_pkg.empty()) return warn("@app_fg_exit: missing package");
        ++ti;
    }
    else {
        if (token_count - ti < 5) return warn("5-field cron requires 5 time tokens");
        out.trigger_type = TriggerType::CRON;
        struct { CronField& f; int lo, hi; const char* n; } fs[] = {
            {out.minute, 0, 59, "minute"}, {out.hour, 0, 23, "hour"},
            {out.dom, 1, 31, "dom"}, {out.month, 1, 12, "month"}, {out.dow, 0, 6, "dow"}
        };
        for (int i = 0; i < 5; ++i) {
            std::string tok(tokens[(size_t)ti + (size_t)i]);
            if (i == 3) {
                int mon = parse_month_name(tok);
                if (mon != -1) tok = std::to_string(mon);
            } else if (i == 4) {
                int wd = parse_weekday_name(tok);
                if (wd != -1) tok = std::to_string(wd);
            }
            if (!fs[i].f.parse(tok, fs[i].lo, fs[i].hi))
                return warn("bad " + std::string(fs[i].n) + " '" + std::string(tokens[(size_t)ti + (size_t)i]) + "'");
        }
        ti += 5;
    }

    if (ti >= token_count) return warn("missing context");
    std::string ctx(tokens[ti++]);
    if (ctx != "any" && ctx != "root" && ctx != "nonroot")
        return warn("bad context '" + ctx + "'");

    if (ctx == "root" && !m_has_root) {
        LOG_SCHED("Scheduler: skip root-only job (non-root context) -> line %d", lineno);
        return false;
    }
    out.context_str = ctx;

    out.id = unique_id(default_owner.empty() ? "j" : std::string(1, default_owner[0]));
    out.owner       = default_owner;
    out.timeout_sec = 30;
    out.overlap     = OverlapPolicy::SKIP;
    out.emit_event  = false;

    while (ti < token_count && !tokens[ti].empty() && tokens[ti][0] == '@') {
        std::string opt(tokens[ti++]);
        if      (opt.compare(0, 4, "@id=") == 0 && opt.size() > 4)     out.id = opt.substr(4);
        else if (opt.compare(0, 7, "@owner=") == 0 && opt.size() > 7)  out.owner = opt.substr(7);
        else if (opt.compare(0, 9, "@timeout=") == 0) {
            int v; if (safe_atoi(opt.c_str() + 9, &v) && v >= 0) out.timeout_sec = v;
        }
        else if (opt.compare(0, 9, "@overlap=") == 0) {
            std::string v = opt.substr(9);
            if (v == "allow") out.overlap = OverlapPolicy::ALLOW;
            else if (v == "kill") out.overlap = OverlapPolicy::KILL;
        }
        else if (opt == "@emit") out.emit_event = true;
        else LOG_SCHED("Scheduler: unknown option '%s' -> ignored", opt.c_str());
    }

    if (ti >= token_count) return warn("missing action");
    std::string action;
    for (size_t i = ti; i < token_count; ++i) {
        if (i > ti) action += ' ';
        action += tokens[i];
    }
    out.action = action;

    if (!out.action.empty() && out.action[0] == '!')      out.action_type = ActionType::BUILTIN;
    else if (!out.action.empty() && out.action[0] == '>')  out.action_type = ActionType::PLUGIN_EVENT;
    else                                                   out.action_type = ActionType::SHELL;

    out.env = env;
    return true;
}

struct RunnerArg {
    std::string           id;
    std::string           action;
    ActionType            action_type;
    int                   timeout_sec;
    OverlapPolicy         overlap;
    bool                  emit_event;
    std::string           trigger;
    bool                  has_root;
    EventEmitter*         emitter;
    std::shared_ptr<std::atomic<bool>> running_flag;
    std::shared_ptr<std::atomic<int>>  running_pid;
    std::atomic<int>*     inflight;
    Scheduler*            sched;
    std::unordered_map<std::string, std::string> env;
};

void Scheduler::dispatch(const ScheduledJob& job, const std::string& trigger) {
    if (job.overlap != OverlapPolicy::ALLOW) {
        bool already = job.running->load(std::memory_order_acquire);
        if (already && job.overlap == OverlapPolicy::SKIP) {
            LOG_SCHED("Scheduler: job '%s' still running -> skip (%s)", job.id.c_str(), trigger.c_str());
            return;
        }
        if (already && job.overlap == OverlapPolicy::KILL) {
            int prev = job.running_pid->load(std::memory_order_acquire);
            if (prev > 0) {
                LOG_SCHED("Scheduler: job '%s' -> SIGKILL PID %d", job.id.c_str(), prev);
                kill(-prev, SIGKILL);
            }
        }
    }

    if (job.action_type == ActionType::BUILTIN) {
        run_builtin(job.action, job.id);
        LOG_SCHED("Scheduler: done id='%s' builtin trigger=%s", job.id.c_str(), trigger.c_str());
        if (job.emit_event && m_emitter)
            m_emitter->emit("SCHED_DONE", job.id, 0, trigger);
        return;
    }

    if (job.action_type == ActionType::PLUGIN_EVENT && m_emitter) {
        m_emitter->emit("SCHED_EVENT", job.id, 0,
                        job.action.size() > 1 ? job.action.substr(1) : job.action);
        LOG_SCHED("Scheduler: done id='%s' event trigger=%s", job.id.c_str(), trigger.c_str());
        return;
    }

    auto* arg = new RunnerArg{
        job.id, job.action, job.action_type,
        job.timeout_sec, job.overlap, job.emit_event,
        trigger, m_has_root, m_emitter,
        job.running, job.running_pid, &m_inflight, this,
        job.env
    };

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    ++m_inflight;
    if (pthread_create(&tid, &attr, job_runner, arg) != 0) {
        LOG_ERROR("Scheduler: pthread_create failed for '%s'", job.id.c_str());
        --m_inflight;
        delete arg;
    }
    pthread_attr_destroy(&attr);
}

void* Scheduler::job_runner(void* raw) {
    auto* a = static_cast<RunnerArg*>(raw);
    a->running_flag->store(true, std::memory_order_release);

    long long t0 = mono_ms();
    if (a->emit_event && a->emitter)
        a->emitter->emit("SCHED_RUN", a->id, (int)getpid(), a->trigger);

    LOG_SCHED("Scheduler: exec id='%s' priv=%s cmd=[%s]",
              a->id.c_str(), a->has_root ? "root" : "shell", a->action.c_str());
    extern char** environ;
    std::vector<std::string> envstrings;
    for (char** e = environ; *e; ++e)
        envstrings.push_back(*e);

    for (const auto& [key, val] : a->env) {
        std::string entry = key + "=" + val;
        bool replaced = false;
        for (auto& ev : envstrings) {
            if (ev.rfind(key + "=", 0) == 0) {
                ev = entry;
                replaced = true;
                break;
            }
        }
        if (!replaced) envstrings.push_back(entry);
    }

    std::vector<const char*> envp;
    for (const auto& s : envstrings) envp.push_back(s.c_str());
    envp.push_back(nullptr);

    const char* argv[] = {"/system/bin/sh", "-c", a->action.c_str(), nullptr};

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
    posix_spawnattr_setpgroup(&attr, 0);

    int exit_code = -1;
    pid_t child = -1;
    int rc = posix_spawn(&child, "/system/bin/sh",
                         nullptr, &attr,
                         const_cast<char* const*>(argv),
                         const_cast<char* const*>(envp.data()));
    posix_spawnattr_destroy(&attr);

    if (rc != 0) {
        LOG_ERROR("Scheduler: posix_spawn failed for '%s': %s", a->id.c_str(), strerror(rc));
        exit_code = -2;
    } else {
        a->running_pid->store(child, std::memory_order_release);

#ifdef SYS_pidfd_open
        int pidfd = (int)syscall(SYS_pidfd_open, child, 0);
#else
        int pidfd = -1;
#endif

        bool have_pidfd = (pidfd >= 0);
        bool use_epoll = (a->timeout_sec > 0 && have_pidfd);

        if (use_epoll) {
            int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
            if (tfd < 0) {
                use_epoll = false;
                close(pidfd); pidfd = -1;
            } else {
                struct itimerspec its{};
                its.it_value.tv_sec = a->timeout_sec;
                timerfd_settime(tfd, 0, &its, nullptr);

                int epfd = epoll_create1(EPOLL_CLOEXEC);
                struct epoll_event ev;
                ev.events = EPOLLIN;
                ev.data.fd = pidfd;
                epoll_ctl(epfd, EPOLL_CTL_ADD, pidfd, &ev);
                ev.data.fd = tfd;
                epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev);

                struct epoll_event events[2];
                bool timed_out = false;
                int n = epoll_wait(epfd, events, 2, -1);
                for (int i = 0; i < n; ++i) {
                    if (events[i].data.fd == tfd) { timed_out = true; break; }
                }

                if (timed_out) {
                    LOG_SCHED("Scheduler: timeout SIGKILL '%s' PID=%d", a->id.c_str(), child);
                    kill(-child, SIGKILL);
                }

                close(tfd); close(pidfd); close(epfd);

                int status;
                waitpid(child, &status, 0);
                if (WIFEXITED(status))      exit_code = WEXITSTATUS(status);
                else if (WIFSIGNALED(status)) exit_code = 128 + WTERMSIG(status);
            }
        }

        if (!use_epoll) {
            if (a->timeout_sec > 0) {
                struct WatchdogArg {
                    pid_t pid;
                    int timeout_sec;
                    std::string job_id;
                    std::atomic<bool> done{false};
                    WatchdogArg(pid_t p, int t, std::string id)
                        : pid(p), timeout_sec(t), job_id(std::move(id)) {}
                };

                auto warg = std::make_shared<WatchdogArg>(child, a->timeout_sec, a->id);

                pthread_t watchdog_tid;
                pthread_create(&watchdog_tid, nullptr, [](void* arg) -> void* {
                    std::shared_ptr<WatchdogArg> w =
                        *static_cast<std::shared_ptr<WatchdogArg>*>(arg);
                    delete static_cast<std::shared_ptr<WatchdogArg>*>(arg);

                    for (int i = 0; i < w->timeout_sec; ++i) {
                        sleep(1);
                        if (w->done.load(std::memory_order_acquire)) return nullptr;
                    }
                    if (kill(-w->pid, 0) == 0) {
                        LOG_SCHED("Scheduler: timeout SIGKILL '%s' PID=%d",
                                  w->job_id.c_str(), w->pid);
                        kill(-w->pid, SIGKILL);
                    }
                    return nullptr;
                }, new std::shared_ptr<WatchdogArg>(warg));
                pthread_detach(watchdog_tid);

                int status;
                waitpid(child, &status, 0);
                warg->done.store(true, std::memory_order_release);
                warg.reset();

                if (WIFEXITED(status))      exit_code = WEXITSTATUS(status);
                else if (WIFSIGNALED(status)) exit_code = 128 + WTERMSIG(status);
            } else {
                int status;
                waitpid(child, &status, 0);
                if (WIFEXITED(status))      exit_code = WEXITSTATUS(status);
                else if (WIFSIGNALED(status)) exit_code = 128 + WTERMSIG(status);
            }
        }

        if (!a->has_root && (exit_code == 1 || exit_code == 126))
            LOG_SCHED("Scheduler: job '%s' exit=%d -> possible permission denial (non-root)",
                      a->id.c_str(), exit_code);

        long long dur = mono_ms() - t0;
        LOG_SCHED("Scheduler: done id='%s' exit=%d dur=%lldms priv=%s trigger=%s",
                  a->id.c_str(), exit_code, dur, a->has_root ? "root" : "shell", a->trigger.c_str());

        if (a->emit_event && a->emitter)
            a->emitter->emit("SCHED_DONE", a->id, exit_code,
                             a->trigger + " dur=" + std::to_string(dur) + "ms");
    }

    a->running_pid->store(-1, std::memory_order_release);
    a->running_flag->store(false, std::memory_order_release);

    pthread_mutex_lock(&a->sched->m_mutex);
    int remaining = --(*a->inflight);
    if (remaining == 0) pthread_cond_signal(&a->sched->m_inflight_cond);
    pthread_mutex_unlock(&a->sched->m_mutex);

    delete a;
    return nullptr;
}

void Scheduler::run_builtin(const std::string& cmd, const std::string& id) {
    if (cmd == "!reload_config" || cmd == "!reload") {
        LOG_SCHED("Scheduler: !reload_config triggered by '%s'", id.c_str());
        if (m_daemon) m_daemon->reload_config();
    } else if (cmd == "!log_stats") {
        LOG_SCHED("Stats: [jobs=%d, inflight=%d, priv=%s]",
                  job_count(), m_inflight.load(), m_has_root ? "root" : "shell");
    } else if (cmd == "!noop") {
        // intentional no-op
    } else {
        LOG_SCHED("Scheduler: unknown builtin '%s' in job '%s'", cmd.c_str(), id.c_str());
    }
}

time_t Scheduler::next_cron_time() const {
    time_t now = time(nullptr);
    auto sp = std::atomic_load_explicit(&m_jobs, std::memory_order_acquire);
    const auto& jobs = *sp;
    time_t earliest = 0;
    for (const auto& j : jobs) {
        if (j.trigger_type != TriggerType::CRON) continue;
        if (!j.is_allowed(m_has_root)) continue;
        time_t next = j.next_trigger(now);
        if (next > 0 && (earliest == 0 || next < earliest))
            earliest = next;
    }
    return earliest;
}