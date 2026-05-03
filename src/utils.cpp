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

#include "utils.h"
#include <fstream>
#include <iostream>
#include <mutex>
#include <ctime>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <cstdarg>

namespace utils {
static std::ofstream g_log_file;
static std::mutex g_log_mutex;
static bool g_stderr_only = false;
static bool g_verbose = false;

static constexpr int LVL_INFO = 1 << 0;
static constexpr int LVL_DEBUG = 1 << 1;
static constexpr int LVL_SCHEDULER = 1 << 2;
static constexpr int LVL_EVENT = 1 << 3;
static int g_levels = LVL_INFO | LVL_EVENT;

bool init_logger(const std::string& log_path, bool verbose) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    g_verbose = verbose;
    if (verbose) g_levels |= LVL_DEBUG;

    g_log_file.open(log_path, std::ios::out | std::ios::app);
    if (!g_log_file.is_open()) {
        std::string fallback = log_path + "." + std::to_string(getuid());
        g_log_file.open(fallback, std::ios::out | std::ios::app);
        if (g_log_file.is_open()) {
            std::cerr << "Warning! log file " << log_path
                      << " unwritable -> using " << fallback << "\n";
        } else {
            g_stderr_only = true;
            std::cerr << "Warning! cannot open log file " << log_path
                      << " fallback: stderr only\n";
        }
    }
    if (g_log_file.is_open()) g_log_file << std::unitbuf;
    return true;
}

void set_log_levels(const std::string& spec) {
    if (spec.empty()) return;
    int levels = LVL_EVENT;
    std::string tok;
    for (size_t i = 0; i <= spec.size(); ++i) {
        char c = (i < spec.size()) ? spec[i] : ';';
        if (c == ';') {
            std::transform(tok.begin(), tok.end(), tok.begin(), ::tolower);
            if (tok == "info")      levels |= LVL_INFO;
            else if (tok == "debug")     levels |= LVL_DEBUG;
            else if (tok == "scheduler") levels |= LVL_SCHEDULER;
            else if (tok == "event")     levels |= LVL_EVENT;
            tok.clear();
        } else { tok += c; }
    }
    std::lock_guard<std::mutex> lock(g_log_mutex);
    g_levels = levels;
}

void close_logger() {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (g_log_file.is_open()) g_log_file.close();
}

static const char* level_char(LogLevel lvl) {
    switch (lvl) {
        case LogLevel::DBG: return "D";
        case LogLevel::INFO:  return "I";
        case LogLevel::SCHED: return "S";
        case LogLevel::EVENT: return "V";
        case LogLevel::WARN:  return "W";
        case LogLevel::ERROR: return "E";
        default: return "?";
    }
}

static bool is_level_enabled(LogLevel lvl) {
    switch (lvl) {
        case LogLevel::DBG: return (g_levels & LVL_DEBUG) != 0;
        case LogLevel::INFO:  return (g_levels & LVL_INFO) != 0;
        case LogLevel::SCHED: return (g_levels & LVL_SCHEDULER) != 0;
        case LogLevel::EVENT: return true;
        case LogLevel::WARN:  return true;
        case LogLevel::ERROR: return true;
        default: return false;
    }
}

void log_write(LogLevel level, const char* fmt, ...) {
    if (!is_level_enabled(level)) return;

    time_t now = time(nullptr);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_buf);

    va_list args;
    va_start(args, fmt);
    char msg_buf[2048];
    vsnprintf(msg_buf, sizeof(msg_buf), fmt, args);
    va_end(args);

    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (!g_stderr_only && g_log_file.is_open()) {
        g_log_file << time_buf << " " << level_char(level) << " " << msg_buf << "\n";
    }
    if (g_verbose || level >= LogLevel::WARN) {
        std::cerr << time_buf << " " << level_char(level) << " " << msg_buf << "\n";
    }
}

void log_debug(const std::string& m) { log_write(LogLevel::DBG, "%s", m.c_str()); }
void log_info(const std::string& m)  { log_write(LogLevel::INFO,  "%s", m.c_str()); }
void log_sched(const std::string& m) { log_write(LogLevel::SCHED, "%s", m.c_str()); }
void log_event(const std::string& m) { log_write(LogLevel::EVENT, "%s", m.c_str()); }
void log_warn(const std::string& m)  { log_write(LogLevel::WARN,  "%s", m.c_str()); }
void log_error(const std::string& m) { log_write(LogLevel::ERROR, "%s", m.c_str()); }

bool check_root() { return getuid() == 0; }

bool detect_cgroup_v2() {
    std::ifstream mounts("/proc/mounts");
    std::string line;
    while (std::getline(mounts, line))
        if (line.find("cgroup2") != std::string::npos) return true;
    return false;
}

std::optional<std::string> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::in | std::ios::binary);
    if (!f.is_open()) return std::nullopt;
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool write_file_atomic(const std::string& path, const char* content, size_t len) {
    std::string tmp = path + ".tmp";
    std::ofstream f(tmp, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!f.is_open()) return false;
    f.write(content, static_cast<std::streamsize>(len));
    if (!f.good()) return false;
    f.close();
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        unlink(tmp.c_str());
        return false;
    }
    return true;
}

}