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
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <optional>
#include <string_view>
#include <fstream>
#include <sstream>
#include <cstdarg>

struct Fd {
    int v = -1;
    Fd() = default;
    explicit Fd(int fd) : v(fd) {}
    ~Fd() { if (v >= 0) ::close(v); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    Fd(Fd&& o) noexcept : v(o.v) { o.v = -1; }
    Fd& operator=(Fd&& o) noexcept {
        if (this != &o) { if (v >= 0) ::close(v); v = o.v; o.v = -1; }
        return *this;
    }
    int get() const { return v; }
    int release() { int t = v; v = -1; return t; }
};

namespace sock {

inline Fd connect_unix(const char* path, bool abstract, int timeout_ms) {
    Fd fd(::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
    if (fd.get() < 0) return Fd{};

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    socklen_t len = 0;
    if (abstract) {
        size_t name_len = strlen(path);
        if (name_len >= sizeof(addr.sun_path) - 1) return Fd{};
        addr.sun_path[0] = '\0';
        memcpy(addr.sun_path + 1, path, name_len);
        len = (socklen_t)(offsetof(sockaddr_un, sun_path) + 1 + name_len);
    } else {
        size_t path_len = strlen(path);
        if (path_len >= sizeof(addr.sun_path)) return Fd{};
        memcpy(addr.sun_path, path, path_len + 1);
        len = (socklen_t)(offsetof(sockaddr_un, sun_path) + path_len + 1);
    }

    int ret = ::connect(fd.get(), (sockaddr*)&addr, len);
    if (ret == 0) return fd;
    if (errno != EINPROGRESS) return Fd{};

    if (timeout_ms > 0) {
        struct pollfd pfd{};
        pfd.fd = fd.get();
        pfd.events = POLLOUT;
        int ready = ::poll(&pfd, 1, timeout_ms);
        if (ready <= 0) return Fd{};

        int so_error = 0;
        socklen_t slen = sizeof(so_error);
        if (::getsockopt(fd.get(), SOL_SOCKET, SO_ERROR, &so_error, &slen) < 0 ||
            so_error != 0)
            return Fd{};
    }
    return fd;
}

}

inline std::string errno_str(const char* context) {
    return std::string(context) + ": " + std::strerror(errno);
}

namespace cfg {
    inline constexpr const char* kEventSockAbstract = "coredaemon";
    inline constexpr const char* kCtrlSockAbstract = "coredaemon-ctrl";
    inline constexpr const char* kCtrlSockPath = "/data/local/tmp/coredaemon/run/coredaemon-ctrl.sock";
    inline constexpr const char* kEventSockDefault = "/data/local/tmp/coredaemon/run/coredaemon.sock";
    inline constexpr const char* kBaseDir = "/data/local/tmp/coredaemon";
    inline constexpr const char* kConfigDir = "/data/local/tmp/coredaemon/etc";
    inline constexpr const char* kLogDir = "/data/local/tmp/coredaemon/log";
    inline constexpr const char* kRunDir = "/data/local/tmp/coredaemon/run";
    inline constexpr const char* kDefaultConfigFile = "/data/local/tmp/coredaemon/etc/coredaemon.conf";
    inline constexpr const char* kDefaultLogFile = "/data/local/tmp/coredaemon/log/coredaemon.log";
    inline constexpr const char* kPidFile = "/data/local/tmp/coredaemon/run/coredaemon.pid";
    inline constexpr const char* kSysPackages = "/data/system/packages.list";
    inline constexpr const char* kCachePackages = "/data/local/tmp/coredaemon/run/packages.list";
    inline constexpr const char* kFgStatusFile = "/data/local/tmp/coredaemon/run/foreground";
    inline constexpr int kDefaultCtrlTimeoutMs = 3000;
}

namespace utils {
    enum class LogLevel { DBG, INFO, SCHED, EVENT, WARN, ERROR };
    void log_write(LogLevel level, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
    bool init_logger(const std::string& log_path, bool verbose);
    void set_log_levels(const std::string& spec);
    void close_logger();
    void log_debug(const std::string& msg);
    void log_info (const std::string& msg);
    void log_sched(const std::string& msg);
    void log_event(const std::string& msg);
    void log_warn (const std::string& msg);
    void log_error(const std::string& msg);
    bool check_root();
    bool detect_cgroup_v2();
}

#define LOG_DEBUG(fmt, ...) utils::log_write(utils::LogLevel::DBG,  fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  utils::log_write(utils::LogLevel::INFO, fmt, ##__VA_ARGS__)
#define LOG_SCHED(fmt, ...) utils::log_write(utils::LogLevel::SCHED,fmt, ##__VA_ARGS__)
#define LOG_EVENT(fmt, ...) utils::log_write(utils::LogLevel::EVENT,fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  utils::log_write(utils::LogLevel::WARN, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) utils::log_write(utils::LogLevel::ERROR,fmt, ##__VA_ARGS__)