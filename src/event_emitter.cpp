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

#include "event_emitter.h"
#include "utils.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <ctime>
#include <cerrno>
#include <algorithm>

EventEmitter::EventEmitter(const std::string& socket_path, bool has_root)
    : m_socket_path(socket_path)
    , m_effective_path(socket_path)
    , m_has_root(has_root) {}

EventEmitter::~EventEmitter() {
    shutdown();
    pthread_rwlock_destroy(&m_rwlock);
}

int EventEmitter::initialize() {
    auto try_filesystem = [&]() -> bool {
        unlink(m_socket_path.c_str());
        m_server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (m_server_fd < 0) return false;
        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        size_t len = m_socket_path.size();
        if (len >= sizeof(addr.sun_path)) {
            close(m_server_fd); m_server_fd = -1;
            return false;
        }
        memcpy(addr.sun_path, m_socket_path.c_str(), len + 1);
        socklen_t addrlen = (socklen_t)(offsetof(sockaddr_un, sun_path) + len + 1);
        if (bind(m_server_fd, reinterpret_cast<sockaddr*>(&addr), addrlen) < 0) {
            close(m_server_fd); m_server_fd = -1; return false;
        }
        chmod(m_socket_path.c_str(), 0666);
        m_abstract = false;
        m_effective_path = m_socket_path;
        return true;
    };

    auto try_abstract = [&]() -> bool {
        const char* name = cfg::kEventSockAbstract;
        size_t name_len = strlen(name);
        struct sockaddr_un addr{};
        if (name_len >= sizeof(addr.sun_path) - 1) {
            return false;
        }
        m_server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (m_server_fd < 0) return false;
        addr.sun_family  = AF_UNIX;
        addr.sun_path[0] = '\0';
        memcpy(addr.sun_path + 1, name, name_len);
        socklen_t len = (socklen_t)(offsetof(sockaddr_un, sun_path) + 1 + name_len);
        if (bind(m_server_fd, reinterpret_cast<sockaddr*>(&addr), len) < 0) {
            close(m_server_fd); m_server_fd = -1; return false;
        }
        m_abstract = true;
        m_effective_path = std::string("@") + name;
        return true;
    };

    bool ok = m_has_root ? try_filesystem() : try_abstract();
    if (!ok) {
        ok = m_has_root ? try_abstract() : try_filesystem();
        if (!ok) {
            LOG_ERROR("EventEmitter: cannot bind any socket");
            return -1;
        }
        LOG_WARN("EventEmitter: using fallback socket type");
    }

    if (listen(m_server_fd, 16) < 0) {
        LOG_ERROR("EventEmitter: listen failed: %s", strerror(errno));
        if (!m_abstract) unlink(m_socket_path.c_str());
        close(m_server_fd); m_server_fd = -1; return -1;
    }

    LOG_INFO("EventEmitter: %s", m_effective_path.c_str());
    if (m_abstract) {
        LOG_DEBUG("  connect : cored_client  (auto-detects abstract)");
        LOG_DEBUG("  verify  : grep @coredaemon /proc/net/unix");
    } else {
        LOG_DEBUG("  connect : cored_client -s %s", m_effective_path.c_str());
    }
    return m_server_fd;
}

void EventEmitter::shutdown() {
    pthread_rwlock_wrlock(&m_rwlock);
    for (int fd : m_clients) close(fd);
    m_clients.clear();
    pthread_rwlock_unlock(&m_rwlock);

    if (m_server_fd >= 0) {
        close(m_server_fd);
        m_server_fd = -1;
    }
    if (!m_abstract) unlink(m_socket_path.c_str());
}

int EventEmitter::accept_one() {
    return accept4(m_server_fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
}

void EventEmitter::add_client(int fd) {
    pthread_rwlock_wrlock(&m_rwlock);
    m_clients.push_back(fd);
    m_client_count.fetch_add(1, std::memory_order_relaxed);
    size_t n = m_clients.size();
    pthread_rwlock_unlock(&m_rwlock);
    LOG_INFO("EventEmitter: client fd=%d connected (total=%zu)", fd, n);
}

void EventEmitter::remove_client(int fd) {
    pthread_rwlock_wrlock(&m_rwlock);
    auto it = std::find(m_clients.begin(), m_clients.end(), fd);
    if (it != m_clients.end()) {
        close(*it);
        m_clients.erase(it);
        m_client_count.fetch_sub(1, std::memory_order_relaxed);
        size_t remaining = m_clients.size();
        pthread_rwlock_unlock(&m_rwlock);
        LOG_INFO("EventEmitter: client fd=%d removed (remaining=%zu)", fd, remaining);
    } else {
        pthread_rwlock_unlock(&m_rwlock);
    }
}

void EventEmitter::emit(const std::string& type, const std::string& pkg,
                         int pid, const std::string& extra) {
    if (__builtin_expect(m_client_count.load(std::memory_order_relaxed) == 0, 1))
        return;
    struct timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm{};
    localtime_r(&ts.tv_sec, &tm);
    char tbuf[32];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm);

    char msg[512];
    int len = snprintf(msg, sizeof(msg), "%s.%03ld|%s|%s|%d|%s\n",
                       tbuf, ts.tv_nsec / 1000000L,
                       type.c_str(), pkg.c_str(), pid, extra.c_str());
    if (len <= 0 || len >= (int)sizeof(msg)) return;
    pthread_rwlock_rdlock(&m_rwlock);
    for (auto it = m_clients.begin(); it != m_clients.end(); ) {
        int fd = *it;
        ssize_t sent = send(fd, msg, (size_t)len, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            close(fd);
            it = m_clients.erase(it);
            m_client_count.fetch_sub(1, std::memory_order_relaxed);
        } else {
            ++it;
        }
    }
    pthread_rwlock_unlock(&m_rwlock);
}