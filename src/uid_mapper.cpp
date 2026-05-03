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

#include "uid_mapper.h"
#include "utils.h"
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <fstream>
#include <algorithm>

static constexpr const char* kSysPackages = "/data/system/packages.list";
static constexpr const char* kCachePackages = "/data/local/tmp/coredaemon/run/packages.list";

UidMapper::UidMapper(bool has_root) : m_has_root(has_root) {}
UidMapper::~UidMapper() {}
int UidMapper::setup() {
    m_watch_path = m_has_root ? kSysPackages : kCachePackages;
    load_map(m_watch_path);
    LOG_INFO("PackageMap: %zu packages loaded", size(), m_watch_path.c_str());
    if (!m_has_root) {
        async_refresh();
    }
    return arm_inotify();
}

int UidMapper::arm_inotify() {
    if (m_inotify_fd < 0) {
        LOG_WARN("UidMapper: no shared inotify fd");
        return -1;
    }
    if (m_watch_wd >= 0) {
        inotify_rm_watch(m_inotify_fd, static_cast<uint32_t>(m_watch_wd));
        m_watch_wd = -1;
    }
    m_watch_wd = inotify_add_watch(m_inotify_fd, m_watch_path.c_str(),
                                   IN_CLOSE_WRITE | IN_MOVED_TO);
    if (m_watch_wd < 0) {
        m_needs_retry = true;
        LOG_INFO("UidMapper: %s not yet watchable, will retry after refresh",
                 m_watch_path.c_str());
        return -1;
    }
    m_needs_retry = false;
    LOG_INFO("UidMapper: watching %s", m_watch_path.c_str());
    return m_inotify_fd;
}

bool UidMapper::try_add_watch(int inotify_fd) {
    if (inotify_fd < 0) return false;
    if (m_watch_wd >= 0) return true;

    m_watch_wd = inotify_add_watch(inotify_fd, m_watch_path.c_str(),
                                   IN_CLOSE_WRITE | IN_MOVED_TO);
    if (m_watch_wd >= 0) {
        LOG_INFO("UidMapper: watching %s (wd=%d)", m_watch_path.c_str(), m_watch_wd);
        return true;
    }
    LOG_INFO("UidMapper: %s not yet watchable, will retry after refresh",
             m_watch_path.c_str());
    if (m_refresh_fn) m_refresh_fn(m_refresh_ctx);
    return false;
}

void UidMapper::handle_inotify() {
    load_map(m_watch_path);
}

std::string UidMapper::lookup(uint32_t uid) const {
    SharedMap sp = std::atomic_load_explicit(&m_map, std::memory_order_acquire);
    auto it = sp->find(uid);
    return (it != sp->end()) ? it->second : std::string{};
}

uint32_t UidMapper::reverse_lookup(const std::string& pkg) const {
    SharedRev sp = std::atomic_load_explicit(&m_reverse_map, std::memory_order_acquire);
    auto it = sp->find(pkg);
    return (it != sp->end()) ? it->second : 0;
}

size_t UidMapper::size() const {
    SharedMap sp = std::atomic_load_explicit(&m_map, std::memory_order_acquire);
    return sp->size();
}

void UidMapper::async_refresh() {
    if (m_has_root) return;
    bool exp = false;
    if (!m_refreshing.compare_exchange_strong(exp, true)) return;

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, refresh_thread, this) != 0) {
        LOG_ERROR("UidMapper: pthread_create failed");
        m_refreshing.store(false);
    }
    pthread_attr_destroy(&attr);
}

void* UidMapper::refresh_thread(void* arg) {
    static_cast<UidMapper*>(arg)->do_refresh();
    return nullptr;
}

void UidMapper::do_refresh() {
    LOG_INFO("UidMapper: cmd package list packages -U");
    FILE* f = popen("cmd package list packages -U 2>/dev/null", "r");
    if (!f) {
        LOG_ERROR("UidMapper: popen failed: %s", strerror(errno));
        m_refreshing.store(false);
        return;
    }

    std::string tmp = std::string(kCachePackages) + ".tmp";
    FILE* out = fopen(tmp.c_str(), "w");
    if (!out) {
        LOG_WARN("UidMapper: cannot write %s", tmp.c_str());
        pclose(f);
        m_refreshing.store(false);
        return;
    }

    char line[512]; int cnt = 0;
    while (fgets(line, sizeof(line), f)) { fputs(line, out); ++cnt; }
    fclose(out); pclose(f);

    if (rename(tmp.c_str(), kCachePackages) == 0) {
        LOG_INFO("UidMapper: refresh done, %d lines", cnt);
        if (m_watch_wd < 0) {
            load_map(kCachePackages);
            m_needs_retry = true;
        }
    } else {
        LOG_ERROR("UidMapper: rename failed: %s", strerror(errno));
    }
    m_refreshing.store(false);
}

void UidMapper::load_map(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return;

    auto fresh = std::make_shared<MapType>();
    auto fresh_rev = std::make_shared<std::unordered_map<std::string, uint32_t>>();
    fresh->reserve(512);

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        if (!line.empty() && line.back() == '\r') line.pop_back();

        uint32_t uid = 0;
        std::string pkg;

        if (line.compare(0, 8, "package:") == 0) {
            size_t uid_pos = line.find(" uid:");
            if (uid_pos == std::string::npos) continue;
            pkg = line.substr(8, uid_pos - 8);
            char* ep;
            long uid_raw = strtol(line.c_str() + uid_pos + 5, &ep, 10);
            if (uid_raw > 1000 && (*ep == '\0' || *ep == '\r' || *ep == '\n'))
                uid = static_cast<uint32_t>(uid_raw);
        } else {
            size_t s1 = line.find(' ');
            if (s1 == std::string::npos) continue;
            pkg = line.substr(0, s1);
            char* ep;
            long uid_raw = strtol(line.c_str() + s1 + 1, &ep, 10);
            if (uid_raw > 1000)
                uid = static_cast<uint32_t>(uid_raw);
        }

        if (uid > 0 && !pkg.empty()) {
            (*fresh)[uid] = pkg;
            (*fresh_rev)[pkg] = uid;
        }
    }

    auto const_map = std::shared_ptr<const MapType>(fresh);
    auto const_rev = std::shared_ptr<const RevMapType>(fresh_rev);
    std::atomic_store_explicit(&m_map, const_map, std::memory_order_release);
    std::atomic_store_explicit(&m_reverse_map, const_rev, std::memory_order_release);
}