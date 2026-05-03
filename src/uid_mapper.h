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
#include <unordered_map>
#include <memory>
#include <atomic>

class UidMapper {
public:
    explicit UidMapper(bool has_root);
    ~UidMapper();
    int setup();
    std::string lookup(uint32_t uid) const;
    uint32_t reverse_lookup(const std::string& pkg) const;
    size_t size() const;
    void async_refresh();
    void set_inotify_fd(int fd) { m_inotify_fd = fd; }
    int  watch_wd() const { return m_watch_wd; }
    void set_watch_wd(int wd) { m_watch_wd = wd; }
    bool try_add_watch(int inotify_fd);
    using RefreshDoneFn = void (*)(void* ctx);
    void set_on_refresh_done(void* ctx, RefreshDoneFn fn) {
        m_refresh_ctx = ctx;
        m_refresh_fn = fn;
    }
    void handle_inotify();
    int arm_inotify();
private:
    void load_map(const std::string& path);
    void do_refresh();
    static void* refresh_thread(void* arg);
    using MapType = std::unordered_map<uint32_t, std::string>;
    using SharedMap = std::shared_ptr<const MapType>;
    using RevMapType = std::unordered_map<std::string, uint32_t>;
    using SharedRev = std::shared_ptr<const RevMapType>;
    bool m_has_root;
    std::string m_watch_path;
    int m_inotify_fd = -1;
    int m_watch_wd = -1;
    std::atomic<bool> m_needs_retry{false};
    SharedMap m_map{std::make_shared<MapType>()};
    SharedRev m_reverse_map{std::make_shared<RevMapType>()};
    std::atomic<bool> m_refreshing{false};
    void* m_refresh_ctx = nullptr;
    RefreshDoneFn m_refresh_fn = nullptr;
};