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
#include <pthread.h>

class EventEmitter {
public:
    explicit EventEmitter(const std::string& socket_path, bool has_root);
    ~EventEmitter();
    int  initialize();
    void shutdown();
    int  accept_one();
    void remove_client(int fd);
    void add_client(int fd);
    void emit(const std::string& type, const std::string& pkg,
              int pid, const std::string& extra);
    const std::string& effective_path() const { return m_effective_path; }
    bool is_abstract() const { return m_abstract; }
    int server_fd() const { return m_server_fd; }
private:
    std::string m_socket_path;
    std::string m_effective_path;
    bool m_has_root;
    bool m_abstract = false;
    int m_server_fd = -1;
    pthread_rwlock_t m_rwlock = PTHREAD_RWLOCK_INITIALIZER;
    std::vector<int> m_clients;
    std::atomic<int> m_client_count{0};
};