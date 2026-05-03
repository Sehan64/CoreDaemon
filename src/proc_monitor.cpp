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

#include "proc_monitor.h"
#include <dirent.h>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

namespace {
    static int g_proc_fd = -1;
    void ensure_proc_fd() {
        if (g_proc_fd < 0) {
            g_proc_fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        }
        lseek(g_proc_fd, 0, SEEK_SET);
    }

    struct linux_dirent64 {
        uint64_t d_ino;
        int64_t d_off;
        uint16_t d_reclen;
        uint8_t d_type;
        char d_name[1];
    };

    template<typename Func>
    void foreach_pid(Func&& callback) {
        ensure_proc_fd();
        if (g_proc_fd < 0) return;

        char buf[65536];
        for (;;) {
            long n = syscall(SYS_getdents64, g_proc_fd, buf, sizeof(buf));
            if (n <= 0) break;
            long pos = 0;
            while (pos < n) {
                const auto* d = reinterpret_cast<const linux_dirent64*>(buf + pos);
                pos += d->d_reclen;
                const char* name = d->d_name;
                if (name[0] < '1' || name[0] > '9') continue;
                char* ep;
                long pid = strtol(name, &ep, 10);
                if (*ep == '\0' && pid > 0)
                    callback(static_cast<int>(pid));
            }
        }
    }
}

namespace ProcMonitor {

void scan_pids_into(std::unordered_set<int>& out) {
    out.clear();
    foreach_pid([&](int pid) { out.insert(pid); });
}

std::unordered_set<int> scan_pids() {
    std::unordered_set<int> result;
    result.reserve(1024);
    scan_pids_into(result);
    return result;
}

std::string read_cmdline(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return "";
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return "";
    buf[n] = '\0';
    size_t len = strnlen(buf, (size_t)n);
    if (len == 0) return "";
    if (buf[0] == '[' || buf[0] == '/') return "";
    if (memchr(buf, '/', len) != nullptr) return "";
    return std::string(buf, len);
}

bool read_cmdline_into(int pid, char* buf, size_t bufsize) {
    if (bufsize == 0) return false;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;

    ssize_t n = read(fd, buf, bufsize - 1);
    close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';

    size_t len = strnlen(buf, (size_t)n);
    if (len == 0) return false;
    if (buf[0] == '[' || buf[0] == '/') return false;
    if (memchr(buf, '/', len) != nullptr) return false;
    return true;
}

}