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
#include <unordered_set>
#include <string>

namespace ProcMonitor {
    constexpr int MAX_PENDING_RETRIES = 10;
    std::unordered_set<int> scan_pids();
    void scan_pids_into(std::unordered_set<int>& out);
    std::string read_cmdline(int pid);
    bool read_cmdline_into(int pid, char* buf, size_t bufsize);
}