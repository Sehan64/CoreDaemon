# CoreDaemon

**CoreDaemon** is a high-performance C++ native daemon designed for one thing: knowing exactly what’s happening on your device without the overhead.

By tapping directly into the Linux kernel’s cgroup interfaces, CoreDaemon detects when applications open, close, or move to the foreground. It operates entirely independently of the Android framework, meaning no Java bloat and most importantly zero polling.

It also includes a full Vixie‑compatible cron scheduler, so you can automate
tasks (like running maintenance scripts) in
response to time schedules or app events.

- **Event‑driven** – `EPOLLPRI` on `cgroup.events`, inotify on cpuctl/cpuset,
  and `signalfd` for signals.  No loops, no timers (except the optional
  `/proc` fallback).
- **Single‑threaded** – a single `epoll` loop handles all monitoring, cron
  scheduling, and client connections.
- **Zero‑overhead** – idle CPU 0.0%, steady‑state RSS <2 MB, no heap
  allocations in hot paths.
- **Root and non‑root** – auto‑detects privileges, uses cgroup v1 and v2 when
  available, with a lightweight `/proc` fallback for older devices.
- **Full cron engine** – classic 5‑field syntax, macros (`@reboot`,
  `@daily`, etc.), and app‑event triggers (`@app_open`, `@app_close`,
  `@app_fg`, `@app_fg_exit`).
- **Unix socket API** – event stream clients (`cored_client`) and a
  control socket for dynamic job management.
- **GPL‑3.0 licensed** – free software. All source is public, all
  modifications must be shared.
