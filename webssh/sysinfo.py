import os
import shutil
import time
from pathlib import Path
from typing import Any


_previous_cpu: tuple[float, int, int] | None = None


def _read_cpu_times() -> tuple[int, int]:
    with open("/proc/stat", encoding="ascii") as stat_file:
        fields = stat_file.readline().split()
    # user nice system idle iowait irq softirq steal; guest time is already counted in user.
    values = [int(value) for value in fields[1:9]]
    return values[3] + values[4], sum(values)


def cpu_percent() -> float | None:
    global _previous_cpu
    try:
        idle, total = _read_cpu_times()
        now = time.monotonic()
        previous = _previous_cpu
        if previous is None or now - previous[0] > 60:
            time.sleep(0.25)
            previous_idle, previous_total = idle, total
            idle, total = _read_cpu_times()
            now = time.monotonic()
        else:
            _, previous_idle, previous_total = previous
    except (OSError, ValueError, IndexError):
        return None
    _previous_cpu = (now, idle, total)
    elapsed = total - previous_total
    if elapsed <= 0:
        return 0.0
    return round(100 * (1 - (idle - previous_idle) / elapsed), 1)


def memory() -> dict[str, Any] | None:
    values: dict[str, int] = {}
    try:
        with open("/proc/meminfo", encoding="ascii") as meminfo:
            for line in meminfo:
                key, _, rest = line.partition(":")
                if key in {"MemTotal", "MemAvailable"}:
                    values[key] = int(rest.split()[0]) * 1024
        total = values["MemTotal"]
        available = values["MemAvailable"]
    except (OSError, ValueError, IndexError, KeyError):
        return None
    used = total - available
    return {"total": total, "used": used, "percent": round(100 * used / total, 1) if total else 0.0}


def disk(path: str) -> dict[str, Any] | None:
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return None
    # Matches df: root-reserved blocks are excluded from the percentage base.
    capacity = usage.used + usage.free
    return {
        "path": path,
        "total": usage.total,
        "used": usage.used,
        "percent": round(100 * usage.used / capacity, 1) if capacity else 0.0,
    }


def temperature() -> float | None:
    readings: list[tuple[str, float]] = []
    for zone in sorted(Path("/sys/class/thermal").glob("thermal_zone*")):
        try:
            kind = (zone / "type").read_text(encoding="ascii").strip().lower()
            value = int((zone / "temp").read_text(encoding="ascii").strip()) / 1000
        except (OSError, ValueError):
            continue
        if -40 < value < 150:
            readings.append((kind, value))
    if not readings:
        return None
    for kind, value in readings:
        if any(tag in kind for tag in ("cpu", "soc", "x86_pkg")):
            return round(value, 1)
    return round(max(value for _, value in readings), 1)


def load_average() -> float | None:
    try:
        return round(os.getloadavg()[0], 2)
    except (AttributeError, OSError):
        return None


def collect(home: str) -> dict[str, Any]:
    return {
        "cpu": cpu_percent(),
        "memory": memory(),
        "disk": disk(home),
        "temperature": temperature(),
        "load": load_average(),
    }
