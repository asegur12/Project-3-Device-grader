"""Grade My Device.

Asks permission, then scans this computer's drives and hardware (read-only)
and prints:
  1. A colored storage bar split into five categories, a storage grade and
     advice on what to do next.
  2. A device report (name/model, size/weight/type, RAM/storage/price), a
     summary, a grade against college / office-job standards, and whether to
     upgrade.

Rules this program follows:
  * Read-only. It only reads sizes, names and hardware values. Nothing is
    moved, renamed, written or deleted.
  * Collected data lives only in memory, is used only for this report, and is
    wiped when the report is finished. No files are created.

Usage:
    python grade_my_device.py
"""

import gc
import hashlib
import os
import platform
import re
import shutil
import string
import subprocess
import sys
import time
import json

# ---------------------------------------------------------------- terminal --

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

# Category key -> (label, ANSI color)
CATEGORIES = {
    "media":     ("Images, screenshots & videos",       "\033[38;5;196m"),  # red
    "docs":      ("Documents & PDFs",                    "\033[38;5;208m"),  # orange
    "downloads": ("Downloads, apps, installers & music", "\033[38;5;226m"),  # yellow
    "system":    ("System, programs & other",            "\033[38;5;33m"),   # blue
    "junk":      ("Duplicate & junk files",              "\033[38;5;213m"),  # pink
}
ORDER = ["media", "docs", "downloads", "system", "junk"]
FREE_COLOR = "\033[38;5;240m"


def enable_terminal():
    """Turn on ANSI colors and UTF-8 output (needed on Windows consoles)."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    if os.name == "nt":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            handle = k32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if k32.GetConsoleMode(handle, ctypes.byref(mode)):
                k32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass


def fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def header(title):
    line = "=" * 64
    print(f"\n{BOLD}{line}\n  {title}\n{line}{RESET}")


def letter(score):
    for cutoff, grade in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= cutoff:
            return grade
    return "F"


# ------------------------------------------------------------- permission --

def ask_permission():
    header("GRADE MY DEVICE")
    print(
        "This program needs permission to:\n"
        "  - Read the sizes and names of files on your drives (to measure\n"
        "    storage use and find duplicate / junk files)\n"
        "  - Read your device's hardware details (model, CPU, RAM, storage,\n"
        "    screen, operating system)\n\n"
        "It is READ-ONLY: nothing is moved, changed or deleted, and the data\n"
        "collected is erased from memory as soon as your report is printed.\n"
    )
    try:
        answer = input("Do you give permission? (y/n): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer not in ("y", "yes"):
        print("\nPermission declined. Nothing was scanned. Closing the program.")
        sys.exit(0)


# --------------------------------------------------------- storage scanning --

MEDIA_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".heic",
    ".heif", ".raw", ".cr2", ".nef", ".arw", ".dng", ".svg", ".ico", ".psd",
    ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".flv", ".webm", ".m4v", ".mpg",
    ".mpeg", ".3gp", ".mts", ".m2ts",
}
DOC_EXT = {
    ".pdf", ".doc", ".docx", ".odt", ".rtf", ".txt", ".md", ".xls", ".xlsx",
    ".ods", ".csv", ".ppt", ".pptx", ".odp", ".pages", ".numbers", ".key",
    ".epub", ".tex", ".one", ".xps", ".json", ".xml",
}
DOWNLOAD_EXT = {
    # music / audio
    ".mp3", ".wav", ".flac", ".aac", ".m4a", ".ogg", ".wma", ".aiff", ".opus",
    # programs, installers, archives
    ".exe", ".msi", ".msix", ".appx", ".dmg", ".pkg", ".deb", ".rpm", ".apk",
    ".iso", ".img", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    # saved websites
    ".html", ".htm", ".mhtml", ".mht", ".webloc", ".url",
}
# Junk anywhere on the disk.
JUNK_EXT_ANYWHERE = {".tmp", ".temp", ".dmp", ".mdmp"}
# Junk only in user folders (programs/games use these names for real data).
JUNK_EXT_USER = {".bak", ".old", ".chk", ".crdownload", ".part"}

# Path fragments (lowercase, "/" separators) that mark junk locations.
JUNK_MARKERS = (
    "/$recycle.bin/", "/.trash/", "/.local/share/trash/", "/appdata/local/temp/",
    "/windows/temp/", "/windows/softwaredistribution/download/",
    "/inetcache/", "/crashdumps/", "/windows/minidump/", "/windows/logs/",
    "/library/logs/", "/library/caches/", "/tmp/", "/var/tmp/", "/.cache/",
)
# Cache folders only count as junk in user data / AppData (browser and app
# caches). Inside installed programs a "cache" folder can be real game data.
CACHE_MARKERS = ("/cache/", "/caches/", "/cache2/", "/code cache/", "/gpucache/")
# Path fragments that mark system / program areas.
SYSTEM_MARKERS = (
    "/windows/", "/program files/", "/program files (x86)/", "/programdata/",
    "/appdata/", "/system volume information/", "/recovery/", "/$windows.~bt/",
    "/$winreagent/", "/drivers/", "/swsetup/", "/oem/", "/intel/", "/amd/",
    "/system/", "/library/", "/applications/", "/usr/",
    "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/var/", "/etc/", "/boot/",
    "/snap/", "/private/",
)
# Linux pseudo filesystems that must never be walked.
SKIP_ROOTS = ("/proc", "/sys", "/dev", "/run")

# Windows file attribute bits
ATTR_REPARSE = 0x400
ATTR_CLOUD = 0x1000 | 0x40000 | 0x400000  # offline / recall-on-open / recall-on-access

DUP_MIN_SIZE = 100 * 1024          # ignore tiny files for duplicate checks
FULL_HASH_LIMIT = 256 * 1024 ** 2  # bigger files are compared by samples


def fixed_drives():
    """Return the root of every local fixed drive."""
    if os.name == "nt":
        import ctypes
        roots = []
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        for i, letter_ in enumerate(string.ascii_uppercase):
            if mask & (1 << i):
                root = f"{letter_}:\\"
                if ctypes.windll.kernel32.GetDriveTypeW(root) == 3:  # DRIVE_FIXED
                    roots.append(root)
        return roots or ["C:\\"]
    return ["/"]


def classify(path_lower, ext, user_area):
    """Pick a category for one file from its location and extension."""
    if ext in JUNK_EXT_ANYWHERE or any(m in path_lower for m in JUNK_MARKERS):
        return "junk"
    if (user_area or "/appdata/" in path_lower) and \
            any(m in path_lower for m in CACHE_MARKERS):
        return "junk"
    if user_area and (ext in JUNK_EXT_USER
                      or os.path.basename(path_lower).startswith("~$")):
        return "junk"
    if not user_area:
        return "system"
    if "/downloads/" in path_lower:
        return "downloads"
    if ext in MEDIA_EXT:
        return "media"
    if ext in DOC_EXT:
        return "docs"
    if ext in DOWNLOAD_EXT:
        return "downloads"
    return "system"


class StorageScan:
    def __init__(self):
        self.total = 0
        self.used = 0
        self.free = 0
        self.drives = []
        self.sizes = {k: 0 for k in ORDER}
        self.junk_only = 0
        self.dup_bytes = 0
        self.dup_groups = []       # (wasted_bytes, count, example_path)
        self.junk_places = {}      # folder label -> bytes
        self.files = 0
        self.skipped = 0
        self._by_size = {}         # size -> [(path, category)]

    # -- walking --
    def run(self):
        for root in fixed_drives():
            try:
                usage = shutil.disk_usage(root)
            except OSError:
                continue
            self.drives.append((root, usage.total, usage.used))
            self.total += usage.total
            self.used += usage.used
            self.free += usage.free

        start = time.time()
        last = 0.0
        for root, _, _ in self.drives:
            stack = [root]
            while stack:
                folder = stack.pop()
                try:
                    with os.scandir(folder) as it:
                        entries = list(it)
                except OSError:
                    self.skipped += 1
                    continue
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            continue
                        st = entry.stat(follow_symlinks=False)
                        attrs = getattr(st, "st_file_attributes", 0)
                        if entry.is_dir(follow_symlinks=False):
                            if attrs & ATTR_REPARSE:
                                continue
                            if os.name != "nt" and entry.path.startswith(SKIP_ROOTS):
                                continue
                            stack.append(entry.path)
                            continue
                        if not entry.is_file(follow_symlinks=False) or attrs & ATTR_CLOUD:
                            continue
                        self._add_file(entry.path, st.st_size)
                    except OSError:
                        self.skipped += 1
                now = time.time()
                if now - last > 0.2:
                    last = now
                    print(f"\r  Scanning {root} ... {self.files:,} files "
                          f"({int(now - start)}s)   ", end="", flush=True)
        print(f"\r  Scanned {self.files:,} files in {int(time.time() - start)}s."
              + " " * 30)
        self._find_duplicates()
        self._finish()

    def _add_file(self, path, size):
        self.files += 1
        p = path.replace("\\", "/").lower()
        ext = os.path.splitext(p)[1]
        user_area = not any(m in p for m in SYSTEM_MARKERS)
        cat = classify(p, ext, user_area)
        self.sizes[cat] += size
        if cat == "junk":
            self.junk_only += size
            self.junk_places[self._junk_label(p)] = \
                self.junk_places.get(self._junk_label(p), 0) + size
        elif user_area and size >= DUP_MIN_SIZE:
            self._by_size.setdefault(size, []).append((path, cat))

    @staticmethod
    def _junk_label(p):
        for label, marker in (
            ("Recycle Bin / Trash", "$recycle.bin"), ("Recycle Bin / Trash", "trash/"),
            ("Temporary files", "/temp/"), ("Temporary files", "/tmp/"),
            ("Windows Update leftovers", "softwaredistribution"),
            ("App & browser caches", "cache"), ("Crash dumps & logs", "dump"),
            ("Crash dumps & logs", "/logs/"),
        ):
            if marker in p:
                return label
        return "Leftover temp / backup files"

    # -- duplicates --
    @staticmethod
    def _sample_hash(path, size):
        h = hashlib.blake2b(digest_size=16)
        with open(path, "rb") as f:
            h.update(f.read(65536))
            if size > 131072:
                f.seek(size // 2)
                h.update(f.read(65536))
                f.seek(-65536, os.SEEK_END)
                h.update(f.read(65536))
        return h.digest()

    @staticmethod
    def _full_hash(path):
        h = hashlib.blake2b(digest_size=20)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.digest()

    def _find_duplicates(self):
        groups = [(s, items) for s, items in self._by_size.items() if len(items) > 1]
        if not groups:
            return
        print(f"  Checking {sum(len(i) for _, i in groups):,} possible duplicates ...",
              end="", flush=True)
        for size, items in groups:
            # Stage 1: quick sample hash. Stage 2: full hash (small enough files).
            sets = [items]
            stages = [lambda p: self._sample_hash(p, size)]
            if size <= FULL_HASH_LIMIT:
                stages.append(self._full_hash)
            for hasher in stages:
                next_sets = []
                for group in sets:
                    buckets = {}
                    for path, cat in group:
                        try:
                            buckets.setdefault(hasher(path), []).append((path, cat))
                        except OSError:
                            continue
                    next_sets += [b for b in buckets.values() if len(b) > 1]
                sets = next_sets
            for copies in sets:
                for _, cat in copies[1:]:          # first copy is the "keeper"
                    self.sizes[cat] -= size
                    self.sizes["junk"] += size
                    self.dup_bytes += size
                self.dup_groups.append((size * (len(copies) - 1), len(copies),
                                        copies[0][0]))
        self.dup_groups.sort(reverse=True)
        print(" done.")

    def _finish(self):
        """Make the five categories add up exactly to the used space."""
        user_cats = ["media", "docs", "downloads", "junk"]
        counted = sum(self.sizes[k] for k in user_cats)
        if counted > self.used and counted:
            scale = self.used / counted
            for k in user_cats:
                self.sizes[k] = int(self.sizes[k] * scale)
            counted = self.used
        # Blue = everything else using the disk (system files, programs,
        # page/hibernate files, restore points and files we could not read).
        self.sizes["system"] = self.used - counted
        self._by_size.clear()

    def wipe(self):
        self.__dict__.clear()


def draw_storage_bar(scan, width=60):
    total = scan.total or 1
    cells = {k: scan.sizes[k] / total * width for k in ORDER}
    # Round while keeping the bar exactly `width` wide, and give every
    # non-empty category at least one cell so its color is visible.
    counts = {k: max(1, round(v)) if scan.sizes[k] > 0 else 0 for k, v in cells.items()}
    used_cells = min(width, sum(counts.values()))
    while sum(counts.values()) > used_cells:
        biggest = max(counts, key=counts.get)
        counts[biggest] -= 1
    bar = "".join(f"{CATEGORIES[k][1]}{'█' * counts[k]}" for k in ORDER)
    bar += f"{FREE_COLOR}{'░' * (width - used_cells)}{RESET}"
    pct = scan.used / total * 100
    print(f"\n  [{bar}]")
    print(f"  {BOLD}{fmt_bytes(scan.used)} used of {fmt_bytes(scan.total)}"
          f"  ({pct:.1f}%){RESET}   {fmt_bytes(scan.free)} free\n")
    for k in ORDER:
        label, color = CATEGORIES[k]
        share = scan.sizes[k] / (scan.used or 1) * 100
        print(f"  {color}█{RESET} {label:<38}{fmt_bytes(scan.sizes[k]):>10}"
              f"  {share:5.1f}% of used")
    print(f"  {FREE_COLOR}░{RESET} {'Free space':<38}{fmt_bytes(scan.free):>10}")
    if len(scan.drives) > 1:
        print(f"\n  {DIM}Drives: " + ", ".join(
            f"{r} {fmt_bytes(u)}/{fmt_bytes(t)}" for r, t, u in scan.drives) + RESET)


def grade_storage(scan):
    """Score 0-100. Penalties for a full disk, little free space and clutter."""
    used_pct = scan.used / (scan.total or 1) * 100
    clutter_pct = scan.sizes["junk"] / (scan.used or 1) * 100
    free_gb = scan.free / 1024 ** 3
    score = 100
    reasons = []
    for limit, penalty in ((90, 40), (80, 25), (70, 12), (50, 5)):
        if used_pct > limit:
            score -= penalty
            reasons.append(f"drive is {used_pct:.0f}% full (-{penalty})")
            break
    for limit, penalty in ((15, 25), (10, 15), (5, 8), (2, 3)):
        if clutter_pct > limit:
            score -= penalty
            reasons.append(f"{clutter_pct:.1f}% of used space is duplicates/junk (-{penalty})")
            break
    if free_gb < 20:
        score -= 10
        reasons.append(f"only {free_gb:.0f} GB free, under the 20 GB safe minimum (-10)")
    return max(score, 0), reasons, used_pct, clutter_pct


def print_storage_report(scan):
    header("PART 1 - STORAGE USAGE")
    draw_storage_bar(scan)
    score, reasons, used_pct, clutter_pct = grade_storage(scan)
    g = letter(score)
    print(f"\n  {BOLD}Storage grade: {g}  ({score}/100){RESET}")
    print(f"  {DIM}Scale: A 90+ | B 80-89 | C 70-79 | D 60-69 | F <60. Points are lost "
          f"for a\n  drive over 50/70/80/90% full, for duplicates/junk above 2/5/10/15% "
          f"of used\n  space, and for less than 20 GB free.{RESET}")
    if reasons:
        print("  Points lost: " + "; ".join(reasons))

    print(f"\n  {BOLD}What to do next:{RESET}")
    tips = []
    if scan.junk_only > 500 * 1024 ** 2:
        places = sorted(scan.junk_places.items(), key=lambda x: -x[1])[:4]
        tips.append(f"Clear about {fmt_bytes(scan.junk_only)} of junk: " + ", ".join(
            f"{name} ({fmt_bytes(b)})" for name, b in places)
            + ". On Windows, 'Disk Cleanup' or Settings > System > Storage >"
              " Temporary files does this safely.")
    if scan.dup_bytes > 200 * 1024 ** 2:
        tips.append(f"{fmt_bytes(scan.dup_bytes)} is taken by duplicate copies "
                    f"({len(scan.dup_groups)} sets). Biggest ones:")
        for wasted, count, example in scan.dup_groups[:3]:
            tips.append(f"    {count} copies, {fmt_bytes(wasted)} extra - {example}")
    if scan.sizes["media"] > 0.25 * scan.used:
        tips.append("Photos and videos are a large share of your space - consider "
                    "moving older ones to cloud storage or an external drive.")
    if scan.sizes["downloads"] > 0.15 * scan.used:
        tips.append("Your Downloads/installers/music take a lot of room - delete "
                    "installers you have already run and old downloads.")
    if used_pct > 80:
        tips.append("Your drive is nearly full; computers slow down when they have "
                    "less than 10-15% free. Uninstall programs you don't use.")
    if g in ("A", "B") and not tips:
        tips.append("Good job! Your storage is healthy, with plenty of free space "
                    "and very little clutter. Keep it up.")
    elif g in ("A", "B"):
        tips.insert(0, "Good job overall - your storage is in good shape. A little "
                       "tidying would make it even better:")
    for t in tips:
        print(("  - " if not t.startswith("    ") else "  ") + t)


# --------------------------------------------------------- hardware info --

def powershell_json(command):
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"{command} | ConvertTo-Json -Compress -Depth 3"],
            capture_output=True, text=True, timeout=60,
        ).stdout.strip()
        data = json.loads(out) if out else None
    except Exception:
        return []
    if data is None:
        return []
    return data if isinstance(data, list) else [data]


def run_text(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
    except Exception:
        return ""


# Win32_SystemEnclosure chassis type codes -> name
CHASSIS = {
    3: "Desktop", 4: "Desktop", 5: "Desktop", 6: "Mini tower desktop",
    7: "Tower desktop", 8: "Portable", 9: "Laptop", 10: "Laptop (notebook)",
    11: "Handheld", 12: "Docking station", 13: "All-in-one desktop",
    14: "Sub-notebook", 15: "Space-saving desktop", 30: "Tablet",
    31: "2-in-1 convertible", 32: "2-in-1 detachable", 35: "Mini PC", 36: "Stick PC",
}


def collect_hardware():
    hw = {
        "maker": "", "model": "", "family": "", "type": "Unknown",
        "is_laptop": False, "screen_in": None, "resolution": None,
        "cpu": "Unknown CPU", "cores": 0, "threads": 0, "ram_gb": 0.0,
        "storage_gb": 0.0, "storage_type": "Unknown", "gpu": "",
        "battery": False, "os": platform.platform(),
    }
    if os.name == "nt":
        cs = (powershell_json("Get-CimInstance Win32_ComputerSystem | Select Manufacturer,"
                              "Model,SystemFamily,TotalPhysicalMemory") or [{}])[0]
        prod = (powershell_json("Get-CimInstance Win32_ComputerSystemProduct | "
                                "Select Version") or [{}])[0]
        hw["maker"] = (cs.get("Manufacturer") or "").strip().title()
        hw["family"] = (prod.get("Version") or cs.get("SystemFamily") or "").strip()
        hw["model"] = (cs.get("Model") or "").strip()
        hw["ram_gb"] = (cs.get("TotalPhysicalMemory") or 0) / 1024 ** 3

        cpu = (powershell_json("Get-CimInstance Win32_Processor | Select Name,"
                               "NumberOfCores,NumberOfLogicalProcessors") or [{}])[0]
        hw["cpu"] = re.sub(r"\s+", " ", cpu.get("Name") or "Unknown CPU").strip()
        hw["cores"] = cpu.get("NumberOfCores") or 0
        hw["threads"] = cpu.get("NumberOfLogicalProcessors") or 0

        enc = (powershell_json("Get-CimInstance Win32_SystemEnclosure | Select ChassisTypes")
               or [{}])[0]
        types = enc.get("ChassisTypes") or []
        types = types if isinstance(types, list) else [types]
        if types:
            hw["type"] = CHASSIS.get(types[0], f"Chassis type {types[0]}")
            hw["is_laptop"] = types[0] in (8, 9, 10, 14, 30, 31, 32)

        disks = powershell_json("Get-PhysicalDisk | Select MediaType,BusType,Size")
        disks = [d for d in disks if d.get("BusType") not in ("USB", 7)]
        hw["storage_gb"] = sum(d.get("Size") or 0 for d in disks) / 1000 ** 3
        kinds = {str(d.get("MediaType")) for d in disks}
        buses = {str(d.get("BusType")) for d in disks}
        if "NVMe" in buses or "17" in buses:
            hw["storage_type"] = "NVMe SSD"
        elif "SSD" in kinds or "4" in kinds:
            hw["storage_type"] = "SSD"
        elif "HDD" in kinds or "3" in kinds:
            hw["storage_type"] = "Hard drive (HDD)"

        mon = powershell_json("Get-CimInstance -Namespace root\\wmi "
                              "WmiMonitorBasicDisplayParams -ErrorAction SilentlyContinue"
                              " | Select MaxHorizontalImageSize,MaxVerticalImageSize")
        if mon and mon[0].get("MaxHorizontalImageSize"):
            w, h = mon[0]["MaxHorizontalImageSize"], mon[0]["MaxVerticalImageSize"]
            hw["screen_in"] = round((w ** 2 + h ** 2) ** 0.5 / 2.54, 1)
        gpu = powershell_json("Get-CimInstance Win32_VideoController | Select Name,"
                              "CurrentHorizontalResolution,CurrentVerticalResolution")
        if gpu:
            hw["gpu"] = ", ".join(g.get("Name") or "" for g in gpu)
            g0 = gpu[0]
            if g0.get("CurrentHorizontalResolution"):
                hw["resolution"] = (g0["CurrentHorizontalResolution"],
                                    g0["CurrentVerticalResolution"])
        hw["battery"] = bool(powershell_json("Get-CimInstance Win32_Battery | Select Name"))
        osinfo = (powershell_json("Get-CimInstance Win32_OperatingSystem | Select Caption,"
                                  "BuildNumber") or [{}])[0]
        if osinfo.get("Caption"):
            hw["os"] = f"{osinfo['Caption'].strip()} (build {osinfo.get('BuildNumber')})"

    elif sys.platform == "darwin":
        hw["maker"] = "Apple"
        hw["model"] = run_text(["sysctl", "-n", "hw.model"]).strip()
        hw["cpu"] = run_text(["sysctl", "-n", "machdep.cpu.brand_string"]).strip() or hw["cpu"]
        hw["cores"] = int(run_text(["sysctl", "-n", "hw.physicalcpu"]).strip() or 0)
        hw["threads"] = int(run_text(["sysctl", "-n", "hw.logicalcpu"]).strip() or 0)
        hw["ram_gb"] = int(run_text(["sysctl", "-n", "hw.memsize"]).strip() or 0) / 1024 ** 3
        hw["storage_gb"] = shutil.disk_usage("/").total / 1000 ** 3
        hw["storage_type"] = "SSD"
        hw["is_laptop"] = "book" in hw["model"].lower()
        hw["type"] = "Laptop" if hw["is_laptop"] else "Desktop"
        hw["battery"] = hw["is_laptop"]
        hw["os"] = "macOS " + platform.mac_ver()[0]

    else:  # Linux
        def read(p):
            try:
                with open(p) as f:
                    return f.read().strip()
            except OSError:
                return ""
        hw["maker"] = read("/sys/class/dmi/id/sys_vendor")
        hw["model"] = read("/sys/class/dmi/id/product_name")
        hw["family"] = read("/sys/class/dmi/id/product_version")
        ctype = read("/sys/class/dmi/id/chassis_type")
        if ctype.isdigit():
            hw["type"] = CHASSIS.get(int(ctype), "Unknown")
            hw["is_laptop"] = int(ctype) in (8, 9, 10, 14, 30, 31, 32)
        info = read("/proc/cpuinfo")
        m = re.search(r"model name\s*:\s*(.+)", info)
        hw["cpu"] = m.group(1) if m else hw["cpu"]
        hw["threads"] = os.cpu_count() or 0
        cores = {(a, b) for a, b in re.findall(
            r"physical id\s*:\s*(\d+).*?core id\s*:\s*(\d+)", info, re.S)}
        hw["cores"] = len(cores) or hw["threads"]
        m = re.search(r"MemTotal:\s*(\d+)", read("/proc/meminfo"))
        hw["ram_gb"] = int(m.group(1)) / 1024 ** 2 if m else 0
        hw["storage_gb"] = shutil.disk_usage("/").total / 1000 ** 3
        hw["battery"] = os.path.isdir("/sys/class/power_supply/BAT0")
    return hw


def cpu_tier(name):
    """0 = entry (Celeron/Pentium/Atom), 1 = i3/Ryzen 3, 2 = i5/Ryzen 5,
    3 = i7/Ryzen 7/Apple M, 4 = i9/Ryzen 9/high end."""
    n = name.lower()
    if re.search(r"celeron|pentium|atom|athlon|\bn\d{3}\b|\bn100\b|a\d-\d{4}", n):
        return 0
    if re.search(r"i9|ryzen 9|ultra 9|m\d (max|ultra)|threadripper|xeon", n):
        return 4
    if re.search(r"i7|ryzen 7|ultra 7|apple m|m\d pro", n):
        return 3
    if re.search(r"i5|ryzen 5|ultra 5|snapdragon x", n):
        return 2
    if re.search(r"i3|ryzen 3|core 3", n):
        return 1
    return 2


def cpu_generation_is_old(name):
    """True for Intel Core 7th gen and older or AMD Ryzen 1000/2000 series."""
    n = name.lower()
    m = re.search(r"(\d+)(st|nd|rd|th) gen", n)
    if m:
        return int(m.group(1)) <= 7
    m = re.search(r"i[3579]-(\d{4,5})", n)
    if m:
        num = m.group(1)
        gen = int(num[:2]) if len(num) == 5 else int(num[0])
        return gen <= 7
    m = re.search(r"ryzen \d (\d)\d{3}", n)
    if m:
        return int(m.group(1)) <= 2
    return False


def estimate_weight_kg(hw):
    if hw["is_laptop"]:
        s = hw["screen_in"] or 14
        if hw["type"] in ("Tablet", "2-in-1 detachable"):
            return 0.9
        for size, kg in ((13.5, 1.3), (14.5, 1.5), (16.2, 1.8)):
            if s <= size:
                return kg
        return 2.6
    if "All-in-one" in hw["type"]:
        return 8.0
    if hw["type"] in ("Mini PC", "Stick PC"):
        return 1.2
    return 7.5


def estimate_price(hw):
    """Rough new-retail value in USD built from the parts inside."""
    tier = cpu_tier(hw["cpu"])
    price = 200 if hw["is_laptop"] else 150
    price += (0, 90, 220, 400, 650)[tier]
    price += hw["cores"] * 12
    price += hw["ram_gb"] * 7
    price += hw["storage_gb"] * (0.09 if "SSD" in hw["storage_type"] else 0.03)
    if cpu_generation_is_old(hw["cpu"]):
        price *= 0.6
    return int(price * 0.8 / 10) * 10, int(price * 1.2 / 10) * 10


# Baselines used for the device grade.
OFFICE_MIN = {"ram": 8, "storage": 256, "cores": 4}
COLLEGE_REC = {"ram": 16, "storage": 512, "cores": 4}


def grade_hardware(hw):
    """100 points: RAM 25, CPU 25, storage size 20, storage type 10, OS 10,
    display 10. Compared against what a college student / office worker needs."""
    pts = {}
    ram = round(hw["ram_gb"])
    pts["RAM"] = (25 if ram >= 16 else 18 if ram >= 8 else 8 if ram >= 4 else 0, 25)

    c = hw["cores"]
    core_pts = 20 if c >= 8 else 17 if c >= 6 else 13 if c >= 4 else 6 if c >= 2 else 2
    tier_pts = (0, 2, 4, 5, 5)[cpu_tier(hw["cpu"])]
    cpu = core_pts + tier_pts - (6 if cpu_generation_is_old(hw["cpu"]) else 0)
    pts["Processor"] = (max(cpu, 0), 25)

    s = hw["storage_gb"]
    pts["Storage size"] = (20 if s >= 480 else 14 if s >= 240 else 7 if s >= 120 else 2, 20)
    st = hw["storage_type"]
    pts["Storage type"] = (10 if "NVMe" in st else 9 if "SSD" in st else 3 if "HDD" in st
                           else 6, 10)

    os_name = hw["os"].lower()
    if "windows 11" in os_name or "macos" in os_name or "linux" in os_name:
        pts["Operating system"] = (10, 10)
    elif "windows 10" in os_name:
        pts["Operating system"] = (5, 10)     # support ended Oct 2025
    else:
        pts["Operating system"] = (8, 10)

    res = hw["resolution"]
    if res is None:
        pts["Display"] = (7, 10)
    else:
        pts["Display"] = (10 if res[1] >= 1080 else 6 if res[1] >= 768 else 3, 10)

    score = sum(p for p, _ in pts.values())
    meets_office = (ram >= OFFICE_MIN["ram"] and s >= OFFICE_MIN["storage"] * 0.93
                    and c >= OFFICE_MIN["cores"] and "HDD" not in st)
    meets_college = (ram >= COLLEGE_REC["ram"] and s >= COLLEGE_REC["storage"] * 0.93
                     and c >= COLLEGE_REC["cores"] and cpu_tier(hw["cpu"]) >= 1
                     and not cpu_generation_is_old(hw["cpu"]))
    return score, pts, meets_office, meets_college


def print_device_report(hw):
    header("PART 2 - DEVICE REPORT")
    family = hw["family"]
    if hw["maker"] and family.lower().startswith(hw["maker"].lower()):
        family = family[len(hw["maker"]):].strip()   # avoid "Lenovo Lenovo ..."
    name = " ".join(x for x in (hw["maker"], family) if x) or "Unknown device"
    print(f"\n  {BOLD}Device:{RESET} {name}")
    print(f"  {BOLD}Model: {RESET} {hw['model'] or 'Unknown'}")

    print(f"\n  {BOLD}Basic components{RESET}")
    print(f"    Type ............ {hw['type']}")
    screen = f"{hw['screen_in']}\" screen" if hw["screen_in"] else "screen size unknown"
    if hw["resolution"]:
        screen += f", {hw['resolution'][0]}x{hw['resolution'][1]}"
    print(f"    Size ............ {screen}")
    kg = estimate_weight_kg(hw)
    print(f"    Weight .......... about {kg:.1f} kg / {kg * 2.2046:.1f} lb "
          f"{DIM}(estimated for this type and size){RESET}")
    print(f"    Battery ......... {'Yes' if hw['battery'] else 'No'}")
    print(f"    Operating system  {hw['os']}")

    print(f"\n  {BOLD}Hardware{RESET}")
    print(f"    Processor ....... {hw['cpu']} ({hw['cores']} cores / "
          f"{hw['threads']} threads)")
    print(f"    RAM ............. {hw['ram_gb']:.1f} GB usable")
    print(f"    Storage ......... {hw['storage_gb']:.0f} GB {hw['storage_type']}")
    if hw["gpu"]:
        print(f"    Graphics ........ {hw['gpu']}")
    lo, hi = estimate_price(hw)
    print(f"    Price ........... about ${lo:,} - ${hi:,} "
          f"{DIM}(estimated new value from its parts){RESET}")

    score, pts, office, college = grade_hardware(hw)
    g = letter(score)
    tier_name = ("entry-level", "budget", "mid-range", "upper mid-range", "high-end")[
        cpu_tier(hw["cpu"])]

    print(f"\n  {BOLD}Summary{RESET}")
    print(f"    Your {name} is a {hw['type'].lower()} with a {tier_name} "
          f"processor, {round(hw['ram_gb'])} GB of RAM and a "
          f"{hw['storage_gb']:.0f} GB {hw['storage_type']}.")
    print(f"    Office-job standard (8 GB RAM, 256 GB SSD, 4+ cores): "
          f"{'MEETS' if office else 'DOES NOT MEET'}")
    print(f"    College standard (16 GB RAM, 512 GB SSD, 4+ core modern CPU): "
          f"{'MEETS' if college else 'DOES NOT MEET'}")

    print(f"\n  {BOLD}Device grade: {g}  ({score}/100){RESET}")
    print("    " + " | ".join(f"{k} {p}/{m}" for k, (p, m) in pts.items()))
    print(f"    {DIM}Scale: A 90+ | B 80-89 | C 70-79 | D 60-69 | F <60{RESET}")

    print(f"\n  {BOLD}Should you upgrade?{RESET}")
    advice = []
    ram = round(hw["ram_gb"])
    if ram < 8:
        advice.append("RAM is below the 8 GB minimum - add memory if your model "
                      "allows it, otherwise this device should be replaced.")
    elif ram < 16:
        advice.append("16 GB of RAM is recommended for college work with many "
                      "browser tabs and apps open - upgrade if your RAM is not soldered.")
    if "HDD" in hw["storage_type"]:
        advice.append("Swap the hard drive for an SSD - it is the single biggest "
                      "speed boost for an older computer.")
    if hw["storage_gb"] < 240:
        advice.append("Storage is small; a 512 GB SSD or external drive is recommended.")
    elif hw["storage_gb"] < 476:
        advice.append("256 GB fills quickly - consider a 512 GB+ SSD or cloud storage.")
    if cpu_generation_is_old(hw["cpu"]) or cpu_tier(hw["cpu"]) == 0 or hw["cores"] < 4:
        advice.append("The processor is below modern standards and can't be upgraded "
                      "easily - plan to replace the device.")
    if "windows 10" in hw["os"].lower():
        advice.append("Windows 10 no longer receives security updates - upgrade to "
                      "Windows 11 if your hardware supports it.")

    if g in ("A", "B") and not advice:
        print("    No upgrade needed. This device comfortably handles college and "
              "office work.")
    elif g in ("A", "B", "C"):
        print("    No full replacement needed - this device handles college and office "
              "work. Optional improvements:")
    else:
        print("    An upgrade or replacement is recommended:")
    for a in advice:
        print(f"    - {a}")


# --------------------------------------------------------------------- main --

def main():
    enable_terminal()
    ask_permission()

    print("\nCollecting hardware details ...")
    hw = collect_hardware()
    print("Scanning storage (read-only). This can take a few minutes on a full drive.")
    scan = StorageScan()
    scan.run()

    print_storage_report(scan)
    print_device_report(hw)

    # Rule 1: dispose of the collected data once the report is printed.
    scan.wipe()
    hw.clear()
    del scan, hw
    gc.collect()
    header("DATA DISPOSAL")
    print("  All data collected for this report (file sizes, file names and\n"
          "  hardware details) has now been deleted from memory. Nothing was\n"
          "  saved to disk, sent anywhere, moved, or deleted on your device.\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RESET}Cancelled. Nothing was changed and no data was kept.")
        sys.exit(1)
