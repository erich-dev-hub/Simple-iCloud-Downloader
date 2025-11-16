#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Simple iCloud Downloader (sid.py)

Commands:
  1) Scan files (incremental):                     --scan
  2) Download missing (scan + incremental):        --download
     Optional filter:                              --filter "2023-01;2023-02"
  3) View stats (reads cache only):                --view
  4) Logout (deletes local session):               --logout

Notes:
- Automatic organization by year/month based on API 'created' date.
- Cache stored in '_cache' folder INSIDE the download_base.
- BATCH SAVING enabled.
- COOKIE ISOLATION enabled.
- Now tracking persistent lifetime stats (scan/download time) in index.json.
"""

import os
import sys
import json
import time
import signal
import hashlib
import argparse
import threading
import configparser
import re
import glob
from collections import deque
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Set

# Added exception imports for clean error handling
from pyicloud import PyiCloudService
from pyicloud.exceptions import PyiCloudFailedLoginException, PyiCloudAPIResponseException

API_FLAVOR = "pyicloud"

# --- Version Info ---
__author__ = "Erich Dev Hub"
__title__ = "Simple iCloud Downloader (SiD)"
__version__ = "0.1.2" 
__repo__ = "https://github.com/erich-dev-hub/Simple-iCloud-Downloader"
# --- End Version Info ---

# ===================== COLORS =====================
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_CYAN = "\033[96m"
C_RESET = "\033[0m"
C_DIM = "\033[2m"

def enable_ansi_windows():
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                new_mode = mode.value | 0x0004
                kernel32.SetConsoleMode(handle, new_mode)
        except Exception:
            pass

# ===================== EXTERNAL CONFIGURATION =====================
def load_config(config_file):
    cfg = configparser.ConfigParser()
    cfg.read(config_file, encoding="utf-8")
    try:
        icloud_user = cfg["icloud"]["user"].strip()
        download_base = cfg["icloud"]["download_base"].strip()
    except Exception:
        print(f"{C_RED}❌ Error: invalid or missing config.ini.{C_RESET}")
        print("   Ensure a config.ini file exists with:")
        print("   [icloud]")
        print("   user = your_apple_email@icloud.com")
        print("   download_base = C:\\Backup_iCloud_Photos")
        sys.exit(1)
    return icloud_user, download_base

# ===================== UTILITIES =====================
def ensure_dirs():
    os.makedirs(DOWNLOAD_BASE, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def from_iso(s: Optional[str]) -> Optional[datetime]:
    if not s: return None
    try: return datetime.fromisoformat(s)
    except: return None

def format_bytes(n: Optional[int]) -> str:
    if n is None: return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(n)
    u = 0
    while size >= 1024 and u < len(units)-1:
        size /= 1024.0
        u += 1
    if units[u] in ("MB", "GB", "TB"):
        return f"{size:.1f} {units[u]}"
    return f"{int(size)} {units[u]}"

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def safe_filename(name: str) -> str:
    return "".join(c for c in name if c not in '<>:"/\\|?*').strip()

def photo_created_dt(photo) -> datetime:
    created = getattr(photo, "created", None)
    if created is None: return datetime.now(timezone.utc)
    if created.tzinfo is None: return created.replace(tzinfo=timezone.utc)
    return created.astimezone(timezone.utc)

def get_photo_id(photo) -> str:
    return getattr(photo, "id", None) or getattr(photo, "uuid", None) or getattr(photo, "guid", None) or ""

def validate_filter(filter_str: str) -> Set[str]:
    if not filter_str: return set()
    months = set()
    parts = filter_str.split(';')
    pattern = re.compile(r"^\d{4}-\d{2}$")
    for p in parts:
        p = p.strip()
        if not p: continue
        if not pattern.match(p):
            print(f"{C_RED}❌ Error: Invalid format '{p}'. Use YYYY-MM.{C_RESET}")
            sys.exit(1)
        months.add(p)
    return months

# ---------- ETA/Speed ----------
class RollingSpeed:
    def __init__(self, window_sec: float = 30.0):
        self.window_sec = window_sec
        self.samples = deque()
        self.total = 0

    def add(self, inc: int):
        t = time.time()
        self.total += inc
        self.samples.append((t, self.total))
        cutoff = t - self.window_sec
        while len(self.samples) > 1 and self.samples[0][0] < cutoff:
            self.samples.popleft()

    def speed_bps(self) -> float: # Bps = Bytes per second OR Items per second
        if len(self.samples) < 2: return 0.0
        t0, b0 = self.samples[0]
        t1, b1 = self.samples[-1]
        dt = max(t1 - t0, 1e-6)
        return max((b1 - b0)/dt, 0.0)

# ===================== CACHE (INDEX) =====================
def load_index() -> Dict[str, Any]:
    if not os.path.exists(INDEX_PATH):
        idx = {
            "last_index_time": None,
            "last_download_time": None,
            "last_stream_total": None,
            "items": {}
        }
    else:
        with open(INDEX_PATH, "r", encoding="utf-8") as f:
            idx = json.load(f)

    idx.setdefault("stats_total_items_scanned", 0)
    idx.setdefault("stats_total_scan_time_minutes", 0.0)
    idx.setdefault("stats_total_megabytes_downloaded", 0.0)
    idx.setdefault("stats_total_download_time_minutes", 0.0)
    
    return idx

def save_index(idx: Dict[str, Any]):
    tmp = INDEX_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(idx, f, ensure_ascii=False, indent=2)
    os.replace(tmp, INDEX_PATH)

# ===================== LOGOUT =====================
def perform_logout():
    print(f"Terminating session for {C_GREEN}{ICLOUD_USER}{C_RESET}...")
    count = 0
    try:
        files = glob.glob(os.path.join(CACHE_DIR, "*"))
        for f in files:
            fname = os.path.basename(f)
            if fname == "index.json": continue
            if os.path.isfile(f) or os.path.islink(f):
                os.remove(f)
                count += 1
        print(f"✅ Session terminated. Deleted {count} session/cookie files.")
        print(f"{C_YELLOW}Note: This removed local access only.{C_RESET}")
    except Exception as e:
        print(f"{C_RED}❌ Error during logout: {e}{C_RESET}")

# ===================== LOGIN =====================
def login_icloud() -> PyiCloudService:
    sys.stdout.write(f"Connecting to iCloud as {ICLOUD_USER} (via {API_FLAVOR})... ")
    sys.stdout.flush()
    try:
        api = PyiCloudService(ICLOUD_USER, cookie_directory=os.path.abspath(CACHE_DIR))
        if getattr(api, "requires_2sa", False):
            sys.stdout.write(f"\n{C_YELLOW}⚠️  Two-factor authentication required!{C_RESET}\n")
            code = input("Enter the code sent to your Apple device: ").strip()
            ok = api.validate_2fa_code(code) if hasattr(api, "validate_2fa_code") else api.validate_2fa(code)
            if not ok:
                print(f"{C_RED}❌ Invalid code!{C_RESET}")
                sys.exit(1)
            print(f"{C_GREEN}✅ 2FA validated successfully.{C_RESET}")
        else:
            sys.stdout.write(f"{C_GREEN}(OK){C_RESET}\n")
            sys.stdout.flush()
        return api
    except PyiCloudAPIResponseException as e:
        sys.stdout.write("\n")
        if "503" in str(e) or "500" in str(e):
            print(f"{C_YELLOW}⚠️  Apple Server Error ({e}){C_RESET}")
            print(f"{C_YELLOW}   Please wait 15-30 minutes and try again.{C_RESET}")
        else:
            print(f"{C_RED}❌ Apple API Error: {e}{C_RESET}")
        sys.exit(1)
    except PyiCloudFailedLoginException as e:
        sys.stdout.write("\n")
        print(f"{C_RED}❌ Login Failed: {e}{C_RESET}")
        print(f"{C_YELLOW}   Please check your email/password and ensure 'Access iCloud Data on the Web'")
        print(f"   is ENABLED in your iCloud settings (see README for details).{C_RESET}")
        sys.exit(1)
    except Exception as e:
        sys.stdout.write("\n")
        print(f"{C_RED}❌ Unexpected Connection Error: {e}{C_RESET}")
        sys.exit(1)

# ===================== STREAMS =====================
def stream_all(api: PyiCloudService):
    return api.photos.all

def stream_since(api: PyiCloudService, since_dt: datetime):
    photos_svc = api.photos
    if hasattr(photos_svc, "since"):
        return photos_svc.since(since_dt)
    return photos_svc.all

# ===================== PANEL =====================
class Panel:
    def __init__(self, user: str, mode_str: str, 
                 to_get_count: int, total_known: int, synced_count: int, total_bytes: int,
                 filter_msg: str = "", only_scan: bool = False):
        self.user = user
        self.mode_str = mode_str
        self.filter_msg = filter_msg
        self.only_scan = only_scan
        
        self.to_get_count = to_get_count
        self.total_known = total_known
        self.synced_count = synced_count
        
        self.scan_done = 0
        self.scan_target = 0
        self.total_download_bytes = max(total_bytes, 0)
        self.bytes_done = 0
        self.start_ts = time.time()
        
        self.speed_dl_instant = RollingSpeed(10.0) 
        self.last_dl_sizes_mb = deque(maxlen=10)
        self.last_dl_times_sec = deque(maxlen=10)
        self.avg_dl_mb_per_sec = 0.0 
        
        self.total_dl_time_this_session = 0.0
        
        self.fixed_mode = True 
        self.first_printed = False
        self.last_error = "" 
        
        # --- FIX: ANSI code to clear from cursor to end of line ---
        self.CLEAR_LINE = "\x1b[K"
        # --- END FIX ---

        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._last_render = 0.0

    def start_heartbeat(self): self._thread.start()
    def stop_heartbeat(self): self._stop.set()
    def _heartbeat_loop(self):
        while not self._stop.is_set():
            self.render()
            time.sleep(1.0) 

    def log_download(self, size_bytes: int, time_sec: float):
        if size_bytes > 0 and time_sec > 0:
            self.bytes_done += size_bytes
            self.speed_dl_instant.add(size_bytes)
            self.total_dl_time_this_session += time_sec
            
            self.last_dl_sizes_mb.append(size_bytes / (1024*1024.0))
            self.last_dl_times_sec.append(time_sec)
            
            total_mb = sum(self.last_dl_sizes_mb)
            total_sec = sum(self.last_dl_times_sec)
            if total_sec > 0:
                self.avg_dl_mb_per_sec = total_mb / total_sec

    def inc_scan(self, inc: int = 1):
        if inc > 0:
            self.scan_done += inc

    def set_scan_target(self, n: int): self.scan_target = max(n, 0)
    def set_total_download_bytes(self, n: int): self.total_download_bytes = max(n, 0)
    def set_total_known(self, n: int): self.total_known = n
    def set_last_error(self, err_msg: str):
        self.last_error = err_msg

    def _bar(self, pct: float, width: int = 25, color: str = "") -> str:
        pct = max(0.0, min(100.0, pct))
        filled = int(round((pct/100.0) * width))
        bar_str = "█"*filled + " "*(width-filled)
        if color:
            return f"{color}{bar_str}{C_RESET}"
        return bar_str

    def _fmt_time(self, secs: float) -> str:
        secs = int(max(0, secs))
        return time.strftime("%H:%M:%S", time.gmtime(secs))
    
    def _fmt_time_eta(self, secs: float) -> str:
        secs = int(max(0, secs))
        
        m, s = divmod(secs, 60)
        h, m = divmod(m, 60)
        
        if secs < 300: # Less than 5 minutes
            return f"{m}m:{s:02d}s left"
        elif secs < 3600: # Less than 1 hour
            return f"{m}m left"
        else: # Hours
            return f"{h}h:{m:02d}m left"

    def render(self):
        now = time.time()
        if now - self._last_render < 0.95 and self.first_printed: return
        self._last_render = now

        scan_pct = (100.0 * self.scan_done / self.scan_target) if self.scan_target else 0.0
        dl_pct   = (100.0 * self.bytes_done / self.total_download_bytes) if self.total_download_bytes else 0.0
        elapsed  = now - self.start_ts
        
        dl_speed_bps = self.speed_dl_instant.speed_bps()
        
        session_scan_time_sec = elapsed - self.total_dl_time_this_session
        scan_speed_ips = 0.0
        if session_scan_time_sec > 1:
            scan_speed_ips = self.scan_done / session_scan_time_sec
        
        eta_scan_sec = 0.0
        eta_dl_sec = 0.0
        eta_str = "ETA: ...?" 

        if self.scan_done > self.scan_target:
             eta_str = "ETA: ...?"
        
        elif self.only_scan:
            if scan_speed_ips > 0:
                items_remaining = max(self.scan_target - self.scan_done, 0)
                eta_scan_sec = items_remaining / scan_speed_ips
            
            if eta_scan_sec > 0:
                eta_str = f"ETA ≈ {self._fmt_time_eta(eta_scan_sec)}"
            else:
                eta_str = "ETA: ...?" 
        
        elif not self.only_scan:
            if self.avg_dl_mb_per_sec > 0:
                if scan_speed_ips > 0:
                    items_remaining = max(self.scan_target - self.scan_done, 0)
                    eta_scan_sec = items_remaining / scan_speed_ips
                
                bytes_remaining = max(self.total_download_bytes - self.bytes_done, 0)
                mb_remaining = bytes_remaining / (1024*1024.0)
                eta_dl_sec = mb_remaining / self.avg_dl_mb_per_sec
                
                total_eta_sec = eta_scan_sec + eta_dl_sec
                
                if total_eta_sec > 0:
                    eta_str = f"ETA ≈ {self._fmt_time_eta(total_eta_sec)}"
                else:
                    eta_str = "ETA: ...?"
            else:
                eta_str = "ETA: ...?"
        
        speed_display_str = ""
        if dl_speed_bps > 0 and not self.only_scan:
            speed_display_str = f"| {format_bytes(int(dl_speed_bps))}/s"

        # --- APPLY CLEAR_LINE TO ALL LINES ---
        header_user = f"{C_GREEN}iCloud User: {self.user}{C_RESET}{self.CLEAR_LINE}"
        header_mode = f"Mode: {C_CYAN}{self.mode_str}{C_RESET}{self.CLEAR_LINE}"
        
        extra_filter = ""
        if self.filter_msg:
            extra_filter = f"\n{self.filter_msg}\n{C_DIM}(*) Filtering applies to downloads only. Full scan is performed.{C_RESET}{self.CLEAR_LINE}"

        header1 = ("=" * 80) + self.CLEAR_LINE
        
        if self.only_scan:
            header2 = f"📂 Total Known Items: {self.total_known:,}{self.CLEAR_LINE}"
        else:
            header2 = (f"📂 Total: {self.total_known:,} | "
                       f"Synced: {self.synced_count:,} | "
                       f"DL'ing: {self.to_get_count:,} {speed_display_str}{self.CLEAR_LINE}")
            
        header3 = ("-" * 80) + self.CLEAR_LINE
        
        line_scan = (f"[🔎] Scan      : {scan_pct:6.2f}% | {self._bar(scan_pct, width=25)} | "
                     f"{self.scan_done:,} / {self.scan_target:,} items{self.CLEAR_LINE}")
        
        line_dl   = (f"[⬇️] Download  : {dl_pct:6.2f}% | {self._bar(dl_pct, width=25, color=C_CYAN)} | "
                     f"{format_bytes(self.bytes_done)} / {format_bytes(self.total_download_bytes)}{self.CLEAR_LINE}")
        
        line_tm   = (f"[⏱️] Time      :  {self._fmt_time(elapsed)} elapsed  | {eta_str}{self.CLEAR_LINE}")
        
        if self.only_scan:
            footer = f"\n{C_YELLOW}Stop by pressing CTRL + C.{C_RESET}{self.CLEAR_LINE}"
            if eta_scan_sec <= 0: eta_scan_str = "ETA: ...?"
            else: eta_scan_str = f"ETA ≈ {self._fmt_time_eta(eta_scan_sec)}"
            
            line_tm_scan = f"[⏱️] Time      :  {self._fmt_time(elapsed)} elapsed  | {eta_scan_str}{self.CLEAR_LINE}"
            block = "\n".join([header_user, header_mode, extra_filter, header1, header2, header3, line_scan, line_tm_scan, header1])
        else:
            footer = (f"\n{C_YELLOW}Stop by pressing CTRL + C. "
                      f"For resuming, just run the command again.{C_RESET}{self.CLEAR_LINE}")
            block = "\n".join([header_user, header_mode, extra_filter, header1, header2, header3, line_scan, line_dl, line_tm, header1])
        
        if self.last_error:
            err_short = self.last_error.replace('\n', ' ')
            if len(err_short) > 78: err_short = err_short[:75] + "..."
            block += f"\n{C_RED}{err_short}{C_RESET}{self.CLEAR_LINE}"
        
        block += footer
        block = block.replace("\n\n", "\n")

        if self.fixed_mode:
            if self.first_printed:
                num_lines = block.count('\n') + 1
                sys.stdout.write(f"\x1b[{num_lines}F")
            else:
                self.first_printed = True
            sys.stdout.write(block + "\n")
            sys.stdout.flush()
        else:
            print(block)

# ===================== SCAN FILES (Formerly update_index) =====================
def scan_files(api: PyiCloudService, index: Dict[str, Any]) -> Dict[str, Any]:
    items = index.get("items", {})
    last_iso = index.get("last_index_time")
    since_dt = from_iso(last_iso)
    
    total_known_local = len(items)
    last_stream_val = index.get("last_stream_total") or 0
    total_known_display = max(last_stream_val, total_known_local, 1)

    panel = Panel(user=ICLOUD_USER,
                  mode_str="SCAN FILES",
                  filter_msg="",
                  to_get_count=0,
                  total_known=total_known_display, 
                  synced_count=0,
                  total_bytes=0,
                  only_scan=True)
    
    panel.set_scan_target(total_known_display) 
    
    try:
        stream = stream_since(api, since_dt) if since_dt else stream_all(api)
    except Exception as e:
        print(f"{C_RED}❌ Error starting stream: {e}{C_RESET}")
        return index

    print()
    panel.start_heartbeat()

    unsaved_changes_count = 0
    last_save_ts = time.time()
    
    session_scan_start_time = time.time()
    count_seen = 0

    def request_save_index(force=False):
        nonlocal unsaved_changes_count, last_save_ts
        if unsaved_changes_count == 0 and not force: return
        now = time.time()
        if force or (unsaved_changes_count >= 20) or (now - last_save_ts > 30):
            save_index(index)
            unsaved_changes_count = 0
            last_save_ts = now

    interrupted = {"flag": False}
    def _sigint(sig, frame):
        interrupted["flag"] = True
    signal.signal(signal.SIGINT, _sigint)

    current_total_in_json = total_known_local
    
    try:
        for photo in stream:
            count_seen += 1
            panel.inc_scan(1)
            
            if interrupted["flag"]: break

            if count_seen > total_known_display:
                total_known_display = count_seen
                panel.set_scan_target(total_known_display)

            pid = get_photo_id(photo)
            if not pid:
                created = photo_created_dt(photo)
                pid = f"{getattr(photo, 'filename', 'unknown')}|{int(created.timestamp())}"

            rec = items.get(pid)
            
            if rec is None:
                created = photo_created_dt(photo)
                filename = getattr(photo, "filename", f"{int(created.timestamp())}.bin")
                size = getattr(photo, "size", None)
                items[pid] = {
                    "id": pid, "filename": filename, "created": created.isoformat(),
                    "size": size, "downloaded": False, "local_path": None, "downloaded_at": None, "sha256": None
                }
                unsaved_changes_count += 1
                current_total_in_json += 1
                panel.set_total_known(current_total_in_json) 
            else:
                changed = False
                fn = getattr(photo, "filename", rec.get("filename"))
                if rec.get("filename") != fn:
                    rec["filename"] = fn
                    changed = True
                sz = getattr(photo, "size", None)
                if (sz is not None) and (rec.get("size") != sz):
                    rec["size"] = sz
                    changed = True
                if changed:
                    unsaved_changes_count += 1
            
            request_save_index(force=False)

    except Exception as e:
        panel.set_last_error(f"Stream error: {e}")

    finally:
        session_total_scan_time_sec = time.time() - session_scan_start_time
        
        if not interrupted["flag"]:
            index["last_stream_total"] = count_seen
        
        index["last_index_time"] = now_utc_iso()
        
        index["stats_total_items_scanned"] += count_seen
        index["stats_total_scan_time_minutes"] += (session_total_scan_time_sec / 60.0)
        
        request_save_index(force=True)
        
        panel.stop_heartbeat()
        panel.render()
        print()
        print("-" * 80)
        print(f"✅ Scan Files Completed. Total Items: {len(items)}")

    return index

# ===================== VIEW STATS (Fixed 80 Cols & Header) =====================
def fmt_lim(n, limit=99999):
    if n > limit: return f"{limit:,}+"
    return f"{n:,}"

def fmt_ts(iso_str):
    if not iso_str: return "N/A"
    try: return iso_str.replace("T", " ").split(".")[0]
    except: return iso_str

def view_stats(index: Dict[str, Any]):
    items = index.get("items", {})
    if not items:
        print(f"{C_YELLOW}ℹ️  Index empty. Please run --scan or --download first.{C_RESET}")
        return

    agg = {}
    total_all_items_in_index = 0 
    total_all_bytes_in_index = 0
    total_dl = 0
    total_dl_bytes = 0
    
    latest_creation_found = None

    for rec in items.values():
        try:
            created = datetime.fromisoformat(rec["created"])
            if latest_creation_found is None or created > latest_creation_found:
                latest_creation_found = created
        except Exception:
            continue
            
        ym = f"{created.year}-{created.month:02d}"
        entry = agg.setdefault(ym, {"count": 0, "bytes": 0, "dl_count": 0, "dl_bytes": 0})

        entry["count"] += 1
        total_all_items_in_index += 1 
        sz = rec.get("size") or 0
        entry["bytes"] += sz
        total_all_bytes_in_index += sz

        if rec.get("downloaded"):
            entry["dl_count"] += 1
            total_dl += 1
            entry["dl_bytes"] += sz
            total_dl_bytes += sz

    SEP_LINE = "=" * 80
    THIN_LINE = "-" * 80

    print(SEP_LINE)
    print(" Month  | St.      Files        |          Size         |  %   |    Progress   |")
    print(THIN_LINE)
    
    for ym in sorted(agg.keys()):
        e = agg[ym]
        count_tot = e["count"]
        bytes_tot = e["bytes"]
        count_dl = e["dl_count"]
        bytes_dl = e["dl_bytes"]

        pct = (bytes_dl / bytes_tot * 100.0) if bytes_tot else 0.0
        is_complete = (count_dl == count_tot) and (count_tot > 0)
        
        status = f"{C_GREEN}✅{C_RESET}" if is_complete else f"{C_YELLOW}⏳{C_RESET}"
        
        s_c_dl = fmt_lim(count_dl, 99999)
        s_c_tot = fmt_lim(count_tot, 99999)
        s_b_dl = format_bytes(bytes_dl)
        s_b_tot = format_bytes(bytes_tot)

        bar_len = 15
        filled = int(pct / 100 * bar_len)
        bar_visual = "█" * filled + " " * (bar_len - filled)
        
        print(f"{ym} | {status} {s_c_dl:>7} / {s_c_tot:<7}  | {s_b_dl:>9} / {s_b_tot:<9} | {pct:>3.0f}% |{C_CYAN}{bar_visual}{C_RESET}|")

    pct_all = (total_dl_bytes / total_all_bytes_in_index * 100.0) if total_all_bytes_in_index else 0.0
    s_gt_b_dl = format_bytes(total_dl_bytes)
    s_gt_b_tot = format_bytes(total_all_bytes_in_index)

    last_stream_val = index.get("last_stream_total") or 0
    total_display_count = max(total_all_items_in_index, last_stream_val)
    
    s_gt_dl = fmt_lim(total_dl, 99999)
    s_gt_tot = fmt_lim(total_display_count, 99999) 

    bar_len = 15
    filled_all = int(pct_all / 100 * bar_len)
    bar_visual_all = "█" * filled_all + " " * (bar_len - filled_all)

    print(THIN_LINE)
    print(f"📦 TOTAL :   {s_gt_dl:>7} / {s_gt_tot:<7}  | {s_gt_b_dl:>9} / {s_gt_b_tot:<9} | {pct_all:>3.0f}% |{C_CYAN}{bar_visual_all}{C_RESET}|")
    print(SEP_LINE)
    
    last_idx = index.get("last_index_time")
    latest_photo_str = latest_creation_found.isoformat() if latest_creation_found else "N/A"
    
    print(f"📅 Last Index Update: {fmt_ts(last_idx)}")
    print(f"📸 Latest Photo Date: {fmt_ts(latest_photo_str)}")
    print()

# ===================== DOWNLOAD =====================

def plan_dest_dir_for(photo) -> str:
    created = photo_created_dt(photo)
    return os.path.join(DOWNLOAD_BASE, f"{created.year}", f"{created.year}_{created.month:02d}")

def download_one(api: PyiCloudService, photo, dest_dir: str) -> str:
    os.makedirs(dest_dir, exist_ok=True)
    created = photo_created_dt(photo)
    raw_name = getattr(photo, "filename", None) or f"{int(created.timestamp())}.bin"
    fname = safe_filename(raw_name)
    path = os.path.join(dest_dir, fname)

    if os.path.exists(path):
        base, ext = os.path.splitext(path)
        i = 1
        while True:
            alt = f"{base}_{i:04d}{ext}"
            if not os.path.exists(alt):
                path = alt
                break
            i += 1

    resp = photo.download()
    if hasattr(resp, "iter_content"):
        with open(path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)
        return path

    raw = getattr(resp, "raw", None)
    if raw is not None and hasattr(raw, "read"):
        with open(path, "wb") as f:
            for chunk in iter(lambda: raw.read(1024 * 1024), b""):
                if chunk:
                    f.write(chunk)
        return path

    if isinstance(resp, (bytes, bytearray)):
        with open(path, "wb") as f:
            f.write(resp)
        return path

    raise RuntimeError("Download response type not supported.")


def download_all(api: PyiCloudService, index: Dict[str, Any], filter_months: Set[str]):
    items = index.get("items", {})
    if not items:
        print(f"{C_YELLOW}ℹ️  Index empty. Performing full scan before download...{C_RESET}")
        index = scan_files(api, index)
        items = index.get("items", {})

    total_known_local = len(items)
    last_stream_val = index.get("last_stream_total") or 0
    total_known_display = max(last_stream_val, total_known_local)

    synced_count = 0
    to_get_pids_from_index = []
    expected_bytes = 0
    
    for pid, rec in items.items():
        if rec.get("downloaded"):
            synced_count += 1
            continue
        
        if filter_months:
            created_str = rec.get("created")
            if created_str:
                ym = created_str[:7]
                if ym not in filter_months:
                    continue 
        
        to_get_pids_from_index.append(pid)
        expected_bytes += (rec.get("size") or 0)

    to_get_set = set(to_get_pids_from_index)
    
    to_get_count_display = 0
    if filter_months:
        to_get_count_display = len(to_get_set)
    else:
        to_get_count_display = total_known_display - synced_count


    filter_msg = ""
    if filter_months:
        sorted_m = sorted(list(filter_months))
        disp = ";".join(sorted_m)
        if len(disp) > 50: disp = disp[:47] + "..."
        filter_msg = f"Filter Active: {C_CYAN}{disp}{C_RESET}"

    last_dl = from_iso(index.get("last_download_time"))
    since_dt = (last_dl - timedelta(seconds=1)) if last_dl else None

    estimated_total_items = max(last_stream_val, total_known_local, 1)

    panel = Panel(user=ICLOUD_USER,
                  mode_str="DOWNLOAD",
                  filter_msg=filter_msg,
                  to_get_count=to_get_count_display,
                  total_known=total_known_display, 
                  synced_count=synced_count,
                  total_bytes=expected_bytes)
    
    panel.set_scan_target(estimated_total_items)

    print()
    panel.start_heartbeat()

    unsaved_changes_count = 0
    last_save_ts = time.time()
    
    session_items_scanned = 0
    session_scan_time_sec = 0.0
    session_bytes_dl = 0
    session_dl_time_sec = 0.0

    def request_save_index(force=False):
        nonlocal unsaved_changes_count, last_save_ts
        if unsaved_changes_count == 0 and not force: return
        now = time.time()
        if force or (unsaved_changes_count >= 20) or (now - last_save_ts > 30):
            save_index(index)
            unsaved_changes_count = 0
            last_save_ts = now

    interrupted = {"flag": False}
    def _sigint(sig, frame):
        interrupted["flag"] = True
    signal.signal(signal.SIGINT, _sigint)

    try:
        stream = stream_all(api)
    except Exception as e:
        panel.stop_heartbeat()
        print(f"\n{C_RED}❌ Error initializing stream: {e}{C_RESET}")
        return

    total_seen_this_run = 0
    main_scan_loop_start = time.time()
    
    try:
        for photo in stream:
            dl_time_this_loop = 0.0 
            
            total_seen_this_run += 1
            panel.inc_scan(1) 
            
            if interrupted["flag"]: break

            if total_seen_this_run > estimated_total_items:
                 estimated_total_items = total_seen_this_run
                 panel.set_scan_target(estimated_total_items)

            pid = get_photo_id(photo)
            if not pid:
                created = photo_created_dt(photo)
                pid = f"{getattr(photo, 'filename', 'unknown')}|{int(created.timestamp())}"

            rec = index["items"].get(pid)
            if rec is None:
                created = photo_created_dt(photo)
                rec = {
                    "id": pid, "filename": getattr(photo, "filename", f"{int(created.timestamp())}.bin"),
                    "created": created.isoformat(),
                    "size": getattr(photo, "size", None),
                    "downloaded": False, "local_path": None, "downloaded_at": None, "sha256": None
                }
                index["items"][pid] = rec
                unsaved_changes_count += 1
                
                ym = created.strftime("%Y-%m")
                if (not filter_months) or (ym in filter_months):
                    to_get_set.add(pid) 
            else:
                changed = False
                fn = getattr(photo, "filename", rec.get("filename"))
                if rec.get("filename") != fn:
                    rec["filename"] = fn
                    changed = True
                sz = getattr(photo, "size", None)
                if (sz is not None) and (rec.get("size") != sz):
                    rec["size"] = sz
                    changed = True
                if changed:
                    unsaved_changes_count += 1

            if pid in to_get_set:
                sz_now = rec.get("size")
                try:
                    dest_dir = plan_dest_dir_for(photo)
                    
                    dl_start = time.time()
                    path = download_one(api, photo, dest_dir)
                    dl_time_this_loop = time.time() - dl_start
                    session_dl_time_sec += dl_time_this_loop 

                    rec2 = index["items"][pid]
                    file_hash = None
                    try: file_hash = sha256_file(path)
                    except: pass
                    
                    rec2["local_path"] = path
                    rec2["downloaded_at"] = now_utc_iso()
                    rec2["sha256"] = file_hash
                    rec2["downloaded"] = True
                    
                    unsaved_changes_count += 1
                    
                    if sz_now is not None:
                        panel.log_download(sz_now, dl_time_this_loop)
                        session_bytes_dl += sz_now 
                    
                    to_get_set.remove(pid)
                    
                except PyiCloudAPIResponseException as e:
                    if "403" in str(e) or "Forbidden" in str(e).upper():
                        panel.stop_heartbeat()
                        print(f"\n{C_RED}❌ CRITICAL ERROR: 403 Forbidden{C_RESET}")
                        print(f"{C_YELLOW}   Failed to download '{rec.get('filename')}'. This almost always means")
                        print(f"   you have 'Advanced Data Protection' enabled in your iCloud settings.")
                        print(f"   Please disable it on your iPhone/iPad and try again (see README for details).{C_RESET}")
                        sys.exit(1)
                    else:
                        panel.set_last_error(f"Failed '{rec.get('filename')}': {e}")
                        pass
                except Exception as e:
                    panel.set_last_error(f"Failed '{rec.get('filename')}': {e}")
                    pass 

            request_save_index(force=False)
            if (not to_get_set) and (not filter_months):
                break

    except Exception as e:
        panel.set_last_error(f"Stream error: {e}")

    finally:
        main_scan_total_time = time.time() - main_scan_loop_start
        main_scan_only_time = main_scan_total_time - session_dl_time_sec
        
        if not interrupted["flag"]:
            index["last_stream_total"] = total_seen_this_run
            
        index["stats_total_items_scanned"] += total_seen_this_run
        index["stats_total_scan_time_minutes"] += (main_scan_only_time / 60.0)
        index["stats_total_megabytes_downloaded"] += (session_bytes_dl / (1024*1024.0))
        index["stats_total_download_time_minutes"] += (session_dl_time_sec / 60.0)
        
        request_save_index(force=True)
        panel.render()

    # --- INCREMENTAL ---
    if not interrupted["flag"]:
        inc_dl_time_sec = 0.0
        inc_bytes_dl = 0
        inc_scan_items = 0
        inc_scan_start = time.time()
        
        try:
            stream_inc = stream_since(api, since_dt) if since_dt else []
        except: stream_inc = []

        newest_time = from_iso(index.get("last_download_time"))

        try:
            for photo in stream_inc:
                dl_time_this_loop = 0.0
                inc_scan_items += 1
                panel.inc_scan(1) 
                
                if interrupted["flag"]: break

                pid = get_photo_id(photo)
                created = photo_created_dt(photo)
                filename = getattr(photo, "filename", f"{int(created.timestamp())}.bin")
                size = getattr(photo, "size", None)
                if not pid: pid = f"{filename}|{int(created.timestamp())}"

                rec = index["items"].get(pid)
                
                ym = created.strftime("%Y-%m")
                should_dl = True
                if filter_months and ym not in filter_months:
                    should_dl = False
                
                if rec and rec.get("downloaded"):
                    pass
                else:
                    if should_dl:
                        try:
                            dest_dir = plan_dest_dir_for(photo)
                            
                            dl_start = time.time()
                            path = download_one(api, photo, dest_dir)
                            dl_time_this_loop = time.time() - dl_start
                            inc_dl_time_sec += dl_time_this_loop
                            
                            rec2 = index["items"].setdefault(pid, {
                                "id": pid, "filename": filename, "created": created.isoformat(),
                                "size": size, "downloaded": False, "local_path": None, "downloaded_at": None, "sha256": None
                            })
                            try: h = sha256_file(path)
                            except: h = None
                            rec2["local_path"] = path
                            rec2["downloaded_at"] = now_utc_iso()
                            rec2["sha256"] = h
                            rec2["downloaded"] = True
                            unsaved_changes_count += 1
                            if size: 
                                panel.log_download(size, dl_time_this_loop)
                                inc_bytes_dl += size
                        except PyiCloudAPIResponseException as e:
                            if "403" in str(e) or "Forbidden" in str(e).upper():
                                panel.stop_heartbeat()
                                print(f"\n{C_RED}❌ CRITICAL ERROR: 403 Forbidden{C_RESET}")
                                print(f"{C_YELLOW}   Failed to download '{filename}'. This almost always means")
                                print(f"   you have 'Advanced Data Protection' enabled in your iCloud settings.")
                                print(f"   Please disable it on your iPhone/iPad and try again (see README for details).{C_RESET}")
                                sys.exit(1)
                            else:
                                panel.set_last_error(f"Failed '{filename}': {e}")
                        except Exception as e:
                            panel.set_last_error(f"Failed '{filename}': {e}")

                if (newest_time is None) or (created > newest_time):
                    newest_time = created
                
                request_save_index(force=False)
        except Exception as e:
            panel.set_last_error(f"Incremental stream error: {e}")
        
        finally:
            inc_scan_total_time = time.time() - inc_scan_start
            inc_scan_only_time = inc_scan_total_time - inc_dl_time_sec

            if newest_time and not interrupted["flag"]:
                index["last_download_time"] = newest_time.astimezone(timezone.utc).isoformat()
            
            index["stats_total_items_scanned"] += inc_scan_items
            index["stats_total_scan_time_minutes"] += (inc_scan_only_time / 60.0)
            index["stats_total_megabytes_downloaded"] += (inc_bytes_dl / (1024*1024.0))
            index["stats_total_download_time_minutes"] += (inc_dl_time_sec / 60.0)
            
            request_save_index(force=True)

    panel.stop_heartbeat()
    panel.render()
    print()
    print("-" * 80)
    print(f"✅ Session finished. Downloaded this session: {format_bytes(panel.bytes_done)}")

# ===================== INTERACTIVE MENU =====================
def show_menu():
    print(f"\n{C_GREEN}=== Simple iCloud Downloader - Quick Menu ==={C_RESET}")
    print("1. Scan Files ( --scan )")
    print("2. Download Everything ( --download )")
    print("3. Download Only Specified Months ( --download --filter ... )")
    print("4. View Download Stats ( --view )")
    print("5. Terminate iCloud Session ( --logout )")
    print("q. Quit")
    print("-" * 40)
    
    choice = input("Option: ").strip().lower()
    
    if choice == '1':
        return ["--scan"]
    elif choice == '2':
        return ["--download"]
    elif choice == '3':
        print(f"\n{C_CYAN}Enter months to download in format YYYY-MM, separated by semicolon.{C_RESET}")
        print("Example: 2023-01;2023-05;2024-12")
        f_str = input("Months: ").strip()
        if not f_str:
            print("No filter entered. Cancelling.")
            sys.exit(0)
        try:
            validate_filter(f_str)
            return ["--download", "--filter", f_str]
        except SystemExit:
            sys.exit(1)
            
    elif choice == '4':
        return ["--view"]
    elif choice == '5':
        return ["--logout"]
    elif choice == 'q':
        print("Exiting.")
        sys.exit(0)
    else:
        print("Invalid option.")
        sys.exit(1)

# ===================== MAIN =====================
def main():
    enable_ansi_windows()

    if len(sys.argv) == 1:
        sys.argv.extend(show_menu())

    ap = argparse.ArgumentParser(description="iCloud sync with cache (index.json)")
    ap.add_argument("--scan", action="store_true", help="Scan iCloud library for new files.")   
    ap.add_argument("--download", action="store_true", help="Download missing files.")
    ap.add_argument("--view", action="store_true", help="Show summary by month.")
    ap.add_argument("--logout", action="store_true", help="Terminate local session.")
    ap.add_argument("--filter", type=str, help="Filter months (YYYY-MM;YYYY-MM) for download only.")
    
    # --- CORREÇÃO DO BUG AQUI ---
    ap.add_argument("--config", type=str, default="config.ini", help="Config file.") # Era add_Ggument
    # --- FIM DA CORREÇÃO ---
    
    ap.add_argument("--update-index", action="store_true", help=argparse.SUPPRESS) 
    ap.add_argument("--view-months", action="store_true", help=argparse.SUPPRESS)
    
    args = ap.parse_args()

    global ICLOUD_USER, DOWNLOAD_BASE, CACHE_DIR, INDEX_PATH

    ICLOUD_USER, DOWNLOAD_BASE = load_config(args.config)
    CACHE_DIR = os.path.join(DOWNLOAD_BASE, "_cache")
    INDEX_PATH = os.path.join(CACHE_DIR, "index.json")
    
    ensure_dirs()

    def handle_sigint(signum, frame):
        print(f"\n{C_YELLOW}⏹️  Interrupted (Ctrl+C). Exiting safely...{C_RESET}")
        sys.exit(1)
    signal.signal(signal.SIGINT, handle_sigint)

    if args.logout:
        perform_logout()
        return

    if (args.view or args.view_months) and not (args.scan or args.update_index or args.download):
        index = load_index()
        view_stats(index)
        return

    api = login_icloud()
    index = load_index()

    if args.scan or args.update_index:
        index = scan_files(api, index)

    if args.download:
        filter_set = validate_filter(args.filter)
        download_all(api, index, filter_set)

    if not (args.scan or args.update_index or args.download or args.view or args.view_months):
        print("ℹ️  Nothing to do.")

if __name__ == "__main__":
    main()