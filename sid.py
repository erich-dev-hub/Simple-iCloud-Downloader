#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iCloud Sync with local cache (index.json)

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
        # cache_dir removed from config, calculated automatically
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

    def speed_bps(self) -> float:
        if len(self.samples) < 2: return 0.0
        t0, b0 = self.samples[0]
        t1, b1 = self.samples[-1]
        dt = max(t1 - t0, 1e-6)
        return max((b1 - b0)/dt, 0.0)

# ===================== CACHE (INDEX) =====================
def load_index() -> Dict[str, Any]:
    if not os.path.exists(INDEX_PATH):
        return {
            "last_index_time": None,
            "last_download_time": None,
            "last_stream_total": None,
            "items": {}
        }
    with open(INDEX_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

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
        self.speed = RollingSpeed(30.0)
        self.fixed_mode = True 
        self.first_printed = False

        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._last_render = 0.0

    def start_heartbeat(self): self._thread.start()
    def stop_heartbeat(self): self._stop.set()
    def _heartbeat_loop(self):
        while not self._stop.is_set():
            self.render()
            time.sleep(1.0)

    def add_bytes(self, inc: int):
        if inc > 0:
            self.bytes_done += inc
            self.speed.add(inc)

    def inc_scan(self, inc: int = 1):
        if inc > 0: self.scan_done += inc

    def set_scan_target(self, n: int): self.scan_target = max(n, 0)
    def set_total_download_bytes(self, n: int): self.total_download_bytes = max(n, 0)
    def set_total_known(self, n: int): self.total_known = n

    def _bar(self, pct: float, width: int = 25) -> str:
        pct = max(0.0, min(100.0, pct))
        filled = int(round((pct/100.0) * width))
        return "█"*filled + " "*(width-filled)

    def _fmt_time(self, secs: float) -> str:
        secs = int(max(0, secs))
        return time.strftime("%H:%M:%S", time.gmtime(secs))

    def render(self):
        now = time.time()
        if now - self._last_render < 0.95 and self.first_printed: return
        self._last_render = now

        scan_pct = (100.0 * self.scan_done / self.scan_target) if self.scan_target else 0.0
        dl_pct   = (100.0 * self.bytes_done / self.total_download_bytes) if self.total_download_bytes else 0.0
        elapsed  = now - self.start_ts
        spd      = self.speed.speed_bps()
        eta = 0.0
        if self.total_download_bytes and spd > 0:
            remaining = max(self.total_download_bytes - self.bytes_done, 0)
            eta = remaining / spd

        header_user = f"{C_GREEN}iCloud User: {self.user}{C_RESET}"
        header_mode = f"Mode: {C_CYAN}{self.mode_str}{C_RESET}"
        
        extra_filter = ""
        if self.filter_msg:
            extra_filter = f"\n{self.filter_msg}\n{C_DIM}(*) Filtering applies to downloads only. Full scan is performed.{C_RESET}"

        header1 = "=" * 80
        
        if self.only_scan:
            header2 = f"📂 Current Index Size: {self.total_known:,} items"
        else:
            header2 = (f"📂 Total indexed: {self.total_known:,} | "
                       f"Synced: {self.synced_count:,} | "
                       f"Downloading: {self.to_get_count:,}...")
            
        header3 = "-" * 80
        
        line_scan = (f"[🔎] Scan      : {scan_pct:6.2f}% | {self._bar(scan_pct)} | "
                     f"{self.scan_done:,} / {self.scan_target:,} items")
        
        line_dl   = (f"[⬇️] Download  : {dl_pct:6.2f}% | {self._bar(dl_pct)} | "
                     f"{format_bytes(self.bytes_done)} / {format_bytes(self.total_download_bytes)}")
        
        line_tm   = (f"[⏱️] Time      :  {self._fmt_time(elapsed)} elapsed"
                     f"  | ETA ≈ {self._fmt_time(eta)} | {format_bytes(int(spd))}/s")
        
        if self.only_scan:
            footer = f"\n{C_YELLOW}Stop by pressing CTRL + C.{C_RESET}"
            line_tm_scan = f"[⏱️] Time      :  {self._fmt_time(elapsed)} elapsed"
            block = "\n".join([header_user, header_mode, extra_filter, header1, header2, header3, line_scan, line_tm_scan, header1, footer])
        else:
            footer = (f"\n{C_YELLOW}Stop by pressing CTRL + C. "
                      f"For resuming, just run the command again.{C_RESET}")
            block = "\n".join([header_user, header_mode, extra_filter, header1, header2, header3, line_scan, line_dl, line_tm, header1, footer])
            
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
    
    total_known = len(items)
    last_stream_val = index.get("last_stream_total") or 0
    estimated_total = max(last_stream_val, total_known, 1)

    panel = Panel(user=ICLOUD_USER,
                  mode_str="SCAN FILES",
                  filter_msg="",
                  to_get_count=0,
                  total_known=total_known,
                  synced_count=0,
                  total_bytes=0,
                  only_scan=True)
    
    panel.set_scan_target(estimated_total)
    
    print("Scanning iCloud metadata (may take a while on 1st run)...")
    try:
        stream = stream_since(api, since_dt) if since_dt else stream_all(api)
    except Exception as e:
        print(f"{C_RED}❌ Error starting stream: {e}{C_RESET}")
        return index

    print()
    panel.start_heartbeat()

    unsaved_changes_count = 0
    last_save_ts = time.time()

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

    count_seen = 0
    
    try:
        for photo in stream:
            count_seen += 1
            panel.inc_scan(1)
            
            if interrupted["flag"]: break

            if count_seen > estimated_total:
                estimated_total = count_seen
                panel.set_scan_target(estimated_total)

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
                total_known += 1
                panel.set_total_known(total_known) 
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
        pass

    finally:
        index["last_stream_total"] = count_seen
        index["last_index_time"] = now_utc_iso()
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
    total_all = 0
    total_all_bytes = 0
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
        total_all += 1
        sz = rec.get("size") or 0
        entry["bytes"] += sz
        total_all_bytes += sz

        if rec.get("downloaded"):
            entry["dl_count"] += 1
            total_dl += 1
            entry["dl_bytes"] += sz
            total_dl_bytes += sz

    SEP_LINE = "=" * 80
    THIN_LINE = "-" * 80

    print(SEP_LINE)
    # Header Config:
    # Month (8) | St. Files (22) | Size (23) | % (6) | Progress (15) | Borders (5) = 79 + 1 empty = 80
    print(" Month  | St.      Files       |          Size         |  %   |   Progress    |")
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

        # Bar length fixed to 15
        bar_len = 15
        filled = int(pct / 100 * bar_len)
        bar_visual = "█" * filled + " " * (bar_len - filled)
        
        print(f"{ym} | {status} {s_c_dl:>7} / {s_c_tot:<7}  | {s_b_dl:>9} / {s_b_tot:<9} | {pct:>3.0f}% |{C_CYAN}{bar_visual}{C_RESET}|")

    pct_all = (total_dl_bytes / total_all_bytes * 100.0) if total_all_bytes else 0.0
    bar_len = 15
    filled_all = int(pct_all / 100 * bar_len)
    bar_visual_all = "█" * filled_all + " " * (bar_len - filled_all)

    s_gt_dl = fmt_lim(total_dl, 99999)
    s_gt_tot = fmt_lim(total_all, 99999)
    s_gt_b_dl = format_bytes(total_dl_bytes)
    s_gt_b_tot = format_bytes(total_all_bytes)

    print(THIN_LINE)
    print(f"📦 TOTAL :   {s_gt_dl:>7} / {s_gt_tot:<7}  | {s_gt_b_dl:>9} / {s_gt_b_tot:<9} | {pct_all:>3.0f}% |{C_CYAN}{bar_visual_all}{C_RESET}|")
    print(SEP_LINE)
    
    last_idx = index.get("last_index_time")
    latest_photo_str = latest_creation_found.isoformat() if latest_creation_found else "N/A"
    
    print(f"📅 Last Index Update: {fmt_ts(last_idx)}")
    print(f"📸 Latest Photo Date: {fmt_ts(latest_photo_str)}")
    print()

# ===================== DOWNLOAD =====================
def download_all(api: PyiCloudService, index: Dict[str, Any], filter_months: Set[str]):
    items = index.get("items", {})
    if not items:
        print(f"{C_YELLOW}ℹ️  Index empty. Performing full scan before download...{C_RESET}")
        index = scan_files(api, index)
        items = index.get("items", {})

    # Identify what to download based on FILTER
    to_get_pids = []
    expected_bytes = 0
    synced_count = 0
    
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
        
        to_get_pids.append(pid)
        expected_bytes += (rec.get("size") or 0)

    to_get_set = set(to_get_pids)
    total_known = len(items)
    
    filter_msg = ""
    if filter_months:
        sorted_m = sorted(list(filter_months))
        disp = ";".join(sorted_m)
        if len(disp) > 50: disp = disp[:47] + "..."
        filter_msg = f"Filter Active: {C_CYAN}{disp}{C_RESET}"

    last_dl = from_iso(index.get("last_download_time"))
    since_dt = (last_dl - timedelta(seconds=1)) if last_dl else None

    last_stream_val = index.get("last_stream_total") or 0
    estimated_total_items = max(last_stream_val, total_known, 1)

    panel = Panel(user=ICLOUD_USER,
                  mode_str="DOWNLOAD",
                  filter_msg=filter_msg,
                  to_get_count=len(to_get_set),
                  total_known=total_known,
                  synced_count=synced_count,
                  total_bytes=expected_bytes)
    
    panel.set_scan_target(estimated_total_items)

    print()
    panel.start_heartbeat()

    unsaved_changes_count = 0
    last_save_ts = time.time()

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

    # --- SCAN ---
    try:
        stream = stream_all(api)
    except Exception as e:
        panel.stop_heartbeat()
        print(f"\n{C_RED}❌ Error initializing stream: {e}{C_RESET}")
        return

    total_seen_this_run = 0

    try:
        for photo in stream:
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
                index["items"][pid] = {
                    "id": pid, "filename": getattr(photo, "filename", f"{int(created.timestamp())}.bin"),
                    "created": created.isoformat(),
                    "size": getattr(photo, "size", None),
                    "downloaded": False, "local_path": None, "downloaded_at": None, "sha256": None
                }
                unsaved_changes_count += 1
            else:
                changed = False
                fn = getattr(photo, "filename", rec.get("filename"))
                if rec.get("filename") != fn:
                    rec["filename"] = fn
                    changed = True
                sz = getattr(photo, "size", None)
                if (sz is not None) and (rec.get("size") != sz):
                    if rec.get("downloaded"):
                        pass 
                    rec["size"] = sz
                    changed = True
                if changed:
                    unsaved_changes_count += 1

            if pid in to_get_set:
                try:
                    dest_dir = plan_dest_dir_for(photo)
                    path = download_one(api, photo, dest_dir)

                    rec2 = index["items"][pid]
                    file_hash = None
                    try: file_hash = sha256_file(path)
                    except: pass
                    
                    rec2["local_path"] = path
                    rec2["downloaded_at"] = now_utc_iso()
                    rec2["sha256"] = file_hash
                    rec2["downloaded"] = True
                    
                    unsaved_changes_count += 1
                    sz_now = rec2.get("size")
                    if sz_now is not None:
                        panel.add_bytes(sz_now)

                except Exception as e:
                    pass

                to_get_set.remove(pid)
            
            request_save_index(force=False)
            if not to_get_set: break

    except Exception:
        pass

    finally:
        current_max = max(index.get("last_stream_total") or 0, total_seen_this_run)
        index["last_stream_total"] = current_max
        request_save_index(force=True)
        panel.render()

    # --- INCREMENTAL ---
    if not interrupted["flag"]:
        try:
            stream_inc = stream_since(api, since_dt) if since_dt else []
        except: stream_inc = []

        newest_time = from_iso(index.get("last_download_time"))

        try:
            for photo in stream_inc:
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
                            path = download_one(api, photo, dest_dir)
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
                            if size: panel.add_bytes(size)
                        except: pass

                if (newest_time is None) or (created > newest_time):
                    newest_time = created
                
                request_save_index(force=False)
        except: pass

        if newest_time and not interrupted["flag"]:
            index["last_download_time"] = newest_time.astimezone(timezone.utc).isoformat()
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
    ap.add_argument("--config", type=str, default="config.ini", help="Config file.")
    args = ap.parse_args()

    global ICLOUD_USER, DOWNLOAD_BASE, CACHE_DIR, INDEX_PATH

    ICLOUD_USER, DOWNLOAD_BASE = load_config(args.config)
    # CACHE_DIR calculated dynamically based on download_base
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

    if (args.view) and not (args.scan or args.download):
        index = load_index()
        view_stats(index)
        return

    api = login_icloud()
    index = load_index()

    if args.scan:
        index = scan_files(api, index)

    if args.download:
        filter_set = validate_filter(args.filter)
        download_all(api, index, filter_set)

    if not (args.scan or args.download or args.view):
        print("ℹ️  Nothing to do.")

if __name__ == "__main__":
    main()