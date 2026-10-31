import os
from pathlib import Path
import psutil
from . import config
def _scan_by_cmdline():
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmdline = " ".join(proc.info.get("cmdline") or []).lower()
            if "benign_ransomware_sim" in cmdline or "ransomguard_sim" in cmdline:
                return {"pid": proc.info["pid"], "name": proc.info["name"], "cmdline": cmdline, "source": "cmdline_scan"}
        except: continue
    return None
def _read_simulator_pid():
    try:
        if config.SIMULATOR_PID_FILE.exists():
            pid = int(config.SIMULATOR_PID_FILE.read_text().strip())
            if psutil.pid_exists(pid) and "benign_ransomware_sim" in " ".join(psutil.Process(pid).cmdline()).lower(): return pid
    except: pass
    return None
def find_process_for_file(path):
    target = str(Path(path).resolve())
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            for f in proc.open_files():
                if os.path.abspath(f.path) == target: return {"pid": proc.pid, "name": proc.info.get("name"), "cmdline": "", "source": "open_files_scan"}
        except: continue
    return None
def find_culprit(affected_paths):
    if info := _scan_by_cmdline(): return info
    if pid := _read_simulator_pid(): return {"pid": pid, "name": psutil.Process(pid).name(), "cmdline": " ".join(psutil.Process(pid).cmdline()), "source": "simulator_pid_file"}
    for p in affected_paths:
        if info := find_process_for_file(p): return info
    return None
def terminate_process(pid):
    try:
        proc = psutil.Process(pid); proc.terminate(); proc.wait(timeout=3); return True
    except psutil.NoSuchProcess: return True
    except Exception: return False