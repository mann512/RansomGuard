import threading, time
from pathlib import Path
from . import canary, config, database, process_guard
from .backup import BackupManager
from .monitor import FileMonitor

class RansomGuard:
    def __init__(self):
        self.db = database.Database()
        self.backup_mgr = BackupManager(db=self.db)
        self.settings = config.load_settings()
        self.monitor = None; self.status = "stopped"
        self._lock = threading.Lock(); self._last_alert = 0.0

    def add_folder(self, folder):
        folder = folder.strip().strip("'\"")
        folder_path = Path(folder).expanduser().resolve()
        if not folder_path.exists():
            try: folder_path.mkdir(parents=True, exist_ok=True)
            except Exception as e: raise ValueError(f"Cannot create folder: {e}")
        
        folder_str = str(folder_path)
        if folder_str not in self.settings["protected_folders"]:
            self.settings["protected_folders"].append(folder_str); config.save_settings(self.settings)
            print(f"[core] planting canaries under {folder_str}")
            canary.plant_canaries_recursive(folder_path)
            self.backup_mgr.snapshot_folder(folder_path)
        return self.settings["protected_folders"]

    def remove_folder(self, folder):
        folder = folder.strip().strip("'\"")
        new_folders = []
        for f in self.settings["protected_folders"]:
            # Compare everything in lowercase to ignore case differences
            if f.lower() != folder.lower():
                new_folders.append(f)
        
        self.settings["protected_folders"] = new_folders
        config.save_settings(self.settings)
        print(f"[core] Removed folder: {folder}")
        return self.settings["protected_folders"]

    def force_snapshot(self):
        count = 0
        for folder in self.settings["protected_folders"]:
            snaps = self.backup_mgr.snapshot_folder(Path(folder))
            count += len(snaps)
        return count

    def update_settings(self, data):
        for k in ("auto_stop", "auto_backup", "consent_given"):
            if k in data: self.settings[k] = bool(data[k])
        config.save_settings(self.settings); return self.settings

    def start(self):
        if self.status == "running": return
        if not self.settings["protected_folders"]: raise ValueError("No folders configured")
        if not self.settings.get("consent_given"): raise ValueError("Consent not given")
        self.monitor = FileMonitor(self.settings["protected_folders"], self._handle_signal)
        self.monitor.start(); self.status = "running"

    def stop(self):
        if self.monitor: self.monitor.stop(); self.monitor = None
        self.status = "stopped"

    def _handle_signal(self, signal):
        if signal["severity"] not in ("critical", "high"): return
        now = time.time()
        if signal["severity"] != "critical" and now - self._last_alert < 6: return
        with self._lock:
            if now - self._last_alert < 3: return
            self._last_alert = now
            affected = sorted(set(self.monitor.detector.recent_affected_paths(30)) | {signal["path"]})
            alert_id = self.db.add_alert(signal["severity"], signal["score"], "; ".join(signal["signals"]), affected)
            print(f"[ALERT #{alert_id}] {signal['severity']} {signal['score']}")
            if self.settings.get("auto_backup", True): self.backup_mgr.forensic_backup(affected, alert_id)
            process_info = process_guard.find_culprit(affected)
            stopped = False
            if process_info and self.settings.get("auto_stop", True):
                stopped = process_guard.terminate_process(process_info["pid"])
                print(f"[ALERT #{alert_id}] culprit: {process_info} | stopped: {stopped}")
            self.db.update_alert_process(alert_id, process_info, stopped)

    def get_status(self):
        return {"status": self.status, "protected_folders": self.settings["protected_folders"], "canaries": canary.verify_canaries(self.settings["protected_folders"]), "settings": self.settings, "stats": self.db.stats()}
    def get_activity(self, limit=100): return self.monitor.detector.recent_events(limit) if self.monitor else []
    def get_threat_level(self): return self.monitor.detector.threat_level() if self.monitor else {"level": 0, "label": "safe", "recent_events": 0, "window": 10}

    def restore_alert(self, alert_id):
        alert = self.db.get_alert(alert_id)
        if not alert: return {"ok": False, "error": "alert not found"}

        results = []; restored_files = set()
        for path in alert["affected_files"]:
            p = Path(path)
            if p.suffix.lower() in config.SUSPICIOUS_EXTENSIONS:
                original_p = p.with_suffix("") # file.txt.locked -> file.txt
                snap = self.db.latest_snapshot_for_path(str(original_p))
                if snap and str(original_p) not in restored_files:
                    res = self.backup_mgr.restore(original_p, Path(snap["backup_path"]))
                    results.append({"file": str(original_p), **res}); restored_files.add(str(original_p))
                    try: p.unlink(missing_ok=True) # Delete the locked file
                    except Exception: pass
                elif not snap: print(f"[restore] No snapshot found for {original_p}")
            else:
                snap = self.db.latest_snapshot_for_path(str(p))
                if snap and str(p) not in restored_files:
                    res = self.backup_mgr.restore(p, Path(snap["backup_path"]))
                    results.append({"file": str(p), **res}); restored_files.add(str(p))
                elif not snap: print(f"[restore] No snapshot found for {p}")

        ok = bool(results) and all(r.get("ok") for r in results)
        if ok: self.db.mark_restored(alert_id)
        return {"ok": ok, "results": results}