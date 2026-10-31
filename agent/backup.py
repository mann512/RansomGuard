import hashlib, os, shutil, uuid
from datetime import datetime, timezone
from pathlib import Path
from . import config

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
    return h.hexdigest()

class BackupManager:
    def __init__(self, backup_dir=None, db=None):
        self.backup_dir = Path(backup_dir or config.BACKUP_DIR)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.db = db

    def backup_file(self, source, phase="forensic", alert_id=None):
        source = Path(source)
        if not source.exists() or not source.is_file(): return None
        try:
            digest = sha256_of(source)
            size = source.stat().st_size
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
            dest_dir = self.backup_dir / digest[:2]
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / f"{ts}_{uuid.uuid4().hex[:6]}_{source.name}"
            shutil.copy2(source, dest)
            if self.db: self.db.add_backup(str(source), str(dest), digest, size, phase=phase, alert_id=alert_id)
            print(f"[backup] Saved {source.name} -> {dest.name} ({phase})")
            return {"original": str(source), "backup": str(dest), "sha256": digest, "size": size}
        except Exception as e:
            print(f"[backup] FAILED to backup {source}: {e}")
            return None

    def snapshot_folder(self, folder, limit=None, max_file_size=None):
        limit = limit or config.SNAPSHOT_MAX_FILES
        max_file_size = max_file_size or config.SNAPSHOT_MAX_FILE_SIZE
        results, folder, count = [], Path(folder), 0
        if not folder.exists(): return results
        
        for root, dirs, files in os.walk(folder):
            root_path = Path(root)
            dirs[:] = [d for d in dirs if d not in config.DEFAULT_SKIP_DIRS]
            for fname in files:
                if count >= limit: return results
                if fname.startswith(config.CANARY_PREFIX): continue
                p = root_path / fname
                try:
                    if not p.is_file() or p.is_symlink() or p.stat().st_size > max_file_size: continue
                    res = self.backup_file(p, phase="snapshot")
                    if res: results.append(res); count += 1
                except Exception: continue
        print(f"[snapshot] {count} files snapshotted under {folder}")
        return results

    def forensic_backup(self, paths, alert_id=None):
        return [res for p in paths if (res := self.backup_file(Path(p), "forensic", alert_id))]

    def restore(self, original_path, backup_path):
        original_path, backup_path = Path(original_path), Path(backup_path)
        if not backup_path.exists(): return {"ok": False, "error": "backup missing"}
        original_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup_path, original_path)
        return {"ok": sha256_of(original_path) == sha256_of(backup_path), "sha256": sha256_of(original_path), "restored_to": str(original_path)}