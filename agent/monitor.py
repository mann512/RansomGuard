import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from . import config
from .detector import Detector, file_entropy
def _should_skip(path):
    try: return any(skip in Path(path).parts for skip in config.MONITOR_SKIP_DIRS)
    except: return False
class Handler(FileSystemEventHandler):
    def __init__(self, detector, on_signal): super().__init__(); self.detector = detector; self.on_signal = on_signal; self._last = {}
    def _debounce(self, key, seconds=0.4):
        now = time.time()
        if key in self._last and now - self._last[key] < seconds: return False
        self._last[key] = now; return True
    def on_modified(self, event):
        if not event.is_directory and not _should_skip(event.src_path) and self._debounce(("mod", event.src_path)):
            if sig := self.detector.record_event(Path(event.src_path), "modified", entropy=file_entropy(Path(event.src_path))): self.on_signal(sig)
    def on_created(self, event):
        if not event.is_directory and not _should_skip(event.src_path):
            if sig := self.detector.record_event(Path(event.src_path), "created"): self.on_signal(sig)
    def on_deleted(self, event):
        if not event.is_directory and not _should_skip(event.src_path):
            if sig := self.detector.record_event(Path(event.src_path), "deleted"): self.on_signal(sig)
    def on_moved(self, event):
        if not event.is_directory and not _should_skip(event.dest_path):
            if sig := self.detector.record_event(Path(event.dest_path), "moved"): self.on_signal(sig)
class FileMonitor:
    def __init__(self, folders, on_signal): 
        self.folders = [str(f) for f in folders] # FIXED: Convert to list instead of map
        self.on_signal = on_signal; self.detector = Detector(); self.observer = None
    def start(self):
        handler = Handler(self.detector, self.on_signal); self.observer = Observer()
        for folder in self.folders:
            if Path(folder).exists(): self.observer.schedule(handler, folder, recursive=True)
        self.observer.start()
    def stop(self):
        if self.observer: self.observer.stop(); self.observer.join(timeout=5); self.observer = None