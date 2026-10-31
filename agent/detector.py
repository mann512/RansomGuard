import math, time
from collections import Counter, deque
from pathlib import Path
from . import config
def shannon_entropy(data):
    if not data: return 0.0
    counts = Counter(data); length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
def file_entropy(path):
    try:
        with open(path, "rb") as f: return shannon_entropy(f.read(config.ENTROPY_MAX_BYTES))
    except Exception: return 0.0
class Detector:
    def __init__(self): self._events = deque(maxlen=4000); self._entropy = {}; self.suppressed_paths = set()
    def suppress(self, path): self.suppressed_paths.add(str(path))
    def unsuppress(self, path): self.suppressed_paths.discard(str(path))
    def record_event(self, path, event_type, entropy=None):
        path = str(path)
        if path in self.suppressed_paths: return None
        now = time.time(); self._events.append((now, path, event_type)); signals, score = [], 0
        if Path(path).name.startswith(config.CANARY_PREFIX) and event_type != "created": score += 100; signals.append("canary modified")
        if entropy is not None:
            prev = self._entropy.get(path); self._entropy[path] = entropy
            if prev is not None and entropy > config.ENTROPY_THRESHOLD and (entropy - prev) > config.ENTROPY_DELTA: score += 30; signals.append(f"entropy spike {prev:.2f}->{entropy:.2f}")
        if Path(path).suffix.lower() in config.SUSPICIOUS_EXTENSIONS: score += 25; signals.append("suspicious ext")
        recent_mods = [e for e in self._events if e[2] == "modified" and now - e[0] <= config.MASS_MOD_WINDOW]
        if len(recent_mods) >= config.MASS_MOD_THRESHOLD: score += 50; signals.append(f"{len(recent_mods)} mods in {config.MASS_MOD_WINDOW}s")
        recent_renames = [e for e in self._events if e[2] == "moved" and now - e[0] <= config.MASS_RENAME_WINDOW]
        if len(recent_renames) >= config.MASS_RENAME_THRESHOLD: score += 40; signals.append(f"{len(recent_renames)} renames in {config.MASS_RENAME_WINDOW}s")
        if score == 0: return None
        sev = "critical" if score >= config.RISK_CRITICAL else "high" if score >= config.RISK_HIGH else "medium" if score >= config.RISK_MEDIUM else "low"
        return {"score": score, "severity": sev, "signals": signals, "path": path}
    def recent_affected_paths(self, window=30):
        now = time.time(); return {e[1] for e in self._events if now - e[0] <= window}
    def recent_events(self, limit=100): return [{"timestamp": ts, "path": p, "event": e} for ts, p, e in list(self._events)[-limit:]]
    def threat_level(self, window=10):
        recent = sum(1 for e in self._events if time.time() - e[0] <= window); level = min(100, recent * 4)
        label = "critical" if level >= 70 else "high" if level >= 40 else "medium" if level >= 15 else "safe"
        return {"level": level, "label": label, "recent_events": recent, "window": window}