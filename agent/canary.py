import os, random, uuid
from pathlib import Path
from . import config
def create_canary(folder):
    folder = Path(folder); folder.mkdir(parents=True, exist_ok=True)
    name = f"{config.CANARY_PREFIX}{uuid.uuid4().hex[:8]}{random.choice(config.CANARY_EXTENSIONS)}"
    path = folder / name; path.write_bytes(b"RansomGuard canary file.\n" * 20); return path
def list_canaries(folder):
    folder = Path(folder)
    return sorted(folder.glob(f"{config.CANARY_PREFIX}*")) if folder.exists() else []
def _walk_pruned(folder):
    folder = Path(folder).resolve(); root_depth = len(folder.parts)
    for root, dirs, files in os.walk(folder):
        root_path = Path(root); depth = len(root_path.parts) - root_depth
        dirs[:] = [d for d in dirs if d not in config.DEFAULT_SKIP_DIRS and not (root_path / d).is_symlink()]
        if depth >= config.CANARY_MAX_DEPTH: dirs[:] = []
        yield root_path, files
def plant_canaries_recursive(folder, max_depth=None, max_count=None):
    folder = Path(folder).resolve()
    if not folder.exists(): return 0
    max_count = max_count if max_count is not None else config.CANARY_MAX_PER_TREE
    created = 0
    for root_path, _files in _walk_pruned(folder):
        if created >= max_count: break
        try:
            if not list_canaries(root_path): create_canary(root_path); created += 1
        except Exception: pass
    return created
def count_canaries_recursive(folder):
    total, samples = 0, []
    for root_path, _files in _walk_pruned(folder):
        cs = list_canaries(root_path); total += len(cs)
        if len(samples) < 20: samples.extend(str(c) for c in cs[:20 - len(samples)])
    return total, samples
def verify_canaries(folders):
    return {str(f): {"count": count_canaries_recursive(f)[0], "healthy": count_canaries_recursive(f)[0] > 0, "files": count_canaries_recursive(f)[1]} for f in map(Path, folders) if f.exists()}
def recreate_missing_canaries(folders): return sum(plant_canaries_recursive(Path(f)) for f in folders)