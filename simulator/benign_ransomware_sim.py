"""
BENIGN ransomware simulator for the RansomGuard demo.
- Overwrites files with random bytes (NOT real encryption).
- Renames files to *.<ext>.locked.
- Writes its own PID so RansomGuard can terminate it.
"""
import argparse
import os
import sys
import time
from pathlib import Path

PID_FILE = Path(__file__).resolve().parent.parent / "data" / "simulator.pid"

def simulate(folder: Path, seconds: int = 25, rate: float = 4.0):
    folder = Path(folder)
    if not folder.is_dir():
        print(f"[sim] Folder not found: {folder}")
        sys.exit(1)

    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))
    print(f"[sim] PID {os.getpid()} simulating on {folder}", flush=True)

    files = [p for p in folder.rglob("*") if p.is_file() and not p.name.startswith(".ransomguard") and not p.name.endswith(".locked")]
    if not files:
        print("[sim] No target files found!")
        return

    end = time.time() + seconds
    touched = 0
    while files and time.time() < end:
        f = files.pop(0)
        try:
            data = f.read_bytes()
            f.write_bytes(os.urandom(len(data)))
            new_path = f.with_suffix(f.suffix + ".locked")
            if not new_path.exists():
                f.rename(new_path)
            touched += 1
            print(f"[sim] touched {f.name}", flush=True)
        except Exception as e:
            print(f"[sim] skip {f.name}: {e}", flush=True)
        time.sleep(1.0 / rate)

    print(f"[sim] done, touched {touched} files", flush=True)
    try: PID_FILE.unlink()
    except FileNotFoundError: pass

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("folder", help="Folder to simulate attacks on (demo only!)")
    ap.add_argument("--seconds", type=int, default=25)
    ap.add_argument("--rate", type=float, default=4.0)
    args = ap.parse_args()
    simulate(Path(args.folder), args.seconds, args.rate)