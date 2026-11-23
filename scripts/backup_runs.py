"""Freeze the current demo results (runs/ without sandboxes) into presentation/demo_backup_<time>.zip.
If Wi-Fi or an API fails during a demo, unzip it into runs/ and serve it: every page and JSON is already there.

    python scripts/backup_runs.py
"""
import zipfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
out_dir = ROOT / "presentation"
out_dir.mkdir(exist_ok=True)
zip_path = out_dir / f"demo_backup_{datetime.now():%Y%m%d_%H%M}.zip"
n = 0
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
    for p in (ROOT / "runs").rglob("*"):
        rel = p.relative_to(ROOT / "runs")
        if p.is_file() and "sandbox" not in rel.parts and "_scanner_probe" not in rel.parts:
            z.write(p, Path("runs") / rel)
            n += 1
print(f"{n} files -> {zip_path}")
print("restore: Expand-Archive <zip> -DestinationPath . -Force   (from the project folder)")
