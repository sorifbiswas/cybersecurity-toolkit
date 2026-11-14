#!/usr/bin/env python3
"""
Cybersecurity Toolkit - File Organizer

Sorts files in a folder into sub-folders by type (Images, Documents, ...).
Useful for tidying downloads, evidence folders and scan-report directories.

Examples:
    python file_organizer.py ~/Downloads --dry-run
    python file_organizer.py ~/Downloads
    python file_organizer.py ~/Downloads --undo
"""

import argparse
import json
import logging
import shutil
import sys
from pathlib import Path

CATEGORIES = {
    "Images": {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp"},
    "Documents": {".pdf", ".doc", ".docx", ".txt", ".md", ".odt", ".rtf"},
    "Spreadsheets": {".xls", ".xlsx", ".csv", ".ods"},
    "Archives": {".zip", ".tar", ".gz", ".rar", ".7z"},
    "Code": {".py", ".sh", ".js", ".c", ".cpp", ".java", ".html", ".css"},
    "Logs_Reports": {".log", ".json", ".xml", ".pcap", ".pcapng"},
    "Media": {".mp3", ".mp4", ".mkv", ".wav", ".avi"},
}
UNDO_FILE = ".organizer_history.json"


def category_for(path: Path) -> str:
    ext = path.suffix.lower()
    for name, exts in CATEGORIES.items():
        if ext in exts:
            return name
    return "Others"


def unique_destination(dest: Path) -> Path:
    """Never overwrite: add _1, _2 ... if the name is already taken."""
    if not dest.exists():
        return dest
    i = 1
    while True:
        candidate = dest.with_name(f"{dest.stem}_{i}{dest.suffix}")
        if not candidate.exists():
            return candidate
        i += 1


def organize(folder: Path, dry_run: bool) -> None:
    moves = []
    for item in sorted(folder.iterdir()):
        # Skip folders, symlinks, hidden files and this script itself
        if (not item.is_file() or item.is_symlink()
                or item.name.startswith(".")
                or item.resolve() == Path(__file__).resolve()):
            continue
        target_dir = folder / category_for(item)
        dest = unique_destination(target_dir / item.name)
        logging.info("%s -> %s", item.name, dest.relative_to(folder))
        if not dry_run:
            target_dir.mkdir(exist_ok=True)
            shutil.move(str(item), str(dest))
            moves.append({"from": str(item), "to": str(dest)})

    if dry_run:
        logging.info("Dry run: kichu move kora hoyni.")
    elif moves:
        (folder / UNDO_FILE).write_text(json.dumps(moves, indent=2))
        logging.info("%d file move hoyeche. Undo: --undo", len(moves))
    else:
        logging.info("Move korar moto kono file nai.")


def undo(folder: Path) -> None:
    history = folder / UNDO_FILE
    if not history.exists():
        logging.error("Undo history paoa jayni.")
        return
    for m in reversed(json.loads(history.read_text())):
        src, dst = Path(m["to"]), Path(m["from"])
        if src.exists() and not dst.exists():
            shutil.move(str(src), str(dst))
            logging.info("Restored: %s", dst.name)
    history.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description="Organize files by type.")
    parser.add_argument("folder", type=Path, help="Folder to organize")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview only, do not move files")
    parser.add_argument("--undo", action="store_true",
                        help="Undo the last organize run")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    folder = args.folder.expanduser().resolve()
    if not folder.is_dir():
        logging.error("Folder paoa jayni: %s", folder)
        return 1

    undo(folder) if args.undo else organize(folder, args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
