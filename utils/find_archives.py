import hashlib
import json
from pathlib import Path
import tarfile
from typing import Any, Dict, Iterable, List, Optional
import zipfile

from socketai_reproduce.config import compact_path_label

ARCHIVE_EXTS = (".tgz", ".tar.gz", ".tar", ".zip")


def sha1_short(p: Path) -> str:
    return hashlib.sha1(str(p).encode()).hexdigest()[:10]


def find_archives(root: Path):
    for p in root.rglob("*"):
        if p.is_file():
            lower = p.name.lower()
            for ext in ARCHIVE_EXTS:
                if lower.endswith(ext):
                    yield p
                    break


def _resolve_within(base: Path, target: Path) -> Path:
    base_resolved = base.resolve()
    target_resolved = target.resolve()
    try:
        target_resolved.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError(f"unsafe archive entry path: {target}") from exc
    return target_resolved


def safe_extract_tar(tar_path: Path, dest: Path):
    with tarfile.open(tar_path, "r:*") as tf:
        for member in tf.getmembers():
            member_path = dest / member.name
            _resolve_within(dest, member_path)
        tf.extractall(dest, filter="data")


def safe_extract_zip(zip_path: Path, dest: Path, pwd: str = "infected"):
    z = zipfile.ZipFile(zip_path)
    try:
        for member in z.infolist():
            member_path = dest / member.filename
            _resolve_within(dest, member_path)
        z.extractall(path=dest, pwd=pwd.encode())
    except RuntimeError:
        z.extractall(path=dest)


def extract_archive_raw(archive_path: Path, tmpdir: Path) -> Path:
    archive_label = compact_path_label(archive_path.stem, max_length=20, default="archive")
    outdir = tmpdir / f"{archive_label}_{sha1_short(archive_path)}"
    outdir.mkdir(parents=True, exist_ok=True)
    if archive_path.suffix.lower() == ".zip" or archive_path.name.lower().endswith(
        ".zip"
    ):
        safe_extract_zip(archive_path, outdir)
    else:
        safe_extract_tar(archive_path, outdir)

    return outdir


def _choose_shortest(paths: List[Path]) -> Path:
    # deterministic: choose the path with fewest components (closest to outdir)
    return sorted(paths, key=lambda p: len(p.parts))[0]


def detect_package_root(extracted_dir: Path) -> Optional[Path]:
    """
    Detect logical package root directory after extraction.
    Priority:
      1) directory named 'package' containing package.json  (common in npm pack layouts)
      2) any directory containing package.json (choose closest)
      3) fallback: extracted_dir itself if it contains package.json
    """
    # 0) extracted_dir itself
    if (extracted_dir / "package.json").exists():
        return extracted_dir

    # 1) **/package/package.json
    candidates = list(extracted_dir.rglob("package/package.json"))
    if candidates:
        pj = _choose_shortest(candidates)
        return pj.parent  # .../package

    # 2) any **/package.json (closest)
    candidates = list(extracted_dir.rglob("package.json"))
    if candidates:
        pj = _choose_shortest(candidates)
        return pj.parent

    return None


def extract_archive(archive_path: Path, tmpdir: Path) -> Path:
    """
    Wrapper around your extract_archive() that returns the *logical package root*
    instead of the raw extracted directory.
    """
    extracted = extract_archive_raw(archive_path, tmpdir)  # your existing function
    pkg_root = detect_package_root(extracted)
    return pkg_root if pkg_root is not None else extracted


def load_nearest_package_json(root: Path) -> Optional[Dict[str, Any]]:
    try:
        cands = list(root.glob("**/package.json"))
        if not cands:
            return None
        cands.sort(key=lambda p: len(p.parts))
        return json.loads(cands[0].read_text(encoding="utf-8", errors="ignore")), cands[
            0
        ]
    except Exception:
        return None, None


JS_EXTS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".cts", ".mts"}
TEXT_EXTS = {
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".cts",
    ".mts",
    ".md",
    ".txt",
    ".sh",
    ".postinstall",
    ".bat",
}


def iter_js_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in JS_EXTS:
            try:
                if p.stat().st_size < 5 * 1024 * 1024:
                    yield p
            except Exception:
                continue


def iner_text_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in TEXT_EXTS:
            try:
                if p.stat().st_size < 5 * 1024 * 1024:
                    yield p
            except Exception:
                continue


import re
from pathlib import Path
from typing import Iterable
import hashlib

# Recognized script extensions (leading dot included)
SCRIPT_EXTS = {
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".cts",
    ".mts",
    ".sh",
    ".bash",
    ".zsh",
    ".ksh",
    ".bat",
    ".cmd",
    ".ps1",
    ".psm1",
}

# Shebang keywords to detect interpreters (lowercase match)
SHEBANG_KEYWORDS = {
    "node",
    "nodejs",
    "sh",
    "bash",
    "zsh",
    "ksh",
    "python",
    "python3",
    "pwsh",
    "powershell",
    "cmd",
    "env",
}

# Maximum read size (same as the original)
MAX_SIZE = 5 * 1024 * 1024


def has_shebang_interpreter(path: Path) -> bool:
    """Read the file header and check for a shebang with known interpreter keywords."""
    try:
        with path.open("rb") as f:
            head = f.read(2048)  # Read the first bytes
    except Exception:
        return False
    if not head:
        return False
    # Only check whether the file starts with #!
    if not head.startswith(b"#!"):
        return False
    # Decode the shebang line to ASCII/UTF-8 and lowercase for keyword matching
    try:
        # Use errors='ignore' to avoid decode errors
        line = head.splitlines()[0].decode("utf-8", errors="ignore").lower()
    except Exception:
        return False
    # Check for any known keyword
    for kw in SHEBANG_KEYWORDS:
        if kw in line:
            return True
    return False


def normalized_sha256_no_ascii_whitespace(path: Path) -> str:
    """
    Compute SHA256 after removing ASCII whitespace bytes (space, tab, CR, LF, VT, FF).
    Reads in chunks to keep memory usage low.
    Returns the hex digest string.
    """
    # ASCII whitespace bytes to remove: 0x09,0x0A,0x0B,0x0C,0x0D,0x20
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                # Strip the specified ASCII whitespace bytes
                norm = chunk.translate(None, b"\t\n\x0b\x0c\r ")
                if norm:
                    h.update(norm)
    except Exception:
        raise
    return h.hexdigest()


def iter_dangerous_files(root: Path) -> Iterable[Path]:
    """
    Walk root and yield potentially risky script files:
    - Files whose extension is in SCRIPT_EXTS
    - Files without an extension but with a shebang pointing to an interpreter
    Skip files larger than MAX_SIZE (default 5 MB).
    """
    for p in root.rglob("*"):
        try:
            if not p.is_file():
                continue
            # Size check (stat first for efficiency)
            try:
                sz = p.stat().st_size
            except Exception:
                continue
            if sz >= MAX_SIZE:
                continue

            ext = p.suffix.lower()
            if ext in SCRIPT_EXTS:
                yield p
                continue

            # If there is no standard extension, check the shebang.
            # Note: some scripts have extensions without shebangs; extension checks already
            # cover most cases.
            if ext == "" or ext not in SCRIPT_EXTS:
                if has_shebang_interpreter(p):
                    yield p
        except Exception:
            # Ignore per-file errors and continue walking
            continue


def iter_text_files(root: Path) -> Iterable[Path]:
    exts = {".sh"}
    for p in root.rglob("*"):
        if p.is_file() and (p.suffix.lower() in exts or p.name == "package.json"):
            try:
                if p.stat().st_size < 5 * 1024 * 1024:
                    yield p
            except Exception:
                continue


def cached_texts(root: Path) -> Dict[Path, str]:
    texts = {}
    for p in iter_text_files(root):
        try:
            texts[p] = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            pass
    return texts


def cached_js_texts(root: Path) -> Dict[Path, str]:
    texts = {}
    for p in iter_js_files(root):
        try:
            texts[p] = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            pass
    return texts
