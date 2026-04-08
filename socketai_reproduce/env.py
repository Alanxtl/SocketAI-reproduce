from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv

_LOADED_ENV_PATHS: set[Path] = set()


def load_project_dotenv(start_dir: Path | None = None) -> Path | None:
    search_start = (start_dir or Path.cwd()).resolve()
    candidates = list(search_start.parents)
    candidates.insert(0, search_start)

    package_root = Path(__file__).resolve().parents[1]
    if package_root not in candidates:
        candidates.append(package_root)

    for base_dir in candidates:
        dotenv_path = base_dir / ".env"
        if not dotenv_path.exists():
            continue
        resolved = dotenv_path.resolve()
        if resolved not in _LOADED_ENV_PATHS:
            load_dotenv(dotenv_path=resolved, override=False)
            _LOADED_ENV_PATHS.add(resolved)
        return resolved
    return None
