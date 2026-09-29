"""Filesystem walk + rule orchestration."""

from __future__ import annotations

import os
import time
from fnmatch import fnmatch
from pathlib import Path

from . import __version__
from .model import Finding
from .rules import rules_for_language
from .taint import LANG_BY_EXT, build_context

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    ".next", "dist", "build", "out", "coverage", ".tox", ".mypy_cache",
    "target", "vendor", ".idea", ".vscode", "uploads",
}
MAX_FILE_BYTES = 512 * 1024


def _looks_binary(chunk: bytes) -> bool:
    return b"\x00" in chunk


def _included(rel: str, include: tuple[str, ...]) -> bool:
    """Include globs match the relative path, any parent-directory prefix,
    or a filename pattern anywhere (e.g. "sqli*", "*.ts", "routes/")."""
    if not include:
        return True
    parts = rel.split("/")
    for g in include:
        if fnmatch(rel, g) or fnmatch(rel, g.rstrip("/") + "/*"):
            return True
        if any(fnmatch("/".join(parts[:i]), g) for i in range(1, len(parts) + 1)):
            return True
        if fnmatch(parts[-1], g):
            return True
    return False


def iter_code_files(root: Path, include: tuple[str, ...] = ()):
    """Yield code files under root (or files directly), filtered by include globs."""
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if not _included(rel, include):
                continue
            if LANG_BY_EXT.get(path.suffix.lower()):
                yield path


COMMENT_PREFIXES = {
    "php": ("//", "/*", "*", "#"),
    "js": ("//", "/*", "*"),
    "java": ("//", "/*", "*"),
    "go": ("//", "/*", "*"),
    "py": ("#",),
}


def _line_is_comment(line: str, lang: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    return stripped.startswith(COMMENT_PREFIXES.get(lang, ()))


def scan_path(root: Path, include: tuple[str, ...] = ()) -> tuple[list[Finding], dict]:
    """Scan root and return (findings, stats). Deterministic: sorted by path."""
    findings: list[Finding] = []
    files_scanned = 0
    lines_scanned = 0
    skipped: list[dict] = []
    started = time.time()

    for path in iter_code_files(root, include):
        rel = path.relative_to(root).as_posix() if root.is_dir() else path.name
        try:
            raw = path.read_bytes()
        except OSError as exc:
            skipped.append({"file": rel, "reason": f"unreadable: {exc}"})
            continue
        if len(raw) > MAX_FILE_BYTES:
            skipped.append({"file": rel, "reason": f"too large ({len(raw)} bytes)"})
            continue
        if _looks_binary(raw[:4096]):
            skipped.append({"file": rel, "reason": "binary"})
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
            skipped.append({"file": rel, "reason": "decoded with replacement (not valid UTF-8)"})

        lang = LANG_BY_EXT[path.suffix.lower()]
        lines = text.splitlines()
        files_scanned += 1
        lines_scanned += len(lines)
        ctx = build_context(rel, lang, text)
        for rule in rules_for_language(lang):
            for i, line in enumerate(ctx.lines):
                if _line_is_comment(line, lang):
                    continue
                finding = rule.check(ctx, i, line)
                if finding is not None:
                    findings.append(finding)

    findings.sort(key=lambda f: (f.file, f.line, f.rule_id))
    stats = {
        "files_scanned": files_scanned,
        "lines_scanned": lines_scanned,
        "findings": len(findings),
        "skipped": skipped,
        "duration_seconds": round(time.time() - started, 3),
        "scanner_version": __version__,
    }
    return findings, stats


def scan_report(root: Path, include: tuple[str, ...] = ()) -> dict:
    findings, stats = scan_path(root, include)
    by_class: dict[str, int] = {}
    for f in findings:
        by_class[f.vuln_class] = by_class.get(f.vuln_class, 0) + 1
    return {
        "tool": "sentinel",
        "version": __version__,
        "root": str(root),
        "include": list(include),
        "stats": stats,
        "findings_by_class": by_class,
        "findings": [f.to_dict() for f in findings],
    }
