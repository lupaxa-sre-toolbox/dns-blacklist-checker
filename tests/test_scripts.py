"""Console script entry points."""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from pathlib import Path


def test_both_commands_share_main() -> None:
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    scripts = data["project"]["scripts"]
    target = "lupaxa.dns_blacklist_checker.cli:main"
    assert scripts["dns-blacklist-checker"] == target
    assert scripts["dnsbl"] == target


def test_python_m_module_requires_target() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": "src"}
    result = subprocess.run(
        [sys.executable, "-m", "lupaxa.dns_blacklist_checker"],
        cwd=repo_root,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "TARGET" in result.stderr
