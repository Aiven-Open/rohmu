#!/usr/bin/env python3
from pathlib import Path

import argparse
import re
import subprocess


def make_release(version: str) -> None:
    if not re.match(r"\d+\.\d+.\d+", version):
        raise ValueError(f"Unexpected version: {version!r}, should be N.N.N")
    project_directory = Path(__file__).parent
    subprocess.run(
        ["git", "-C", str(project_directory), "tag", "-s", "-a", f"releases/{version}", "-m", f"Version {version}"],
        check=True,
    )
    subprocess.run(["git", "-C", str(project_directory), "log", "-n", "1", "-p"], check=True)
    print("Run 'git push --follow-tags' to confirm the release")


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Make a rohmu release")
    parser.add_argument("version")
    args = parser.parse_args()
    make_release(args.version)
