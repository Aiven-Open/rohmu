#!/usr/bin/env python3
import argparse
from pathlib import Path
import re
import subprocess


def make_release(version: str) -> None:
    if not re.match(r"\d+\.\d+.\d+", version):
        raise ValueError(f"Unexpected version: {version!r}, should be N.N.N")
    project_directory = Path(__file__).parent
    version_filename = project_directory / "rohmu/version.py"
    version_filename.write_text(f'VERSION = "{version}"\n')
    subprocess.run(["git", "-C", str(project_directory), "add", str(version_filename)], check=True)
    subprocess.run(["git", "-C", str(project_directory), "commit", "-m", f"Bump to version {version}"], check=True)
    subprocess.run(["git", "-C", str(project_directory), "tag", "-a", f"releases/{version}", "-m", f"Version {version}"], check=True)
    subprocess.run(["git", "-C", str(project_directory), "log", "-n", "1", "-p"], check=True)
    print("Run 'git push --tags' to confirm the release")


if __name__ == '__main__':
    parser = argparse.ArgumentParser("Make a rohmu release")
    parser.add_argument("version")
    args = parser.parse_args()
    make_release(args.version)
