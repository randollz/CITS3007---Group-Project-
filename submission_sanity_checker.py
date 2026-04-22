#!/usr/bin/env python3

"""
sanity-check a project submission.

Takes one argument, path to a zip file containing Makefile and source code
"""

import argparse
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

def die(msg: str, code: int = 1) -> None:
  "exit with an error message"
  print(msg, file=sys.stderr)
  raise SystemExit(code)

_GROUP_PATTERN = re.compile(r"group[^a-zA-Z0-9]*\d{1,2}", re.IGNORECASE)

def filename_matches_group(zip_path: Path) -> bool:
  """
  Returns True if the zip filename contains:
    'group' (case-insensitive),
    followed by zero or more non-alphanumeric characters,
    followed by 1-2 digits.
  """
  filename = zip_path.name
  return _GROUP_PATTERN.search(filename) is not None

def has_bad_artifacts(root: Path) -> bool:
  "check for binary artifacts"
  bad_suffixes = {".pdf", ".zip", ".o"}
  bad_names = {".git", "bun_parser"}

  for p in root.rglob("*"):
    if p.name in bad_names:
      return True
    if p.is_file() and p.suffix in bad_suffixes:
      return True

  return False

def run_command(cmd, cwd: Path, err_msg: str) -> None:
  "run command in a directory"
  print("+", " ".join(cmd), file=sys.stderr)
  result = subprocess.run(cmd, cwd=cwd, check=False)
  if result.returncode != 0:
    die(err_msg)

def file_count_excessive(root: Path, limit: int) -> bool:
  """
  Count total files + directories under root (including root).
  False if the count exceeds `limit`.
  """
  count = 1  # include root itself

  for _ in root.rglob("*"):
    count += 1
    if count > limit:
      return True
  return False

def die_on_file_size_excessive(root: Path, max_bytes: int = 512 * 1024) -> None:
  """
  Ensure no file under root exceeds max_bytes (default 512 KiB).
  """
  for p in root.rglob("*"):
    if p.is_file():
      size = p.stat().st_size
      if size > max_bytes:
        die(f"invalid submission, file too large: {p} ({size} bytes)")

def process_setup_script(setup_path: Path, cwd: Path) -> None:
  "run setup script"
  try:
    with setup_path.open("r", encoding="utf-8") as f:
      for line in f:
        if line.startswith("sudo apt-get install") or line.startswith("git clone"):
          cmd = line.split()
          run_command(cmd, cwd, f"setup.sh command failed: {line}")
  except FileNotFoundError:
    pass

def main() -> None:
  "main"
  parser = argparse.ArgumentParser()
  parser.add_argument("zip_path", type=Path)
  args = parser.parse_args()

  zip_path = args.zip_path
  if not zip_path.exists():
    die("zip file does not exist")

  if not filename_matches_group(zip_path):
    print("Tip: does your filename describe what group this submission is for?")

  with tempfile.TemporaryDirectory() as tmpdir:
    root = Path(tmpdir)

    with zipfile.ZipFile(zip_path, "r") as z:
      z.extractall(root)

    if not (root / "Makefile").exists():
      die("invalid submission, no Makefile")

    if has_bad_artifacts(root):
      die("invalid submission, contains binary artifacts")

    file_limit = 20
    if file_count_excessive(root, file_limit):
      die(f"invalid submission, too many files/directories (>{file_limit})")

    die_on_file_size_excessive(root)

    setup_file = root / "setup.sh"
    if setup_file.exists():
      process_setup_script(setup_file, root)

    run_command(["make", "all"], root, "compilation failed")

    if not (root / "bun_parser").exists():
      die("compilation failed to produce a 'bun_parser' binary")

    print("Makefile produced a bun_parser executable")
    sys.exit(0)


if __name__ == "__main__":
  main()
