#!/bin/sh
# Usage: ./check.sh /path/to/laravel-project [extra args]
# Compatible with: Linux, macOS, WSL2, Git Bash

set -e

PROJECT="${1:?Usage: ./check.sh /path/to/laravel-project}"
shift

# Resolve absolute path — works on Linux, macOS, Git Bash, WSL2
# (realpath is not available on stock macOS without coreutils)
resolve_path() {
    if command -v realpath > /dev/null 2>&1; then
        realpath "$1"
    else
        # POSIX fallback: cd + pwd
        (cd "$1" && pwd)
    fi
}

ABS_PATH="$(resolve_path "$PROJECT")"

# On Git Bash (Windows), Docker expects /c/Users/... not C:\Users\...
# Git Bash already converts paths automatically via MSYS, so no conversion needed.

docker run --rm \
  -v "${ABS_PATH}:/project:ro" \
  laravel-sca-checker \
  /project "$@"
