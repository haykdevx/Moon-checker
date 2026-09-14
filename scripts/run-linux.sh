#!/usr/bin/env bash
# Run Moon Checker on Linux. Requires Java 21+.
# For full coverage (all users, kernel state) run as root:  sudo ./run-linux.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JAR="$ROOT/target/moon-checker.jar"
if [ ! -f "$JAR" ]; then
  echo "Building jar..."; (cd "$ROOT" && mvn -q -DskipTests package)
fi
exec java -jar "$JAR"
