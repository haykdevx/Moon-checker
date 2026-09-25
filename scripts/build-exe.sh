#!/usr/bin/env bash
#
# Builds dist/MoonCheck.exe — a standalone Windows executable that:
#   * requests administrator rights at launch (embedded UAC manifest),
#   * bundles its own Java runtime (players need nothing installed),
#   * wraps the shaded moon-checker.jar.
#
# Runs entirely on Linux (no Windows needed). Downloads launch4j and a Temurin
# Windows JRE on first run and caches them under build/.
#
# Usage:  scripts/build-exe.sh
# Output also lands in build/panel-downloads/, which web/deploy/deploy.sh publishes
# on the Moon panel's download page and registers as a trusted build.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build"
DIST="$BUILD/dist"
mkdir -p "$BUILD"
VERSION="$(sed -n 's:.*<version>\(.*\)</version>.*:\1:p' "$ROOT/pom.xml" | head -1)"
VERSION4="$VERSION.0"

# Maven from PATH, or the official image when it is not installed.
mvn_run() {
  if command -v mvn >/dev/null 2>&1; then
    (cd "$ROOT" && mvn "$@")
  else
    docker run --rm -u "$(id -u):$(id -g)" -v "$HOME/.m2:/var/maven/.m2" -v "$ROOT:/src" -w /src \
      maven:3.9-eclipse-temurin-21 mvn -Duser.home=/var/maven -Dmaven.repo.local=/var/maven/.m2/repository "$@"
  fi
}

L4J_URL="https://downloads.sourceforge.net/project/launch4j/launch4j-3/3.50/launch4j-3.50-linux-x64.tgz"
JRE_URL="https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jre/hotspot/normal/eclipse"

echo ">> Building shaded jar ($VERSION)"
mvn_run -q -B -ntp -DskipTests package
cp "$ROOT/target/moon-checker.jar" "$BUILD/moon-checker.jar"

if [ ! -d "$BUILD/launch4j" ]; then
  echo ">> Downloading launch4j"
  curl -sL -o "$BUILD/l4j.tgz" "$L4J_URL"
  tar xzf "$BUILD/l4j.tgz" -C "$BUILD"
fi

if [ ! -d "$BUILD/runtime-src" ]; then
  echo ">> Downloading Temurin 21 Windows JRE"
  curl -sL -o "$BUILD/jre.zip" "$JRE_URL"
  mkdir -p "$BUILD/jre-tmp" && (cd "$BUILD/jre-tmp" && unzip -q ../jre.zip)
  mv "$BUILD/jre-tmp/"jdk-* "$BUILD/runtime-src"
  rm -rf "$BUILD/jre-tmp"
fi

echo ">> Writing admin manifest"
cat > "$BUILD/moon.manifest" <<'EOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" processorArchitecture="amd64" name="ru.cs2moon.MoonCheck" type="win32"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
    </application>
  </compatibility>
</assembly>
EOF

# stayAlive=true: the launcher waits for the JVM and returns its exit code, so
# scripted runs (MoonCheck.exe --diagnose / --headless) report success or failure.
echo ">> Writing launch4j config"
cat > "$BUILD/l4j-config.xml" <<EOF
<launch4jConfig>
  <dontWrapJar>false</dontWrapJar>
  <headerType>gui</headerType>
  <jar>$BUILD/moon-checker.jar</jar>
  <outfile>$DIST/MoonCheck.exe</outfile>
  <errTitle>Moon Checker</errTitle>
  <chdir>.</chdir>
  <priority>normal</priority>
  <supportUrl>https://cs2-moon.ru/</supportUrl>
  <stayAlive>true</stayAlive>
  <restartOnCrash>false</restartOnCrash>
  <manifest>$BUILD/moon.manifest</manifest>
  <jre>
    <path>runtime</path>
    <requiresJdk>false</requiresJdk>
    <requires64Bit>true</requires64Bit>
  </jre>
  <versionInfo>
    <fileVersion>$VERSION4</fileVersion>
    <txtFileVersion>$VERSION</txtFileVersion>
    <fileDescription>Moon CS2 anti-cheat checker</fileDescription>
    <copyright>cs2-moon.ru</copyright>
    <productVersion>$VERSION4</productVersion>
    <txtProductVersion>$VERSION</txtProductVersion>
    <productName>Moon Checker</productName>
    <companyName>cs2-moon.ru</companyName>
    <internalName>MoonCheck</internalName>
    <originalFilename>MoonCheck.exe</originalFilename>
    <language>ENGLISH_US</language>
  </versionInfo>
</launch4jConfig>
EOF

echo ">> Running launch4j"
mkdir -p "$DIST"
rm -f "$DIST/MoonCheck.exe" # launch4j can exit 0 on a config error: never ship a stale exe
java -jar "$BUILD/launch4j/launch4j.jar" "$BUILD/l4j-config.xml"
[ -s "$DIST/MoonCheck.exe" ] || { echo "launch4j did not produce MoonCheck.exe" >&2; exit 1; }

echo ">> Staging bundled runtime"
rm -rf "$DIST/runtime"
cp -r "$BUILD/runtime-src" "$DIST/runtime"

echo ">> Packaging zip"
(cd "$DIST" && zip -qr -9 "$BUILD/MoonCheck-$VERSION-win64.zip" MoonCheck.exe runtime)

echo ">> Staging panel downloads"
rm -rf "$BUILD/panel-downloads"
mkdir -p "$BUILD/panel-downloads"
cp "$BUILD/MoonCheck-$VERSION-win64.zip" "$BUILD/panel-downloads/"
cp "$ROOT/target/moon-checker.jar" "$BUILD/panel-downloads/moon-checker-$VERSION.jar"

echo ""
echo "Done."
echo "  Standalone folder : $DIST  (ship the whole folder)"
echo "  Zip               : $BUILD/MoonCheck-$VERSION-win64.zip"
echo "  exe sha256        : $(sha256sum "$DIST/MoonCheck.exe" | cut -d' ' -f1)"
