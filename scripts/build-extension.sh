#!/usr/bin/env bash
set -euo pipefail
ghidra_root="${1:-${GHIDRA_INSTALL_DIR:-}}"
jdk_root="${2:-${JAVA_HOME:-}}"
[[ -n "$ghidra_root" && -n "$jdk_root" ]] || { echo 'Usage: build-extension.sh <Ghidra directory> <JDK directory>' >&2; exit 2; }
ghidra_root="$(cd "$ghidra_root" && pwd)"
repo="$(cd "$(dirname "$0")/.." && pwd)"
version="$(sed -n 's/^application.version=//p' "$ghidra_root/Ghidra/application.properties" | tr -d '\r')"
release="$(sed -n 's/^application.release.name=//p' "$ghidra_root/Ghidra/application.properties" | tr -d '\r')"
java_release="$(sed -n 's/^application.java.compiler=//p' "$ghidra_root/Ghidra/application.properties" | tr -d '\r')"
# Build artifacts stay under ignored build/; no source or prior output is removed.
mkdir -p "$repo/build" "$repo/dist"
build="$(mktemp -d "$repo/build/extension.XXXXXXXX")"
classes="$build/classes"
stage="$build/stage"
extension="$stage/RedlineGhidraMcp"
mkdir -p "$classes" "$extension/lib"
classpath=''
while IFS= read -r -d '' file; do classpath="${classpath:+$classpath:}$file"; done < <(find "$ghidra_root/Ghidra" -type f -path '*/lib/*.jar' ! -path '*/data/*' -print0)
[[ -n "$classpath" ]] || { echo 'No Ghidra jars found' >&2; exit 2; }
quote_arg() { local value="$1"; value="${value//\\/\\\\}"; value="${value//\"/\\\"}"; printf '"%s"\n' "$value"; }
{
  for value in --release "$java_release" -proc:none -encoding UTF-8 -classpath "$classpath" -d "$classes"; do quote_arg "$value"; done
  while IFS= read -r -d '' file; do quote_arg "$file"; done < <(find "$repo/java/src/main/java" -name '*.java' -print0)
} > "$build/javac.args"
"$jdk_root/bin/javac" "@$build/javac.args"
# The jar basename must start with the module name for production plugin discovery.
"$jdk_root/bin/jar" --create --file "$extension/lib/RedlineGhidraMcp.jar" -C "$classes" .
sed -e "s/@ghidraVersion@/$version/g" -e "s/@date@/$(date +%F)/g" "$repo/java/extension.properties" > "$extension/extension.properties"
cp "$repo/java/Module.manifest" "$extension/Module.manifest"
archive="$repo/dist/ghidra_${version}_${release}_$(date +%Y%m%d-%H%M%S)_RedlineGhidraMcp.zip"
"$jdk_root/bin/jar" --create --no-manifest --file "$archive" -C "$stage" RedlineGhidraMcp
printf '%s\n' "$archive"
