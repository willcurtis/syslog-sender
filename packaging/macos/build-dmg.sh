#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION="$(python -c 'from logsalvo import __version__; print(__version__)')"
MACHINE_ARCH="$(uname -m)"

case "$MACHINE_ARCH" in
  arm64|x86_64) ARCH="$MACHINE_ARCH" ;;
  *)
    echo "Unsupported macOS architecture: $MACHINE_ARCH" >&2
    exit 1
    ;;
esac

BUILD_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/logsalvo-macos-$ARCH.XXXXXX")"
APP_DIST="$BUILD_ROOT/dist"
DMG_STAGE="$BUILD_ROOT/dmg"
ICONSET="$BUILD_ROOT/LogSalvo.iconset"
ICON="$BUILD_ROOT/LogSalvo.icns"
DMG_NAME="LogSalvo-$VERSION-macOS-$ARCH-unsigned.dmg"
DMG_PATH="$PROJECT_ROOT/dist/$DMG_NAME"

cleanup() {
  case "$BUILD_ROOT" in
    "${TMPDIR:-/tmp}"/logsalvo-macos-*) rm -rf -- "$BUILD_ROOT" ;;
    *) echo "Refusing to clean unexpected temporary path: $BUILD_ROOT" >&2 ;;
  esac
}
trap cleanup EXIT

rm -f -- "$DMG_PATH" "$DMG_PATH.sha256"
mkdir -p "$ICONSET" "$APP_DIST" "$DMG_STAGE" "$PROJECT_ROOT/dist"

SOURCE_ICON="$PROJECT_ROOT/logsalvo/assets/tts-round-outline.png"
while read -r filename pixels; do
  sips -z "$pixels" "$pixels" "$SOURCE_ICON" --out "$ICONSET/$filename" >/dev/null
done <<'SIZES'
icon_16x16.png 16
icon_16x16@2x.png 32
icon_32x32.png 32
icon_32x32@2x.png 64
icon_128x128.png 128
icon_128x128@2x.png 256
icon_256x256.png 256
icon_256x256@2x.png 512
icon_512x512.png 512
icon_512x512@2x.png 1024
SIZES
iconutil -c icns "$ICONSET" -o "$ICON"

python -m PyInstaller \
  --clean \
  --noconfirm \
  --windowed \
  --name LogSalvo \
  --icon "$ICON" \
  --osx-bundle-identifier com.thetechshed.logsalvo \
  --distpath "$APP_DIST" \
  --workpath "$BUILD_ROOT/pyinstaller" \
  --specpath "$BUILD_ROOT" \
  --collect-data logsalvo \
  "$PROJECT_ROOT/packaging/macos/launcher.py"

test -x "$APP_DIST/LogSalvo.app/Contents/MacOS/LogSalvo"
test -f "$APP_DIST/LogSalvo.app/Contents/Resources/LogSalvo.icns"
PLIST="$APP_DIST/LogSalvo.app/Contents/Info.plist"
if /usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$PLIST" &>/dev/null; then
  /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$PLIST"
else
  /usr/libexec/PlistBuddy -c "Add :CFBundleShortVersionString string $VERSION" "$PLIST"
fi
if /usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "$PLIST" &>/dev/null; then
  /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $VERSION" "$PLIST"
else
  /usr/libexec/PlistBuddy -c "Add :CFBundleVersion string $VERSION" "$PLIST"
fi
clear_extended_attributes() {
  find "$APP_DIST/LogSalvo.app" -type f -exec xattr -c {} +
  find "$APP_DIST/LogSalvo.app" -type d -exec xattr -c {} +
}
clear_extended_attributes
if ! codesign --force --deep --sign - "$APP_DIST/LogSalvo.app"; then
  clear_extended_attributes
  codesign --force --deep --sign - "$APP_DIST/LogSalvo.app"
fi
plutil -lint "$APP_DIST/LogSalvo.app/Contents/Info.plist"

cp -R "$APP_DIST/LogSalvo.app" "$DMG_STAGE/"
ln -s /Applications "$DMG_STAGE/Applications"
hdiutil create \
  -volname "LogSalvo $VERSION Development" \
  -srcfolder "$DMG_STAGE" \
  -ov \
  -format UDZO \
  "$DMG_PATH"

(
  cd "$PROJECT_ROOT/dist"
  shasum -a 256 "$DMG_NAME" > "$DMG_NAME.sha256"
)

echo "Created $DMG_PATH"
echo "Created $DMG_PATH.sha256"
