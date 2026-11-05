#!/bin/bash
# Builds HyRoute.app for macOS (Apple Silicon and Intel in one universal
# bundle) and zips it: dist/HyRoute-<version>-macos-universal.zip. Runs on a Mac with the
# Xcode command line tools and Go. The cores (hysteria, xray) are
# downloaded from the URLs pinned in build/deps.json and checked against
# their SHA-256 there. The bundle is not signed by a developer ID: macOS
# asks the user to allow it once (docs/MACOS.md).
#
#   scripts/build-macos.sh [version]
set -euo pipefail
cd "$(dirname "$0")/.."
version=${1:-$(git describe --tags --always 2>/dev/null || echo v0.0.0-dev)}
build=$(git rev-parse --short HEAD 2>/dev/null || echo dev)
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then build="$build-dirty"; fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
deps=build/deps.json
dep() { plutil -extract "$1" raw -o - "$deps"; }
check() { # file sha256
	got=$(shasum -a 256 "$1" | cut -d' ' -f1)
	if [ "$got" != "$2" ]; then
		echo "checksum mismatch: $1: $got, want $2" >&2
		exit 1
	fi
}

for arch in arm64 amd64; do
	echo "== HyRoute $arch"
	CGO_ENABLED=1 GOOS=darwin GOARCH=$arch \
		CGO_LDFLAGS="-framework UniformTypeIdentifiers -mmacosx-version-min=11.0" \
		CGO_CFLAGS="-mmacosx-version-min=11.0" \
		go build -trimpath -tags desktop,production \
		-ldflags "-s -w -X main.version=$version -X main.build=$build" \
		-o "$work/HyRoute-$arch" ./cmd/hyroute
	CGO_ENABLED=0 GOOS=darwin GOARCH=$arch go build -trimpath \
		-ldflags "-s -w -X main.version=$version" -o "$work/hyroutectl-$arch" ./cmd/hyroutectl

	echo "== hysteria $arch"
	curl -fsSL -o "$work/hysteria-$arch" "$(dep macos.hysteria.$arch.url)"
	check "$work/hysteria-$arch" "$(dep macos.hysteria.$arch.sha256)"

	echo "== xray $arch"
	curl -fsSL -o "$work/xray-$arch.zip" "$(dep macos.xray.$arch.url)"
	check "$work/xray-$arch.zip" "$(dep macos.xray.$arch.sha256)"
	mkdir -p "$work/x-$arch"
	unzip -q -o "$work/xray-$arch.zip" xray -d "$work/x-$arch"
	check "$work/x-$arch/xray" "$(dep macos.xray.$arch.xray)"
	mv "$work/x-$arch/xray" "$work/xray-$arch"
done

app="$work/HyRoute.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
lipo -create -output "$app/Contents/MacOS/HyRoute" "$work/HyRoute-arm64" "$work/HyRoute-amd64"
lipo -create -output "$app/Contents/Resources/hysteria" "$work/hysteria-arm64" "$work/hysteria-amd64"
lipo -create -output "$app/Contents/Resources/xray" "$work/xray-arm64" "$work/xray-amd64"
lipo -create -output "$app/Contents/Resources/hyroutectl" "$work/hyroutectl-arm64" "$work/hyroutectl-amd64"
chmod 755 "$app/Contents/MacOS/HyRoute" "$app/Contents/Resources/hysteria" "$app/Contents/Resources/xray" "$app/Contents/Resources/hyroutectl"
sed "s/@VERSION@/${version#v}/g" build/macos/Info.plist > "$app/Contents/Info.plist"
cp THIRD-PARTY-NOTICES* LICENSE* "$app/Contents/Resources/" 2>/dev/null || true

# The icon: build/windows/icon.png in every size macOS asks for.
iconset="$work/HyRoute.iconset"
mkdir -p "$iconset"
for s in 16 32 128 256 512; do
	sips -z $s $s build/windows/icon.png --out "$iconset/icon_${s}x${s}.png" >/dev/null
	sips -z $((s * 2)) $((s * 2)) build/windows/icon.png --out "$iconset/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns -o "$app/Contents/Resources/HyRoute.icns" "$iconset"

# Ad hoc signature: Apple Silicon runs only signed code, and a bundle
# signed as a whole is not reported as damaged.
codesign --force --deep --sign - "$app"
codesign --verify --deep "$app"

mkdir -p dist
zip="dist/HyRoute-${version#v}-macos-universal.zip"
rm -f "$zip"
ditto -c -k --keepParent "$app" "$zip"
echo "$zip ($build)"
(cd dist && shasum -a 256 "$(basename "$zip")" > SHA256SUMS-macos)
