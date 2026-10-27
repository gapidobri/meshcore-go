#!/bin/sh
# Regenerates testdata/golden.json from the upstream C++ MeshCore sources.
#
# Usage: tools/golden/gen.sh [workdir]
#
# Clones meshcore-dev/meshcore and rweather/arduinolibs (Crypto) at pinned
# commits, builds harness.cpp against them for the host, and runs it.
set -eu

MESHCORE_REPO=https://github.com/meshcore-dev/meshcore
MESHCORE_REV=81dbae592ffad40b4212bc0b37e82b38da08f4bc
CRYPTO_REPO=https://github.com/rweather/arduinolibs
CRYPTO_REV=37a76b8f7516568e1c575b6dc9268da1ccaac6b6

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
work=${1:-$(mktemp -d)}
mkdir -p "$work"

fetch() { # repo rev dir
	if [ ! -d "$3/.git" ]; then
		git init -q "$3"
		git -C "$3" remote add origin "$1"
	fi
	git -C "$3" fetch -q --depth 1 origin "$2"
	git -C "$3" checkout -q FETCH_HEAD
}

fetch "$MESHCORE_REPO" "$MESHCORE_REV" "$work/meshcore"
fetch "$CRYPTO_REPO" "$CRYPTO_REV" "$work/arduinolibs"

mc=$work/meshcore
cr=$work/arduinolibs/libraries/Crypto
obj=$work/obj
mkdir -p "$obj"

for f in "$mc"/lib/ed25519/*.c; do
	cc -O1 -c -I"$mc/lib/ed25519" "$f" -o "$obj/$(basename "$f" .c).o"
done

c++ -std=c++17 -O1 -w \
	-I"$here/shim" -I"$mc/src" -I"$mc/lib/ed25519" -I"$cr" \
	"$here/harness.cpp" "$here/shim/rng_stub.cpp" \
	"$mc/src/Packet.cpp" "$mc/src/Utils.cpp" "$mc/src/Identity.cpp" \
	"$mc/src/Dispatcher.cpp" "$mc/src/Mesh.cpp" \
	"$mc/src/helpers/AdvertDataHelpers.cpp" "$mc/src/helpers/TxtDataHelpers.cpp" \
	"$mc/src/helpers/StaticPoolPacketManager.cpp" \
	"$cr/AES128.cpp" "$cr/AESCommon.cpp" "$cr/BlockCipher.cpp" \
	"$cr/SHA256.cpp" "$cr/SHA512.cpp" "$cr/Hash.cpp" "$cr/Crypto.cpp" \
	"$cr/Ed25519.cpp" "$cr/Curve25519.cpp" "$cr/BigNumberUtil.cpp" \
	"$obj"/*.o \
	-o "$work/harness"

mkdir -p "$root/testdata"
"$work/harness" > "$root/testdata/golden.json"
echo "wrote $root/testdata/golden.json"
