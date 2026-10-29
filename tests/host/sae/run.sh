#!/bin/sh
# Host-side SAE tests. Run on macOS from the repository root:
#   sh tests/host/sae/run.sh
set -e

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="$root/build/host-tests"
mkdir -p "$out"

# Everything is compiled as C++: ec_p256_m31.c and i31.c use static_cast, and a
# single language keeps the BearSSL symbols from being mangled differently.
# The shim header is force-included because the vendored crypto headers assume
# the kernel's sys/types.h has already supplied u_int/u8/uint32_t.
clang++ -x c++ -std=c++17 -O1 -g -Wall -Wextra -Wno-unused-parameter \
	-include "$here/shim/sae_shim.h" \
	-I"$here/shim" -I"$root/itl80211/openbsd" \
	"$here/sae_host_test.cpp" \
	"$root/itl80211/openbsd/net80211/ieee80211_sae.c" \
	"$root/itl80211/openbsd/crypto/ec_p256_m31.c" \
	"$root/itl80211/openbsd/crypto/i31.c" \
	"$root/itl80211/openbsd/crypto/sha2.c" \
	"$root/itl80211/openbsd/crypto/sha1.c" \
	"$root/itl80211/openbsd/crypto/sha1-pbkdf2.c" \
	"$root/itl80211/openbsd/crypto/md5.c" \
	"$root/itl80211/openbsd/crypto/hmac.c" \
	-Wno-error \
	-o "$out/sae_host_test"

exec "$out/sae_host_test"
