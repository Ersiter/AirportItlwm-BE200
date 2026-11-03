#!/bin/sh
# Host-side SAE tests. Run on macOS from the repository root:
#   sh tests/host/sae/run.sh
set -e

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="$root/build/host-tests"
mkdir -p "$out"

# Compile the production formatters and identity selection in the host test.
{
    sed -n -e '/^#define.*IEEE80211_ADDR_EQ(/p' -e '/^#define.*IEEE80211_ADDR_COPY(/p' "$root/itl80211/openbsd/net80211/ieee80211_var.h"
    sed -n '/^#define LE_WRITE_2(/,/^} while (0)/p' "$root/itl80211/openbsd/net80211/ieee80211_priv.h"
    sed -n '/^#define SAE_STATE_NOTHING/,/^$/p' "$root/itl80211/openbsd/net80211/ieee80211_node.h"
    sed -n '/^struct ieee80211_sae {/,/^};/p' "$root/itl80211/openbsd/net80211/ieee80211_node.h"
    sed -n '/^#define.*IEEE80211_F_SAE_PWE/p' "$root/itl80211/openbsd/net80211/ieee80211_var.h"
    sed -n '/^enum ieee80211_akm {/,/^};/p' "$root/itl80211/openbsd/net80211/ieee80211_crypto.h"
    cat <<'EOF'
struct ieee80211_node {
    struct ieee80211_sae ni_sae;
    uint8_t ni_macaddr[6], ni_mld_addr[6];
    int ni_mld_valid;
    uint16_t ni_rsnxecaps;
    enum ieee80211_akm ni_rsnakms;
};
struct ieee80211com {
    uint8_t ic_myaddr[6], ic_wcl_peer_mld_addr[6];
    uint8_t ic_wcl_local_mlo_addrs[4][6];
    bool ic_wcl_peer_is_mlo, ic_wcl_local_mlo_addrs_valid, ic_eht_cap_valid;
    struct ieee80211_sae_auth ic_sae_auth;
    uint8_t ic_sae_pwe[64];
    int ic_sae_pwe_valid, ic_xflags;
    bool test_sae_enabled;
};
#define AIRPORT_WCL 1
EOF
    for name in ieee80211_sae_select_auth ieee80211_sae_auth_current ieee80211_rsn_uses_mld; do
        printf '\nstatic inline int\n'
        sed -n "/^$name(/,/^}/p" "$root/itl80211/openbsd/net80211/ieee80211_var.h"
    done
    for name in ieee80211_rsn_own_addr ieee80211_rsn_peer_addr; do
        printf '\nstatic inline const uint8_t *\n'
        sed -n "/^$name(/,/^}/p" "$root/itl80211/openbsd/net80211/ieee80211_var.h"
    done
    printf '\nstatic u_int8_t *\n'
    sed -n '/^ieee80211_add_sae_confirm(/,/^}/p' "$root/itl80211/openbsd/net80211/ieee80211_output.c"
    printf '\nstatic u_int8_t *\n'
    sed -n '/^ieee80211_add_sae_commit(/,/^}/p' "$root/itl80211/openbsd/net80211/ieee80211_output.c"
    cat <<'EOF'
// The allocation boundary supplies exactly the requested body size. ASAN then
// checks the production authentication constructor's length accounting.
struct host_mbuf { uint8_t *data; size_t len, packet_len; };
typedef struct host_mbuf *mbuf_t;
#define MBUF_DONTWAIT 0
#define MT_DATA 0
#define mtod(m, type) reinterpret_cast<type>((m)->data)
static mbuf_t ieee80211_getmgmt(int, int, u_int size)
{
    mbuf_t m = new host_mbuf;
    m->data = new uint8_t[size]();
    m->len = m->packet_len = size;
    return m;
}
static void mbuf_pkthdr_setlen(mbuf_t m, size_t len) { m->packet_len = len; }
static void mbuf_setlen(mbuf_t m, size_t len) { m->len = len; }
static void mbuf_freem(mbuf_t m) { delete[] m->data; delete m; }
static int ieee80211_node_allow_wpa3(ieee80211com *ic, ieee80211_node *)
{
    return ic->test_sae_enabled;
}
EOF
    printf '\nmbuf_t\n'
    sed -n '/^ieee80211_get_auth(/,/^}/p' "$root/itl80211/openbsd/net80211/ieee80211_output.c"
} > "$out/sae_confirm_output.inc"

# Everything is compiled as C++: ec_p256_m31.c and i31.c use static_cast, and a
# single language keeps the BearSSL symbols from being mangled differently.
# The shim header is force-included because the vendored crypto headers assume
# the kernel's sys/types.h has already supplied u_int/u8/uint32_t.
if [ "${SAE_HNP_COMPAT:-0}" = 1 ]; then
    hnp_define=-DIEEE80211_SAE_HNP_COMPAT
else
    hnp_define=
fi

${CXX:-clang++} ${CXXFLAGS:-} $hnp_define -x c++ -std=c++17 -O1 -g -Wall -Wextra -Wno-unused-parameter \
	-include "$here/shim/sae_shim.h" \
	-I"$here/shim" -I"$root/itl80211/openbsd" -I"$out" \
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
