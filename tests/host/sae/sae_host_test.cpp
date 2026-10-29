/*
 * Host-side tests for the SAE primitive layer.
 *
 * These run the production ieee80211_sae.c unmodified against a thin shim, so
 * a regression shows up here instead of on a device behind a WPA3 handshake
 * that cannot be observed frame by frame.
 *
 * The confirm digest is rebuilt here from the specification rather than from
 * the implementation, so an ordering or label change in the driver fails the
 * test instead of agreeing with itself.
 *
 * Build and run: sh tests/host/sae/run.sh
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* hmac.h uses SHA1_CTX but only pulls in sha2.h and md5.h itself. */
#include <crypto/sha1.h>
#include <crypto/hmac.h>
#include <crypto/i31.h>
#include <crypto/ec_p256_m31.h>

#include <net80211/ieee80211.h>
#include <net80211/ieee80211_var.h>

/* Declarations live in the driver only; the whole test is built as C++. */
uint16_t ieee80211_sae_verify_commit_elem(const uint8_t **scalar,
    const uint8_t **element_x, const uint8_t **element_y,
    const uint8_t *frm, size_t remain, const unsigned char *own_scalar,
    const unsigned char *own_element_x, const unsigned char *own_element_y);
int ieee80211_sae_verify_confirm(const uint8_t *frm, size_t remain,
    const uint8_t *kck, const uint8_t *own_scalar,
    const uint8_t *own_element_x, const uint8_t *own_element_y,
    const uint8_t *peer_scalar, const uint8_t *peer_element_x,
    const uint8_t *peer_element_y);
int ieee80211_sae_password_to_pt(uint8_t *, const uint8_t *, size_t,
    const uint8_t *, size_t);
int ieee80211_sae_derive_password_elem(uint8_t *, const uint8_t *,
    const uint8_t *, const uint8_t *);
#ifdef IEEE80211_SAE_HNP_COMPAT
int ieee80211_sae_derive_password_elem_hnp(uint8_t *, const uint8_t *,
    size_t, const uint8_t *, const uint8_t *);
#endif

void explicit_bzero(void *p, size_t n)
{
    volatile uint8_t *v = static_cast<volatile uint8_t *>(p);
    while (n--)
        *v++ = 0;
}

int timingsafe_bcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *x = static_cast<const uint8_t *>(a);
    const uint8_t *y = static_cast<const uint8_t *>(b);
    uint8_t r = 0;
    while (n--)
        r |= *x++ ^ *y++;
    return r != 0;
}

/*
 * Mirrors ieee80211_crypto.c:ieee80211_kdf(). It lives here only so that
 * ieee80211_sae.c links without pulling net80211 in; the paths under test
 * never reach it.
 */
void ieee80211_kdf(const u_int8_t *key, size_t key_len, const u_int8_t *label,
    size_t label_len, const u_int8_t *context, size_t context_len,
    u_int8_t *output, size_t len)
{
    HMAC_SHA256_CTX ctx;
    u_int8_t digest[SHA256_DIGEST_LENGTH];
    u_int16_t i, iter, length;

    length = htole16(len * NBBY);
    for (i = 1; len != 0; i++) {
        HMAC_SHA256_Init(&ctx, key, key_len);
        iter = htole16(i);
        HMAC_SHA256_Update(&ctx, (u_int8_t *)&iter, sizeof iter);
        HMAC_SHA256_Update(&ctx, label, label_len);
        HMAC_SHA256_Update(&ctx, context, context_len);
        HMAC_SHA256_Update(&ctx, (u_int8_t *)&length, sizeof length);
        if (len < SHA256_DIGEST_LENGTH) {
            HMAC_SHA256_Final(digest, &ctx);
            memcpy(output, digest, len);
            break;
        }
        HMAC_SHA256_Final(output, &ctx);
        output += SHA256_DIGEST_LENGTH;
        len -= SHA256_DIGEST_LENGTH;
    }
}

static int failures;
static int checks;

#define CHECK(name, cond)                                            \
    do {                                                             \
        ++checks;                                                    \
        if (!(cond)) {                                               \
            printf("FAIL  %s\n", name);                              \
            ++failures;                                              \
        } else {                                                     \
            printf("ok    %s\n", name);                              \
        }                                                            \
    } while (0)

#define GROUP_LEN  2
#define SCALAR_LEN IEEE80211_SAE_MAX_ECC_PRIME_LEN
#define ELEM_LEN   (2 * IEEE80211_SAE_MAX_ECC_PRIME_LEN)

static const int p256 = BR_EC_secp192r1; /* group 19, P-256 */

/* A scalar that is > 1 and < the group order when read big-endian. */
static void
make_scalar(uint8_t *out, uint8_t seed)
{
    memset(out, seed, SCALAR_LEN);
    out[0] = 0x00;
    out[1] = 0x01;
}

static void
point_for(const uint8_t *scalar, uint8_t *pt)
{
    pt[0] = 0x04;
    br_ec_p256_m31.mulgen(pt, scalar, SCALAR_LEN, p256);
}

/* frm = group(2) || scalar(32) || x(32) || y(32) */
static void
make_commit(uint8_t *frm, uint16_t group, const uint8_t *scalar, const uint8_t *pt)
{
    frm[0] = group & 0xff;
    frm[1] = group >> 8;
    memcpy(frm + 2, scalar, SCALAR_LEN);
    memcpy(frm + 2 + SCALAR_LEN, pt + 1, ELEM_LEN);
}

static void
test_commit_parsing(void)
{
    uint8_t own_scalar[SCALAR_LEN], peer_scalar[SCALAR_LEN];
    uint8_t own_point[65], peer_point[65];
    uint8_t frm[IEEE80211_SAE_COMMIT_MIN_LEN + 3];
    const uint8_t *s, *x, *y;

    make_scalar(own_scalar, 0x11);
    make_scalar(peer_scalar, 0x22);
    point_for(own_scalar, own_point);
    point_for(peer_scalar, peer_point);

    memset(frm, 0, sizeof(frm));

    make_commit(frm, IEEE80211_SAE_CURVE_ID_P256, peer_scalar, peer_point);
    CHECK("commit: exact 98-byte body accepted",
        ieee80211_sae_verify_commit_elem(&s, &x, &y, frm,
            IEEE80211_SAE_COMMIT_MIN_LEN, own_scalar, own_point + 1,
            own_point + 1 + SCALAR_LEN) == IEEE80211_STATUS_SUCCESS);

    /*
     * Regression: an H2E peer may append optional elements after the commit
     * element. Rejecting those made every H2E handshake fail on the device.
     */
    frm[IEEE80211_SAE_COMMIT_MIN_LEN + 0] = 244; /* RSNXE */
    frm[IEEE80211_SAE_COMMIT_MIN_LEN + 1] = 1;
    frm[IEEE80211_SAE_COMMIT_MIN_LEN + 2] = 0x20;
    CHECK("commit: trailing optional element still accepted",
        ieee80211_sae_verify_commit_elem(&s, &x, &y, frm,
            IEEE80211_SAE_COMMIT_MIN_LEN + 3, own_scalar, own_point + 1,
            own_point + 1 + SCALAR_LEN) == IEEE80211_STATUS_SUCCESS);

    CHECK("commit: truncated body rejected",
        ieee80211_sae_verify_commit_elem(&s, &x, &y, frm,
            IEEE80211_SAE_COMMIT_MIN_LEN - 1, own_scalar, own_point + 1,
            own_point + 1 + SCALAR_LEN) == IEEE80211_STATUS_UNSPECIFIED);

    make_commit(frm, 25 /* not P-256 */, peer_scalar, peer_point);
    CHECK("commit: unsupported group rejected",
        ieee80211_sae_verify_commit_elem(&s, &x, &y, frm,
            IEEE80211_SAE_COMMIT_MIN_LEN, own_scalar, own_point + 1,
            own_point + 1 + SCALAR_LEN) == IEEE80211_STATUS_BAD_FC_GROUP);

    make_commit(frm, IEEE80211_SAE_CURVE_ID_P256, own_scalar, own_point);
    CHECK("commit: reflection of our own scalar rejected",
        ieee80211_sae_verify_commit_elem(&s, &x, &y, frm,
            IEEE80211_SAE_COMMIT_MIN_LEN, own_scalar, own_point + 1,
            own_point + 1 + SCALAR_LEN) == IEEE80211_STATUS_UNSPECIFIED);

    /* A point that is not on the curve must be refused. */
    make_commit(frm, IEEE80211_SAE_CURVE_ID_P256, peer_scalar, peer_point);
    frm[2 + SCALAR_LEN] ^= 0x01;
    CHECK("commit: off-curve element rejected",
        ieee80211_sae_verify_commit_elem(&s, &x, &y, frm,
            IEEE80211_SAE_COMMIT_MIN_LEN, own_scalar, own_point + 1,
            own_point + 1 + SCALAR_LEN) == IEEE80211_STATUS_UNSPECIFIED);
}

/* CN(KCK, send-confirm, peer-scalar, peer-element, own-scalar, own-element) */
static void
spec_confirm(uint8_t *out, const uint8_t *kck, const uint8_t *send_confirm,
    const uint8_t *peer_scalar, const uint8_t *peer_point,
    const uint8_t *own_scalar, const uint8_t *own_point)
{
    HMAC_SHA256_CTX ctx;
    HMAC_SHA256_Init(&ctx, kck, 32);
    HMAC_SHA256_Update(&ctx, send_confirm, 2);
    HMAC_SHA256_Update(&ctx, peer_scalar, SCALAR_LEN);
    HMAC_SHA256_Update(&ctx, peer_point + 1, ELEM_LEN);
    HMAC_SHA256_Update(&ctx, own_scalar, SCALAR_LEN);
    HMAC_SHA256_Update(&ctx, own_point + 1, ELEM_LEN);
    HMAC_SHA256_Final(out, &ctx);
}

static void
test_rsnxe(void)
{
    uint8_t rsnxe[5];
    static const uint8_t ap_extended[] = {244, 2, 0x31, 0x80};
    static const uint8_t m3_same[] = {244, 2, 0x31, 0x80};
    static const uint8_t m3_changed[] = {244, 2, 0x21, 0x80};
    static const uint8_t missing_h2e[] = {244, 2, 0x11, 0x80};
    static const uint8_t truncated[] = {244, 2, 0x31};
    static const uint8_t bad_field_length[] = {244, 2, 0x30, 0x80};
    static const uint8_t wrong_id[] = {48, 1, 0x20};
    uint8_t *end = ieee80211_add_rsnxe_h2e(rsnxe);

    CHECK("RSNXE: H2E generation emits the one-byte capability",
        end - rsnxe == 3 && rsnxe[0] == IEEE80211_ELEMID_RSNXE &&
        rsnxe[1] == 1 && rsnxe[2] == IEEE80211_RSNXECAP_H2E);
    CHECK("RSNXE: H2E accepted with valid extra and unknown capabilities",
        ieee80211_rsnxe_has_h2e(ap_extended, sizeof(ap_extended)));
    CHECK("RSNXE: complete AP capability matches M3",
        ieee80211_rsnxe_matches(ap_extended, sizeof(ap_extended),
            m3_same, sizeof(m3_same)));
    CHECK("RSNXE: changed non-H2E AP capability rejected in M3",
        !ieee80211_rsnxe_matches(ap_extended, sizeof(ap_extended),
            m3_changed, sizeof(m3_changed)));
    CHECK("RSNXE: missing H2E bit rejected",
        !ieee80211_rsnxe_has_h2e(missing_h2e, sizeof(missing_h2e)));
    CHECK("RSNXE: truncated element rejected",
        !ieee80211_rsnxe_valid(truncated, sizeof(truncated)));
    CHECK("RSNXE: field length encoding checked",
        !ieee80211_rsnxe_valid(bad_field_length, sizeof(bad_field_length)));
    CHECK("RSNXE: wrong element ID rejected",
        !ieee80211_rsnxe_valid(wrong_id, sizeof(wrong_id)));
}

static void
test_h2e_pwe(void)
{
    static const uint8_t password[] = "password";
    static const uint8_t ssid[] = "sae-test";
    static const uint8_t ownaddr[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t bssid[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    static const uint8_t zero[64] = {};
    uint8_t pt[64], pwe[64];

    memset(pwe, 0, sizeof(pwe));
    CHECK("SAE H2E: password token derivation succeeds",
        ieee80211_sae_password_to_pt(pt, password, sizeof(password) - 1,
            ssid, sizeof(ssid) - 1) == 0);
    CHECK("SAE H2E: PWE derivation succeeds",
        ieee80211_sae_derive_password_elem(pwe, pt, ownaddr, bssid) == 0);
    CHECK("SAE H2E: derived PWE is nonzero",
        memcmp(pwe, zero, sizeof(pwe)) != 0);
}

static void
test_sae_policy(void)
{
#ifndef IEEE80211_SAE_HNP_COMPAT
    CHECK("SAE policy: HnP unavailable by default",
        !ieee80211_sae_hnp_compat_allowed(0, 5180));
#else
    uint8_t pwe[64];
    static const uint8_t password[] = "password";
    static const uint8_t ownaddr[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t bssid[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    static const uint8_t zero[64] = {};

    CHECK("SAE policy: explicit HnP compatibility enables 5 GHz",
        ieee80211_sae_hnp_compat_allowed(0, 5180));
    CHECK("SAE policy: explicit HnP compatibility remains off on 6 GHz",
        !ieee80211_sae_hnp_compat_allowed(0, 5955));
    CHECK("SAE policy: H2E AP never selects HnP",
        !ieee80211_sae_hnp_compat_allowed(1, 5180));
    memset(pwe, 0, sizeof(pwe));
    CHECK("SAE HnP: experimental PWE derivation succeeds",
        ieee80211_sae_derive_password_elem_hnp(pwe, password,
            sizeof(password) - 1, ownaddr, bssid) == 0);
    CHECK("SAE HnP: derived PWE is nonzero",
        memcmp(pwe, zero, sizeof(pwe)) != 0);
#endif
}

static void
test_confirm(void)
{
    uint8_t own_scalar[SCALAR_LEN], peer_scalar[SCALAR_LEN];
    uint8_t own_point[65], peer_point[65];
    uint8_t kck[32];
    uint8_t frm[2 + 32];

    make_scalar(own_scalar, 0x11);
    make_scalar(peer_scalar, 0x22);
    point_for(own_scalar, own_point);
    point_for(peer_scalar, peer_point);
    memset(kck, 0x5a, sizeof(kck));

    frm[0] = 0x01;
    frm[1] = 0x00;
    spec_confirm(frm + 2, kck, frm, peer_scalar, peer_point, own_scalar, own_point);

    CHECK("confirm: digest built from the spec is accepted",
        ieee80211_sae_verify_confirm(frm, sizeof(frm), kck, own_scalar,
            own_point + 1, own_point + 1 + SCALAR_LEN, peer_scalar,
            peer_point + 1, peer_point + 1 + SCALAR_LEN) == 0);

    frm[2 + 31] ^= 0x80;
    CHECK("confirm: corrupted verifier rejected",
        ieee80211_sae_verify_confirm(frm, sizeof(frm), kck, own_scalar,
            own_point + 1, own_point + 1 + SCALAR_LEN, peer_scalar,
            peer_point + 1, peer_point + 1 + SCALAR_LEN) != 0);
}

int
main(void)
{
    test_commit_parsing();
    test_rsnxe();
    test_h2e_pwe();
    test_sae_policy();
    test_confirm();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
