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
int ieee80211_sae_derive_commit_elem(uint8_t *, uint8_t *, uint8_t *,
    uint8_t *, const uint8_t *);
uint16_t ieee80211_sae_derive_shared_secret(uint8_t *, const uint8_t *,
    const uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *);
int ieee80211_sae_derive_secret_keys(uint8_t *, uint8_t *, uint8_t *,
    const uint8_t *, const uint8_t *, const uint8_t *);
int ieee80211_sae_password_to_pt(uint8_t *, const uint8_t *, size_t,
    const uint8_t *, size_t);
int ieee80211_sae_derive_password_elem(uint8_t *, const uint8_t *,
    const uint8_t *, const uint8_t *);
#ifdef IEEE80211_SAE_HNP_COMPAT
int ieee80211_sae_derive_password_elem_hnp(uint8_t *, const uint8_t *,
    size_t, const uint8_t *, const uint8_t *);
#endif

static const uint8_t *random_scalars;
static size_t random_scalars_left;

/* Fixed IEEE rand/mask for commit generation; other tests need dummy bytes. */
void arc4random_buf(void *out, size_t len)
{
    if (random_scalars == nullptr) {
        memset(out, 0xa5, len);
        return;
    }
    if (len > random_scalars_left)
        abort();
    memcpy(out, random_scalars, len);
    random_scalars += len;
    random_scalars_left -= len;
}

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
 * ieee80211_sae.c links without pulling net80211 in. Published key vectors
 * and independently computed carry cases check the KDF output.
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

/* IEEE 802.11-2020 Annex J.10, also checked by hostap common_module_tests.c.
 * The PWE and shared x coordinate were independently recovered from its mask,
 * rand and commits; KCK/PMK/PMKID are the published expected values. */
static void
test_shared_secret_and_keys(void)
{
    static const uint8_t own_commit[] = {
        0x13, 0x00, 0x2e, 0x2c, 0x0f, 0x0d, 0xb5, 0x24,
        0x40, 0xad, 0x14, 0x6d, 0x96, 0x71, 0x14, 0xce,
        0x00, 0x5c, 0xe1, 0xea, 0xb0, 0xaa, 0x2c, 0x2e,
        0x5c, 0x28, 0x71, 0xb7, 0x74, 0xf6, 0xc2, 0x57,
        0x5c, 0x65, 0xd5, 0xad, 0x9e, 0x00, 0x82, 0x97,
        0x07, 0xaa, 0x36, 0xba, 0x8b, 0x85, 0x97, 0x38,
        0xfc, 0x96, 0x1d, 0x08, 0x24, 0x35, 0x05, 0xf4,
        0x7c, 0x03, 0x53, 0x76, 0xd7, 0xac, 0x4b, 0xc8,
        0xd7, 0xb9, 0x50, 0x83, 0xbf, 0x43, 0x82, 0x7d,
        0x0f, 0xc3, 0x1e, 0xd7, 0x78, 0xdd, 0x36, 0x71,
        0xfd, 0x21, 0xa4, 0x6d, 0x10, 0x91, 0xd6, 0x4b,
        0x6f, 0x9a, 0x1e, 0x12, 0x72, 0x62, 0x13, 0x25,
        0xdb, 0xe1,
    };
    static const uint8_t peer_commit[] = {
        0x13, 0x00, 0x59, 0x1b, 0x96, 0xf3, 0x39, 0x7f,
        0xb9, 0x45, 0x10, 0x08, 0x48, 0xe7, 0xb5, 0x50,
        0x54, 0x3b, 0x67, 0x20, 0xd8, 0x83, 0x37, 0xee,
        0x93, 0xfc, 0x49, 0xfd, 0x6d, 0xf7, 0xe0, 0x8b,
        0x52, 0x23, 0xe7, 0x1b, 0x9b, 0xb0, 0x48, 0xd3,
        0x87, 0x3f, 0x20, 0x55, 0x69, 0x53, 0xa9, 0x6c,
        0x91, 0x53, 0x6f, 0xd8, 0xee, 0x6c, 0xa9, 0xb4,
        0xa6, 0x8a, 0x14, 0x8b, 0x05, 0x6a, 0x90, 0x9b,
        0xe0, 0x3e, 0x83, 0xae, 0x20, 0x8f, 0x60, 0xf8,
        0xef, 0x55, 0x37, 0x85, 0x80, 0x74, 0xdb, 0x06,
        0x68, 0x70, 0x32, 0x39, 0x98, 0x62, 0x99, 0x9b,
        0x51, 0x1e, 0x0a, 0x15, 0x52, 0xa5, 0xfe, 0xa3,
        0x17, 0xc2,
    };
    static const uint8_t rand[] = {
        0x99, 0x24, 0x65, 0xfd, 0x3d, 0xaa, 0x3c, 0x60,
        0xaa, 0x65, 0x65, 0xb7, 0xf6, 0x2a, 0x2a, 0x7f,
        0x2e, 0x12, 0xdd, 0x12, 0xf1, 0x98, 0xfa, 0xf4,
        0xfb, 0xed, 0x89, 0xd7, 0xff, 0x1a, 0xce, 0x94,
    };
    static const uint8_t pwe[] = {
        0xda, 0x6e, 0xb7, 0xb0, 0x6a, 0x1a, 0xc5, 0x62,
        0x49, 0x74, 0xf9, 0x0a, 0xfd, 0xd6, 0xa8, 0xe9,
        0xd5, 0x72, 0x26, 0x34, 0xcf, 0x98, 0x7c, 0x34,
        0xde, 0xfc, 0x91, 0xa9, 0x87, 0x4e, 0x56, 0x58,
        0xf4, 0xfe, 0xfd, 0x13, 0x0b, 0xd5, 0xbe, 0x08,
        0xfe, 0x68, 0xaf, 0x3e, 0x4a, 0x29, 0x02, 0x72,
        0xec, 0x06, 0x5f, 0xd3, 0x67, 0x1f, 0x3c, 0x25,
        0xbf, 0x8e, 0xc4, 0x19, 0xdd, 0xc9, 0xb8, 0x22,
    };
    static const uint8_t mask[] = {
        0x95, 0x07, 0xa9, 0x0f, 0x77, 0x7a, 0x04, 0x4d,
        0x6a, 0x08, 0x30, 0xb9, 0x1e, 0xa3, 0xd5, 0xdd,
        0x70, 0xbe, 0xce, 0x44, 0xe1, 0xac, 0xff, 0xb8,
        0x69, 0x83, 0xb5, 0xe1, 0xbf, 0x9f, 0xb3, 0x22,
    };
    static const uint8_t expected_k[] = {
        0x18, 0x9f, 0x66, 0x6f, 0x31, 0x81, 0xb4, 0xa1,
        0x70, 0x1c, 0x2b, 0xf7, 0xd3, 0x4d, 0x64, 0x4e,
        0x66, 0xb5, 0xa1, 0x04, 0xac, 0xb9, 0x9a, 0xdf,
        0x25, 0xf3, 0xd4, 0x8b, 0x87, 0x8c, 0x08, 0x1f,
    };
    static const uint8_t expected_kck[] = {
        0x1e, 0x73, 0x3f, 0x6d, 0x9b, 0xd5, 0x32, 0x56,
        0x28, 0x73, 0x04, 0x33, 0x88, 0x31, 0xb0, 0x9a,
        0x39, 0x40, 0x6d, 0x12, 0x10, 0x17, 0x07, 0x3a,
        0x5c, 0x30, 0xdb, 0x36, 0xf3, 0x6c, 0xb8, 0x1a,
    };
    static const uint8_t expected_pmk[] = {
        0x4e, 0x4d, 0xfa, 0xb1, 0xa2, 0xdd, 0x8a, 0xc1,
        0xa9, 0x17, 0x90, 0xf9, 0x53, 0xfa, 0xaa, 0x45,
        0x2a, 0xe5, 0xc6, 0x87, 0x3a, 0xb7, 0x5b, 0x63,
        0x60, 0x5b, 0xa6, 0x63, 0xf8, 0xa7, 0xfe, 0x59,
    };
    static const uint8_t expected_pmkid[] = {
        0x87, 0x47, 0xa6, 0x00, 0xee, 0xa3, 0xf9, 0xf2,
        0x24, 0x75, 0xdf, 0x58, 0xca, 0x1e, 0x54, 0x98,
    };
    static const uint8_t peer_confirm[] = {
        0x01, 0x00, 0xe6, 0x32, 0xb0, 0xce, 0x42, 0xc2,
        0x2f, 0x54, 0xb2, 0x66, 0x0b, 0x02, 0xd0, 0x34,
        0xcc, 0xb2, 0x0f, 0x93, 0x24, 0x65, 0x28, 0xf4,
        0x0f, 0x4f, 0x7f, 0xce, 0x40, 0xfd, 0x83, 0x21,
        0x66, 0xa7,
    };
    const uint8_t *scalar = peer_commit + 2, *x = peer_commit + 34;
    const uint8_t *y = peer_commit + 66;
    uint8_t k[32] = {}, kck[32] = {}, pmk[32] = {}, pmkid[16] = {};

    uint8_t random_input[64], generated_rand[32] = {}, generated_commit[98] = {};
    memcpy(random_input, rand, sizeof(rand));
    memcpy(random_input + sizeof(rand), mask, sizeof(mask));
    random_scalars = random_input;
    random_scalars_left = sizeof(random_input);
    generated_commit[0] = 19;
    generated_commit[1] = 0;
    int result = ieee80211_sae_derive_commit_elem(generated_commit + 2,
        generated_commit + 34, generated_commit + 66, generated_rand, pwe);
    random_scalars = nullptr;
    CHECK("SAE vector: commit generation succeeds", result == 0);
    CHECK("SAE vector: scalar and masked element match IEEE commit",
        memcmp(generated_commit, own_commit, sizeof(own_commit)) == 0);
    CHECK("SAE vector: retained rand matches the generated commit",
        memcmp(generated_rand, rand, sizeof(rand)) == 0);

    CHECK("SAE vector: peer commit accepted",
        ieee80211_sae_verify_commit_elem(&scalar, &x, &y, peer_commit,
            sizeof(peer_commit), own_commit + 2, own_commit + 34,
            own_commit + 66) == IEEE80211_STATUS_SUCCESS);
    CHECK("SAE vector: shared secret succeeds",
        ieee80211_sae_derive_shared_secret(k, scalar, x, y, pwe, rand) == 0);
    CHECK("SAE vector: shared x coordinate matches",
        memcmp(k, expected_k, sizeof(k)) == 0);
    CHECK("SAE vector: key derivation succeeds",
        ieee80211_sae_derive_secret_keys(kck, pmk, pmkid, k,
            own_commit + 2, scalar) == 0);
    CHECK("SAE vector: KCK matches IEEE vector",
        memcmp(kck, expected_kck, sizeof(kck)) == 0);
    CHECK("SAE vector: PMK matches IEEE vector",
        memcmp(pmk, expected_pmk, sizeof(pmk)) == 0);
    CHECK("SAE vector: PMKID matches IEEE vector",
        memcmp(pmkid, expected_pmkid, sizeof(pmkid)) == 0);
    CHECK("SAE vector: peer confirm accepted with derived KCK",
        ieee80211_sae_verify_confirm(peer_confirm, sizeof(peer_confirm),
            kck, own_commit + 2, own_commit + 34, own_commit + 66,
            scalar, x, y) == 0);

    /* Another valid PWE preserves frame layout but changes KCK and CN. */
    CHECK("SAE vector: alternate PWE still derives a curve secret",
        ieee80211_sae_derive_shared_secret(k, scalar, x, y,
            own_commit + 34, rand) == 0);
    CHECK("SAE vector: alternate PWE key derivation succeeds",
        ieee80211_sae_derive_secret_keys(kck, pmk, pmkid, k,
            own_commit + 2, scalar) == 0);
    CHECK("SAE vector: different PWE fails at confirm",
        ieee80211_sae_verify_confirm(peer_confirm, sizeof(peer_confirm),
            kck, own_commit + 2, own_commit + 34, own_commit + 66,
            scalar, x, y) != 0);

    {
        static const uint8_t a[] = {
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
            0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x4f,
        };
        static const uint8_t b[] = {
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
            0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x4e,
        };
        static const uint8_t expected_kck[] = {
            0xc0, 0x25, 0x0f, 0xd2, 0x3c, 0x86, 0x4e, 0x12,
            0x4c, 0x7f, 0x76, 0x77, 0xee, 0x0f, 0x74, 0x8d,
            0x07, 0x42, 0xf3, 0x05, 0x6c, 0x59, 0xd2, 0x8e,
            0x21, 0x18, 0x92, 0xf7, 0x62, 0x0c, 0xf1, 0x60,
        };
        static const uint8_t expected_pmk[] = {
            0x78, 0x48, 0x3b, 0x5e, 0x64, 0x83, 0xfb, 0xff,
            0xd6, 0x9d, 0x2a, 0x12, 0x32, 0x55, 0xec, 0x5e,
            0x08, 0x47, 0x58, 0x94, 0xc1, 0x2d, 0x88, 0xe4,
            0x80, 0xd2, 0x03, 0x54, 0x11, 0xce, 0xae, 0x95,
        };
        static const uint8_t expected_pmkid[] = {
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        };
        CHECK("SAE KDF: 257-bit scalar sum reduced",
            ieee80211_sae_derive_secret_keys(kck, pmk, pmkid,
                expected_k, a, b) == 0 &&
            memcmp(kck, expected_kck, sizeof(kck)) == 0 &&
            memcmp(pmk, expected_pmk, sizeof(pmk)) == 0 &&
            memcmp(pmkid, expected_pmkid, sizeof(pmkid)) == 0);
    }

    {
        static const uint8_t a[] = {
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
            0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x4f,
        };
        static const uint8_t b[] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        };
        static const uint8_t expected_kck[] = {
            0x00, 0x4b, 0x44, 0x67, 0x84, 0x10, 0x80, 0x5c,
            0x52, 0xc2, 0xb6, 0xe5, 0x10, 0xce, 0x82, 0x21,
            0xbd, 0x05, 0x79, 0xe9, 0xdd, 0xde, 0x74, 0x69,
            0x14, 0xa6, 0xc4, 0x20, 0x4d, 0x63, 0x58, 0xfb,
        };
        static const uint8_t expected_pmk[] = {
            0xcf, 0xa9, 0x52, 0x9a, 0xee, 0x60, 0x67, 0x8c,
            0xb0, 0x34, 0x31, 0x68, 0x01, 0x36, 0xfe, 0xef,
            0x3f, 0x00, 0xe9, 0x30, 0xb0, 0x48, 0x15, 0x86,
            0x9b, 0x4c, 0x88, 0x8e, 0x4e, 0xef, 0x3d, 0xa4,
        };
        static const uint8_t expected_pmkid[] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };
        CHECK("SAE KDF: zero scalar sum padded",
            ieee80211_sae_derive_secret_keys(kck, pmk, pmkid,
                expected_k, a, b) == 0 &&
            memcmp(kck, expected_kck, sizeof(kck)) == 0 &&
            memcmp(pmk, expected_pmk, sizeof(pmk)) == 0 &&
            memcmp(pmkid, expected_pmkid, sizeof(pmkid)) == 0);
    }
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
    test_shared_secret_and_keys();
    test_confirm();
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
