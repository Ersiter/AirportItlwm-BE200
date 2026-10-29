/*
 * The only net80211 definitions the SAE primitive layer actually needs.
 * Values mirror itl80211/openbsd/net80211/ieee80211.h; the host build uses
 * them so that a drift there shows up as a failing test rather than as a
 * silently different protocol on the device.
 */
#ifndef SAE_SHIM_NET80211_VAR_H
#define SAE_SHIM_NET80211_VAR_H

#include "sae_shim.h"

#define IEEE80211_ADDR_LEN		6
#define IEEE80211_PMKID_LEN		16
#define IEEE80211_PMK_LEN		32
#define IEEE80211_SAE_MAX_ECC_PRIME_LEN	32
#define IEEE80211_SAE_CURVE_ID_P256	19
#define IEEE80211_SAE_COMMIT_MIN_LEN	(2 + (3 * IEEE80211_SAE_MAX_ECC_PRIME_LEN))

#define IEEE80211_STATUS_SUCCESS	0
#define IEEE80211_STATUS_UNSPECIFIED	1
#define IEEE80211_STATUS_BAD_FC_GROUP	77

#endif
