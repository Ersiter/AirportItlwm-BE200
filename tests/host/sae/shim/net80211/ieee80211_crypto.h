#include "sae_shim.h"

/* Provided by the test harness; the SAE paths under test never call it. */
void ieee80211_kdf(const u_int8_t *, size_t, const u_int8_t *, size_t,
    const u_int8_t *, size_t, u_int8_t *, size_t);
