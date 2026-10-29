/*
 * Host-build shim for the SAE primitive layer.
 *
 * ieee80211_sae.c uses no struct ieee80211com / ieee80211_node fields, so the
 * only thing it needs from net80211 is a handful of constants. Everything the
 * kernel would normally supply (types, endian helpers, assertions) lives here
 * so the real crypto sources can be compiled unmodified on a host.
 */
#ifndef SAE_HOST_SHIM_H
#define SAE_HOST_SHIM_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

#ifndef __packed
#define __packed __attribute__((__packed__))
#endif

#include <machine/endian.h>
#include <libkern/OSByteOrder.h>

#ifndef BYTE_ORDER
#define BYTE_ORDER     __DARWIN_BYTE_ORDER
#endif
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN  __DARWIN_LITTLE_ENDIAN
#endif
#ifndef BIG_ENDIAN
#define BIG_ENDIAN     __DARWIN_BIG_ENDIAN
#endif

#define htole16(x) OSSwapHostToLittleInt16(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#ifndef le32toh
#define le32toh(x) OSSwapLittleToHostInt32(x)
#endif
#ifndef hweight8
#define hweight8(x) __builtin_popcount((unsigned char)(x))
#endif
#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

typedef uint8_t  u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;
typedef uint8_t  u_char;
typedef unsigned int u_int;

/* The Linux-compat header the driver builds with supplies these. */
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

#ifndef NBBY
#define NBBY 8
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef howmany
#define howmany(x, y) (((x) + ((y) - 1)) / (y))
#endif

#define LE_READ_2(p) \
    ((uint16_t)(((const uint8_t *)(p))[0] | (((const uint8_t *)(p))[1] << 8)))
#define LE_READ_4(p) \
    ((uint32_t)(((const uint8_t *)(p))[0] | (((const uint8_t *)(p))[1] << 8) | \
                (((const uint8_t *)(p))[2] << 16) | (((const uint8_t *)(p))[3] << 24)))
#define BE_READ_2(p) \
    ((uint16_t)(((const uint8_t *)(p))[1] | (((const uint8_t *)(p))[0] << 8)))

#define DPRINTF(x)      do { } while (0)
#define _KASSERT(x)     do { } while (0)

void explicit_bzero(void *, size_t);
int timingsafe_bcmp(const void *, const void *, size_t);

#endif
