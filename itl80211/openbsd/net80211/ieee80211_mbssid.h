#ifndef _NET80211_IEEE80211_MBSSID_H_
#define _NET80211_IEEE80211_MBSSID_H_

#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace IEEE80211Mbssid {

struct Profile {
    uint8_t bssid[6];
    uint8_t transmitted[6];
    size_t offset, length;
    uint16_t capability;
    uint8_t index, indicator, dtimPeriod, dtimCount;
    bool hasDtim;
};

struct Cursor {
    size_t element, sub, end;
    uint8_t indicator;
    uint8_t seen[32];
};

inline bool validElements(const uint8_t *ies, size_t length)
{
    size_t pos = 0;
    while (pos < length) {
        if (length - pos < 2 || size_t(ies[pos + 1]) + 2 > length - pos)
            return false;
        if (ies[pos] == 255 && ies[pos + 1] == 0)
            return false;
        pos += 2 + ies[pos + 1];
    }
    return true;
}

inline bool nextProfile(const uint8_t *ies, size_t length,
    const uint8_t transmitted[6], Cursor &cursor, Profile &out)
{
    while (cursor.element < length || cursor.sub < cursor.end) {
        if (cursor.sub >= cursor.end) {
            const size_t pos = cursor.element;
            if (length - pos < 2 || size_t(ies[pos + 1]) + 2 > length - pos)
                return false;
            cursor.element += 2 + ies[pos + 1];
            if (ies[pos] != 71 || ies[pos + 1] < 3 ||
                ies[pos + 2] == 0 || ies[pos + 2] > 8)
                continue;
            cursor.indicator = ies[pos + 2];
            cursor.sub = pos + 3;
            cursor.end = cursor.element;
        }
        const size_t sub = cursor.sub;
        if (cursor.end - sub < 2 || size_t(ies[sub + 1]) + 2 > cursor.end - sub) {
            cursor.sub = cursor.end;
            continue;
        }
        cursor.sub += 2 + ies[sub + 1];
        if (ies[sub] != 0)
            continue;
        const uint8_t *own = ies + sub + 2;
        const size_t ownLength = ies[sub + 1];
        if (ownLength < 4 || own[0] != 83 || own[1] != 2 ||
            !validElements(own, ownLength))
            continue;
        const uint8_t *ssid = nullptr, *index = nullptr;
        bool duplicate = false;
        for (size_t pos = 4; pos < ownLength; pos += 2 + own[pos + 1]) {
            if (own[pos] == 0) {
                duplicate |= ssid != nullptr;
                ssid = own + pos;
            } else if (own[pos] == 85) {
                duplicate |= index != nullptr;
                index = own + pos;
            }
        }
        if (duplicate || !ssid || ssid[1] > 32 || !index ||
            (index[1] != 1 && index[1] != 3) || index[2] == 0 ||
            index[2] >= (1U << cursor.indicator))
            continue;
        const unsigned mask = (1U << cursor.indicator) - 1;
        const uint8_t last = uint8_t((transmitted[5] & ~mask) |
            ((transmitted[5] + index[2]) & mask));
        if (cursor.seen[last / 8] & (1U << (last % 8)))
            continue;
        cursor.seen[last / 8] |= uint8_t(1U << (last % 8));
        out = {};
        memcpy(out.transmitted, transmitted, 6);
        memcpy(out.bssid, transmitted, 6);
        out.bssid[5] = last;
        out.offset = sub + 2;
        out.length = ownLength;
        out.capability = uint16_t(own[2] | (own[3] << 8));
        out.index = index[2];
        out.indicator = cursor.indicator;
        out.hasDtim = index[1] == 3;
        if (out.hasDtim) {
            out.dtimPeriod = index[3];
            out.dtimCount = index[4];
        }
        return true;
    }
    return false;
}

inline bool sameType(const uint8_t *a, const uint8_t *b)
{
    return a[0] == b[0] && (a[0] != 255 || a[2] == b[2]);
}

inline bool profileControl(const uint8_t *ie)
{
    return ie[0] == 71 || ie[0] == 83 || ie[0] == 85 ||
        (ie[0] == 255 && ie[2] == 56);
}

/*
 * Element inheritance for a profile carried inside another BSS's frame, after
 * cfg80211_gen_new_ie(): the reporting frame's elements are kept unless the
 * profile has its own element of that type or lists it in a Non-Inheritance
 * element, then the profile's elements follow. Used for Multiple BSSID
 * nontransmitted profiles and for Multi-Link per-STA profiles.
 */
inline bool mergeElements(const uint8_t *ies, size_t length,
    const uint8_t *own, size_t ownLength, const Profile *dtim,
    uint8_t *out, size_t capacity, size_t &outLength)
{
    outLength = 0;
    if (!validElements(ies, length) || !validElements(own, ownLength))
        return false;
    const uint8_t *noninherit = nullptr;
    for (size_t pos = 0; pos < ownLength; pos += 2 + own[pos + 1]) {
        if (own[pos] != 255 || own[pos + 2] != 56)
            continue;
        const uint8_t *ie = own + pos;
        if (noninherit || ie[1] < 3 || ie[3] > ie[1] - 3 ||
            size_t(3 + ie[3] + ie[4 + ie[3]]) != ie[1])
            return false;
        noninherit = ie;
    }
    size_t written = 0;
    bool inheritFragment = false;
    for (size_t pos = 0; pos < length; pos += 2 + ies[pos + 1]) {
        const uint8_t *ie = ies + pos;
        if (ie[0] == 242 && !inheritFragment)
            continue;
        inheritFragment = false;
        if (profileControl(ie) || (ie[0] == 255 && ie[2] == 107))
            continue; // An AP's Multi-Link identity is specific to that BSSID.
        bool skip = false;
        for (size_t p = 0; p < ownLength; p += 2 + own[p + 1])
            skip |= sameType(ie, own + p);
        if (noninherit) {
            const bool ext = ie[0] == 255;
            const size_t start = ext ? 5 + noninherit[3] : 4;
            const size_t count = ext ? noninherit[4 + noninherit[3]] : noninherit[3];
            for (size_t p = 0; p < count; ++p)
                skip |= noninherit[start + p] == (ext ? ie[2] : ie[0]);
        }
        if (skip)
            continue;
        const size_t size = 2 + ie[1];
        if (size > capacity - written)
            return false;
        memcpy(out + written, ie, size);
        if (ie[0] == 5 && ie[1] >= 4 && dtim && dtim->hasDtim) {
            out[written + 2] = dtim->dtimCount;
            out[written + 3] = dtim->dtimPeriod;
        }
        written += size;
        inheritFragment = ie[1] == 255;
    }
    for (size_t pos = 0; pos < ownLength; pos += 2 + own[pos + 1]) {
        const uint8_t *ie = own + pos;
        if (profileControl(ie))
            continue;
        const size_t size = 2 + ie[1];
        if (size > capacity - written)
            return false;
        memcpy(out + written, ie, size);
        written += size;
    }
    outLength = written;
    return true;
}

inline bool mergeProfile(const uint8_t *ies, size_t length, const Profile &profile,
    uint8_t *out, size_t capacity, size_t &outLength)
{
    outLength = 0;
    if (profile.offset > length || profile.length > length - profile.offset)
        return false;
    return mergeElements(ies, length, ies + profile.offset, profile.length,
        &profile, out, capacity, outLength);
}

} // namespace IEEE80211Mbssid
#endif
