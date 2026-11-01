#include "../AirportItlwm/WCL/WCL.hpp"

#include <assert.h>
#include <stdio.h>
#include <string.h>

namespace {

uint8_t frame[512];
size_t length = 0;
size_t mbLengthAt = 0;

void element(uint8_t id, const uint8_t *payload, size_t size)
{
    frame[length++] = id;
    frame[length++] = uint8_t(size);
    if (size)
        memcpy(frame + length, payload, size);
    length += size;
}

/* Nontransmitted BSSID Profile, laid out the way the captured frame does it:
 * the capability element, then that BSS's SSID, then its index. */
void profile(const char *ssid, uint8_t index)
{
    uint8_t body[128];
    size_t n = 0;
    body[n++] = 83;              /* Nontransmitted BSSID Capability */
    body[n++] = 2;
    body[n++] = 0x11;
    body[n++] = 0x11;
    body[n++] = 0;               /* SSID element */
    body[n++] = uint8_t(strlen(ssid));
    memcpy(body + n, ssid, strlen(ssid));
    n += strlen(ssid);
    body[n++] = 85;              /* Multiple BSSID-Index */
    body[n++] = 3;               /* BSSID index, DTIM period, DTIM count */
    body[n++] = index;
    body[n++] = 1;
    body[n++] = 0;
    frame[length++] = 0;         /* subelement: Nontransmitted BSSID Profile */
    frame[length++] = uint8_t(n);
    memcpy(frame + length, body, n);
    length += n;
}

/* Element id 71, then the MaxBSSID Indicator, then the subelements. */
void multipleBssid(uint8_t maxIndicator)
{
    frame[length++] = 71;
    frame[length++] = 0;         /* filled in by endMultipleBssid */
    mbLengthAt = length - 1;
    frame[length++] = maxIndicator;
}

/* The element length covers the subelements, so it is known only at the end. */
void endMultipleBssid()
{
    frame[mbLengthAt] = uint8_t(length - mbLengthAt - 1);
}

void reset()
{
    length = 0;
    memset(frame, 0, sizeof(frame));
}

const uint8_t kTransmitted[6] = { 0x6e, 0x7f, 0xf0, 0x0d, 0xb5, 0x3a };

} // namespace

int main()
{
    using AirportWCL::MbssidProfile;
    using AirportWCL::decodeMbssidProfiles;
    using AirportWCL::mbssidDeriveBssid;
    MbssidProfile out[8];
    const uint8_t empty = 0;

    /* The captured 6 GHz shape: empty SSID, the name in a profile, and an
     * indicator of 1 so the two BSSIDs differ in the last bit. */
    reset();
    element(0, &empty, 0);
    multipleBssid(1);
    profile("1Joey_6", 1);
    endMultipleBssid();
    unsigned n = decodeMbssidProfiles(frame, length, kTransmitted, out, 8);
    assert(n == 1);
    assert(out[0].ssidLength == 7);
    assert(memcmp(out[0].ssid, "1Joey_6", 7) == 0);
    assert(out[0].bssid[5] == 0x3b);
    assert(memcmp(out[0].bssid, kTransmitted, 5) == 0);

    /* An indicator of 3 replaces the low three bits: 0x3a -> 0x39. */
    reset();
    element(0, &empty, 0);
    multipleBssid(3);
    profile("1Joey_6", 1);
    endMultipleBssid();
    n = decodeMbssidProfiles(frame, length, kTransmitted, out, 8);
    assert(n == 1);
    assert(out[0].bssid[5] == 0x39);

    /* Two profiles under a wider indicator both come out. */
    reset();
    element(0, &empty, 0);
    multipleBssid(2);
    profile("1Joey_6", 1);
    profile("backhaul", 2);
    endMultipleBssid();
    n = decodeMbssidProfiles(frame, length, kTransmitted, out, 8);
    assert(n == 2);
    assert(out[0].bssid[5] == 0x39);
    assert(out[1].bssid[5] == 0x3a);
    assert(memcmp(out[1].ssid, "backhaul", 8) == 0);

    /* A profile with no name is not a name and must not become one. */
    reset();
    element(0, &empty, 0);
    multipleBssid(1);
    profile("", 1);
    endMultipleBssid();
    assert(decodeMbssidProfiles(frame, length, kTransmitted, out, 8) == 0);

    /* An index outside the set is not an address we can derive. */
    reset();
    element(0, &empty, 0);
    multipleBssid(1);
    profile("1Joey_6", 2);
    endMultipleBssid();
    assert(decodeMbssidProfiles(frame, length, kTransmitted, out, 8) == 0);

    /* No Multiple BSSID element: nothing to say. */
    reset();
    const uint8_t rates[1] = { 0x82 };
    element(1, rates, 1);
    assert(decodeMbssidProfiles(frame, length, kTransmitted, out, 8) == 0);

    /* A frame cut short must be refused, not walked past its end. */
    reset();
    element(0, &empty, 0);
    multipleBssid(2);
    profile("1Joey_6", 1);
    endMultipleBssid();
    assert(decodeMbssidProfiles(frame, length - 3, kTransmitted, out, 8) == 0);

    /* An indicator wider than one octet still derives the right address. */
    uint8_t derived[6];
    const uint8_t base[6] = { 0x02, 0x00, 0x00, 0x00, 0x01, 0xff };
    mbssidDeriveBssid(base, 9, 0x101, derived);
    assert(derived[5] == 0x01);
    assert(derived[4] == 0x01);

    /* SSID statuses: the case that matters is telling them apart. */
    using AirportWCL::SsidStatus;
    using AirportWCL::parseSsid;
    uint8_t name[32];
    uint8_t nameLength = 0;

    reset();
    const uint8_t visibleName[] = { '1', 'J', 'o', 'e', 'y', '_', '6' };
    element(0, visibleName, sizeof(visibleName));
    assert(parseSsid(frame, length, name, sizeof(name), nameLength) == SsidStatus::Ok);
    assert(nameLength == 7);
    assert(memcmp(name, "1Joey_6", 7) == 0);

    reset();
    element(0, &empty, 0);
    nameLength = 9;
    assert(parseSsid(frame, length, name, sizeof(name), nameLength) == SsidStatus::Hidden);
    assert(nameLength == 0);

    reset();
    const uint8_t zeros[8] = {};
    element(0, zeros, sizeof(zeros));
    assert(parseSsid(frame, length, name, sizeof(name), nameLength) == SsidStatus::AllZero);

    reset();
    const uint8_t rates2[1] = { 0x82 };
    element(1, rates2, sizeof(rates2));
    assert(parseSsid(frame, length, name, sizeof(name), nameLength) == SsidStatus::NoElement);

    /* A name element whose length runs past the buffer is truncated, not Ok. */
    reset();
    frame[length++] = 0;
    frame[length++] = 20;
    memcpy(frame + length, visibleName, sizeof(visibleName));
    length += sizeof(visibleName);
    assert(parseSsid(frame, length, name, sizeof(name), nameLength) == SsidStatus::Truncated);

    /* Longer than a name may be. */
    reset();
    const uint8_t longName[33] = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                   1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
    element(0, longName, sizeof(longName));
    assert(parseSsid(frame, length, name, sizeof(name), nameLength) == SsidStatus::TooLong);

    /* The profile's own elements replace the transmitting BSS's. */
    reset();
    element(0, &empty, 0);           /* the set's empty SSID ... */
    const uint8_t keep[3] = { 0xde, 0xad, 0xbe };
    element(250, keep, sizeof(keep));/* ... an element the profile keeps ... */
    multipleBssid(1);
    profile("1Joey_6", 1);           /* ... and its own SSID on top */
    endMultipleBssid();
    n = decodeMbssidProfiles(frame, length, kTransmitted, out, 8);
    assert(n == 1);
    uint8_t merged[256];
    size_t mergedLength = 0;
    assert(AirportWCL::mergeMbssidProfile(frame, length, out[0], merged,
                                          sizeof(merged), mergedLength));
    unsigned ssidCount = 0, keepCount = 0, setCount = 0;
    for (size_t pos = 0; pos + 2 <= mergedLength; pos += 2 + merged[pos + 1]) {
        const size_t elementLength = merged[pos + 1];
        assert(pos + 2 + elementLength <= mergedLength);
        if (merged[pos] == 0) {
            assert(elementLength == 7);
            assert(memcmp(merged + pos + 2, "1Joey_6", 7) == 0);
            ++ssidCount;
        } else if (merged[pos] == 250) {
            ++keepCount;
        } else if (merged[pos] == 71) {
            ++setCount;
        }
    }
    assert(ssidCount == 1);   /* the set's empty one did not survive */
    assert(keepCount == 1);   /* an element the profile does not restate */
    assert(setCount == 0);    /* the set's own element is gone */

    printf("wcl_mbssid: ok\n");
    return 0;
}
