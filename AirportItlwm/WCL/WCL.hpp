//
//  WCL.hpp
//  AirportItlwm
//
//  Created by laobamac on 2026/10/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifndef AirportWCL_hpp
#define AirportWCL_hpp

#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace AirportWCL {

enum class ChannelBand : uint16_t { GHz2 = 0, GHz5 = 0xc000, GHz6 = 0x4000 };

inline bool validChannel(unsigned channel, ChannelBand band) {
    if (band == ChannelBand::GHz6)
        return channel >= 1 && channel <= 233 && (channel - 1) % 4 == 0;
    return channel >= 1 && channel <= (band == ChannelBand::GHz2 ? 14U : 196U) &&
        (band != ChannelBand::GHz5 || channel > 14);
}

inline uint16_t channelSpec20(unsigned channel, ChannelBand band) {
    return validChannel(channel, band) ? uint16_t(channel | 0x1000 | uint16_t(band)) : 0;
}

inline bool decodeChannelSpec20(uint16_t spec, unsigned &channel, ChannelBand &band) {
    uint16_t bandBits = spec & 0xc000;
    band = bandBits == 0xc000 ? ChannelBand::GHz5 :
        bandBits == 0x4000 ? ChannelBand::GHz6 : ChannelBand::GHz2;
    unsigned number = spec & 0xff;
    if (channelSpec20(number, band) != spec)
        return false;
    channel = number;
    return true;
}

enum class MacUpdate { Invalid, Unchanged, Busy, Change };
inline MacUpdate planMacUpdate(const uint8_t *current, const uint8_t *requested,
                               size_t length, bool initializing) {
    if (!current || !requested || length != 6 || (requested[0] & 1))
        return MacUpdate::Invalid;
    uint8_t bits = 0;
    for (unsigned i = 0; i < 6; ++i) bits |= requested[i];
    if (!bits) return MacUpdate::Invalid;
    if (memcmp(current, requested, 6) == 0) return MacUpdate::Unchanged;
    return initializing ? MacUpdate::Busy : MacUpdate::Change;
}

// Returns true when this is an internal MAC operation, not an adapter reset.
inline bool consumeMacReconfiguration(bool &pending, bool ready) {
    if (!pending) return false;
    if (ready) pending = false;
    return true;
}

struct HardwareAddress {
    uint32_t version;
    uint8_t address[6];
    uint8_t padding[2];
};
static_assert(sizeof(HardwareAddress) == 12, "HW_ADDR native wire size");
static_assert(offsetof(HardwareAddress, address) == 4, "HW_ADDR native address offset");
inline bool copyHardwareAddress(const uint8_t *address, HardwareAddress &out) {
    out = {};
    if (planMacUpdate(address, address, 6, false) == MacUpdate::Invalid) return false;
    out.version = 1;
    memcpy(out.address, address, 6);
    return true;
}

enum BeaconFlags : uint32_t {
    SSIDPresent = 1U << 1,
    RSSIValid = 1U << 14
};

enum Message : uint32_t {
    ResetInterface = 49,
    DriverAvailable = 55,
    Supplicant = 76,
    ScanResult = 201,
    Deauth = 203,
    AssocComplete = 211,
    FirstBeacon = 212,
    ConnectComplete = 213,
    JoinAbortComplete = 214,
    LinkStatus = 216,
    LqmUpdate = 39,
    ScanDone = 237
};

struct SupplicantEvent {
    uint32_t version;
    uint32_t event;
    uint32_t status;
    uint32_t flags;
    uint8_t reserved[24];
};
static_assert(sizeof(SupplicantEvent) == 0x28, "Native supplicant event size");
static_assert(offsetof(SupplicantEvent, status) == 8, "Native supplicant result");

struct SequoiaLqmUpdate {
    uint8_t rssiValid;
    uint8_t reserved0[3];
    int32_t rssi;
    uint8_t reserved1[0x150 - 8];
};
static_assert(sizeof(SequoiaLqmUpdate) == 0x150, "Sequoia LQM size");
static_assert(offsetof(SequoiaLqmUpdate, rssi) == 4, "Sequoia LQM RSSI offset");

// WCLNetManager::handleLqmUpdate consumes this 0x1dc snapshot.
// Only beacon reception is valid; unavailable radio measurements stay invalid.
struct LqmBeaconUpdate {
    uint8_t prefix[0x28];
    uint32_t receivedDelta;
    uint32_t scheduledDelta;
    uint8_t beaconValid;
    uint8_t reserved[0x1d8 - 0x31];
    uint8_t snapshotValid;
    uint8_t countersValid;
    uint8_t tail[2];
};
static_assert(sizeof(LqmBeaconUpdate) == 0x1dc, "WCL LQM update size");
static_assert(offsetof(LqmBeaconUpdate, receivedDelta) == 0x28, "WCL beacon delta offset");
static_assert(offsetof(LqmBeaconUpdate, beaconValid) == 0x30, "WCL beacon valid offset");
static_assert(offsetof(LqmBeaconUpdate, snapshotValid) == 0x1d8, "WCL snapshot valid offset");
inline bool makeBeaconUpdate(uint32_t receivedDelta, LqmBeaconUpdate &out)
{
    out = {};
    if (!receivedDelta)
        return false;
    out.receivedDelta = receivedDelta;
    out.beaconValid = out.snapshotValid = out.countersValid = 1;
    return true;
}

struct DriverAvailability {
    uint32_t version;
    uint32_t reserved0;
    uint32_t available;
    uint32_t reserved1;
    uint32_t reason;
    uint32_t subReason;
    uint8_t reserved2[0xf8 - 24];
};

static_assert(sizeof(DriverAvailability) == 0xf8, "DriverAvailability size");

struct BeaconMetadata {
    uint32_t ieLength;
    uint16_t channelSpec;
    uint8_t ssid[32];
    uint8_t ssidLength;
    uint8_t channel;
    uint8_t reserved0;
    uint8_t bssid[6];
    uint8_t reserved1;
    int32_t rssi;
    int16_t noise;
    int16_t snr;
    uint16_t interval;
    uint16_t capability;
#if !defined(__IO80211_TARGET) || __IO80211_TARGET != __MAC_15_2
    uint32_t reserved2;
#endif
    uint32_t flags;
};

struct AssociationEvent {
    uint16_t status;
    uint16_t reason;
    uint8_t mlo;
    uint8_t bssid[6];
    uint8_t reserved;
    uint32_t mloData[2];
    int32_t driverStatus;
    int32_t driverReason;
};

struct ConnectionPeer {
    uint8_t bssid[6];
    uint16_t reserved;
    int32_t driverStatus;
    int32_t driverReason;
};

struct FirstBeaconEvent {
    uint16_t status;
    uint16_t reason;
    ConnectionPeer peer;
};

struct ConnectionEvent {
    uint16_t status;
    uint16_t reason;
    ConnectionPeer peers[10];
};

struct LinkStatusEvent {
    uint8_t bssid[6];
    uint8_t up;
    uint8_t inSleep;
    uint32_t reason;
    uint32_t reserved;
};
static_assert(sizeof(LinkStatusEvent) == 16, "LinkStatusEvent size");
static_assert(offsetof(LinkStatusEvent, up) == 6, "LinkStatusEvent up offset");

struct DeauthEvent {
    int32_t driverStatus;
    int32_t driverReason;
    uint16_t reason;
    uint8_t bssid[6];
    uint8_t disassociation;
    uint8_t reserved[3];
};

struct __attribute__((packed)) ChannelEntry {
    uint16_t channelSpec;
    uint8_t reserved[4];
    uint8_t channel;
    uint8_t flags;
};

struct __attribute__((packed)) ChannelInfo {
    ChannelEntry channels[400];
    uint16_t count;
    uint8_t country[3];
    uint8_t supports6GHz;
};

#if defined(__IO80211_TARGET) && __IO80211_TARGET == __MAC_15_2
static_assert(sizeof(BeaconMetadata) == 0x40, "Sequoia BeaconMetadata size");
static_assert(offsetof(BeaconMetadata, flags) == 0x3c, "Sequoia BeaconMetadata flags");
#else
static_assert(sizeof(BeaconMetadata) == 0x44, "BeaconMetadata size");
static_assert(offsetof(BeaconMetadata, flags) == 0x40, "BeaconMetadata flags");
#endif
static_assert(offsetof(BeaconMetadata, bssid) == 0x29, "BeaconMetadata BSSID");
static_assert(offsetof(BeaconMetadata, rssi) == 0x30, "BeaconMetadata RSSI");
static_assert(sizeof(AssociationEvent) == 0x1c, "AssociationEvent size");
static_assert(sizeof(FirstBeaconEvent) == 0x14, "FirstBeaconEvent size");
static_assert(sizeof(ConnectionEvent) == 0xa4, "ConnectionEvent size");
static_assert(sizeof(DeauthEvent) == 0x14, "DeauthEvent size");
static_assert(sizeof(ChannelInfo) == 0xc86, "ChannelInfo size");

struct NativeChannelInfo {
    uint32_t version;
    uint32_t reserved0;
    uint8_t country[4];
    uint16_t count;
    uint16_t channelSpec[400];
    uint8_t channel[400];
    uint8_t indoor[400];
    uint8_t dfs[400];
    uint8_t passive[400];
    uint8_t supports40MHz[400];
    uint8_t supports80MHz[400];
    uint8_t reserved1[2];
    uint32_t firmwareChannelSpec[400];
    uint32_t channelBitmap[400];
    uint8_t reserved2[0x2720 - 0x1910];
};
static_assert(sizeof(NativeChannelInfo) == 0x2720, "CHANNELS_INFO native size");
static_assert(offsetof(NativeChannelInfo, country) == 8, "CHANNELS_INFO country");
static_assert(offsetof(NativeChannelInfo, count) == 0xc, "CHANNELS_INFO count");
static_assert(offsetof(NativeChannelInfo, channelSpec) == 0xe, "CHANNELS_INFO chanspec");
static_assert(offsetof(NativeChannelInfo, channel) == 0x32e, "CHANNELS_INFO channel");
static_assert(offsetof(NativeChannelInfo, indoor) == 0x4be, "CHANNELS_INFO indoor");
static_assert(offsetof(NativeChannelInfo, dfs) == 0x64e, "CHANNELS_INFO DFS");
static_assert(offsetof(NativeChannelInfo, passive) == 0x7de, "CHANNELS_INFO passive");
static_assert(offsetof(NativeChannelInfo, supports40MHz) == 0x96e, "CHANNELS_INFO 40 MHz");
static_assert(offsetof(NativeChannelInfo, supports80MHz) == 0xafe, "CHANNELS_INFO 80 MHz");
static_assert(offsetof(NativeChannelInfo, firmwareChannelSpec) == 0xc90, "CHANNELS_INFO firmware chanspec");
static_assert(offsetof(NativeChannelInfo, channelBitmap) == 0x12d0, "CHANNELS_INFO bitmap");

inline bool appendChannel(NativeChannelInfo &info, unsigned channel, ChannelBand band,
                          bool dfs, bool passive, bool supports40MHz, bool supports80MHz)
{
    uint16_t spec = channelSpec20(channel, band);
    if (!spec || info.count >= 400)
        return false;
    unsigned index = info.count++;
    info.channelSpec[index] = spec;
    info.firmwareChannelSpec[index] = spec;
    info.channel[index] = channel;
    info.dfs[index] = dfs;
    info.passive[index] = passive;
    info.supports40MHz[index] = supports40MHz;
    info.supports80MHz[index] = supports80MHz;
    info.channelBitmap[index] = 3U | (band == ChannelBand::GHz5 ? 4U :
        (band == ChannelBand::GHz6 ? 0x200U : 0U)) |
        (dfs ? 8U : 0U) | (passive ? 32U : 0U);
    return true;
}

struct TrafficCounters {
    uint64_t realtimeInfraTx;
    uint64_t realtimeInfraRx;
    uint64_t infraTx;
    uint64_t infraRx;
    uint64_t realtimeAwdlTx;
    uint64_t realtimeNanTx;
    uint64_t timestampNanoseconds;
};
static_assert(sizeof(TrafficCounters) == 0x38, "WCL_TRAFFIC_COUNTERS native size");
static_assert(offsetof(TrafficCounters, timestampNanoseconds) == 0x30, "WCL traffic timestamp");

inline TrafficCounters makeTrafficCounters(const uint64_t *tx, const uint64_t *rx,
                                           uint64_t timestampNanoseconds)
{
    TrafficCounters out = {};
    out.realtimeInfraTx = tx[2] + tx[3];
    out.realtimeInfraRx = rx[2] + rx[3];
    for (unsigned ac = 0; ac < 4; ++ac) {
        out.infraTx += tx[ac];
        out.infraRx += rx[ac];
    }
    out.timestampNanoseconds = timestampNanoseconds;
    return out;
}

struct ScanTiming {
    uint32_t maxOutTU;
    bool fragmented;
};

inline ScanTiming scanTiming(uint32_t awayMilliseconds, bool associated,
                             bool supportsFragmentation)
{
    if (!associated)
        return {0, false};
    if (!awayMilliseconds)
        return {120, false};
    uint64_t requested = uint64_t(awayMilliseconds) * 1000 / 1024;
    uint32_t minimum = supportsFragmentation ? 44 : 110;
    uint32_t maxOut = requested < minimum ? minimum :
        requested > 120 ? 120 : uint32_t(requested);
    return {maxOut, maxOut < 110};
}

inline uint16_t read16(const uint8_t *p) {
    return uint16_t(p[0]) | uint16_t(p[1]) << 8;
}

inline uint32_t read32(const uint8_t *p) {
    return uint32_t(read16(p)) | uint32_t(read16(p + 2)) << 16;
}

inline bool scanUsesProbes(bool requested, bool activeRequest) {
    return requested ? activeRequest : true;
}

inline bool probeChannel(bool active, bool passiveOnly, bool dfs) {
    return active && !passiveOnly && !dfs;
}

struct ScanRequest {
    uint32_t identifier;
    uint32_t type;
    uint8_t ssid[32];
    uint32_t ssidLength;
    uint8_t bssid[6];
    uint32_t channelCount;
    uint8_t channels[32];
    uint8_t channels6GHz[32];
};

// RX buffers may carry trailing FCS or DMA padding after the IE chain.
// Return the length of the strictly parsed IE prefix so callers can forward
// the valid elements without rejecting the whole frame.
inline size_t validIEPrefix(const uint8_t *data, size_t length, size_t tailAllowance = 8) {
    if (!data || length > 2048)
        return 0;
    size_t offset = 0;
    while (offset < length) {
        size_t remaining = length - offset;
        if (remaining <= tailAllowance)
            break;
        if (size_t(data[offset + 1]) + 2 > remaining)
            return 0;
        offset += size_t(data[offset + 1]) + 2;
    }
    return offset;
}

inline bool scanChannelSelected(const uint8_t *channels, bool restricted, unsigned channel) {
    return !restricted || (channel < 256 && (channels[channel / 8] & (1U << (channel % 8))));
}

inline bool scanChannelSelected(const uint8_t *channels, const uint8_t *channels6GHz,
                                bool is6GHz, bool restricted, unsigned channel) {
    return scanChannelSelected(is6GHz ? channels6GHz : channels, restricted, channel);
}

inline bool is6GHzPsc(unsigned channel) {
    return channel >= 5 && channel <= 229 && (channel - 5) % 16 == 0;
}

inline uint32_t shortSsid(const uint8_t *ssid, size_t length) {
    uint32_t crc = ~0U;
    for (size_t i = 0; i < length; ++i) {
        crc ^= ssid[i];
        for (unsigned bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
    }
    return ~crc;
}

inline bool decodeScan(const void *buffer, size_t length, ScanRequest &out) {
    if (!buffer || length < 0x58)
        return false;
    const uint8_t *p = static_cast<const uint8_t *>(buffer);
    uint32_t count = read32(p + 0x54), ssidLength = read32(p + 0x1c);
    uint32_t type = read32(p + 0x40);
    if (count > 400 || ssidLength > 32 || type < 1 || type > 4 ||
        length < 0x58 + size_t(count) * 12)
        return false;
    out = {};
    out.identifier = read32(p);
    out.type = type;
    out.ssidLength = ssidLength;
    out.channelCount = count;
    memcpy(out.ssid, p + 0x20, ssidLength);
    memcpy(out.bssid, p + 0x14, 6);
    // Native entries are apple80211_channel: version, channel, flags (12 bytes).
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t *entry = p + 0x58 + size_t(i) * 12;
        uint32_t channel = read32(entry + 4), flags = read32(entry + 8);
        uint32_t bands = flags & (0x8 | 0x10 | 0x2000);
        if (bands && (bands & (bands - 1)))
            continue;
        ChannelBand band = bands == 0x2000 ? ChannelBand::GHz6 :
            (bands == 0x10 || (!bands && channel > 14) ?
                ChannelBand::GHz5 : ChannelBand::GHz2);
        if (!validChannel(channel, band))
            continue;
        uint8_t *map = band == ChannelBand::GHz6 ? out.channels6GHz : out.channels;
        map[channel / 8] |= 1U << (channel % 8);
    }
    return true;
}

struct JoinRequest {
    uint32_t lowerAuth;
    uint32_t upperAuth;
    uint32_t ssidLength;
    uint8_t ssid[32];
    uint32_t keyLength;
    uint32_t keyCipher;
    uint16_t keyIndex;
    uint8_t key[64];
    uint8_t bssid[6];
    uint8_t peerIsMlo;
    uint8_t peerMldAddress[6];
    uint16_t channelSpec;
    uint16_t rsnLength;
    uint8_t rsn[257];
};

inline bool validCipherKey(uint32_t cipher, uint32_t length, uint16_t flags,
                           uint16_t index, uint32_t rscLength) {
    // Native WCL accepts PMK/MSK for enterprise, not legacy PTK/GTK.
    (void)flags; // PTK/GTK selectors do not apply to PMK material.
    (void)index;
    return (cipher == 6 || cipher == 7 || cipher == 9) && length == 32 && rscLength <= 8;
}

inline bool validRSNOverride(const uint8_t *ie, size_t length) {
    if (!ie || length > 257) return false;
    if (!length) return true;
    if (length < 4 || size_t(ie[1]) + 2 != length) return false;
    if (ie[0] == 48) return ie[2] == 1 && ie[3] == 0;
    return length >= 8 && ie[0] == 221 && ie[2] == 0 && ie[3] == 0x50 &&
        ie[4] == 0xf2 && ie[5] == 1 && ie[6] == 1 && ie[7] == 0;
}

enum class LegacyAuth { Invalid, Open, Wep, Personal, PersonalSAE, Enterprise };

enum class DerivedCredentialKind : uint8_t { Personal, SAE };
struct DerivedCredentialCache {
    uint8_t valid;
    DerivedCredentialKind kind;
    uint8_t ssidLength;
    uint8_t credentialLength;
    uint8_t resultLength;
    uint8_t ssid[32];
    uint8_t credential[64];
    uint8_t result[64];
};

inline bool matchesDerivedCredential(const DerivedCredentialCache &cache,
                                     DerivedCredentialKind kind,
                                     const uint8_t *ssid, size_t ssidLength,
                                     const uint8_t *credential, size_t credentialLength) {
    return cache.valid && cache.kind == kind && ssid && ssidLength && ssidLength <= 32 &&
        credential && credentialLength && credentialLength <= 63 &&
        cache.resultLength == (kind == DerivedCredentialKind::Personal ? 32 : 64) &&
        cache.ssidLength == ssidLength && cache.credentialLength == credentialLength &&
        memcmp(cache.ssid, ssid, ssidLength) == 0 &&
        memcmp(cache.credential, credential, credentialLength) == 0;
}

inline LegacyAuth classifyLegacyAuth(const JoinRequest &j) {
    // Values from apple80211_authtype/cipher_type, used by the WCL association request.
    if (!validRSNOverride(j.rsn, j.rsnLength)) return LegacyAuth::Invalid;
    if (j.lowerAuth != 1) return LegacyAuth::Invalid;
    if (!j.upperAuth) {
        if (!j.keyLength) return LegacyAuth::Open;
        if (j.keyIndex < 4 && ((j.keyLength == 5 && j.keyCipher == 1) ||
                              (j.keyLength == 13 && j.keyCipher == 2)))
            return LegacyAuth::Wep;
        return LegacyAuth::Invalid;
    }
    const uint32_t personal = (1u << 1) | (1u << 3) | (1u << 10);
    const uint32_t enterprise = (1u << 0) | (1u << 2) | (1u << 11);
    const uint32_t sae = 1u << 12;
    if (j.upperAuth & ~(personal | enterprise | sae)) return LegacyAuth::Invalid;
    if ((j.upperAuth & sae) && j.upperAuth != sae) return LegacyAuth::Invalid;
    if ((j.upperAuth & personal) && (j.upperAuth & enterprise)) return LegacyAuth::Invalid;
    if (j.upperAuth & personal) {
        if (j.keyLength == 32 && (j.keyCipher == 6 || j.keyCipher == 7))
            return LegacyAuth::Personal;
        if (j.keyCipher == 10 && j.keyLength >= 8 && j.keyLength <= 63 &&
            !memchr(j.key, 0, j.keyLength))
            return LegacyAuth::Personal;
        return LegacyAuth::Invalid;
    }
    // Native WCL carries the raw SAE password (cipher 10), not a PMK.
    if (j.upperAuth == sae) {
        if (j.keyLength < 1 || j.keyLength > 63 || j.keyCipher != 10)
            return LegacyAuth::Invalid;
        if (j.rsnLength >= 8 &&
            (j.rsn[4] != 0 || j.rsn[5] != 0x0f || j.rsn[6] != 0xac ||
             j.rsn[7] != 4))
            return LegacyAuth::Invalid;
        return LegacyAuth::PersonalSAE;
    }
    if (j.upperAuth & enterprise)
        return (!j.keyLength || (j.keyLength == 32 && (j.keyCipher == 6 || j.keyCipher == 7))) ?
            LegacyAuth::Enterprise : LegacyAuth::Invalid;
    return LegacyAuth::Invalid;
}

inline bool decodeJoin(const void *buffer, size_t length, JoinRequest &out) {
    if (!buffer || length < 0x218)
        return false;
    const uint8_t *p = static_cast<const uint8_t *>(buffer);
    uint32_t count = read32(p + 0x214), ssidLength = read32(p + 0x1c);
    uint32_t keyLength = read32(p + 0x44);
    uint16_t rsnLength = read16(p + 0xd4);
    if (!count || count > 10 || !ssidLength || ssidLength > 32 ||
        keyLength > 64 || rsnLength > 257 || length < 0x218 + size_t(count) * 18)
        return false;
    if (p[0x21c] & 1)
        return false;
    uint8_t addressBits = 0;
    for (unsigned i = 0; i < 6; ++i)
        addressBits |= p[0x21c + i];
    if (!addressBits)
        return false;
    out = {};
    out.lowerAuth = read32(p + 0x10);
    out.upperAuth = read32(p + 0x14);
    out.ssidLength = ssidLength;
    memcpy(out.ssid, p + 0x20, ssidLength);
    out.keyLength = keyLength;
    out.keyCipher = read32(p + 0x48);
    out.keyIndex = read16(p + 0x4e);
    memcpy(out.key, p + 0x50, keyLength);
    memcpy(out.bssid, p + 0x21c, 6);
    out.peerIsMlo = (p[0x1e0] & 0x80) != 0;
    if (out.peerIsMlo) {
        uint8_t mldAddressBits = 0;
        for (unsigned i = 0; i < 6; ++i)
            mldAddressBits |= p[0x1d7 + i];
        if (!mldAddressBits || (p[0x1d7] & 1))
            return false;
        memcpy(out.peerMldAddress, p + 0x1d7, 6);
    }
    out.channelSpec = read16(p + 0x228);
    out.rsnLength = rsnLength;
    memcpy(out.rsn, p + 0xd6, rsnLength);
    return true;
}

}
#endif
