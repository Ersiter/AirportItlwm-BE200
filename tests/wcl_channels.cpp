#include "../AirportItlwm/WCL/WCL.hpp"

#include <assert.h>

static void write32(uint8_t *buffer, uint32_t value)
{
    buffer[0] = uint8_t(value);
    buffer[1] = uint8_t(value >> 8);
    buffer[2] = uint8_t(value >> 16);
    buffer[3] = uint8_t(value >> 24);
}

static void addChannel(uint8_t *buffer, uint32_t index, uint32_t channel,
                       uint32_t flags)
{
    uint8_t *entry = buffer + 0x58 + index * 12;
    write32(entry + 4, channel);
    write32(entry + 8, flags);
}

int main()
{
    using AirportWCL::ChannelBand;
    using AirportWCL::NativeChannelInfo;

    assert(AirportWCL::validChannel(1, ChannelBand::GHz2));
    assert(AirportWCL::validChannel(1, ChannelBand::GHz6));
    assert(AirportWCL::validChannel(149, ChannelBand::GHz5));
    assert(AirportWCL::validChannel(149, ChannelBand::GHz6));
    assert(AirportWCL::validChannel(233, ChannelBand::GHz6));
    assert(!AirportWCL::validChannel(0, ChannelBand::GHz6));
    assert(!AirportWCL::validChannel(2, ChannelBand::GHz6));
    assert(!AirportWCL::validChannel(237, ChannelBand::GHz6));
    assert(AirportWCL::channelSpec20(1, ChannelBand::GHz2) == 0x1001);
    assert(AirportWCL::channelSpec20(1, ChannelBand::GHz6) == 0x5001);
    assert(AirportWCL::channelSpec20(149, ChannelBand::GHz5) == 0xd095);
    assert(AirportWCL::channelSpec20(149, ChannelBand::GHz6) == 0x5095);
    assert(AirportWCL::channelSpec20(233, ChannelBand::GHz6) == 0x50e9);

    unsigned channel = 0;
    ChannelBand band = ChannelBand::GHz2;
    assert(AirportWCL::decodeChannelSpec20(0x1001, channel, band));
    assert(channel == 1 && band == ChannelBand::GHz2);
    assert(AirportWCL::decodeChannelSpec20(0xd095, channel, band));
    assert(channel == 149 && band == ChannelBand::GHz5);
    assert(AirportWCL::decodeChannelSpec20(0x5095, channel, band));
    assert(channel == 149 && band == ChannelBand::GHz6);
    assert(!AirportWCL::decodeChannelSpec20(0x3001, channel, band));
    assert(!AirportWCL::decodeChannelSpec20(0x9001, channel, band));
    assert(!AirportWCL::decodeChannelSpec20(0x5096, channel, band));

    AirportWCL::JoinRequest join = {};
    join.lowerAuth = 1;
    join.upperAuth = 1u << 3;
    join.keyLength = 32;
    join.keyCipher = 6;
    assert(AirportWCL::classifyLegacyAuth(join) == AirportWCL::LegacyAuth::Personal);
    join.keyLength = 8;
    join.keyCipher = 10;
    memcpy(join.key, "password", 8);
    assert(AirportWCL::classifyLegacyAuth(join) == AirportWCL::LegacyAuth::Personal);
    memset(join.key, 'a', 63);
    join.keyLength = 63;
    assert(AirportWCL::classifyLegacyAuth(join) == AirportWCL::LegacyAuth::Personal);
    join.keyLength = 7;
    assert(AirportWCL::classifyLegacyAuth(join) == AirportWCL::LegacyAuth::Invalid);
    join.keyLength = 64;
    assert(AirportWCL::classifyLegacyAuth(join) == AirportWCL::LegacyAuth::Invalid);
    join.keyLength = 8;
    join.key[4] = 0;
    assert(AirportWCL::classifyLegacyAuth(join) == AirportWCL::LegacyAuth::Invalid);

    const uint8_t transitionRsn[] = {
        48, 24, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4,
        2, 0, 0, 0x0f, 0xac, 2, 0, 0x0f, 0xac, 8, 0xc0, 0
    };
    memcpy(join.rsn, transitionRsn, sizeof(transitionRsn));
    join.rsnLength = sizeof(transitionRsn);
    memcpy(join.key, "password", 8);
    join.keyLength = 8;
    join.keyCipher = 10;
    join.upperAuth = 1u << 3;
    assert(AirportWCL::classifyLegacyAuth(join) == AirportWCL::LegacyAuth::Personal);
    join.upperAuth = 1u << 12;
    assert(AirportWCL::classifyLegacyAuth(join) == AirportWCL::LegacyAuth::PersonalSAE);
    join.upperAuth |= 1u << 3;
    assert(AirportWCL::classifyLegacyAuth(join) == AirportWCL::LegacyAuth::Invalid);

    const uint8_t wpa2OnlyRsn[] = {
        48, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4,
        1, 0, 0, 0x0f, 0xac, 2, 0xc0, 0
    };
    memcpy(join.rsn, wpa2OnlyRsn, sizeof(wpa2OnlyRsn));
    join.rsnLength = sizeof(wpa2OnlyRsn);
    join.upperAuth = 1u << 3;
    assert(AirportWCL::classifyLegacyAuth(join) == AirportWCL::LegacyAuth::Personal);

    AirportWCL::DerivedCredentialCache cached = {};
    cached.valid = 1;
    cached.kind = AirportWCL::DerivedCredentialKind::Personal;
    cached.ssidLength = 4;
    cached.credentialLength = 8;
    cached.resultLength = 32;
    memcpy(cached.ssid, "home", 4);
    memcpy(cached.credential, "password", 8);
    assert(AirportWCL::matchesDerivedCredential(cached,
        AirportWCL::DerivedCredentialKind::Personal,
        reinterpret_cast<const uint8_t *>("home"), 4,
        reinterpret_cast<const uint8_t *>("password"), 8));
    assert(!AirportWCL::matchesDerivedCredential(cached,
        AirportWCL::DerivedCredentialKind::Personal,
        reinterpret_cast<const uint8_t *>("away"), 4,
        reinterpret_cast<const uint8_t *>("password"), 8));
    assert(!AirportWCL::matchesDerivedCredential(cached,
        AirportWCL::DerivedCredentialKind::Personal,
        reinterpret_cast<const uint8_t *>("home"), 4,
        reinterpret_cast<const uint8_t *>("passw0rd"), 8));
    assert(!AirportWCL::matchesDerivedCredential(cached,
        AirportWCL::DerivedCredentialKind::SAE,
        reinterpret_cast<const uint8_t *>("home"), 4,
        reinterpret_cast<const uint8_t *>("password"), 8));
    cached.kind = AirportWCL::DerivedCredentialKind::SAE;
    cached.resultLength = 64;
    assert(AirportWCL::matchesDerivedCredential(cached,
        AirportWCL::DerivedCredentialKind::SAE,
        reinterpret_cast<const uint8_t *>("home"), 4,
        reinterpret_cast<const uint8_t *>("password"), 8));
    cached.valid = 0;
    assert(!AirportWCL::matchesDerivedCredential(cached,
        AirportWCL::DerivedCredentialKind::Personal,
        reinterpret_cast<const uint8_t *>("home"), 4,
        reinterpret_cast<const uint8_t *>("password"), 8));

    uint8_t requestBuffer[0x58 + 4 * 12] = {};
    write32(requestBuffer + 0x40, 1);
    write32(requestBuffer + 0x54, 4);
    addChannel(requestBuffer, 0, 1, 0x8);
    addChannel(requestBuffer, 1, 1, 0x2000);
    addChannel(requestBuffer, 2, 149, 0x10);
    addChannel(requestBuffer, 3, 149, 0x2000);
    AirportWCL::ScanRequest request = {};
    assert(AirportWCL::decodeScan(requestBuffer, sizeof(requestBuffer), request));
    assert(AirportWCL::scanChannelSelected(request.channels, true, 1));
    assert(AirportWCL::scanChannelSelected(request.channels6GHz, true, 1));
    assert(AirportWCL::scanChannelSelected(request.channels, true, 149));
    assert(AirportWCL::scanChannelSelected(request.channels6GHz, true, 149));

    assert(AirportWCL::is6GHzPsc(5));
    assert(AirportWCL::is6GHzPsc(21));
    assert(AirportWCL::is6GHzPsc(229));
    assert(!AirportWCL::is6GHzPsc(1));
    assert(!AirportWCL::is6GHzPsc(9));
    const uint8_t crcInput[] = "123456789";
    assert(AirportWCL::shortSsid(crcInput, sizeof(crcInput) - 1) == 0xcbf43926U);

    uint8_t mappedLegacy[32] = {}, mapped6GHz[32] = {};
    mappedLegacy[1 / 8] |= 1U << (1 % 8);
    mapped6GHz[1 / 8] |= 1U << (1 % 8);
    assert(AirportWCL::scanChannelSelected(mappedLegacy, mapped6GHz, false, true, 1));
    assert(AirportWCL::scanChannelSelected(mappedLegacy, mapped6GHz, true, true, 1));
    mapped6GHz[1 / 8] &= ~(1U << (1 % 8));
    assert(!AirportWCL::scanChannelSelected(mappedLegacy, mapped6GHz, true, true, 1));
    assert(AirportWCL::scanChannelSelected(mappedLegacy, mapped6GHz, false, true, 1));

    uint8_t only6GHzBuffer[0x58 + 2 * 12] = {};
    write32(only6GHzBuffer + 0x40, 1);
    write32(only6GHzBuffer + 0x54, 2);
    addChannel(only6GHzBuffer, 0, 1, 0x2000);
    addChannel(only6GHzBuffer, 1, 149, 0x2000);
    assert(AirportWCL::decodeScan(only6GHzBuffer, sizeof(only6GHzBuffer), request));
    assert(!AirportWCL::scanChannelSelected(request.channels, true, 1));
    assert(!AirportWCL::scanChannelSelected(request.channels, true, 149));
    assert(AirportWCL::scanChannelSelected(request.channels6GHz, true, 1));
    assert(AirportWCL::scanChannelSelected(request.channels6GHz, true, 149));

    uint8_t onlyLegacyBuffer[0x58 + 2 * 12] = {};
    write32(onlyLegacyBuffer + 0x40, 1);
    write32(onlyLegacyBuffer + 0x54, 2);
    addChannel(onlyLegacyBuffer, 0, 1, 0x8);
    addChannel(onlyLegacyBuffer, 1, 149, 0x10);
    assert(AirportWCL::decodeScan(onlyLegacyBuffer, sizeof(onlyLegacyBuffer), request));
    assert(AirportWCL::scanChannelSelected(request.channels, true, 1));
    assert(AirportWCL::scanChannelSelected(request.channels, true, 149));
    assert(!AirportWCL::scanChannelSelected(request.channels6GHz, true, 1));
    assert(!AirportWCL::scanChannelSelected(request.channels6GHz, true, 149));

    uint8_t invalidBuffer[0x58 + 3 * 12] = {};
    write32(invalidBuffer + 0x40, 1);
    write32(invalidBuffer + 0x54, 3);
    addChannel(invalidBuffer, 0, 149, 0x8 | 0x2000);
    addChannel(invalidBuffer, 1, 237, 0x2000);
    addChannel(invalidBuffer, 2, 2, 0x2000);
    assert(AirportWCL::decodeScan(invalidBuffer, sizeof(invalidBuffer), request));
    assert(!AirportWCL::scanChannelSelected(request.channels, true, 149));
    assert(!AirportWCL::scanChannelSelected(request.channels6GHz, true, 149));
    assert(!AirportWCL::scanChannelSelected(request.channels6GHz, true, 237));
    assert(!AirportWCL::scanChannelSelected(request.channels6GHz, true, 2));

    NativeChannelInfo channels = {};
    assert(AirportWCL::appendChannel(channels, 149, ChannelBand::GHz6,
        false, true, false, false));
    assert(channels.count == 1);
    assert(channels.channelSpec[0] == 0x5095);
    assert(channels.channelBitmap[0] & 0x200);
    assert(!(channels.channelBitmap[0] & 4));
    assert(channels.sixGHz[0] == 1);
    assert(!AirportWCL::appendChannel(channels, 237, ChannelBand::GHz6,
        false, true, false, false));
    assert(channels.count == 1);

    NativeChannelInfo five = {};
    assert(AirportWCL::appendChannel(five, 36, ChannelBand::GHz5,
        false, false, true, true));
    assert(five.sixGHz[0] == 0);
    assert(five.indoor[0] == 0);
    return 0;
}
