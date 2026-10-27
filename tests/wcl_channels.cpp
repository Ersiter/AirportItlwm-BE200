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
    assert(!AirportWCL::appendChannel(channels, 237, ChannelBand::GHz6,
        false, true, false, false));
    assert(channels.count == 1);
    return 0;
}
