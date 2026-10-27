"""Compile the production MCC response parser and channel-map path on the host."""
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = (root / "itlwm/hal_iwx/ItlIwx.cpp").read_text(encoding="utf-8")
registers = (root / "itlwm/hal_iwx/if_iwxreg.h").read_text(encoding="utf-8")


def function(text, opening):
    start = text.index(opening)
    brace = text.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


def declaration(text, opening):
    start = text.index(opening)
    brace = text.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:text.index(";", end) + 1]


def array(text, opening):
    start = text.index(opening)
    end = text.index("};", start) + 2
    return text[start:end]


structures = "\n".join(
    declaration(registers, name)
    for name in (
        "struct iwx_mcc_update_resp_v3",
        "struct iwx_mcc_update_resp {",
        "struct iwx_mcc_update_resp_v8",
    )
)
response_view = declaration(source, "struct iwx_mcc_response_view {")
parser = function(source, "static int\niwx_parse_mcc_update_response(")
apply_response = function(source, "static int\niwx_apply_mcc_update_response(")
version_normalizer = function(source, "static uint8_t\niwx_mcc_response_version_for_parse(")
lookup_notif = function(source, "uint8_t ItlIwx::\niwx_lookup_notif_ver(")
fw_cmd_version = declaration(registers, "struct iwx_fw_cmd_version {")
rx_packet_len = function(registers, "static uint32_t\niwx_rx_packet_len(")
rx_payload_len = function(registers, "static uint32_t\niwx_rx_packet_payload_len(")
channel_arrays = "\n".join(
    array(source, name)
    for name in (
        "const uint8_t iwx_nvm_channels_8000[]",
        "static const uint8_t iwx_nvm_channels_uhb[]",
    )
)
channel_map = function(source, "void ItlIwx::\niwx_init_channel_map(")

program = r'''
#include <cstddef>
#include <cstdint>
#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <vector>
#define __packed __attribute__((packed))
#define nitems(array) (sizeof(array) / sizeof((array)[0]))
#define IWX_NUM_2GHZ_CHANNELS 14
#define IWX_NUM_CHANNELS 110
#define IWX_FIRST_2GHZ_HT_MINUS 5
#define IWX_LAST_2GHZ_HT_PLUS 9
#define IWX_NVM_CHANNEL_VALID (1u << 0)
#define IWX_NVM_CHANNEL_ACTIVE (1u << 1)
#define IWX_NVM_CHANNEL_40MHZ (1u << 2)
#define IWX_NVM_CHANNEL_80MHZ (1u << 3)
#define IWX_NVM_CHANNEL_160MHZ (1u << 4)
#define IWX_NVM_CHANNEL_DFS (1u << 5)
#define IWX_FW_CMD_VER_UNKNOWN 99
#define IWX_LONG_GROUP 1
#define IWX_MCC_UPDATE_CMD 0xc8
#define IWX_FH_RSCSR_FRAME_SIZE_MSK 0x00003fff
#define IEEE80211_CHAN_2GHZ (1u << 0)
#define IEEE80211_CHAN_5GHZ (1u << 1)
#define IEEE80211_CHAN_CCK (1u << 2)
#define IEEE80211_CHAN_OFDM (1u << 3)
#define IEEE80211_CHAN_DYN (1u << 4)
#define IEEE80211_CHAN_A (1u << 5)
#define IEEE80211_CHAN_PASSIVE (1u << 6)
#define IEEE80211_CHAN_HT20 (1u << 7)
#define IEEE80211_CHAN_HT40U (1u << 8)
#define IEEE80211_CHAN_HT40D (1u << 9)
#define IEEE80211_CHAN_VHT80 (1u << 10)
#define IEEE80211_CHAN_VHT160 (1u << 11)
#define IEEE80211_CHAN_DFS (1u << 12)
#define IEEE80211_CHAN_6GHZ (1u << 13)
#define IEEE80211_IS_CHAN_2GHZ(channel) (((channel)->ic_flags & IEEE80211_CHAN_2GHZ) != 0)
#define IWX_UCODE_TLV_API_SCAN_EXT_CHAN_VER 58
#define IWX_UCODE_TLV_API_BAND_IN_RX_DATA 59
#define isset(array, bit) (((array)[(bit) / 8] & (1u << ((bit) % 8))) != 0)
#define DPRINTFN(...) do {} while (0)
static uint16_t le16toh(uint16_t value) { return value; }
static uint32_t le32toh(uint32_t value) { return value; }
static uint16_t le16_to_cpup(const uint16_t *value) { return *value; }
static uint32_t le32_to_cpup(const uint32_t *value) { return *value; }
struct iwx_cmd_header { uint8_t cmd, group_id, idx, qid; } __packed;
struct iwx_rx_packet {
    uint32_t len_n_flags;
    struct iwx_cmd_header hdr;
    uint8_t data[512];
} __packed;
RX_PACKET_LEN
RX_PAYLOAD_LEN
struct ieee80211_channel { int ic_freq = 0; uint32_t ic_flags = 0; };
struct ieee80211com { ieee80211_channel ic_channels[256]; };
struct iwx_nvm_data {
    bool sku_cap_band_52GHz_enable = true;
    bool sku_cap_11n_enable = true;
    bool sku_cap_11ac_enable = true;
    bool vht160_supported = false;
};
FW_CMD_VERSION
struct iwx_softc {
    ieee80211com sc_ic{};
    iwx_nvm_data sc_nvm{};
    uint8_t sc_ucode_api[16]{};
    bool sc_uhb_supported = false;
    int n_cmd_versions = 0;
    iwx_fw_cmd_version cmd_versions[4]{};
};
static int ieee80211_ieee2mhz(int channel, int band) { return channel * 5 + band; }
class ItlIwx {
public:
    uint8_t iwx_lookup_notif_ver(struct iwx_softc *, uint8_t, uint8_t);
    void iwx_init_channel_map(struct iwx_softc *, uint16_t *, uint32_t *, int);
};
STRUCTURES
RESPONSE_VIEW
ARRAYS
LOOKUP_NOTIF
VERSION_NORMALIZER
PARSER
APPLY_RESPONSE
CHANNEL_MAP

static_assert(sizeof(iwx_mcc_update_resp_v3) == 16, "MCC v3 header ABI");
static_assert(offsetof(iwx_mcc_update_resp_v3, n_channels) == 12, "MCC v3 count offset");
static_assert(sizeof(iwx_mcc_update_resp) == 20, "MCC v4 header ABI");
static_assert(offsetof(iwx_mcc_update_resp, n_channels) == 16, "MCC v4 count offset");
static_assert(sizeof(iwx_mcc_update_resp_v8) == 24, "MCC v8 header ABI");
static_assert(offsetof(iwx_mcc_update_resp_v8, n_channels) == 20, "MCC v8 count offset");

static void require(bool ok, const char *message) {
    if (!ok) { std::cerr << "FAIL: " << message << "\n"; std::exit(1); }
}

static iwx_rx_packet *make_packet(uint32_t payload_len) {
    auto *pkt = new iwx_rx_packet{};
    pkt->len_n_flags = sizeof(pkt->hdr) + payload_len;
    return pkt;
}

static void test_v8_response_maps_real_channels() {
    constexpr uint32_t count = 50;
    const size_t payload_len = sizeof(iwx_mcc_update_resp_v8) + count * sizeof(uint32_t);
    auto *pkt = make_packet(static_cast<uint32_t>(payload_len));
    auto *wire = reinterpret_cast<iwx_mcc_update_resp_v8 *>(pkt->data);
    wire->status = 0;
    wire->mcc = 0x434e;
    wire->cap = 0x12345678;
    wire->time = 7;
    wire->geo_info = 1;
    wire->source_id = 5;
    wire->n_channels = count;
    for (uint32_t i = 0; i < count; ++i)
        wire->channels[i] = (i == 0 ? IWX_NVM_CHANNEL_VALID | IWX_NVM_CHANNEL_ACTIVE : 0);

    iwx_mcc_response_view view{};
    iwx_softc sc{};
    ItlIwx driver;
    sc.n_cmd_versions = 1;
    sc.cmd_versions[0] = {IWX_MCC_UPDATE_CMD, IWX_LONG_GROUP, 1, 8};
    const uint8_t reported_version = driver.iwx_lookup_notif_ver(
        &sc, IWX_LONG_GROUP, IWX_MCC_UPDATE_CMD);
    require(reported_version == 8, "GL86 notification version table lookup");
    require(iwx_apply_mcc_update_response(
                pkt, iwx_mcc_response_version_for_parse(reported_version), true, &view) == 0,
            "v8 response parse and validation");
    require(view.status == 0 && view.cap == 0x12345678 && view.mcc == 0x434e,
            "v8 little-endian fields and accepted status retained");
    require(view.n_channels == count && view.channels == wire->channels,
            "v8 channel array view");

    driver.iwx_init_channel_map(&sc, nullptr,
                               const_cast<uint32_t *>(view.channels), view.n_channels);
    require(sc.sc_ic.ic_channels[1].ic_freq == 6,
            "v8 channel map reaches real channel mapper");
    require((sc.sc_ic.ic_channels[1].ic_flags & (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_HT20)) ==
            (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_HT20),
            "v8 channel flags mapped");
    wire->status = 4;
    require(iwx_apply_mcc_update_response(pkt, 8, true, &view) == 0 &&
            view.status == 4, "nonzero status remains available to caller");
    delete pkt;
}

static void test_v4_capability_layout() {
    constexpr uint32_t count = 1;
    const size_t payload_len = sizeof(iwx_mcc_update_resp) + sizeof(uint32_t);
    auto *pkt = make_packet(static_cast<uint32_t>(payload_len));
    auto *wire = reinterpret_cast<iwx_mcc_update_resp *>(pkt->data);
    wire->status = 0;
    wire->mcc = 0x5553;
    wire->cap = 0x1234;
    wire->n_channels = count;
    wire->channels[0] = IWX_NVM_CHANNEL_VALID;
    iwx_mcc_response_view view{};
    require(iwx_parse_mcc_update_response(pkt, 7, true, &view) == 0, "v4 response parse");
    require(view.cap == 0x1234 && view.n_channels == count, "v4 fields normalized");
    delete pkt;

    pkt = make_packet(static_cast<uint32_t>(payload_len));
    wire = reinterpret_cast<iwx_mcc_update_resp *>(pkt->data);
    wire->n_channels = count;
    wire->channels[0] = IWX_NVM_CHANNEL_VALID;
    iwx_softc sc{};
    ItlIwx driver;
    const uint8_t version = driver.iwx_lookup_notif_ver(&sc, IWX_LONG_GROUP,
                                                         IWX_MCC_UPDATE_CMD);
    require(version == IWX_FW_CMD_VER_UNKNOWN, "missing MCC version uses unknown sentinel");
    require(iwx_parse_mcc_update_response(pkt,
                iwx_mcc_response_version_for_parse(version), true, &view) == 0,
            "unknown notification version falls back to v4 capability");
    delete pkt;
}

static void test_v3_layout() {
    constexpr uint32_t count = 1;
    const size_t payload_len = sizeof(iwx_mcc_update_resp_v3) + sizeof(uint32_t);
    auto *pkt = make_packet(static_cast<uint32_t>(payload_len));
    auto *wire = reinterpret_cast<iwx_mcc_update_resp_v3 *>(pkt->data);
    wire->status = 0;
    wire->mcc = 0x5553;
    wire->cap = 0x7f;
    wire->n_channels = count;
    wire->channels[0] = IWX_NVM_CHANNEL_VALID;
    iwx_mcc_response_view view{};
    require(iwx_parse_mcc_update_response(pkt, 0, false, &view) == 0, "v3 response parse");
    require(view.cap == 0x7f && view.n_channels == count, "v3 fields normalized");
    delete pkt;

    pkt = make_packet(static_cast<uint32_t>(payload_len));
    wire = reinterpret_cast<iwx_mcc_update_resp_v3 *>(pkt->data);
    wire->n_channels = count;
    wire->channels[0] = IWX_NVM_CHANNEL_VALID;
    iwx_softc sc{};
    ItlIwx driver;
    const uint8_t version = driver.iwx_lookup_notif_ver(&sc, IWX_LONG_GROUP,
                                                         IWX_MCC_UPDATE_CMD);
    require(version == IWX_FW_CMD_VER_UNKNOWN, "missing MCC version uses unknown sentinel");
    require(iwx_parse_mcc_update_response(pkt,
                iwx_mcc_response_version_for_parse(version), false, &view) == 0,
            "unknown notification version falls back to v3 without capability");
    delete pkt;
}

static void test_bad_lengths() {
    iwx_mcc_response_view view{};
    auto *short_pkt = make_packet(sizeof(iwx_mcc_update_resp_v8) - 1);
    require(iwx_parse_mcc_update_response(short_pkt, 8, true, &view) == EIO,
            "short v8 header rejected");
    require(!view.header_valid, "short header leaves status diagnostics pending");
    delete short_pkt;

    auto *mismatch = make_packet(sizeof(iwx_mcc_update_resp_v8) + sizeof(uint32_t) + 1);
    auto *wire = reinterpret_cast<iwx_mcc_update_resp_v8 *>(mismatch->data);
    wire->status = 2;
    wire->n_channels = 1;
    iwx_softc sc{};
    require(iwx_apply_mcc_update_response(mismatch, 8, true, &view) == EIO,
            "v8 trailing bytes rejected");
    require(view.header_valid && view.status == 2 && view.n_channels == 1,
            "malformed response retains safe header diagnostics");
    require(sc.sc_ic.ic_channels[1].ic_freq == 0,
            "malformed response does not update the channel map");
    delete mismatch;

    auto *oversized = make_packet(sizeof(iwx_mcc_update_resp_v8));
    reinterpret_cast<iwx_mcc_update_resp_v8 *>(oversized->data)->n_channels = UINT32_MAX;
    require(iwx_parse_mcc_update_response(oversized, 8, true, &view) == EIO,
            "v8 channel count bounded by payload");
    delete oversized;
}

int main() {
    test_v8_response_maps_real_channels();
    test_v4_capability_layout();
    test_v3_layout();
    test_bad_lengths();
    std::cout << "production MCC response/channel-map checks passed\n";
}
'''.replace("FW_CMD_VERSION", fw_cmd_version).replace("STRUCTURES", structures).replace("RESPONSE_VIEW", response_view).replace("ARRAYS", channel_arrays).replace("LOOKUP_NOTIF", lookup_notif).replace("VERSION_NORMALIZER", version_normalizer).replace("RX_PACKET_LEN", rx_packet_len).replace("RX_PAYLOAD_LEN", rx_payload_len).replace("PARSER", parser).replace("APPLY_RESPONSE", apply_response).replace("CHANNEL_MAP", channel_map)

with tempfile.TemporaryDirectory(prefix="itlwm-mcc-response-") as folder:
    folder = Path(folder)
    test = folder / "mcc_response.cpp"
    test.write_text(program)
    binary = folder / "mcc_response"
    subprocess.run(shlex.split(os.environ.get("CXX", "c++")) + [
        "-std=c++14", "-Wall", "-Wextra", "-Wno-unused-parameter", "-Werror", str(test), "-o", str(binary)
    ], check=True)
    subprocess.run([str(binary)], check=True)
