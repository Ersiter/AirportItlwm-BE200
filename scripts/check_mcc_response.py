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
mcc_profile_changed = function(source, "static bool\niwx_mcc_profile_changed(")
mcc_profile_needs_apply = function(source, "static bool\niwx_mcc_profile_needs_apply(")
version_normalizer = function(source, "static uint8_t\niwx_mcc_response_version_for_parse(")
restrictions = function(source, "static uint8_t\niwx_mcc_channel_restrictions(")
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
proto_source = (root / "itl80211/openbsd/net80211/ieee80211_proto.c").read_text(encoding="utf-8")
vht_negotiate = function(proto_source, "void\nieee80211_vht_negotiate(")
he_negotiate = function(proto_source, "void\nieee80211_he_negotiate(")
eht_negotiate = function(proto_source, "void\nieee80211_eht_negotiate(")

program = r'''
#include <cstddef>
#include <cstdint>
#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <vector>
#include <algorithm>
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
#define IWX_MCC_RESP_NEW_CHAN_PROFILE 0
#define IWX_MCC_RESP_SAME_CHAN_PROFILE 1
#define IWX_MCC_RESP_INVALID 2
#define IWX_MCC_RESP_NVM_DISABLED 3
#define IWX_MCC_RESP_ILLEGAL 4
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
#define IEEE80211_CHAN_NO_40MHZ (1u << 0)
#define IEEE80211_CHAN_NO_80MHZ (1u << 1)
#define IEEE80211_CHAN_NO_160MHZ (1u << 2)
#define IEEE80211_CHAN_NO_320MHZ (1u << 3)
#define IEEE80211_CHAN_NO_HE (1u << 4)
#define IEEE80211_CHAN_NO_EHT (1u << 5)
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
struct ieee80211_channel { int ic_freq = 0; uint32_t ic_flags = 0; uint8_t ic_reg_flags = 0; };
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
MCC_PROFILE_CHANGED
MCC_PROFILE_NEEDS_APPLY
RESTRICTIONS
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

static void test_mcc_channel_restrictions() {
    const uint8_t v4 = iwx_mcc_channel_restrictions((1u << 7) | (1u << 3) | (1u << 2) | (1u << 10), 4, false);
    require((v4 & (IEEE80211_CHAN_NO_40MHZ | IEEE80211_CHAN_NO_320MHZ | IEEE80211_CHAN_NO_HE)) ==
            (IEEE80211_CHAN_NO_40MHZ | IEEE80211_CHAN_NO_320MHZ | IEEE80211_CHAN_NO_HE),
            "v4 legacy width and HE bits decode");
    require(!(v4 & (IEEE80211_CHAN_NO_80MHZ | IEEE80211_CHAN_NO_160MHZ | IEEE80211_CHAN_NO_EHT)),
            "v4 width permissions and EHT default decode");

    const uint8_t v6 = iwx_mcc_channel_restrictions((1u << 8) | (1u << 4) | (1u << 3) | (1u << 10), 6, false);
    require((v6 & (IEEE80211_CHAN_NO_320MHZ | IEEE80211_CHAN_NO_HE)) ==
            (IEEE80211_CHAN_NO_320MHZ | IEEE80211_CHAN_NO_HE),
            "v6 wide-channel and HE restrictions decode");
    require(!(v6 & (IEEE80211_CHAN_NO_40MHZ | IEEE80211_CHAN_NO_80MHZ | IEEE80211_CHAN_NO_160MHZ | IEEE80211_CHAN_NO_EHT)),
            "v6 width permissions and EHT default decode");

    const uint8_t v8 = iwx_mcc_channel_restrictions((1u << 4) | (1u << 3) | (1u << 16) | (1u << 13) | (1u << 8), 8, false);
    require((v8 & (IEEE80211_CHAN_NO_HE | IEEE80211_CHAN_NO_EHT)) ==
            (IEEE80211_CHAN_NO_HE | IEEE80211_CHAN_NO_EHT),
            "v8 HE and EHT disable bits decode");
    require(!(v8 & (IEEE80211_CHAN_NO_40MHZ | IEEE80211_CHAN_NO_80MHZ | IEEE80211_CHAN_NO_160MHZ | IEEE80211_CHAN_NO_320MHZ)),
            "v8 width permissions including 320 MHz decode");
    require(iwx_mcc_channel_restrictions(0, 8, true) == 0,
            "2 GHz exempts global width restrictions");
}

static void test_6ghz_nvm_width_mapping() {
    iwx_softc sc{};
    sc.sc_uhb_supported = true;
    sc.sc_ucode_api[IWX_UCODE_TLV_API_SCAN_EXT_CHAN_VER / 8] |= 1u << (IWX_UCODE_TLV_API_SCAN_EXT_CHAN_VER % 8);
    sc.sc_ucode_api[IWX_UCODE_TLV_API_BAND_IN_RX_DATA / 8] |= 1u << (IWX_UCODE_TLV_API_BAND_IN_RX_DATA % 8);
    ItlIwx driver;
    std::vector<uint32_t> profile(IWX_NUM_CHANNELS);
    profile[51] = IWX_NVM_CHANNEL_VALID | IWX_NVM_CHANNEL_40MHZ |
                  IWX_NVM_CHANNEL_80MHZ | IWX_NVM_CHANNEL_160MHZ;
    driver.iwx_init_channel_map(&sc, nullptr, profile.data(), profile.size());
    const auto &valid = sc.sc_ic.ic_channels[182];
    require((valid.ic_flags & (IEEE80211_CHAN_6GHZ | IEEE80211_CHAN_HT40U | IEEE80211_CHAN_HT40D)) ==
            (IEEE80211_CHAN_6GHZ | IEEE80211_CHAN_HT40U | IEEE80211_CHAN_HT40D),
            "valid 6 GHz NVM channel enables 40 MHz directions");
    require(!(valid.ic_reg_flags & (IEEE80211_CHAN_NO_40MHZ | IEEE80211_CHAN_NO_80MHZ | IEEE80211_CHAN_NO_160MHZ | IEEE80211_CHAN_NO_320MHZ)) &&
            sc.sc_nvm.vht160_supported,
            "valid 6 GHz NVM widths map without restrictions and enable 160 MHz");

    std::fill(profile.begin(), profile.end(), 0);
    profile[52] = IWX_NVM_CHANNEL_160MHZ;
    driver.iwx_init_channel_map(&sc, nullptr, profile.data(), profile.size());
    require(sc.sc_ic.ic_channels[183].ic_freq == 0 && !sc.sc_nvm.vht160_supported,
            "invalid 6 GHz NVM channel cannot enable 160 MHz");
}

static void test_mcc_profile_needs_apply() {
    require(iwx_mcc_profile_needs_apply(IWX_MCC_RESP_SAME_CHAN_PROFILE, false),
            "first same-profile response applies the legal channel map");
    require(!iwx_mcc_profile_needs_apply(IWX_MCC_RESP_SAME_CHAN_PROFILE, true),
            "same-profile response is deduplicated after synchronization");
    require(iwx_mcc_profile_needs_apply(IWX_MCC_RESP_NEW_CHAN_PROFILE, true),
            "new profile replaces a synchronized channel map");
    require(iwx_mcc_profile_needs_apply(IWX_MCC_RESP_ILLEGAL, true),
            "illegal response applies the effective regulatory profile");
    require(!iwx_mcc_profile_needs_apply(IWX_MCC_RESP_INVALID, true),
            "invalid response does not replace the channel map");
}

int main() {
    test_mcc_profile_needs_apply();
    test_mcc_channel_restrictions();
    test_6ghz_nvm_width_mapping();
    test_v8_response_maps_real_channels();
    test_v4_capability_layout();
    test_v3_layout();
    test_bad_lengths();
    std::cout << "production MCC response/channel-map checks passed\n";
}
'''.replace("FW_CMD_VERSION", fw_cmd_version).replace("STRUCTURES", structures).replace("RESPONSE_VIEW", response_view).replace("ARRAYS", channel_arrays).replace("LOOKUP_NOTIF", lookup_notif).replace("VERSION_NORMALIZER", version_normalizer).replace("MCC_PROFILE_CHANGED", mcc_profile_changed).replace("MCC_PROFILE_NEEDS_APPLY", mcc_profile_needs_apply).replace("RESTRICTIONS", restrictions).replace("RX_PACKET_LEN", rx_packet_len).replace("RX_PAYLOAD_LEN", rx_payload_len).replace("PARSER", parser).replace("APPLY_RESPONSE", apply_response).replace("CHANNEL_MAP", channel_map)

bandwidth_program = r'''
#include <cstdint>
#include <cstdlib>
#include <iostream>
#define nitems(array) (sizeof(array) / sizeof((array)[0]))
#define XYLog(...) do {} while (0)
#define IEEE80211_CHAN_2GHZ 0x00000001
#define IEEE80211_CHAN_5GHZ 0x00000002
#define IEEE80211_CHAN_6GHZ 0x40000000
#define IEEE80211_IS_CHAN_5GHZ(channel) (((channel)->ic_flags & IEEE80211_CHAN_5GHZ) != 0)
#define IEEE80211_CHAN_NO_40MHZ 0x01
#define IEEE80211_CHAN_NO_80MHZ 0x02
#define IEEE80211_CHAN_NO_160MHZ 0x04
#define IEEE80211_CHAN_NO_320MHZ 0x08
#define IEEE80211_CHAN_NO_HE 0x10
#define IEEE80211_CHAN_NO_EHT 0x20
#define IEEE80211_CHAN_WIDTH_20 0
#define IEEE80211_CHAN_WIDTH_40 1
#define IEEE80211_CHAN_WIDTH_80 2
#define IEEE80211_CHAN_WIDTH_160 3
#define IEEE80211_CHAN_WIDTH_320 4
#define IEEE80211_CHAN_WIDTH_80P80 5
#define IEEE80211_NODE_VHT 0x100000U
#define IEEE80211_NODE_VHT_SGI80 0x20000000U
#define IEEE80211_NODE_VHT_SGI160 0x40000000U
#define IEEE80211_MODE_11AC 1
#define IEEE80211_F_NOVHT 0x01
#define IEEE80211_F_VHTON 0x02
#define IEEE80211_F_WEPON 0x04
#define IEEE80211_F_RSNON 0x08
#define IEEE80211_CIPHER_USEGROUP 0x01
#define IEEE80211_CIPHER_TKIP 0x02
#define IEEE80211_C_SUPPORTS_VHT_EXT_NSS_BW 0x01
#define IEEE80211_VHTCAP_SUPP_CHAN_WIDTH_MASK 0x0000000cU
#define IEEE80211_VHTCAP_SUPP_CHAN_WIDTH_160MHZ 0x00000004U
#define IEEE80211_VHTCAP_SUPP_CHAN_WIDTH_160_80P80MHZ 0x00000008U
#define IEEE80211_VHTCAP_EXT_NSS_BW_MASK 0xc0000000U
#define IEEE80211_VHTCAP_EXT_NSS_BW_SHIFT 30
#define IEEE80211_VHT_CHANWIDTH_USE_HT 0
#define IEEE80211_VHT_CHANWIDTH_80MHZ 1
#define IEEE80211_VHT_CHANWIDTH_160MHZ 2
#define IEEE80211_VHT_CHANWIDTH_80P80MHZ 3
#define IEEE80211_HT_OP_MODE_CCFS2_MASK 0x0000fc00U
#define IEEE80211_HT_OP_MODE_CCFS2_SHIFT 10
#define IEEE80211_VHTCAP_SHORT_GI_80 0x00000020U
#define IEEE80211_VHTCAP_SHORT_GI_160 0x00000040U
#define IEEE80211_VHTCAP_SHORT_GI_80_MASK IEEE80211_VHTCAP_SHORT_GI_80
#define IEEE80211_VHTCAP_SHORT_GI_160_MASK IEEE80211_VHTCAP_SHORT_GI_160
#define IEEE80211_VHTCAP_SUPP_CHAN_WIDTH_MASK_S 2
#define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_IN_2G 0x02
#define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G 0x04
#define IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G 0x08
#define IEEE80211_EHT_PHY_CAP0_320MHZ_IN_6GHZ 0x02
#define IEEE80211_HE_OPERATION_TWT_REQUIRED 0x00000008
#define IEEE80211_HE_OPERATION_VHT_OPER_INFO 0x00004000
#define IEEE80211_HE_OPERATION_CO_HOSTED_BSS 0x00008000
#define IEEE80211_HE_OPERATION_6GHZ_OP_INFO 0x00020000
#define IEEE80211_HE_6GHZ_OPER_CTRL_CHANWIDTH 0x03
#define IEEE80211_EHT_OPER_INFO_PRESENT 0x01
#define IEEE80211_NODE_QOS 0x0002
#define IEEE80211_NODE_HT 0x0400
#define IEEE80211_NODE_HE 0x200000
#define IEEE80211_NODE_HECAP 0x400000
#define IEEE80211_NODE_HEOP 0x800000
#define IEEE80211_NODE_EHTCAP 0x4000000
#define IEEE80211_NODE_EHTOP 0x8000000
#define IEEE80211_NODE_EHT 0x10000000
#define IEEE80211_IS_CHAN_2GHZ(channel) (((channel)->ic_flags & IEEE80211_CHAN_2GHZ) != 0)
#define IEEE80211_IS_CHAN_6GHZ(channel) (((channel)->ic_flags & IEEE80211_CHAN_6GHZ) != 0)
#define abs(value) std::abs(value)
static uint16_t le16toh(uint16_t value) { return value; }
struct ieee80211_channel { int ic_freq = 0; uint32_t ic_flags = 0; uint8_t ic_reg_flags = 0; uint16_t ic_center_freq1 = 0, ic_center_freq2 = 0; };
struct ieee80211_he_cap_elem { uint8_t phy_cap_info[11]{}; };
struct ieee80211_he_mcs_nss_supp { uint16_t tx_mcs_160 = 0, rx_mcs_160 = 0; };
struct ieee80211_eht_cap_elem { uint8_t phy_cap_info[9]{}; };
struct ieee80211_eht_mcs_nss_supp { uint8_t data[9]{}; };
struct ieee80211_he_6ghz_oper { uint8_t primary, control, ccfs0, ccfs1; };
struct ieee80211_node {
    ieee80211_channel *ni_chan = nullptr;
    uint32_t ni_flags = 0, ni_he_oper_params = 0;
    uint32_t ni_vhtcaps = 0, ni_rsnciphers = 0;
    uint16_t ni_htop1 = 0;
    uint8_t ni_vht_chan1 = 0, ni_vht_chan2 = 0, ni_vht_chanwidth = 0;
    bool vht_supported = true;
    uint8_t ni_he_optional[8]{}, ni_eht_oper[8]{}, ni_eht_oper_width = 0;
    uint8_t ni_eht_ccfs0 = 0, ni_eht_ccfs1 = 0, ni_eht_mcs_nss_len = 0;
    uint8_t ni_eht_mcs_nss[9]{}, ni_chw = IEEE80211_CHAN_WIDTH_20;
    uint16_t ni_eht_center_freq1 = 0, ni_eht_puncture = 0;
    uint32_t ni_he_txrate_kbps = 0, ni_he_tx_nss = 0;
    bool ni_he_requested = false, ni_eht_requested = false, he_cap_valid = false;
    ieee80211_he_cap_elem ni_he_cap_elem{};
    ieee80211_he_mcs_nss_supp ni_he_mcs_nss_supp{};
    ieee80211_eht_cap_elem ni_eht_cap_elem{};
};
struct ieee80211com {
    uint32_t ic_modecaps = 0, ic_userflags = 0, ic_flags = 0, ic_caps = 0;
    struct { unsigned is_vht_nego_no_mandatory_mcs = 0, is_vht_nego_bad_crypto = 0; } ic_stats;
    ieee80211_he_cap_elem ic_he_cap_elem{};
    ieee80211_he_mcs_nss_supp ic_he_mcs_nss_supp{};
    bool ic_eht_cap_valid = false;
    ieee80211_eht_cap_elem ic_eht_cap_elem{};
    ieee80211_eht_mcs_nss_supp ic_eht_mcs_nss_supp{};
};
static int ieee80211_he_supported(ieee80211com *, ieee80211_node *ni) {
    return ni->he_cap_valid && !(ni->ni_chan->ic_reg_flags & IEEE80211_CHAN_NO_HE);
}
static bool ieee80211_node_supports_vht(ieee80211_node *ni) { return ni->vht_supported; }
static bool ieee80211_node_supports_vht_sgi80(ieee80211_node *) { return false; }
static bool ieee80211_node_supports_vht_sgi160(ieee80211_node *) { return false; }
static unsigned u32_get_bits(uint32_t value, uint32_t mask) { return (value & mask) >> __builtin_ctz(mask); }
static uint16_t ieee80211_he_mcs_intersection(uint16_t, uint16_t) { return 0; }
static int ieee80211_chan2number(ieee80211com *, ieee80211_channel *channel) {
    return (channel->ic_freq - 5950) / 5;
}
static int ieee80211_ieee2mhz(int channel, int band) {
    return channel * 5 + ((band & IEEE80211_CHAN_6GHZ) ? 5950 :
        ((band & IEEE80211_CHAN_5GHZ) ? 5000 : 2407));
}
VHT_NEGOTIATION
HE_NEGOTIATION
EHT_NEGOTIATION
static void require(bool ok, const char *message) {
    if (!ok) { std::cerr << "FAIL: " << message << "\n"; std::exit(1); }
}
static void setup_5ghz(ieee80211com &ic, ieee80211_node &ni, ieee80211_channel &channel,
    uint8_t op_width, uint8_t seg0, uint8_t seg1) {
    channel.ic_freq = 5180;
    channel.ic_flags = IEEE80211_CHAN_5GHZ;
    ni.ni_chan = &channel;
    ni.ni_flags = IEEE80211_NODE_HT | IEEE80211_NODE_QOS |
        IEEE80211_NODE_HECAP | IEEE80211_NODE_HEOP;
    ni.ni_he_requested = true;
    ni.he_cap_valid = true;
    ni.ni_he_cap_elem.phy_cap_info[0] = 0x0c;
    ic.ic_he_cap_elem.phy_cap_info[0] = 0x0c;
    ni.ni_vhtcaps = IEEE80211_VHTCAP_SUPP_CHAN_WIDTH_160MHZ;
    ni.ni_vht_chanwidth = op_width;
    ni.ni_vht_chan1 = seg0;
    ni.ni_vht_chan2 = seg1;
    ic.ic_modecaps = 1U << IEEE80211_MODE_11AC;
    ic.ic_flags = IEEE80211_F_VHTON;
}
static void test_5ghz_vht_operation_and_he_width_fallback() {
    ieee80211com ic{}; ieee80211_node ni{}; ieee80211_channel channel{};
    setup_5ghz(ic, ni, channel, IEEE80211_VHT_CHANWIDTH_80MHZ, 42, 50);
    ieee80211_vht_negotiate(&ic, &ni);
    require(ni.ni_chw == IEEE80211_CHAN_WIDTH_160 && channel.ic_center_freq1 == 5250,
        "5 GHz VHT 80 MHz operation segments identify 160 MHz center");
    ieee80211_he_negotiate(&ic, &ni);
    require((ni.ni_flags & IEEE80211_NODE_HE) && ni.ni_chw == IEEE80211_CHAN_WIDTH_160 &&
        channel.ic_center_freq1 == 5250, "HE preserves AP 160 MHz when local, peer, and MCC allow it");

    ieee80211com ap80_ic{}; ieee80211_node ap80_ni{}; ieee80211_channel ap80_channel{};
    setup_5ghz(ap80_ic, ap80_ni, ap80_channel, IEEE80211_VHT_CHANWIDTH_80MHZ, 42, 0);
    ieee80211_vht_negotiate(&ap80_ic, &ap80_ni);
    ieee80211_he_negotiate(&ap80_ic, &ap80_ni);
    require(ap80_ni.ni_chw == IEEE80211_CHAN_WIDTH_80 && ap80_channel.ic_center_freq1 == 5210,
        "5 GHz AP 80 MHz operation remains 80 despite peer 160 capability");

    ieee80211com direct_ic{}; ieee80211_node direct_ni{}; ieee80211_channel direct_channel{};
    setup_5ghz(direct_ic, direct_ni, direct_channel, IEEE80211_VHT_CHANWIDTH_160MHZ, 50, 0);
    ieee80211_vht_negotiate(&direct_ic, &direct_ni);
    require(direct_ni.ni_chw == IEEE80211_CHAN_WIDTH_160 && direct_channel.ic_center_freq1 == 5250,
        "5 GHz direct VHT 160 MHz operation uses segment 0 center");

    ieee80211com no160_ic{}; ieee80211_node no160_ni{}; ieee80211_channel no160_channel{};
    setup_5ghz(no160_ic, no160_ni, no160_channel, IEEE80211_VHT_CHANWIDTH_80MHZ, 42, 50);
    no160_channel.ic_reg_flags = IEEE80211_CHAN_NO_160MHZ;
    ieee80211_vht_negotiate(&no160_ic, &no160_ni);
    ieee80211_he_negotiate(&no160_ic, &no160_ni);
    require(no160_ni.ni_chw == IEEE80211_CHAN_WIDTH_80 && no160_channel.ic_center_freq1 == 5210,
        "5 GHz MCC NO160 falls back to AP primary 80 MHz segment");

    ieee80211com no80_ic{}; ieee80211_node no80_ni{}; ieee80211_channel no80_channel{};
    setup_5ghz(no80_ic, no80_ni, no80_channel, IEEE80211_VHT_CHANWIDTH_80MHZ, 42, 50);
    no80_channel.ic_reg_flags = IEEE80211_CHAN_NO_160MHZ | IEEE80211_CHAN_NO_80MHZ;
    ieee80211_vht_negotiate(&no80_ic, &no80_ni);
    ieee80211_he_negotiate(&no80_ic, &no80_ni);
    require(no80_ni.ni_chw == IEEE80211_CHAN_WIDTH_40 && no80_channel.ic_center_freq1 == 5190,
        "5 GHz MCC NO80 retains the primary 40 MHz segment");
}
static void setup_6ghz(ieee80211com &ic, ieee80211_node &ni, ieee80211_channel &channel) {
    channel.ic_freq = 5975;
    channel.ic_flags = IEEE80211_CHAN_6GHZ;
    ni.ni_chan = &channel;
    ni.ni_flags = IEEE80211_NODE_QOS | IEEE80211_NODE_HECAP | IEEE80211_NODE_HEOP |
                  IEEE80211_NODE_EHTCAP | IEEE80211_NODE_EHTOP;
    ni.ni_he_requested = true;
    ni.ni_eht_requested = true;
    ni.he_cap_valid = true;
    ni.ni_he_cap_elem.phy_cap_info[0] = 0x0c;
    ic.ic_he_cap_elem.phy_cap_info[0] = 0x0c;
    ni.ni_he_oper_params = IEEE80211_HE_OPERATION_6GHZ_OP_INFO;
    ni.ni_he_optional[0] = 5;
    ni.ni_he_optional[1] = 3;
    ni.ni_he_optional[2] = 7;
    ni.ni_he_optional[3] = 15;
    ic.ic_eht_cap_valid = true;
    ni.ni_eht_cap_elem.phy_cap_info[0] = IEEE80211_EHT_PHY_CAP0_320MHZ_IN_6GHZ;
    ic.ic_eht_cap_elem.phy_cap_info[0] = IEEE80211_EHT_PHY_CAP0_320MHZ_IN_6GHZ;
    ni.ni_eht_mcs_nss_len = sizeof(ni.ni_eht_mcs_nss);
    for (unsigned i = 0; i < 9; i += 3) {
        ni.ni_eht_mcs_nss[i] = 0x11;
        ic.ic_eht_mcs_nss_supp.data[i] = 0x11;
    }
}
static void set_eht_320(ieee80211_node &ni) {
    ni.ni_eht_oper[0] = IEEE80211_EHT_OPER_INFO_PRESENT;
    ni.ni_eht_oper_width = 4;
    ni.ni_eht_ccfs0 = 15;
    ni.ni_eht_ccfs1 = 31;
}
static void test_he_160_and_no160_fallback() {
    ieee80211com ic{}; ieee80211_node ni{}; ieee80211_channel channel{};
    setup_6ghz(ic, ni, channel);
    ieee80211_he_negotiate(&ic, &ni);
    require((ni.ni_flags & IEEE80211_NODE_HE) && ni.ni_chw == IEEE80211_CHAN_WIDTH_160 &&
            channel.ic_center_freq1 == 6025, "HE 6 GHz 160 MHz operation center");

    ieee80211com no160_ic{}; ieee80211_node no160_ni{}; ieee80211_channel no160_channel{};
    setup_6ghz(no160_ic, no160_ni, no160_channel);
    no160_ni.ni_chan->ic_reg_flags = IEEE80211_CHAN_NO_160MHZ;
    ieee80211_he_negotiate(&no160_ic, &no160_ni);
    require((no160_ni.ni_flags & IEEE80211_NODE_HE) &&
            no160_ni.ni_chw == IEEE80211_CHAN_WIDTH_80 && no160_channel.ic_center_freq1 == 5985,
            "NO160 falls back to HE 80 MHz center");
}
static void test_eht_320_no320_and_he_fallback() {
    ieee80211com ic{}; ieee80211_node ni{}; ieee80211_channel channel{};
    setup_6ghz(ic, ni, channel);
    ni.ni_he_optional[1] = 2; ni.ni_he_optional[2] = 7;
    ieee80211_he_negotiate(&ic, &ni);
    set_eht_320(ni);
    ieee80211_eht_negotiate(&ic, &ni);
    require((ni.ni_flags & IEEE80211_NODE_EHT) && ni.ni_chw == IEEE80211_CHAN_WIDTH_320 &&
            ni.ni_eht_center_freq1 == 6105, "EHT operation selects 320 MHz center");

    ieee80211com limited_ic{}; ieee80211_node limited_ni{}; ieee80211_channel limited_channel{};
    setup_6ghz(limited_ic, limited_ni, limited_channel);
    limited_ni.ni_he_optional[1] = 2; limited_ni.ni_he_optional[2] = 7;
    limited_channel.ic_reg_flags = IEEE80211_CHAN_NO_320MHZ;
    ieee80211_he_negotiate(&limited_ic, &limited_ni);
    set_eht_320(limited_ni);
    ieee80211_eht_negotiate(&limited_ic, &limited_ni);
    require((limited_ni.ni_flags & IEEE80211_NODE_EHT) &&
            limited_ni.ni_chw == IEEE80211_CHAN_WIDTH_160 && limited_ni.ni_eht_center_freq1 == 6025,
            "NO320 falls back to EHT 160 MHz center");
}
static void test_eht_no_info_and_invalid_centers() {
    ieee80211com ic{}; ieee80211_node ni{}; ieee80211_channel channel{};
    setup_6ghz(ic, ni, channel);
    ni.ni_he_optional[1] = 2; ni.ni_he_optional[2] = 7;
    ieee80211_he_negotiate(&ic, &ni);
    ni.ni_eht_oper[0] = 0;
    ieee80211_eht_negotiate(&ic, &ni);
    require((ni.ni_flags & IEEE80211_NODE_EHT) && ni.ni_chw == IEEE80211_CHAN_WIDTH_80 &&
            ni.ni_eht_center_freq1 == 5985, "EHT without operation info retains HE 80 MHz");

    ieee80211com bad_ic{}; ieee80211_node bad_ni{}; ieee80211_channel bad_channel{};
    setup_6ghz(bad_ic, bad_ni, bad_channel);
    bad_ni.ni_he_optional[1] = 2; bad_ni.ni_he_optional[2] = 7;
    ieee80211_he_negotiate(&bad_ic, &bad_ni);
    set_eht_320(bad_ni); bad_ni.ni_eht_ccfs1 = 29;
    ieee80211_eht_negotiate(&bad_ic, &bad_ni);
    require(!(bad_ni.ni_flags & IEEE80211_NODE_EHT) && bad_ni.ni_chw == IEEE80211_CHAN_WIDTH_80 &&
            bad_channel.ic_center_freq1 == 5985, "invalid EHT center leaves negotiated HE width intact");
}
static void test_eht_primary_puncture_and_phy_restrictions() {
    ieee80211com puncture_ic{}; ieee80211_node puncture_ni{}; ieee80211_channel puncture_channel{};
    setup_6ghz(puncture_ic, puncture_ni, puncture_channel);
    puncture_ni.ni_he_optional[1] = 2; puncture_ni.ni_he_optional[2] = 7;
    ieee80211_he_negotiate(&puncture_ic, &puncture_ni);
    set_eht_320(puncture_ni); puncture_ni.ni_eht_puncture = 1u << 1;
    ieee80211_eht_negotiate(&puncture_ic, &puncture_ni);
    require(!(puncture_ni.ni_flags & IEEE80211_NODE_EHT) &&
            puncture_ni.ni_chw == IEEE80211_CHAN_WIDTH_80, "primary 20 MHz puncture rejects EHT");

    ieee80211com nohe_ic{}; ieee80211_node nohe_ni{}; ieee80211_channel nohe_channel{};
    setup_6ghz(nohe_ic, nohe_ni, nohe_channel);
    nohe_channel.ic_reg_flags = IEEE80211_CHAN_NO_HE;
    ieee80211_he_negotiate(&nohe_ic, &nohe_ni);
    ieee80211_eht_negotiate(&nohe_ic, &nohe_ni);
    require(!(nohe_ni.ni_flags & (IEEE80211_NODE_HE | IEEE80211_NODE_EHT)),
            "NO_HE prevents HE and EHT negotiation");

    ieee80211com noeht_ic{}; ieee80211_node noeht_ni{}; ieee80211_channel noeht_channel{};
    setup_6ghz(noeht_ic, noeht_ni, noeht_channel);
    noeht_ni.ni_he_optional[1] = 2; noeht_ni.ni_he_optional[2] = 7;
    noeht_channel.ic_reg_flags = IEEE80211_CHAN_NO_EHT;
    ieee80211_he_negotiate(&noeht_ic, &noeht_ni);
    set_eht_320(noeht_ni);
    ieee80211_eht_negotiate(&noeht_ic, &noeht_ni);
    require((noeht_ni.ni_flags & IEEE80211_NODE_HE) && !(noeht_ni.ni_flags & IEEE80211_NODE_EHT),
            "NO_EHT retains HE and prevents EHT negotiation");
}
int main() {
    test_5ghz_vht_operation_and_he_width_fallback();
    test_he_160_and_no160_fallback();
    test_eht_320_no320_and_he_fallback();
    test_eht_no_info_and_invalid_centers();
    test_eht_primary_puncture_and_phy_restrictions();
    std::cout << "production VHT/HE/EHT bandwidth checks passed\n";
}
'''.replace("VHT_NEGOTIATION", vht_negotiate).replace("HE_NEGOTIATION", he_negotiate).replace("EHT_NEGOTIATION", eht_negotiate)

with tempfile.TemporaryDirectory(prefix="itlwm-mcc-response-") as folder:
    folder = Path(folder)
    test = folder / "mcc_response.cpp"
    test.write_text(program)
    binary = folder / "mcc_response"
    subprocess.run(shlex.split(os.environ.get("CXX", "c++")) + [
        "-std=c++14", "-Wall", "-Wextra", "-Wno-unused-parameter", "-Werror", str(test), "-o", str(binary)
    ], check=True)
    subprocess.run([str(binary)], check=True)

    bandwidth_test = folder / "he_eht_bandwidth.cpp"
    bandwidth_test.write_text(bandwidth_program)
    bandwidth_binary = folder / "he_eht_bandwidth"
    subprocess.run(shlex.split(os.environ.get("CXX", "c++")) + [
        "-std=c++14", "-Wall", "-Wextra", "-Wno-unused-parameter", "-Werror",
        str(bandwidth_test), "-o", str(bandwidth_binary)
    ], check=True)
    subprocess.run([str(bandwidth_binary)], check=True)
