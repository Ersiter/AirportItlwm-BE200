"""Compile production NVM/MAC address handlers against a small host shim."""
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = (root / "itlwm/hal_iwx/ItlIwx.cpp").read_text()
registers = (root / "itlwm/hal_iwx/if_iwxreg.h").read_text()


def definition(text, opening):
    start = text.index(opening)
    brace = text.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


functions = "\n".join(definition(source, marker) for marker in (
    "static void iwx_flip_hw_address(",
    "int ItlIwx::\niwx_set_mac_addr_from_csr(",
    "int ItlIwx::\niwx_is_valid_mac_addr(",
    "int ItlIwx::\niwx_nvm_get(",
))
structures = "\n".join(definition(registers, f"struct {name} {{") + ";" for name in (
    "iwx_nvm_get_info", "iwx_nvm_get_info_general", "iwx_nvm_get_info_sku",
    "iwx_nvm_get_info_phy", "iwx_nvm_get_info_regulatory_v1",
    "iwx_nvm_get_info_regulatory", "iwx_nvm_get_info_rsp_v3",
    "iwx_nvm_get_info_rsp",
))
csr_macros = registers[registers.index("#define IWX_CSR_ADDR_BASE(sc)"):]
csr_macros = csr_macros[:csr_macros.index("\n\n")]

program = r'''
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <vector>
#define XYLog(...) do {} while (0)
#define DEVNAME(sc) "host-test"
#define IWX_DEVICE_FAMILY_BZ 3
#define IWX_UCODE_TLV_API_REGULATORY_NVM_INFO 48
#define IWX_UCODE_TLV_CAPA_LAR_SUPPORT 10
#define IWX_NVM_MAC_SKU_FLAGS_802_11AC_ENABLED (1u << 3)
#define IWX_NVM_MAC_SKU_FLAGS_802_11N_ENABLED (1u << 2)
#define IWX_NVM_MAC_SKU_FLAGS_802_11AX_ENABLED (1u << 4)
#define IWX_NVM_MAC_SKU_FLAGS_BAND_2_4_ENABLED (1u << 0)
#define IWX_NVM_MAC_SKU_FLAGS_BAND_5_2_ENABLED (1u << 1)
#define IWX_NVM_MAC_SKU_FLAGS_MIMO_DISABLED (1u << 5)
#define IWX_CMD_WANT_RESP 1
#define IWX_CMD_SEND_IN_RFKILL 2
#define IWX_REGULATORY_AND_NVM_GROUP 12
#define IWX_NVM_GET_INFO 2
#define IWX_NUM_CHANNELS 110
#define IWX_NUM_CHANNELS_V1 51
#define IWX_WIDE_ID(group, cmd) (((group) << 8) | (cmd))
#define isset(array, bit) (((array)[(bit) / 32] & (1u << ((bit) % 32))) != 0)
CSR_MACROS
#define IWX_READ(sc, reg) iwx_read((sc), (reg))
#define ETHER_IS_MULTICAST(addr) (((addr)[0] & 1) != 0)
using u8 = uint8_t;
static uint32_t htole32(uint32_t v) { return v; }
static uint32_t le32toh(uint32_t v) { return v; }
static uint16_t le16toh(uint16_t v) { return v; }
static const uint8_t etherbroadcastaddr[6] = {255,255,255,255,255,255};
static const uint8_t etheranyaddr[6] = {};
STRUCTURES
struct iwx_nvm_data {
    uint8_t hw_addr[6]{};
    uint16_t nvm_version{};
    uint8_t n_hw_addrs{}, sku_cap_11ac_enable{}, sku_cap_11n_enable{};
    uint8_t sku_cap_11ax_enable{}, sku_cap_band_24GHz_enable{};
    uint8_t sku_cap_band_52GHz_enable{}, sku_cap_mimo_disable{};
    uint8_t valid_tx_ant{}, valid_rx_ant{}, lar_enabled{};
};
struct iwx_rx_packet { uint32_t payload_len{}; uint8_t data[512]{}; };
struct FakeDevice {
    std::map<std::string, uint32_t> values;
    void setProperty(const char *key, uint32_t value, int) { values[key] = value; }
};
struct iwx_softc {
    int sc_device_family = IWX_DEVICE_FAMILY_BZ;
    uint32_t sc_ucode_api[4]{};
    uint32_t sc_enabled_capa[4]{};
    iwx_nvm_data sc_nvm{};
    FakeDevice *sc_pcitag{};
};
struct iwx_host_cmd {
    int flags{};
    const void *data[1]{};
    size_t len[1]{};
    int id{};
    size_t resp_pkt_len{};
    iwx_rx_packet *resp_pkt{};
};
static std::map<uint32_t, uint32_t> registers;
static uint32_t iwx_read(iwx_softc *, uint32_t reg) { return registers[reg]; }
static size_t iwx_rx_packet_payload_len(const iwx_rx_packet *pkt) { return pkt->payload_len; }
static int command_error, response_length = -1, lock_result = 1, lock_calls, free_count;
static std::vector<uint32_t> read_addresses;
static std::vector<uint16_t> channel_count;
static int iwx_send_cmd(iwx_softc *, iwx_host_cmd *cmd) {
    if (command_error) return command_error;
    cmd->resp_pkt = new iwx_rx_packet{};
    cmd->resp_pkt->payload_len = response_length < 0 ? cmd->resp_pkt_len - sizeof(iwx_rx_packet) : response_length;
    return 0;
}
class ItlIwx {
public:
    int iwx_set_mac_addr_from_csr(iwx_softc *, iwx_nvm_data *);
    int iwx_is_valid_mac_addr(const uint8_t *);
    int iwx_nvm_get(iwx_softc *);
    bool iwx_nic_lock(iwx_softc *) { ++lock_calls; return lock_result; }
    void iwx_nic_unlock(iwx_softc *) {}
    void iwx_free_resp(iwx_softc *, iwx_host_cmd *cmd) { ++free_count; delete cmd->resp_pkt; cmd->resp_pkt = nullptr; }
    void iwx_init_channel_map(iwx_softc *, const uint16_t *, const uint32_t *, int count) { channel_count.push_back(count); }
};
FUNCTIONS
static void require(bool ok, const char *name) {
    if (!ok) { std::cerr << "FAILED: " << name << '\n'; std::exit(1); }
}
static void set_mac_regs(uint32_t base, bool valid_strap, bool valid_otp) {
    registers.clear(); read_addresses.clear();
    if (valid_strap) { registers[base + 8] = 0x02001122; registers[base + 12] = 0x00004433; }
    if (valid_otp) { registers[base] = 0x0200aabb; registers[base + 4] = 0x0000ccdd; }
}
static void test_mac(int family, uint32_t base, bool strap, bool otp,
                     const char *expected_mac, int expected_error, const char *label) {
    FakeDevice device;
    iwx_softc sc; sc.sc_device_family = family; sc.sc_pcitag = &device;
    iwx_nvm_data nvm{}; lock_result = 1;
    set_mac_regs(base, strap, otp);
    ItlIwx driver;
    int error = driver.iwx_set_mac_addr_from_csr(&sc, &nvm);
    require(error == expected_error, label);
    require(device.values["AirportItlwm-NVMCSRBase"] == base, "CSR base property");
    if (expected_mac) require(std::memcmp(nvm.hw_addr, expected_mac, 6) == 0, "resolved MAC");
    require(lock_calls > 0, "NIC lock called");
}
static void test_nvm(int api48, int resp_len, int lock, int cmd_err,
                     int expected_error, int expected_len, const char *label, int valid_mac = 1) {
    FakeDevice device;
    iwx_softc sc; sc.sc_pcitag = &device;
    if (api48) sc.sc_ucode_api[1] = 1u << 16;
    lock_result = lock; lock_calls = free_count = 0; command_error = cmd_err; response_length = resp_len;
    set_mac_regs(IWX_CSR_ADDR_BASE(&sc), valid_mac, false);
    channel_count.clear();
    ItlIwx driver;
    int error = driver.iwx_nvm_get(&sc);
    require(error == expected_error, label);
    require(device.values["AirportItlwm-NVMInfoAPIVersion"] == (api48 ? 4u : 3u), "selected response version");
    require(device.values["AirportItlwm-NVMInfoExpectedLength"] == (api48 ? 468u : 128u), "expected response size");
    if (!cmd_err) require(device.values["AirportItlwm-NVMInfoResponseLength"] == uint32_t(resp_len), "actual response size");
    require(device.values["AirportItlwm-NVMCSRAddressValid"] ==
            (!cmd_err && resp_len == expected_len && lock ? uint32_t(valid_mac) : UINT32_MAX),
            "MAC validity diagnostic");
    require(free_count == (!cmd_err ? 1 : 0), "NVM response released");
    if (!cmd_err && resp_len == expected_len && lock && expected_error == 0)
        require(channel_count.size() == 1 && channel_count[0] == (api48 ? 110 : 51), "channel profile path");
}
int main() {
    static const uint8_t strap_mac[6] = {2,0,0x11,0x22,0x44,0x33};
    static const uint8_t otp_mac[6] = {2,0,0xaa,0xbb,0xcc,0xdd};
    test_mac(IWX_DEVICE_FAMILY_BZ, 0x30, true, false, (const char *)strap_mac, 0, "BZ strap");
    test_mac(IWX_DEVICE_FAMILY_BZ, 0x30, false, true, (const char *)otp_mac, 0, "BZ OTP fallback");
    test_mac(2, 0x380, true, false, (const char *)strap_mac, 0, "legacy strap");
    test_mac(2, 0x380, false, false, nullptr, 0, "invalid MAC retained for caller validation");
    FakeDevice device; iwx_softc sc; sc.sc_pcitag = &device; lock_result = 0;
    ItlIwx driver; iwx_nvm_data nvm{};
    require(driver.iwx_set_mac_addr_from_csr(&sc, &nvm) == EBUSY, "setter lock error");
    test_nvm(1, 468, 1, 0, 0, 468, "v4 success");
    test_nvm(0, 128, 1, 0, 0, 128, "v3 success");
    test_nvm(1, 467, 1, 0, EIO, 468, "length mismatch rejected");
    test_nvm(1, 468, 1, 0, EINVAL, 468, "invalid CSR MAC rejected", 0);
    test_nvm(1, 468, 0, 0, EBUSY, 468, "lock failure propagated");
    test_nvm(1, 468, 1, EINVAL, EINVAL, 468, "send failure propagated");
    std::cout << "production NVM/MAC handlers: 11 cases passed\n";
}
'''.replace("STRUCTURES", structures).replace("CSR_MACROS", csr_macros).replace("FUNCTIONS", functions)

with tempfile.TemporaryDirectory(prefix="itlwm-nvm-mac-") as folder:
    folder = Path(folder)
    test = folder / "nvm_mac.cpp"
    test.write_text(program)
    binary = folder / "nvm_mac"
    subprocess.run(shlex.split(os.environ.get("CXX", "c++")) + [
        "-std=c++14", "-Wall", "-Wextra", "-Werror", str(test), "-o", str(binary)
    ], check=True)
    subprocess.run([str(binary)], check=True)
