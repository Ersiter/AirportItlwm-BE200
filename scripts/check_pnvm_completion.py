"""Compile the production PNVM wait and notification handlers against a host shim."""
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = (root / "itlwm/hal_iwx/ItlIwx.cpp").read_text()


def definition(text, opening):
    start = text.index(opening)
    brace = text.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


load_handler = definition(source, "int ItlIwx::\niwx_load_pnvm(")
notify_handler = definition(source, "static void\niwx_record_pnvm_notification(")
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
#define IWX_DEVICE_FAMILY_BZ 3
#define IWX_UCODE_TLV_CAPA_FRAGMENTED_PNVM_IMG 32
#define IWX_PNVM_COMPLETE 0x04
#define IWX_UREG_DOORBELL_TO_ISR6 0x0
#define IWX_UREG_DOORBELL_TO_ISR6_PNVM 0x0
#define isset(array, bit) (((array)[(bit) / 32] & (1u << ((bit) % 32))) != 0)
static uint32_t le32toh(uint32_t value) { return value; }
struct iwx_fw_info {};
struct FakeDevice {
    std::map<std::string, uint32_t> values;
    void setProperty(const char *key, uint32_t value, int) { values[key] = value; }
};
struct iwx_softc {
    int sc_device_family = 2;
    uint32_t sku_id[3] = {1, 0, 0};
    uint32_t sc_enabled_capa[4] = {};
    int sc_init_complete = 0;
    uint32_t sc_pnvm_status = 0;
    uint32_t sc_pnvm_payload_len = 0;
    FakeDevice *sc_pcitag = nullptr;
    iwx_fw_info sc_fw;
};
struct iwx_rx_packet { uint32_t payload_len; uint8_t data[8]; };
struct iwl_pnvm_init_complete_ntfy { uint32_t status; } __attribute__((packed));
static size_t iwx_rx_packet_payload_len(const iwx_rx_packet *pkt) { return pkt->payload_len; }
static int read_error, wait_error, lock_ok, wait_count, doorbell_count, free_count;
static iwx_rx_packet test_packet{};

NOTIFY_HANDLER

class ItlIwx {
public:
    int iwx_load_pnvm(struct iwx_softc *);
    int iwx_read_pnvm(struct iwx_softc *) { return read_error; }
    int iwx_nic_lock(struct iwx_softc *) { return lock_ok; }
    void iwx_nic_unlock(struct iwx_softc *) {}
    void iwx_write_umac_prph(struct iwx_softc *, uint32_t, uint32_t) { ++doorbell_count; }
    int iwx_wait_notification(struct iwx_softc *sc, int *flags, int mask, uint32_t) {
        ++wait_count;
        if (!wait_error) {
            iwx_record_pnvm_notification(sc, &test_packet);
            *flags |= mask;
        }
        return wait_error;
    }
    void iwx_pnvm_free(struct iwx_fw_info *) { ++free_count; }
};

LOAD_HANDLER

static void require(bool ok, const char *name) {
    if (!ok) { std::cerr << "FAILED: " << name << '\n'; std::exit(1); }
}
static void run_case(const char *name, int expected_error, int read, int lock,
                     int wait, uint32_t payload_len, uint32_t status,
                     uint32_t expected_status, uint32_t expected_len) {
    read_error = read; lock_ok = lock; wait_error = wait;
    wait_count = doorbell_count = free_count = 0;
    test_packet = {};
    test_packet.payload_len = payload_len;
    std::memcpy(test_packet.data, &status, sizeof(status));
    FakeDevice device;
    iwx_softc sc;
    sc.sc_pcitag = &device;
    ItlIwx driver;
    int error = driver.iwx_load_pnvm(&sc);
    require(error == expected_error, name);
    require(sc.sc_pnvm_status == expected_status, "stored raw status");
    require(sc.sc_pnvm_payload_len == expected_len, "stored payload length");
    require(device.values["AirportItlwm-PNVMStatus"] == expected_status, "IORegistry raw status");
    require(device.values["AirportItlwm-PNVMPayloadLength"] == expected_len, "IORegistry payload length");
    require(device.values["AirportItlwm-PNVMVersion"] == 0xffffffffu, "PNVM version pending reset");
    require(device.values["AirportItlwm-PNVMSizeBytes"] == 0xffffffffu, "PNVM size pending reset");
    require(device.values["AirportItlwm-PNVMSegmentCount"] == 0xffffffffu, "PNVM segments pending reset");
    require(device.values["AirportItlwm-PNVMSkuId0"] == 1, "selected SKU capture");
    require(wait_count == (read || !lock ? 0 : 1), "wait call count");
    require(doorbell_count == (read || !lock ? 0 : 1), "doorbell call count");
    require(free_count == (read || !lock || wait == ENXIO ? 0 : 1), "PNVM buffer free count");
    require((sc.sc_init_complete & IWX_PNVM_COMPLETE) ==
            (wait == 0 && !read && lock ? IWX_PNVM_COMPLETE : 0), "notification completion flag");
}
int main() {
    run_case("status 0 accepted", 0, 0, 1, 0, 4, 0, 0, 4);
    run_case("nonzero status retained", 0, 0, 1, 0, 4, 1, 1, 4);
    run_case("all-one valid status distinguished by length", 0, 0, 1, 0, 4, 0xffffffffu, 0xffffffffu, 4);
    run_case("short payload rejected", EINVAL, 0, 1, 0, 3, 0, 0xffffffffu, 3);
    run_case("long payload rejected", EINVAL, 0, 1, 0, 8, 0, 0xffffffffu, 8);
    run_case("timeout preserved", EWOULDBLOCK, 0, 1, EWOULDBLOCK, 0, 0, 0xffffffffu, 0xffffffffu);
    run_case("device removal preserved", ENXIO, 0, 1, ENXIO, 0, 0, 0xffffffffu, 0xffffffffu);
    run_case("PNVM parse failure preserved", EINVAL, EINVAL, 1, 0, 0, 0, 0xffffffffu, 0xffffffffu);
    run_case("doorbell lock failure preserved", EBUSY, 0, 0, 0, 0, 0, 0xffffffffu, 0xffffffffu);
    std::cout << "production PNVM completion handler: 9 cases passed\n";
}
'''

program = program.replace("NOTIFY_HANDLER", notify_handler)
program = program.replace("LOAD_HANDLER", load_handler)

with tempfile.TemporaryDirectory(prefix="itlwm-pnvm-completion-") as folder:
    folder = Path(folder)
    test = folder / "pnvm_completion.cpp"
    test.write_text(program)
    binary = folder / "pnvm_completion"
    subprocess.run(shlex.split(os.environ.get("CXX", "c++")) + [
        "-std=c++14", "-Wall", "-Wextra", "-Werror", str(test), "-o", str(binary)
    ], check=True)
    subprocess.run([str(binary)], check=True)
