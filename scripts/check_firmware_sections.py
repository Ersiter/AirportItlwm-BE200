"""Run the driver's section storage and grouping code against embedded firmware."""
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = (root / 'itlwm/hal_iwx/ItlIwx.cpp').read_text()
header = (root / 'itlwm/hal_iwx/if_iwxvar.h').read_text()
registers = (root / 'itlwm/hal_iwx/if_iwxreg.h').read_text()

def definition(text, opening):
    start = text.index(opening)
    brace = text.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]

types = '\n'.join(definition(header, name) + ';' for name in [
    'enum iwx_ucode_type {', 'struct iwx_fw_onesect {', 'struct iwx_fw_sects {'
])
capacity = re.search(r'^#define IWX_UCODE_SECT_MAX\s+(\d+)', header, re.M).group(1)
dram_capacity = re.search(r'^#define IWX_MAX_DRAM_ENTRY\s+(\d+)', registers, re.M).group(1)
functions = '\n'.join(definition(source, name) for name in [
    'int ItlIwx::\niwx_firmware_store_section(', 'int ItlIwx::\niwx_get_num_sections('
])
program = r'''
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <iostream>
#include <vector>
#define DPRINTFN(...) do {} while (0)
#define IWX_UCODE_SECT_MAX CAPACITY
#define IWX_CPU1_CPU2_SEPARATOR_SECTION 0xffffcccc
#define IWX_PAGING_SEPARATOR_SECTION 0xaaaabbbb
TYPES
struct iwx_softc { struct { iwx_fw_sects fw_sects[IWX_UCODE_TYPE_MAX]; } sc_fw; };
class ItlIwx {
public:
    int iwx_firmware_store_section(iwx_softc *, iwx_ucode_type, uint8_t *, size_t);
    int iwx_get_num_sections(const iwx_fw_sects *, int);
};
FUNCTIONS
static void require(bool success, const char *message) {
    if (!success) { std::cerr << message << '\n'; std::exit(1); }
}
static uint32_t word(const uint8_t *data) {
    uint32_t value; std::memcpy(&value, data, sizeof(value)); return value;
}
int main(int argc, char **argv) {
    require(argc == 2, "expected a firmware file");
    std::ifstream file(argv[1], std::ios::binary);
    require(file.good(), "cannot open firmware");
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), {});
    require(data.size() >= 88 && word(data.data()) == 0 &&
            word(data.data() + 4) == 0x0a4c5749, "invalid firmware header");
    iwx_softc device = {};
    ItlIwx driver;
    int sections = 0;
    for (size_t offset = 88; offset + 8 <= data.size();) {
        uint32_t type = word(data.data() + offset);
        uint32_t length = word(data.data() + offset + 4);
        require(length <= data.size() - offset - 8, "truncated firmware TLV");
        if (type == 19) {
            int error = driver.iwx_firmware_store_section(&device,
                IWX_UCODE_TYPE_REGULAR, data.data() + offset + 8, length);
            if (error) {
                std::cerr << "section " << sections + 1 << " rejected: " << error << '\n';
                return 1;
            }
            ++sections;
        }
        offset += 8 + ((length + size_t(3)) & ~size_t(3));
    }
    require(sections > 0, "no runtime sections");
    auto &stored = device.sc_fw.fw_sects[IWX_UCODE_TYPE_REGULAR];
    int lmac = driver.iwx_get_num_sections(&stored, 0);
    int umac = driver.iwx_get_num_sections(&stored, lmac + 1);
    int paging = driver.iwx_get_num_sections(&stored, lmac + umac + 2);
    require(lmac + umac + paging + 2 == sections, "missing firmware separators");
    require(lmac <= DRAM_CAPACITY && umac <= DRAM_CAPACITY &&
            paging <= DRAM_CAPACITY, "firmware exceeds context DMA arrays");
    uint8_t extra[4] = {};
    require(driver.iwx_firmware_store_section(&device, IWX_UCODE_TYPE_REGULAR,
            extra, 3) == EINVAL, "short section accepted");
    require(driver.iwx_firmware_store_section(&device, IWX_UCODE_TYPE_MAX,
            extra, sizeof(extra)) == EINVAL, "invalid image type accepted");
    while (stored.fw_count < IWX_UCODE_SECT_MAX)
        require(driver.iwx_firmware_store_section(&device, IWX_UCODE_TYPE_REGULAR,
                extra, sizeof(extra)) == 0, "unused capacity rejected");
    auto last = stored.fw_sect[IWX_UCODE_SECT_MAX - 1];
    require(driver.iwx_firmware_store_section(&device, IWX_UCODE_TYPE_REGULAR,
            extra, sizeof(extra)) == EINVAL, "section overflow accepted");
    require(stored.fw_count == IWX_UCODE_SECT_MAX &&
            stored.fw_sect[IWX_UCODE_SECT_MAX - 1].fws_data == last.fws_data,
            "overflow changed stored sections");
    std::cout << argv[1] << ": accepted " << sections << " sections; LMAC=" << lmac
              << " UMAC=" << umac << " paging=" << paging << "; bounds checks passed\n";
}
'''.replace('DRAM_CAPACITY', dram_capacity).replace('CAPACITY', capacity)
program = program.replace('TYPES', types).replace('FUNCTIONS', functions)
with tempfile.TemporaryDirectory(prefix='itlwm-sections-') as folder:
    folder = Path(folder)
    test = folder / 'sections.cpp'
    test.write_text(program)
    binary = folder / 'sections'
    subprocess.run(shlex.split(os.environ.get('CXX', 'c++')) + [
        '-std=c++14', '-Wall', '-Wextra', '-Werror', str(test), '-o', str(binary)
    ], check=True)
    for name in ['iwlwifi-gl-c0-fm-c0-86.ucode', 'iwlwifi-so-a0-gf-a0-68.ucode']:
        subprocess.run([str(binary), str(root / 'itlwm/firmware' / name)], check=True)
