"""Check the production HE 6 GHz IE against wire-format capability vectors."""
import os
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[3]
source = (root / 'itl80211/openbsd/net80211/ieee80211_output.c').read_text(encoding='utf-8')
a = source.index('static uint8_t *\nieee80211_add_he_6ghz_capa(')
b = source.index('\nuint8_t *\nieee80211_add_ehtcaps(', a)
production = source[a:b]
header = (root / 'itl80211/openbsd/net80211/ieee80211.h').read_text(encoding='utf-8')
names = ['IEEE80211_AMPDU_PARAM_SS', 'IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK',
         'IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT', 'IEEE80211_VHTCAP_MAX_MPDU_MASK',
         'IEEE80211_VHTCAP_TX_ANTENNA_PATTERN', 'IEEE80211_VHTCAP_RX_ANTENNA_PATTERN',
         'IEEE80211_HE_6GHZ_CAP_TX_ANTPAT_CONS', 'IEEE80211_HE_6GHZ_CAP_RX_ANTPAT_CONS',
         'IEEE80211_HE_6GHZ_CAP_SM_PS', 'IEEE80211_HE_6GHZ_CAP_SM_PS_SHIFT',
         'IEEE80211_HTCAP_SMPS_MASK', 'IEEE80211_HTCAP_SMPS_SHIFT']
lines = header.splitlines()
def definition(name):
    i = next(i for i, line in enumerate(lines) if line.startswith('#define') and line.split()[1] == name)
    parts = [lines[i]]
    while parts[-1].rstrip().endswith('\\'):
        i += 1
        parts.append(lines[i])
    return '\n'.join(parts)
macros = '\n'.join(definition(name) for name in names)
code = r"""
#include <cassert>
#include <cstdint>
#include <cstring>
@@MACROS@@
#define IEEE80211_ELEMID_EXTENSION 255
#define IEEE80211_ELEMID_EXT_HE_6GHZ_CAPA 59
#define LE_WRITE_2(p,v) do { (p)[0]=uint8_t(v); (p)[1]=uint8_t((v)>>8); } while (0)
struct ieee80211com { uint8_t ic_ampdu_params; uint16_t ic_htcaps; uint32_t ic_vhtcaps; };
@@PRODUCTION@@
int main() {
    // IEEE 802.11 HE 6 GHz Capability: SMPS bits 10:9, matching Linux mac80211.
    for (unsigned mode : {0U, 1U, 3U})
    for (unsigned spacing = 0; spacing < 8; spacing++)
    for (unsigned exponent = 0; exponent < 8; exponent++)
    for (unsigned mpdu = 0; mpdu < 3; mpdu++)
    for (unsigned antennas = 0; antennas < 4; antennas++) {
        ieee80211com ic{};
        ic.ic_ampdu_params = uint8_t(spacing << 2);
        ic.ic_htcaps = uint16_t(mode << 2);
        ic.ic_vhtcaps = mpdu | (exponent << 23) |
            ((antennas & 1) ? (1U << 29) : 0) |
            ((antennas & 2) ? (1U << 28) : 0);
        uint8_t bytes[7]; memset(bytes, 0xa5, sizeof(bytes));
        auto end = ieee80211_add_he_6ghz_capa(bytes + 1, &ic);
        assert(end == bytes + 6 && bytes[0] == 0xa5 && bytes[6] == 0xa5);
        assert(bytes[1] == 255 && bytes[2] == 3 && bytes[3] == 59);
        unsigned value = bytes[4] | (unsigned(bytes[5]) << 8);
        unsigned expected = spacing | (exponent << 3) | (mpdu << 6) |
            (mode << 9) | ((antennas & 1) ? 0x2000 : 0) |
            ((antennas & 2) ? 0x1000 : 0);
        assert(value == expected);
        assert(((value >> 9) & 3) == ((ic.ic_htcaps >> 2) & 3));
    }
}
""".replace('@@MACROS@@', macros).replace('@@PRODUCTION@@', production)
code = '#include <initializer_list>\n' + code
with tempfile.TemporaryDirectory(prefix='itlwm-he-6ghz-', **({'ignore_cleanup_errors': True} if os.name == 'nt' else {})) as folder:
    out = Path(folder)
    (out / 'test.cpp').write_text(code, encoding='utf-8')
    if os.name == 'nt':
        vswhere = Path(os.environ['ProgramFiles(x86)']) / 'Microsoft Visual Studio/Installer/vswhere.exe'
        vs = subprocess.check_output([str(vswhere), '-latest', '-products', '*', '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'], text=True).strip()
        command = '@echo off\ncall "' + str(Path(vs) / 'VC/Auxiliary/Build/vcvars64.bat') + '" >nul\ncl /nologo /std:c++17 /EHsc /Zi /fsanitize=address test.cpp /Fe:test.exe\nif %errorlevel% neq 0 exit /b %errorlevel%\ntest.exe\n'
        (out / 'run.cmd').write_text(command, encoding='utf-8')
        subprocess.run(['cmd', '/d', '/c', str(out / 'run.cmd')], cwd=out, check=True)
    else:
        subprocess.run(['c++', '-std=c++17', '-fsanitize=address,undefined', str(out / 'test.cpp'), '-o', str(out / 'test')], check=True)
        subprocess.run([str(out / 'test')], check=True)
print('PASS 2304 HE 6 GHz capability vectors: SMPS, MPDU limits, density and antenna consistency')
