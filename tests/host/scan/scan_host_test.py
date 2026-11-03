"""Exercise production 6 GHz basic-rate negotiation and PHY mode transitions."""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[3])
parser.add_argument('--output', type=Path)
args = parser.parse_args()
repo = args.repo.resolve()
temporary = tempfile.TemporaryDirectory(prefix='itlwm-scan-') if args.output is None else None
out = args.output.resolve() if args.output else Path(temporary.name)
out.mkdir(parents=True, exist_ok=True)
source = (repo/'itl80211/openbsd/net80211/ieee80211.c').read_text(encoding='utf-8')
proto = (repo/'itl80211/openbsd/net80211/ieee80211_proto.c').read_text(encoding='utf-8')
headers = '\n'.join((repo/'itl80211/openbsd/net80211'/name).read_text(encoding='utf-8')
    for name in ['ieee80211.h', 'ieee80211_var.h'])
def function(text, name):
    match = re.search(r'(?m)^(?:static )?(?:int|enum ieee80211_phymode)\n' + name + r'\(', text)
    assert match, name
    end = text.index('\n}', match.start()) + 2
    return text[match.start():end]
definitions = []
for line in headers.replace('\\\n', '').splitlines():
    if re.match(r'#define\s+IEEE80211_(?:CHAN_|IS_CHAN_|MODE_MAX\b|RATE_(?:BASIC|VAL)\b|F_DO(?:SORT|FRATE|NEGO|DEL)\b)', line):
        definitions.append(line)
mode = re.search(r'enum ieee80211_phymode\s*\{.*?\};', headers, re.S).group()
code = r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <initializer_list>
using u_int=unsigned;using u_int8_t=uint8_t;
#define IEEE80211_STA_ONLY 1
#define XYLog(...) ((void)0)
#define DPRINTF(x) ((void)0)
#define nitems(x) (sizeof(x)/sizeof((x)[0]))
#define isset(a,i) ((a)[(i)/8]&(1U<<((i)%8)))
#define isclr(a,i) (!isset(a,i))
#define setbit(a,i) ((a)[(i)/8]|=uint8_t(1U<<((i)%8)))
'''
code += '\n'.join(definitions) + '\n' + mode + r'''
struct _ifnet{};
struct ieee80211_channel {uint32_t ic_flags;unsigned ic_freq;};
struct ieee80211_rateset {uint8_t rs_nrates,rs_rates[32];};
struct ieee80211com {
 _ifnet ic_if;int ic_curmode;unsigned ic_modecaps;int ic_fixed_rate=-1;
 ieee80211_channel ic_channels[IEEE80211_CHAN_MAX+1]{};
 uint8_t ic_chan_active[31]{};
 ieee80211_channel*ic_ibss_chan=nullptr;
 ieee80211_rateset ic_sup_rates[IEEE80211_MODE_MAX]{};
};
struct ieee80211_node {ieee80211_channel*ni_chan;ieee80211_rateset ni_rates;};
static void panic(const char*,...){throw std::runtime_error("panic");}
static unsigned ieee80211_chan2ieee(ieee80211com*ic,const ieee80211_channel*c){return unsigned(c-ic->ic_channels);}
static void ieee80211_reset_scan(_ifnet*){}
static void ieee80211_reset_erp(ieee80211com*){}
'''
code += function(source, 'ieee80211_chan2mode') + '\n'
if 'ieee80211_chan_in_mode(' in source:
    code += function(source, 'ieee80211_chan_in_mode') + '\n'
code += function(source, 'ieee80211_setmode') + '\n' + function(proto, 'ieee80211_fix_rate')
code += r'''
int main(){
 ieee80211com ic{};ic.ic_modecaps=(1U<<IEEE80211_MODE_MAX)-1;
 ic.ic_sup_rates[IEEE80211_MODE_11A]={8,{12,18,24,36,48,72,96,108}};
 ic.ic_sup_rates[IEEE80211_MODE_11B]={4,{2,4,11,22}};
 ic.ic_sup_rates[IEEE80211_MODE_11G]={12,{2,4,11,22,12,18,24,36,48,72,96,108}};
 ic.ic_channels[1]={IEEE80211_CHAN_2GHZ|IEEE80211_CHAN_CCK|IEEE80211_CHAN_OFDM,2412};
 ic.ic_channels[40]={IEEE80211_CHAN_5GHZ|IEEE80211_CHAN_OFDM|IEEE80211_CHAN_HT20,5200};
 ic.ic_channels[195]={IEEE80211_CHAN_6GHZ|IEEE80211_CHAN_OFDM,6215};
 ic.ic_channels[196]={IEEE80211_CHAN_6GHZ|IEEE80211_CHAN_OFDM|IEEE80211_CHAN_HT40U,6235};
 assert(ieee80211_setmode(&ic,IEEE80211_MODE_AUTO)==0);
 ieee80211_node six{&ic.ic_channels[195],{3,{0x8c,0x98,0xb0}}};
 ieee80211_node five{&ic.ic_channels[40],{3,{0x8c,0x98,0xb0}}};
 int rate6=ieee80211_fix_rate(&ic,&six,IEEE80211_F_DONEGO);
 int rate5=ieee80211_fix_rate(&ic,&five,IEEE80211_F_DONEGO);
 assert(!(rate6&IEEE80211_RATE_BASIC)&&rate6==rate5);
 assert(ieee80211_setmode(&ic,ieee80211_chan2mode(&ic,six.ni_chan))==0);
 assert(isset(ic.ic_chan_active,195));
 ieee80211_fix_rate(&ic,&six,IEEE80211_F_DOSORT|IEEE80211_F_DONEGO|IEEE80211_F_DODEL);
 assert(six.ni_rates.rs_nrates==3);
 assert(ieee80211_setmode(&ic,IEEE80211_MODE_11AX)==0);
 assert(isset(ic.ic_chan_active,195)&&isset(ic.ic_chan_active,196));
 assert(!isset(ic.ic_chan_active,197));
 rate6=ieee80211_fix_rate(&ic,&six,IEEE80211_F_DONEGO);
 assert(!(rate6&IEEE80211_RATE_BASIC));
 assert(ieee80211_setmode(&ic,IEEE80211_MODE_11B)==0);
 assert(!isset(ic.ic_chan_active,195)&&!isset(ic.ic_chan_active,196));
 for(auto mode:{IEEE80211_MODE_11N,IEEE80211_MODE_11AC}){
  assert(ieee80211_setmode(&ic,mode)==0);
  assert(!isset(ic.ic_chan_active,195)&&!isset(ic.ic_chan_active,196));
 }
 puts("PASS 6 GHz: OFDM basic rates negotiate before authentication and after HE association; 20 MHz and HT40 channel eligibility");
}
'''
(out/'scan-test.cpp').write_text(code, encoding='utf-8')
if os.name == 'nt':
    vswhere=Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio/Installer/vswhere.exe'
    vs=subprocess.check_output([str(vswhere),'-latest','-products','*','-requires',
        'Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],text=True).strip()
    cmd=out/'run.cmd'
    cmd.write_text('@echo off\ncall "'+str(Path(vs)/'VC/Auxiliary/Build/vcvars64.bat')+'" >nul\n'
        'cl /nologo /std:c++17 /EHsc /W3 /Od /Zi /fsanitize=address /Fe:scan-test.exe scan-test.cpp\n'
        'if errorlevel 1 exit /b %errorlevel%\nscan-test.exe\n', encoding='utf-8')
    result=subprocess.run(['cmd.exe','/d','/c',str(cmd)],cwd=out,capture_output=True)
else:
    cxx=os.environ.get('CXX') or shutil.which('clang++') or shutil.which('g++')
    subprocess.run([cxx,'-std=c++17','-g','-fsanitize=address,undefined',
        str(out/'scan-test.cpp'),'-o',str(out/'scan-test')],check=True)
    result=subprocess.run([str(out/'scan-test')],cwd=out,capture_output=True)
log=(result.stdout+result.stderr).decode('mbcs' if os.name=='nt' else 'utf-8',errors='replace')
(out/'scan-test.log').write_text(log,encoding='utf-8')
print(log)
raise SystemExit(result.returncode)
