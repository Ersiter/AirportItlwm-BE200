"""Execute the production Beacon EDCA boundary with distinct scan-cache nodes."""
import os,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[3]
source=(root/'itl80211/openbsd/net80211/ieee80211_input.c').read_text(encoding='utf-8')
a=source.index('    /*\n     * We do not try to update EDCA parameters')
a=source.index('    if (',a);b=source.index('\n    }',a)+6
body=source[a:b]
code=r"""
#include <cassert>
#include <cstdint>
#include <cstring>
#define IEEE80211_NODE_QOS 1U
#define IEEE80211_S_RUN 4
#define IEEE80211_IS_CHAN_6GHZ(c) ((c)->six)
#define IEEE80211_ADDR_EQ(a,b) (memcmp(a,b,6)==0)
struct Channel{bool six;};
struct ieee80211_node{unsigned ni_flags=1;uint8_t ni_macaddr[6]{},ni_bssid[6]{};Channel*ni_chan;};
struct ieee80211com{unsigned ic_state=4;ieee80211_node*ic_bss;};
static unsigned updates;
static int ieee80211_parse_edca_params(ieee80211com*,const uint8_t*){++updates;return 0;}
static int ieee80211_parse_wmm_params(ieee80211com*,const uint8_t*){++updates;return 0;}
static void beacon(ieee80211com*ic,ieee80211_node*ni,const uint8_t*edcaie,const uint8_t*wmmie){BODY}
int main(){
 for(bool six:{false,true}){
  Channel channel{six};ieee80211_node live{},cached{},other{};
  live.ni_chan=cached.ni_chan=other.ni_chan=&channel;
  live.ni_bssid[0]=cached.ni_macaddr[0]=2;other.ni_macaddr[0]=4;
  ieee80211com ic{4,&live};uint8_t ie[1]{};updates=0;
  beacon(&ic,&other,ie,nullptr);assert(updates==0&&other.ni_flags==1);
  beacon(&ic,&cached,ie,nullptr);assert(updates==1);
  beacon(&ic,&cached,nullptr,ie);assert(updates==2);
  ic.ic_state=1;beacon(&ic,&cached,ie,nullptr);assert(updates==2);
  ic.ic_state=4;live.ni_flags=0;beacon(&ic,&cached,ie,nullptr);assert(updates==2);
 }
}
""".replace('BODY',body).replace('#include <cassert>','#include <cassert>\n#include <initializer_list>')
with tempfile.TemporaryDirectory(prefix='itlwm-beacon-edca-') as folder:
 out=Path(folder);(out/'test.cpp').write_text(code,encoding='utf-8')
 if os.name=='nt':
  vswhere=Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio/Installer/vswhere.exe'
  vs=subprocess.check_output([str(vswhere),'-latest','-products','*','-requires','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],text=True).strip()
  command='@echo off\ncall "'+str(Path(vs)/'VC/Auxiliary/Build/vcvars64.bat')+'" >nul\ncl /nologo /std:c++17 /EHsc /fsanitize=address test.cpp /Fe:test.exe\nif errorlevel 1 exit /b %errorlevel%\ntest.exe\n'
  (out/'run.cmd').write_text(command,encoding='utf-8')
  subprocess.run(['cmd','/d','/c',str(out/'run.cmd')],cwd=out,check=True)
 else:
  subprocess.run(['c++','-std=c++17','-fsanitize=address,undefined',str(out/'test.cpp'),'-o',str(out/'test')],check=True)
  subprocess.run([str(out/'test')],check=True)
print('PASS Beacon EDCA: associated cached BSSID only, neighbors/scanning/non-QoS excluded on 5 and 6 GHz')
