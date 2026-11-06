"""Execute production TX completion admission and teardown wait across queue wraps."""
import os,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[3]
source=(root/'itlwm/hal_iwx/ItlIwx.cpp').read_text(encoding='utf-8')
a=source.index('\niwx_rx_tx_ba_notif(');body=source[a:source.index('\n}',a)+2]
a=body.index('    if (ba_res->sta_id >= 32');b=body.index('    sc->sc_tx_timer',a)
guard=body[a:b].replace('return;','return false;')
a=body.find('    if (ic->ic_state != IEEE80211_S_RUN)')
if a>=0:guard+=body[a:body.index('    if (!le16toh',a)].replace('return;','return false;')
source=(root/'itlwm/hal_iwx/ItlIwxMld.cpp').read_text(encoding='utf-8')
a=source.index('        auto wait_txq =');b=source.index('\n        };',a)+11
wait=source[a:b]
reg=(root/'itlwm/hal_iwx/if_iwxreg.h').read_text(encoding='utf-8')
macro=next(l for l in reg.splitlines() if l.startswith('#define IWX_AGG_SSN_TO_TXQ_IDX'))
code=r"""
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <initializer_list>
#define nitems(a) (sizeof(a)/sizeof((a)[0]))
#define IWX_INVALID_QUEUE 65535
#define IWX_STATION_ID 0
#define IWX_FLUSH_WAIT_MS 2000
#define kMillisecondScale 1
#define THREAD_UNINT 0
#define THREAD_AWAKENED 0
#define THREAD_TIMED_OUT 1
#define IEEE80211_S_RUN 4
using AbsoluteTime=uint64_t;
MACRO
struct ieee80211com{unsigned ic_state=1;};
struct iwx_tx_ring{unsigned tail=0,cur=0,ring_count=256,queued=0;};
struct SC{unsigned sc_generation=1;bool sc_use_mld_api=true;uint32_t sc_mld_sta_mask=128,sc_mld_active_sta_mask=0;ieee80211com sc_ic;iwx_tx_ring txq[4];};
struct BA{unsigned sta_id=7;};
static bool accepts(SC*sc,BA*ba_res){auto*ic=&sc->sc_ic;GUARD return true;}
struct Gate{SC*sc;unsigned calls=0;int commandSleep(unsigned*,AbsoluteTime,int){
 ++calls;BA ba;if(!accepts(sc,&ba))return THREAD_TIMED_OUT;
 auto&r=sc->txq[2];r.tail=IWX_AGG_SSN_TO_TXQ_IDX(r.cur,r.ring_count);r.queued=0;return THREAD_TIMED_OUT;
}};
static void clock_interval_to_deadline(unsigned,unsigned,uint64_t*p){*p=1;}
static int drain(SC*sc,Gate*gate,unsigned qid=2){unsigned generation=sc->sc_generation;
 auto getMainCommandGate=[&]{return gate;};@@WAIT@@ return wait_txq(qid);}
int main(){
 SC sc;BA ba;assert(accepts(&sc,&ba));sc.sc_ic.ic_state=4;assert(accepts(&sc,&ba));
 ba.sta_id=8;assert(!accepts(&sc,&ba));ba.sta_id=32;assert(!accepts(&sc,&ba));
 sc.sc_use_mld_api=false;ba.sta_id=0;assert(accepts(&sc,&ba));ba.sta_id=7;assert(!accepts(&sc,&ba));
 sc.sc_use_mld_api=true;sc.sc_ic.ic_state=1;Gate gate{&sc};
 for(unsigned size:{16,256,1024}){
  auto&r=sc.txq[2];r.ring_count=size;r.cur=2*size;r.tail=0;r.queued=0;gate.calls=0;
  assert(drain(&sc,&gate)==0&&gate.calls==0);
  r.cur=2*size+7;r.tail=4;r.queued=3;assert(drain(&sc,&gate)==0&&gate.calls==1&&r.queued==0);
 }
 assert(drain(&sc,&gate,IWX_INVALID_QUEUE)==0);
 sc.sc_mld_sta_mask=0;sc.txq[2].tail=4;sc.txq[2].queued=3;assert(drain(&sc,&gate)==EWOULDBLOCK);
}
""".replace('MACRO',macro).replace('GUARD',guard).replace('@@WAIT@@',wait)
with tempfile.TemporaryDirectory(prefix='itlwm-tx-drain-', ignore_cleanup_errors=os.name == 'nt') as folder:
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
print('PASS TX drain: configured inactive stations reclaim outside RUN; logical pointers wrap to queue windows; real timeout remains an error')
