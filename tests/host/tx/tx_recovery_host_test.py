"""Exercise production TX admission and software-queue preservation during recovery."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[3])
parser.add_argument('--output', type=Path)
args = parser.parse_args()
repo = args.repo.resolve()
temporary = tempfile.TemporaryDirectory(prefix='itlwm-tx-recovery-') if args.output is None else None
out = args.output.resolve() if args.output else Path(temporary.name)
out.mkdir(parents=True, exist_ok=True)
source = (repo/'itlwm/hal_iwx/ItlIwx.cpp').read_text(encoding='utf-8')
start = source.index('IOReturn ItlIwx::\n_iwx_start_task(')
sender = source[start:source.index('\n}', start)+2]
start = source.index('iwx_tx(struct iwx_softc *sc, mbuf_t m, struct ieee80211_node *ni, int ac)\n{')
start = source.index('\n', source.index('{', start))+1
admission = source[start:source.index('    struct ieee80211com *ic =', start)]
code = r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <vector>
#include <functional>
#include <algorithm>
#define AIRPORT 1
#define IFF_RUNNING 1U
#define IFF_UP 2U
#define IWX_FLAG_SHUTDOWN 1U
#define IWX_FLAG_TXFLUSH 2U
#define IWX_FLAG_HW_ERR 4U
#define IWX_FLAG_RFKILL 8U
#define IEEE80211_S_RUN 4
#define IEEE80211_F_TX_MGMT_ONLY 1U
#define EDCA_AC_BE 0
#define NBPFILTER 0
#define container_of(p,type,field) ((p)->owner)
using IOReturn=int;struct OSObject{};
constexpr int kIOReturnSuccess=0,kIOReturnError=1;
struct ieee80211_node{int references=0;};
struct ether_header{uint8_t bytes[14];};
struct mbuf{int id;ieee80211_node*node;};using mbuf_t=mbuf*;
static std::vector<int>freed;
static void mbuf_freem(mbuf_t m){assert(std::count(freed.begin(),freed.end(),m->id)==0);freed.push_back(m->id);delete m;}
static size_t mbuf_len(mbuf_t){return sizeof(ether_header);}
static int mbuf_pullup(mbuf_t*,size_t){return 0;}
static void*mbuf_pkthdr_rcvif(mbuf_t m){return m->node;}
struct ifqueue{bool active=false;std::deque<mbuf_t>queue;};
static bool ifq_is_oactive(ifqueue*q){return q->active;}
static void ifq_set_oactive(ifqueue*q){q->active=true;}
static mbuf_t ifq_dequeue(ifqueue*q){if(q->queue.empty())return nullptr;auto m=q->queue.front();q->queue.pop_front();return m;}
static mbuf_t mq_dequeue(std::deque<mbuf_t>*q){if(q->empty())return nullptr;auto m=q->front();q->pop_front();return m;}
struct Statistics{unsigned outputErrors=0,outputPackets=0;};
struct _ifnet{void*if_softc=nullptr;unsigned if_flags=IFF_RUNNING|IFF_UP;int if_timer=0;ifqueue if_snd;Statistics stats,*netStat=&stats;};
struct ieee80211com{_ifnet ic_if;int ic_state=IEEE80211_S_RUN;unsigned ic_xflags=0;std::deque<mbuf_t>ic_mgtq;};
static void ieee80211_release_node(ieee80211com*,ieee80211_node*n){assert(n->references>0);--n->references;}
static mbuf_t ieee80211_encap(_ifnet*,mbuf_t m,ieee80211_node**ni){*ni=m->node;++(*ni)->references;return m;}
class ItlIwx;
struct iwx_softc{ItlIwx*owner=nullptr;ieee80211com sc_ic;unsigned sc_flags=0;int ns_nstate=IEEE80211_S_RUN,sc_tx_timer=0;std::vector<int>qfullmsk;};
class ItlIwx{public:
 iwx_softc com;unsigned submissions=0;std::function<int(iwx_softc*)>submit;
 ItlIwx(){com.owner=this;com.sc_ic.ic_if.if_softc=&com;}
 static IOReturn _iwx_start_task(OSObject*,void*,void*,void*,void*);
 int iwx_tx(iwx_softc*,mbuf_t,ieee80211_node*,int);
};
int ItlIwx::iwx_tx(iwx_softc*sc,mbuf_t m,ieee80211_node*ni,int){
ADMISSION
 ++submissions;int error=submit?submit(sc):0;mbuf_freem(m);
 if(!error)ieee80211_release_node(&sc->sc_ic,ni);
 return error;
}
SENDER
static void start(ItlIwx&d){ItlIwx::_iwx_start_task(nullptr,&d.com.sc_ic.ic_if,nullptr,nullptr,nullptr);}
int main(){
 for(unsigned flag:{IWX_FLAG_SHUTDOWN,IWX_FLAG_TXFLUSH,IWX_FLAG_HW_ERR,IWX_FLAG_RFKILL}){
  ItlIwx d;ieee80211_node node;freed.clear();auto&ic=d.com.sc_ic;
  ic.ic_if.if_snd.queue.push_back(new mbuf{1,&node});ic.ic_mgtq.push_back(new mbuf{2,&node});node.references=1;
  d.com.sc_flags=flag;start(d);assert(d.submissions==0&&freed.empty()&&ic.ic_if.if_snd.queue.size()==1&&ic.ic_mgtq.size()==1);
  d.com.sc_flags=0;start(d);assert(d.submissions==2&&freed.size()==2&&node.references==0);
 }
 for(unsigned fault:{IWX_FLAG_HW_ERR,IWX_FLAG_RFKILL,IWX_FLAG_SHUTDOWN}){
  ItlIwx d;ieee80211_node node;freed.clear();auto&q=d.com.sc_ic.ic_if.if_snd;
  for(int i=0;i<4;i++)q.queue.push_back(new mbuf{i,&node});
  d.submit=[&](iwx_softc*s){s->sc_flags|=fault;return EIO;};start(d);
  assert(d.submissions==1&&freed.size()==1&&q.queue.size()==3&&node.references==0);
  d.submit={};d.com.sc_flags=0;start(d);assert(d.submissions==4&&freed.size()==4&&q.queue.empty()&&node.references==0);
 }
 for(unsigned fault:{IWX_FLAG_HW_ERR,IWX_FLAG_RFKILL,IWX_FLAG_SHUTDOWN}){
  ItlIwx d;ieee80211_node node;freed.clear();d.com.sc_flags=fault;
  assert(d.iwx_tx(&d.com,new mbuf{7,&node},&node,0)==ENXIO&&freed.size()==1&&d.submissions==0);
 }
 puts("PASS TX recovery: management/data queues preserved on fault, mid-drain failure stops dequeue, restart resumes once, direct submissions rejected");
}
'''.replace('ADMISSION', admission).replace('SENDER', sender)
(out/'tx-test.cpp').write_text(code, encoding='utf-8')
if os.name == 'nt':
    vswhere = Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio/Installer/vswhere.exe'
    vs = subprocess.check_output([str(vswhere), '-latest', '-products', '*', '-requires',
        'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'], text=True).strip()
    cmd = out/'run.cmd'
    cmd.write_text('@echo off\ncall "'+str(Path(vs)/'VC/Auxiliary/Build/vcvars64.bat')+'" >nul\n'
        'cl /nologo /std:c++17 /EHsc /W3 /Od /Zi /fsanitize=address /Fe:tx-test.exe tx-test.cpp\n'
        'if errorlevel 1 exit /b %errorlevel%\ntx-test.exe\n', encoding='utf-8')
    result = subprocess.run(['cmd.exe', '/d', '/c', str(cmd)], cwd=out, capture_output=True)
else:
    cxx = os.environ.get('CXX') or shutil.which('clang++') or shutil.which('g++')
    subprocess.run([cxx, '-std=c++17', '-g', '-fsanitize=address,undefined',
        str(out/'tx-test.cpp'), '-o', str(out/'tx-test')], check=True)
    result = subprocess.run([str(out/'tx-test')], cwd=out, capture_output=True)
log = (result.stdout+result.stderr).decode('mbcs' if os.name == 'nt' else 'utf-8', errors='replace')
(out/'tx-test.log').write_text(log, encoding='utf-8')
print(log)
raise SystemExit(result.returncode)
