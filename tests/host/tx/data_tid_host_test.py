"""Execute production MLD data-queue preparation and TX selection without BA."""
import os, subprocess, tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[3]
source = (root/'itlwm/hal_iwx/ItlIwx.cpp').read_text(encoding='utf-8')
mld = (root/'itlwm/hal_iwx/ItlIwxMld.cpp').read_text(encoding='utf-8')

def function(text, name):
    start = text.index(name)
    begin = text.index('{', start)
    depth = 1
    end = begin + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]

tx = function(source, 'iwx_tx(struct')
a = tx.index('    tid = IWX_MGMT_TID;')
b = tx.index('#ifdef AIRPORT_VTD', a)
selection = tx[a:b]
dhcp = function(source, 'iwx_is_dhcp_tx_payload(mbuf_t')
allocation = function(source, 'iwx_tvqm_alloc_txq(struct')
ba_task = function(source, 'iwx_ba_task(void')
a = ba_task.index('            ring = &sc->txq[qid];')
b = ba_task.index('            ba->ba_timeout_val', a)
ba_sequence = ba_task[a:b]
registers = (root/'itlwm/hal_iwx/if_iwxreg.h').read_text(encoding='utf-8')
window_macro = next(l for l in registers.splitlines() if l.startswith('#define IWX_AGG_SSN_TO_TXQ_IDX'))
run = function(mld, 'iwx_mld_run(struct')
a = run.index('    in->in_ni.ni_txrate = 0;')
preparation = run[a:run.rfind('}')]
code = r"""
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <vector>
#include <initializer_list>
#define AIRPORT_VTD 1
#define IWX_MAX_TID_COUNT 8
#define IWX_MGMT_TID 15
#define IWX_INVALID_QUEUE 65535
#define IWX_DEFAULT_QUEUE_SIZE 256
#define IWX_DATA_PATH_GROUP 5
#define IWX_MLD_SCD_QUEUE_CONFIG_CMD 0x17
#define IWX_WIDE_ID(g,c) (((g)<<8)|(c))
#define IEEE80211_NODE_QOS 1
#define IEEE80211_BA_AGREED 2
#define IEEE80211_FC0_TYPE_DATA 8
#define IEEE80211_FC0_SUBTYPE_NODATA 0x40
#define IEEE80211_QOS_TID 15
#define XYLog(...) ((void)0)
#define IEEE80211_IS_MULTICAST(p) ((p)[0]&1)
@@WINDOW_MACRO@@
struct ieee80211_tx_ba { int ba_state=0; unsigned ba_winstart=0,ba_winend=0,ba_winsize=64; };
struct iwx_tx_ring { unsigned cur=0,ring_count=256; };
struct ieee80211_node { unsigned ni_flags=1; int ni_txrate=0,ni_txmcs=0; ieee80211_tx_ba ni_tx_ba[8]; };
struct iwx_node { ieee80211_node in_ni; };
struct ieee80211_frame { bool qos=false; unsigned tag=0; uint8_t i_addr1[6]={0}; };
static bool ieee80211_has_qos(ieee80211_frame *p) { return p->qos; }
static unsigned ieee80211_get_qos(ieee80211_frame *p) { return p->tag; }
struct mbuf { bool freed=false; std::vector<uint8_t> bytes; };
using mbuf_t=mbuf*;
#define MIN(a,b) ((a)<(b)?(a):(b))
static size_t mbuf_pkthdr_len(mbuf_t m) { return m->bytes.size(); }
static int mbuf_copydata(mbuf_t m,size_t off,size_t len,void *dst) {
 if(off+len>m->bytes.size())return EINVAL;
 memcpy(dst,m->bytes.data()+off,len);return 0;
}
static bool @@DHCP@@
static void mbuf_freem(mbuf *p) { p->freed=true; }
struct iwx_softc {
 bool sc_use_mld_api=true; int sc_generation=1,first_data_qid=1;
 struct { int qid=IWX_INVALID_QUEUE; } sc_tid_data[8];
 iwx_tx_ring txq[16];
 int calls=0,fail_tid=-1,rate_error=0,failures=0; bool reset=false;
};
struct ItlIwx {
 int iwx_tvqm_alloc_txq(iwx_softc*,int,int);
 int iwx_tvqm_enable_txq(iwx_softc *sc,int tid,int,unsigned) {
  sc->calls++; if(sc->reset) sc->sc_generation++;
  return tid==sc->fail_tid ? -ENOSPC : tid+2;
 }
 int iwx_rs_init(iwx_softc *sc,iwx_node*,bool) { return sc->rate_error; }
 void iwx_mld_record_state_failure(iwx_softc *sc,const char*,const char*,int,unsigned,int) { sc->failures++; }
 int prepare(iwx_softc *sc,iwx_node *in) { int err; @@PREPARE@@ }
 void start_ba(iwx_softc *sc,ieee80211_tx_ba *ba) { int qid=2;iwx_tx_ring *ring;@@BA_SEQUENCE@@ }
 int select(iwx_softc *sc,ieee80211_node *ni,ieee80211_frame *wh,unsigned type,unsigned subtype,mbuf *m) {
  int tid,qid; @@SELECT@@ return qid;
 }
};
int ItlIwx::@@ALLOCATE@@
int main(int argc,char**) {
 ItlIwx d; iwx_softc sc; iwx_node in; ieee80211_frame wh; mbuf m;
 if(argc==1) {
  for(int tid=0;tid<8;tid++) sc.sc_tid_data[tid].qid=tid+2;
  for(unsigned ssn:{0u,256u,4095u}) for(unsigned cursor:{2u,256u,4103u}) {
   auto &ba=in.in_ni.ni_tx_ba[0];ba.ba_winstart=ssn;sc.txq[2].cur=cursor;
   d.start_ba(&sc,&ba);assert(ba.ba_winstart==ssn&&ba.ba_winend==((ssn+63)&0xfff));
  }
  // DHCP/EAPOL before aggregation and after DELBA use data TID 0.
  assert(d.select(&sc,&in.in_ni,&wh,8,0,&m)==2);
  for(int tid=0;tid<8;tid++) for(int state:{0,1,2,3}) {
   wh.qos=true;wh.tag=tid;in.in_ni.ni_tx_ba[tid].ba_state=state;
   assert(d.select(&sc,&in.in_ni,&wh,8,0x80,&m)==tid+2);
  }
  assert(d.select(&sc,&in.in_ni,&wh,8,0xc0,&m)==1);
  assert(d.select(&sc,&in.in_ni,&wh,0,0,&m)==1);
  wh.qos=false; assert(d.select(&sc,&in.in_ni,&wh,8,0x40,&m)==1);
  wh.qos=true;wh.tag=8;assert(d.select(&sc,&in.in_ni,&wh,8,0x80,&m)==ENXIO&&m.freed);
  m.freed=false;wh.tag=0;sc.sc_tid_data[0].qid=IWX_INVALID_QUEUE;
  assert(d.select(&sc,&in.in_ni,&wh,8,0x80,&m)==ENXIO&&m.freed);
  mbuf dhcp;dhcp.bytes.resize(44);
  const uint8_t snap[]={0xaa,0xaa,3,0,0,0,8,0};memcpy(dhcp.bytes.data(),snap,8);
  dhcp.bytes[8]=0x45;dhcp.bytes[11]=36;dhcp.bytes[17]=17;
  dhcp.bytes[29]=68;dhcp.bytes[31]=67;dhcp.bytes[33]=16;
  assert(iwx_is_dhcp_tx_payload(&dhcp));
  for(size_t length=0;length<44;length++) {
   mbuf truncated=dhcp;truncated.bytes.resize(length);assert(!iwx_is_dhcp_tx_payload(&truncated));
  }
  for(int pos:{0,6,8,11,14,15,17,29,31,33}) {
   mbuf bad=dhcp;bad.bytes[pos]=0xff;assert(!iwx_is_dhcp_tx_payload(&bad));
  }
  mbuf options=dhcp;options.bytes.insert(options.bytes.begin()+28,4,0);
  options.bytes[8]=0x46;options.bytes[11]=40;assert(iwx_is_dhcp_tx_payload(&options));
  assert(!iwx_is_dhcp_tx_payload(nullptr));
  sc.sc_use_mld_api=false;sc.sc_tid_data[0].qid=2;
  for(int state:{0,1,2}) {
   in.in_ni.ni_tx_ba[0].ba_state=state;
   assert(d.select(&sc,&in.in_ni,&wh,8,0x80,&m)==(state==2?2:1));
  }
 } else {
  assert(d.prepare(&sc,&in)==0&&sc.calls==8);
  for(int tid=0;tid<8;tid++) assert(sc.sc_tid_data[tid].qid==tid+2);
  assert(d.prepare(&sc,&in)==0&&sc.calls==8); // RUN refresh and BA reuse.
  for(int tid=0;tid<8;tid++) assert(d.iwx_tvqm_alloc_txq(&sc,tid,100)==tid+2);
  assert(sc.calls==8);
  sc=iwx_softc{};in.in_ni.ni_flags=0;
  assert(d.prepare(&sc,&in)==0&&sc.calls==1);
  sc=iwx_softc{};in.in_ni.ni_flags=1;sc.fail_tid=3;
  assert(d.prepare(&sc,&in)==ENOSPC&&sc.calls==4&&sc.failures==1);
  sc=iwx_softc{};sc.reset=true;assert(d.prepare(&sc,&in)==ENXIO);
  sc=iwx_softc{};sc.rate_error=EIO;assert(d.prepare(&sc,&in)==EIO&&sc.calls==0);
 }
}
""".replace('@@PREPARE@@', preparation).replace('@@SELECT@@', selection).replace('@@ALLOCATE@@', allocation).replace('@@DHCP@@', dhcp).replace('@@WINDOW_MACRO@@', window_macro).replace('@@BA_SEQUENCE@@', ba_sequence)
with tempfile.TemporaryDirectory(prefix='itlwm-data-tid-', **({'ignore_cleanup_errors': True} if os.name=='nt' else {})) as folder:
    out=Path(folder);(out/'test.cpp').write_text(code,encoding='utf-8')
    if os.name=='nt':
        vswhere=Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio/Installer/vswhere.exe'
        vs=subprocess.check_output([str(vswhere),'-latest','-products','*','-requires','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],text=True).strip()
        setup='call "'+str(Path(vs)/'VC/Auxiliary/Build/vcvars64.bat')+'" >nul\n'
        command='@echo off\n'+setup+'cl /nologo /std:c++17 /EHsc /Zi /fsanitize=address test.cpp /Fe:test.exe\nif %errorlevel% neq 0 exit /b %errorlevel%\ntest.exe\nif %errorlevel% neq 0 exit /b %errorlevel%\ntest.exe prepare\n'
        (out/'run.cmd').write_text(command,encoding='utf-8')
        subprocess.run(['cmd','/d','/c',str(out/'run.cmd')],cwd=out,check=True)
    else:
        subprocess.run(['c++','-std=c++17','-fsanitize=address,undefined',str(out/'test.cpp'),'-o',str(out/'test')],check=True)
        subprocess.run([str(out/'test')],check=True)
        subprocess.run([str(out/'test'),'prepare'],check=True)
print('PASS data TIDs: DHCP/EAPOL and QoS data independent of BA; management/null and legacy preserved; RUN prepares/reuses queues and propagates allocation/reset errors; bounded DHCP recognition; negotiated BA SSN preserved across descriptor wraps')
