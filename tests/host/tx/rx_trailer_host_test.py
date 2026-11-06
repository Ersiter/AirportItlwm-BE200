"""Verify production RX trailer removal and padding against exact frame bytes."""
import os, subprocess, tempfile
from pathlib import Path

root=Path(__file__).resolve().parents[3]
source=(root/'itlwm/hal_iwx/ItlIwx.cpp').read_text(encoding='utf-8')
a=source.index('iwx_rx_mpdu_mq(struct')
start=source.find('    /* Match iwl_mvm_create_skb:',a)
if start<0: start=source.index('    /* Account for padding following the frame header. */',a)
end=source.index('    memset(&rxi, 0, sizeof(rxi));',start)
production=source[start:end]
reg=(root/'itlwm/hal_iwx/if_iwxreg.h').read_text(encoding='utf-8')
names=['IWX_RX_MPDU_MFLG1_MIC_CRC_LEN_MASK','IWX_RX_MPDU_MFLG1_MIC_CRC_LEN_SHIFT','IWX_RX_MPDU_MFLG2_PAD','IWX_RX_MPDU_RES_STATUS_SEC_ENC_MSK','IWX_RX_MPDU_RES_STATUS_SEC_CCM_ENC']
macros='\n'.join(next(l for l in reg.splitlines() if l.startswith('#define') and l.split()[1]==name) for name in names)
code=r"""
#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>
#include <initializer_list>
@@MACROS@@
#define IEEE80211_M_MONITOR 1
#define IEEE80211_FC0_TYPE_MASK 0x0c
#define IEEE80211_FC0_TYPE_CTL 0x04
#define IEEE80211_FC0_SUBTYPE_MASK 0xf0
#define IEEE80211_FC0_SUBTYPE_CTS 0xc0
#define IEEE80211_FC0_SUBTYPE_ACK 0xd0
#define IEEE80211_CCMP_HDRLEN 8
#define le16toh(x) (x)
struct ieee80211_frame { uint8_t i_fc[2];uint8_t body[22]; };
struct ieee80211_frame_min { uint8_t bytes[16]; };
struct ieee80211_frame_cts { uint8_t bytes[10]; };
struct ieee80211_frame_ack { uint8_t bytes[10]; };
struct mbuf { std::vector<uint8_t> bytes; bool freed=false; };
static void* mbuf_data(mbuf*m){return m->bytes.data();}
static void mbuf_adj(mbuf*m,int n){if(n<0)m->bytes.resize(m->bytes.size()+n);else m->bytes.erase(m->bytes.begin(),m->bytes.begin()+n);}
static void mbuf_freem(mbuf*m){m->freed=true;}
#define mtod(m,t) reinterpret_cast<t>(mbuf_data(m))
struct Stats{unsigned inputErrors=0;};
struct IF{Stats*netStat;};
struct ieee80211com { int ic_opmode=0; IF ifp; };
#define IC2IFP(ic) (&(ic)->ifp)
static unsigned ieee80211_get_hdrlen(ieee80211_frame*w){return (w->i_fc[0]&0x80)?26:24;}
struct Desc {unsigned mac_flags1=0,mac_flags2=0;uint16_t status=0;};
static void prepare(ieee80211com*ic,mbuf*m,Desc*desc){uint32_t len=m->bytes.size(),hdrlen;@@PRODUCTION@@}
int main(){
 Stats stats;ieee80211com ic;ic.ifp.netStat=&stats;
 for(unsigned header:{24,26})for(unsigned crypt:{0,8})for(unsigned trailer=0;trailer<=30;trailer+=2)for(bool pad:{false,true})for(bool monitor:{false,true}){
  std::vector<uint8_t> frame(header+crypt+73);
  for(unsigned i=0;i<frame.size();i++)frame[i]=uint8_t(i*17+3);
  frame[0]=(header==26)?0x88:0x08;
  mbuf m{frame};if(pad)m.bytes.insert(m.bytes.begin()+header+crypt,2,0xee);
  m.bytes.insert(m.bytes.end(),trailer,0xdd);
  Desc desc;desc.mac_flags1=(trailer/2)<<4;desc.mac_flags2=pad?IWX_RX_MPDU_MFLG2_PAD:0;
  desc.status=crypt?IWX_RX_MPDU_RES_STATUS_SEC_CCM_ENC:0;
  ic.ic_opmode=monitor?IEEE80211_M_MONITOR:0;prepare(&ic,&m,&desc);
  auto expected=frame;if(monitor)expected.insert(expected.end(),trailer,0xdd);
  assert(!m.freed&&m.bytes==expected&&stats.inputErrors==0);
 }
 ic.ic_opmode=0;mbuf short_frame;short_frame.bytes.resize(24);Desc bad;bad.mac_flags1=0xf0;
 prepare(&ic,&short_frame,&bad);assert(short_frame.freed&&stats.inputErrors==1);
}
""".replace('@@MACROS@@',macros).replace('@@PRODUCTION@@',production)
with tempfile.TemporaryDirectory(prefix='itlwm-rx-trailer-',**({'ignore_cleanup_errors':True} if os.name=='nt' else {})) as folder:
    out=Path(folder);(out/'test.cpp').write_text(code,encoding='utf-8')
    if os.name=='nt':
        vswhere=Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio/Installer/vswhere.exe'
        vs=subprocess.check_output([str(vswhere),'-latest','-products','*','-requires','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],text=True).strip()
        command='@echo off\ncall "'+str(Path(vs)/'VC/Auxiliary/Build/vcvars64.bat')+'" >nul\ncl /nologo /std:c++17 /EHsc /Zi /fsanitize=address test.cpp /Fe:test.exe\nif %errorlevel% neq 0 exit /b %errorlevel%\ntest.exe\n'
        (out/'run.cmd').write_text(command,encoding='utf-8')
        subprocess.run(['cmd','/d','/c',str(out/'run.cmd')],cwd=out,check=True)
    else:
        subprocess.run(['c++','-std=c++17','-fsanitize=address,undefined',str(out/'test.cpp'),'-o',str(out/'test')],check=True)
        subprocess.run([str(out/'test')],check=True)
print('PASS RX bytes: exact payload after all MIC/CRC lengths, QoS/CCMP padding, monitor retention and truncated-trailer rejection')
