"""Exercise the production MBSSID parser and RX expansion with a host mbuf boundary."""
import argparse
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[3])
parser.add_argument('--output', type=Path)
args = parser.parse_args()
root = args.repo.resolve()
temporary = tempfile.TemporaryDirectory(prefix='itlwm-mbssid-') if args.output is None else None
out = args.output.resolve() if args.output else Path(temporary.name)
out.mkdir(parents=True, exist_ok=True)
source = (root/'itl80211/openbsd/net80211/ieee80211_input.c').read_text(encoding='utf-8')
start = source.index('\nieee80211_recv_probe_resp(') + 1
end = source.index('\n}', start) + 2
wrapper = 'void\n' + source[start:end]
code = r'''
#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>
#ifdef _MSC_VER
#define __attribute__(x)
#endif
#include "itl80211/openbsd/net80211/ieee80211_mbssid.h"
#define MBSSID_RX_WRAPPER 1
#define MCLBYTES 2048
#define MBUF_DONTWAIT 0
#define MT_DATA 0
#define mtod(m,t) ((t)((m)->data.data()))
#define IEEE80211_ADDR_COPY(a,b) memcpy((a),(b),6)
struct ieee80211_frame {uint8_t fc[2],duration[2],i_addr1[6],i_addr2[6],i_addr3[6],sequence[2];};
static_assert(sizeof(ieee80211_frame)==24,"frame header");
struct mbuf {std::vector<uint8_t>data;size_t len;};
using mbuf_t=mbuf*;
struct ieee80211com{};
struct ieee80211_node{};
struct ieee80211_rxinfo {unsigned channel=5,band=6;};
static size_t mbuf_len(mbuf_t m){return m->len;}
static bool allocationFailure=false;
static unsigned allocations=0,frees=0;
static int mbuf_getcluster(int,int,size_t size,mbuf_t*out){
 if(allocationFailure){*out=nullptr;return 12;}
 *out=new mbuf{std::vector<uint8_t>(size),size};++allocations;return 0;
}
static void mbuf_setlen(mbuf_t m,size_t len){assert(len<=m->data.size());m->len=len;}
static void mbuf_pkthdr_setlen(mbuf_t m,size_t len){assert(len==m->len);}
static void mbuf_freem(mbuf_t m){delete m;++frees;}
struct Result {std::vector<uint8_t> frame;bool profile;IEEE80211Mbssid::Profile metadata;};
static std::vector<Result>results;
static void ieee80211_recv_probe_resp_bss(ieee80211com*,mbuf_t m,ieee80211_node*,
 ieee80211_rxinfo*rxi,int isprobe,const IEEE80211Mbssid::Profile*p){
 assert(rxi->channel==5&&rxi->band==6&&isprobe==0);
 Result r{{m->data.begin(),m->data.begin()+m->len},p!=nullptr,{}};
 if(p)r.metadata=*p;results.push_back(r);
}
'''
code += wrapper + '\n#include "tests/wcl_mbssid.cpp"\n'
code += r'''
void rxTests(){
 ieee80211com ic;ieee80211_node ni;ieee80211_rxinfo rxi;
 auto receive=[&](const Bytes&ies){
  mbuf m{Bytes(36),36};m.data.insert(m.data.end(),ies.begin(),ies.end());m.len=m.data.size();
  auto*wh=mtod(&m,ieee80211_frame*);memcpy(wh->i_addr2,transmitted,6);memcpy(wh->i_addr3,transmitted,6);
  m.data[34]=1;results.clear();ieee80211_recv_probe_resp(&ic,&m,&ni,&rxi,0);
 };
 Bytes ies={0,0};element(ies,1,{0x8c,0x98,0xb0});Bytes extra;element(extra,48,owe);
 addSet(ies,3,profile("1Joey_6",1,extra));receive(ies);
 assert(results.size()==2&&results[0].profile&&!results[1].profile);
 auto&child=results[0];auto*wh=(const ieee80211_frame*)child.frame.data();
 assert(wh->i_addr2[5]==0x3b&&wh->i_addr3[5]==0x3b&&child.frame[34]==0x11&&child.frame[35]==0x11);
 assert(memcmp(child.metadata.transmitted,transmitted,6)==0&&child.metadata.index==1&&child.metadata.indicator==3);
 Bytes merged(child.frame.begin()+36,child.frame.end());
 assert(memcmp(find(merged,0)+2,"1Joey_6",7)==0&&find(merged,1));
 assert(AirportWCL::rsnIsOWE(find(merged,48),owe.size()+2));
 assert(!find(merged,71)&&allocations==1&&frees==1);
 // This is the downstream parser boundary: child frame and parent have distinct identities.
 // Both use the original RX channel/RSSI/timestamp object and normal BSS parsing.
 ies={0,0};for(uint8_t i=1;i<=12;++i)addSet(ies,4,profile("test",i));
 receive(ies);assert(results.size()==13&&allocations==2&&frees==2);
 allocationFailure=true;receive(ies);assert(results.size()==1&&!results[0].profile);allocationFailure=false;
 Bytes malformed;Bytes bad; element(bad,255,{56,2,48});addSet(malformed,3,profile("bad",1,bad));
 receive(malformed);assert(results.size()==1&&!results[0].profile&&allocations==3&&frees==3);
 for(size_t len=0;len<36;len++){
  mbuf m{Bytes(len),len};results.clear();ieee80211_recv_probe_resp(&ic,&m,&ni,&rxi,0);
  assert(results.size()==1&&!results[0].profile);
 }
 std::puts("PASS MBSSID RX: production wrapper emits named child frames before hidden parent, correct BSSID/security/capability and original RX metadata, all profiles, allocation failure");
}
'''
(out/'mbssid-test.cpp').write_text(code,encoding='utf-8')
if os.name == 'nt':
    vswhere=Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio/Installer/vswhere.exe'
    vs=subprocess.check_output([str(vswhere),'-latest','-products','*','-requires',
        'Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],text=True).strip()
    vcvars=Path(vs)/'VC/Auxiliary/Build/vcvars64.bat'
    cmd=out/'run.cmd'
    cmd.write_text('@echo off\ncall "'+str(vcvars)+'" >nul\n'
        'cl /nologo /std:c++17 /EHsc /W3 /Od /Zi /fsanitize=address /I"'+str(root)+'" /Fe:mbssid-test.exe mbssid-test.cpp\n'
        'if errorlevel 1 exit /b %errorlevel%\nmbssid-test.exe\n'
        'if errorlevel 1 exit /b %errorlevel%\n'
        'cl /nologo /std:c++17 /EHsc /W3 /Od /Zi /fsanitize=address /D__IO80211_TARGET=150200 /D__MAC_15_2=150200 /I"'+str(root)+'" /Fe:mbssid-sequoia-test.exe mbssid-test.cpp\n'
        'if errorlevel 1 exit /b %errorlevel%\nmbssid-sequoia-test.exe\n',encoding='utf-8')
    result=subprocess.run(['cmd.exe','/d','/c',str(cmd)],cwd=out,capture_output=True)
else:
    cxx=os.environ.get('CXX') or shutil.which('clang++') or shutil.which('g++')
    subprocess.run([cxx,'-std=c++17','-g','-fsanitize=address,undefined',
        '-I'+str(root),str(out/'mbssid-test.cpp'),'-o',str(out/'mbssid-test')],check=True)
    result=subprocess.run([str(out/'mbssid-test')],cwd=out,capture_output=True)
log=(result.stdout+result.stderr).decode('mbcs' if os.name=='nt' else 'utf-8',errors='replace')
(out/'mbssid-test.log').write_text(log,encoding='utf-8')
print(log)
raise SystemExit(result.returncode)