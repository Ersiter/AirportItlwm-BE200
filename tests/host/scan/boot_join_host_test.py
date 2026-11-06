"""Execute accepted join preservation across STOPPED and READY."""
import os,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[3]
source=(root/'AirportItlwm/WCL/WCL.cpp').read_text(encoding='utf-8')
a=source.index('            if (!ready) {',source.index('case IEEE80211_EVT_DRIVER_STOPPED:'))
b=source.index('            // An address application',a)
stopped=source[a:b]
def function(name):
 a=source.index('void AirportItlwmSkywalkInterface::'+name+'(')
 return source[a:source.index('\n}',a)+2]
code=r"""
#include <cassert>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#ifdef _WIN32
#define __attribute__(x)
#pragma pack(push, 1)
#endif
#include "AirportItlwm/WCL/WCL.hpp"
#ifdef _WIN32
#pragma pack(pop)
#endif
using IOReturn=int;
constexpr int IFF_UP=1,kIOReturnOffline=2,kIOReturnAborted=3,kIOReturnSuccess=0;
static void explicit_bzero(void*p,size_t n){memset(p,0,n);}
struct Timer{unsigned cancels=0;void cancelTimeout(){++cancels;}};
struct IC{struct{unsigned if_flags=IFF_UP;}ic_if;bool ic_wcl_mac_reconfig=false,ic_wcl_join_requested=false,ic_wcl_peer_is_mlo=false,ic_wcl_enterprise=false;uint8_t ic_wcl_peer_mld_addr[6]{},ic_psk[32]{};};
using ieee80211com=IC;
#define bzero(p,n) memset(p,0,n)
struct Hal{IC ic;IC*get80211Controller(){return &ic;}};
struct Pci{void setProperty(const char*,const char*){}};
struct Instance{Pci pci,*pciNub=&pci;unsigned events=0;void postMessage(void*,unsigned,const void*,size_t,bool){++events;}};
class AirportItlwmSkywalkInterface{public:
 bool joinPending=true,joinDeferred=true,wclStopping=false,portAuthorized=false;
 AirportWCL::JoinRequest deferredJoin{};uint8_t joinBSSID[6]{};
 Timer timer,*joinTimer=&timer;Hal hal,*fHalService=&hal;Instance inst,*instance=&inst;
 unsigned joins=0;IOReturn startWCLJoin(AirportWCL::JoinRequest&){++joins;return 0;}
 void purgeWCLUserEapol(){}void updateWCLLinkQuality(bool){}void clearWCLPMKSA(){}
 void clearWCLSAE(IC*){}void clearWCLDerivedCredential(){}void publishWCLAuthDiagnostic(const char*){}
 void finishWCLScan(IOReturn){}void finishWCLJoin(uint16_t,uint16_t,IOReturn);void resumeWCLJoin();
 void stopped(){bool ready=false;auto ic=&hal.ic;STOPPED}
};
FUNCTIONS
int main(){
 AirportItlwmSkywalkInterface d;d.deferredJoin.key[0]=42;
 d.stopped();assert(d.joinPending&&d.joinDeferred&&d.deferredJoin.key[0]==42&&d.inst.events==0);
 d.resumeWCLJoin();assert(d.joins==1&&!d.joinDeferred&&!d.joinPending&&d.deferredJoin.key[0]==0);
 d.resumeWCLJoin();assert(d.joins==1);
 AirportItlwmSkywalkInterface off;off.hal.ic.ic_if.if_flags=0;off.stopped();assert(!off.joinPending&&!off.joinDeferred&&off.inst.events==1);
 AirportItlwmSkywalkInterface active;active.joinDeferred=false;active.stopped();assert(!active.joinPending&&active.inst.events==1);
 AirportItlwmSkywalkInterface timeout;timeout.finishWCLJoin(1,1004,2);timeout.resumeWCLJoin();assert(timeout.joins==0&&!timeout.joinDeferred);
}
""".replace('STOPPED',stopped).replace('FUNCTIONS',function('resumeWCLJoin')+'\n'+function('finishWCLJoin'))
with tempfile.TemporaryDirectory(prefix='itlwm-boot-join-', ignore_cleanup_errors=os.name == 'nt') as folder:
 out=Path(folder);(out/'test.cpp').write_text(code,encoding='utf-8')
 if os.name=='nt':
  vswhere=Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio/Installer/vswhere.exe'
  vs=subprocess.check_output([str(vswhere),'-latest','-products','*','-requires','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],text=True).strip()
  command='@echo off\ncall "'+str(Path(vs)/'VC/Auxiliary/Build/vcvars64.bat')+'" >nul\ncl /nologo /std:c++17 /EHsc /fsanitize=address /I"'+str(root)+'" test.cpp /Fe:test.exe\nif errorlevel 1 exit /b %errorlevel%\ntest.exe\n'
  (out/'run.cmd').write_text(command,encoding='utf-8')
  subprocess.run(['cmd','/d','/c',str(out/'run.cmd')],cwd=out,check=True)
 else:
  subprocess.run(['c++','-std=c++17','-fsanitize=address,undefined','-I'+str(root),str(out/'test.cpp'),'-o',str(out/'test')],check=True)
  subprocess.run([str(out/'test')],check=True)
print('PASS boot join: STOPPED retains accepted deferred request; READY resumes once; power-off, active failure and timeout still cancel')
