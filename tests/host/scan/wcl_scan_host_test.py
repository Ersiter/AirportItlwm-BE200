"""Exercise production WCL scan replacement, BSS caching and completion ordering."""
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
temporary = tempfile.TemporaryDirectory(prefix='itlwm-wcl-scan-') if args.output is None else None
out = args.output.resolve() if args.output else Path(temporary.name)
out.mkdir(parents=True, exist_ok=True)
wcl = (repo/'AirportItlwm/WCL/WCL.cpp').read_text(encoding='utf-8')
iwx = (repo/'itlwm/hal_iwx/ItlIwx.cpp').read_text(encoding='utf-8')
net = (repo/'itl80211/openbsd/net80211/ieee80211.c').read_text(encoding='utf-8')
header = (repo/'AirportItlwm/AirportItlwmSkywalkInterface.hpp').read_text(encoding='utf-8')

def function(text, signature):
    start = text.index(signature)
    return text[start:text.index('\n}', start) + 2] + '\n'

code = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <algorithm>
#ifdef _WIN32
#define __attribute__(x)
#pragma pack(push,1)
#endif
#include "AirportItlwm/WCL/WCL.hpp"
#ifdef _WIN32
#pragma pack(pop)
#endif
using IOReturn=int;
constexpr int kIOReturnSuccess=0,kIOReturnAborted=1,kIOReturnNotReady=2,
 kIOReturnBusy=3,kIOReturnUnsupported=4,kIOReturnError=5,kIOReturnTimeout=6;
constexpr unsigned WCL_SCAN_TIMEOUT_MS=20000;
#define AIRPORT_WCL 1
#define IEEE80211_CHAN_MAX 255
#define IEEE80211_S_INIT 0
#define IEEE80211_S_SCAN 1
#define IEEE80211_S_AUTH 2
#define IEEE80211_S_ASSOC 3
#define IEEE80211_S_RUN 4
#define IEEE80211_F_BGSCAN 1U
#define IEEE80211_F_DISABLE_BG_AUTO_CONNECT 2U
#define IEEE80211_F_RSNON 4U
#define IFF_RUNNING 1U
#define IFF_UP 2U
#define IWX_FLAG_SCANNING 1U
#define IWX_FLAG_BGSCAN 2U
#define IEEE80211_EVT_SCAN_DONE 7
#define APPLE80211_M_SCAN_DONE 10
#define IWM_MIN_DBM -100
#define DPRINTF(x) ((void)0)
#define nitems(x) (sizeof(x)/sizeof((x)[0]))
#define isset(a,i) ((a)[(i)/8]&(1U<<((i)%8)))
#define setbit(a,i) ((a)[(i)/8]|=uint8_t(1U<<((i)%8)))
#define IEEE80211_IS_CHAN_6GHZ(c) ((c)->six)
#define IEEE80211_ADDR_EQ(a,b) (memcmp(a,b,6)==0)
#define bzero(a,n) memset(a,0,n)
struct _ifnet{unsigned if_flags=IFF_RUNNING|IFF_UP;};
struct ieee80211_channel{unsigned ic_freq=0,number=0;bool six=false;};
struct ieee80211_node{int ni_rssi=60;unsigned ni_intval=100;bool ni_port_valid=true;};
struct ieee80211com{
 _ifnet ic_if;unsigned ic_state=IEEE80211_S_RUN,ic_flags=0;int ic_mgt_timer=0;
 ieee80211_channel ic_channels[256]{};
uint8_t ic_chan_active[32]{};
 bool ic_wcl_scan_requested=false,ic_wcl_scan_restart=false,ic_wcl_scan_active=false,ic_wcl_scan_restart_supported=true;
 bool ic_wcl_scan_restricted=false;uint8_t ic_wcl_scan_ssid_length=0,ic_wcl_scan_ssid[32]{};
 uint8_t ic_wcl_scan_channels[32]{},ic_wcl_scan_channels6GHz[32]{},ic_wcl_scan_rnr_count=0;
 long ic_last_cache_scan_ts=0;ieee80211_node peer,*ic_bss=&peer;
 int(*ic_bgscan_start)(ieee80211com*)=nullptr;
 int(*ic_newstate)(ieee80211com*,int,int)=nullptr;
};
static void ieee80211_seed_scan_rnr(ieee80211com*ic){ic->ic_wcl_scan_rnr_count=0;}
static unsigned ieee80211_chan2number(ieee80211com*,const ieee80211_channel*c){return c->number;}
struct fake_timeval{long tv_sec,tv_usec;};
#define timeval fake_timeval
static void microtime(timeval*t){t->tv_sec=100;t->tv_usec=0;}
static void ieee80211_free_allnodes(ieee80211com*,int){}
struct OSNumber{unsigned value=0;unsigned unsigned32BitValue(){return value;}};
#define OSDynamicCast(t,p) static_cast<t*>(p)
struct Pci{
 std::map<std::string,OSNumber> numbers;
 void*getProperty(const char*k){auto i=numbers.find(k);return i==numbers.end()?nullptr:&i->second;}
 void setProperty(const char*k,uint64_t n,int){numbers[k].value=unsigned(n);}
 void setProperty(const char*,const char*){}
 void setProperty(const char*,const void*,size_t){}
};
static std::map<void*,size_t> allocations;
static bool fail_allocation=false;
static void*IOMalloc(size_t n){if(fail_allocation)return nullptr;void*p=std::malloc(n);assert(p);allocations[p]=n;return p;}
static void IOFree(void*p,size_t n){assert(allocations.at(p)==n);allocations.erase(p);std::free(p);}
struct Timer{unsigned timeout=0;void cancelTimeout(){timeout=0;}void setTimeoutMS(unsigned t){timeout=t;}};
struct Hal{ieee80211com ic;ieee80211com*get80211Controller(){return &ic;}};
static unsigned clock_ms=0;
struct Message{unsigned kind,time;std::vector<uint8_t>bytes;};
struct Instance{
 Pci pci,*pciNub=&pci;std::vector<Message>messages;
 IOReturn postMessage(void*,unsigned kind,const void*p,size_t n,bool){messages.push_back({kind,clock_ms,{static_cast<const uint8_t*>(p),static_cast<const uint8_t*>(p)+n}});return 0;}
};
void ieee80211_begin_cache_bgscan(_ifnet*);
class AirportItlwmSkywalkInterface{public:
 Hal hal,*fHalService=&hal;Instance inst,*instance=&inst;Timer timer,*scanSource=&timer;
 bool scanPending=false,scanCompleted=false,scanDeferred=false,joinPending=false,wclStopping=false;
 AirportWCL::ScanRequest deferredScan{};
 uint8_t wclBssInfo[sizeof(AirportWCL::BeaconMetadata)+0x800]{};
 bool assocNotified=false,wclBssValid=false;uint8_t joinBSSID[6]{};
 unsigned wclScanDoneCount=0,wcl6GHzPublished=0;
 IOReturn postMessage(unsigned kind,const void*p,size_t n,bool b){return inst.postMessage(this,kind,p,n,b);}
 STRUCT_MEMBERS
 IOReturn startWCLScan(const AirportWCL::ScanRequest&);
 void finishWCLScan(IOReturn);
 void completeWCLScan();
 void keepWCLScanResult(const AirportWCL::BeaconMetadata*,size_t);
 void clearWCLScanResults();
 void postWCLScanResult(const ieee80211_node*,const uint8_t*,const uint8_t*,size_t,uint16_t,unsigned,bool,const uint8_t*,size_t,uint16_t);
 void scanDone(){auto ic=&hal.ic;switch(IEEE80211_EVT_SCAN_DONE){DONE_CASE default:break;}}
};
struct iwx_softc{ieee80211com sc_ic;unsigned sc_flags=0;int sc_generation=0;bool sc_scan_active=false,sc_scan_batch_pending=false,sc_use_mld_api=false;void*sc_nswq=nullptr;int sc_scan_task=0;};
static AirportItlwmSkywalkInterface*active=nullptr;
class ItlIwx{public:
 unsigned aborts=0,sends=0;bool fail_abort=false;
 int iwx_scan_abort(iwx_softc*s){++aborts;assert(s->sc_ic.ic_wcl_scan_restart);active->scanDone();assert(!active->scanCompleted);if(fail_abort)return 16;s->sc_flags=0;s->sc_ic.ic_flags&=~(IEEE80211_F_BGSCAN|IEEE80211_F_DISABLE_BG_AUTO_CONNECT);return 0;}
 int iwx_umac_scan(iwx_softc*,int);
};
int ItlIwx::iwx_umac_scan(iwx_softc*sc,int){
SCAN_ENTRY
 ++sends;return 0;}
static ItlIwx driver;
static unsigned old_channels=0;
static int submit_scan(ieee80211com*ic){
 iwx_softc transport;transport.sc_ic=*ic;
 transport.sc_flags=old_channels?IWX_FLAG_BGSCAN:0;
 int error=driver.iwx_umac_scan(&transport,1);
 ic->ic_wcl_scan_restart=transport.sc_ic.ic_wcl_scan_restart;
 ic->ic_flags=transport.sc_ic.ic_flags;
 if(!error){ic->ic_flags&=~IEEE80211_F_BGSCAN;old_channels=0;}
 return error;
}
'''
start = header.index('    struct WCLScanResultCopy {')
end = header.index('    bool wclBssValid;', start)
code = code.replace('STRUCT_MEMBERS', header[start:end])
start = wcl.index('        case IEEE80211_EVT_SCAN_DONE:')
end = wcl.index('        case IEEE80211_EVT_STA_ASSOC_DONE:', start)
code = code.replace('DONE_CASE', wcl[start:end])
start = iwx.index('iwx_umac_scan(struct iwx_softc *sc, int bgscan)\n{')
start = iwx.index('\n', iwx.index('{', start)) + 1
end = iwx.index('    if (iwx_lookup_cmd_ver', start)
code = code.replace('SCAN_ENTRY', iwx[start:end])
code += function(net, 'void\nieee80211_begin_cache_bgscan(')
for name in ['startWCLScan', 'finishWCLScan', 'keepWCLScanResult', 'clearWCLScanResults', 'completeWCLScan', 'postWCLScanResult']:
    return_type = 'IOReturn' if name == 'startWCLScan' else 'void'
    code += function(wcl, return_type+' AirportItlwmSkywalkInterface::'+name+'(')
code += r'''
#include <cerrno>
#define XYLog(...) ((void)0)
#define IWX_FLAG_SCAN_ABORTING 4U
#define IWX_FLAG_SHUTDOWN 8U
#define IWX_LONG_GROUP 1
#define IWX_SCAN_ABORT_UMAC 2
#define IWX_WIDE_ID(a,b) ((a)*256+(b))
#define IWX_UMAC_SCAN_ABORT_STATUS_NOT_FOUND 1U
#define IWX_SCAN_OFFLOAD_COMPLETED 1
#define THREAD_UNINT 0
#define THREAD_AWAKENED 0
#define THREAD_TIMED_OUT 1
#define kSecondScale 1
using AbsoluteTime=uint64_t;
static void clock_interval_to_deadline(int,int,uint64_t*p){*p=1000;}
struct iwx_umac_scan_abort{uint32_t uid;};
struct iwx_host_cmd{int id;size_t len[1];const void*data[1];unsigned flags;};
static void iwx_del_task(iwx_softc*,void*,int*){}
static void iwx_scan_state_reset(iwx_softc*s){s->sc_scan_active=s->sc_scan_batch_pending=false;}
class AbortDriver{public:
 iwx_softc*current=nullptr;unsigned sent=0,sleeps=0,mode=0,reply=0;int command_error=0;
 struct Gate{
  AbortDriver*d;
  int commandSleep(unsigned*f,AbsoluteTime,int){
   ++d->sleeps;
   if(d->mode==1)return THREAD_TIMED_OUT;
   if(d->mode==2)return 2;
   if(d->mode==3){++d->current->sc_generation;return THREAD_AWAKENED;}
   *f&=~(IWX_FLAG_SCANNING|IWX_FLAG_BGSCAN);return THREAD_AWAKENED;
  }
 }gate{this};
 Gate*getMainCommandGate(){return &gate;}
 int iwx_send_cmd_status(iwx_softc*,iwx_host_cmd*,uint32_t*s){++sent;*s=reply;return command_error;}
 int iwx_umac_scan_abort(iwx_softc*){++sent;return command_error;}
 void iwx_endscan(iwx_softc*s,int,bool){s->sc_flags&=~(IWX_FLAG_SCANNING|IWX_FLAG_BGSCAN);}
 int iwx_scan_abort(iwx_softc*);
};
'''
code += function(iwx, 'int ItlIwx::\niwx_scan_abort(').replace('ItlIwx::', 'AbortDriver::', 1)
code += r'''
static void abort_tests(){
 for(bool mld:{false,true})for(unsigned reply:{0U,1U}){
  iwx_softc sc;sc.sc_flags=IWX_FLAG_BGSCAN;sc.sc_use_mld_api=mld;
  AbortDriver d;d.current=&sc;d.reply=reply;
  assert(d.iwx_scan_abort(&sc)==0&&d.sent==1&&d.sleeps==1&&sc.sc_flags==0);
 }
 for(unsigned mode:{1U,2U,3U}){
  iwx_softc sc;sc.sc_flags=IWX_FLAG_SCANNING;sc.sc_use_mld_api=true;
  AbortDriver d;d.current=&sc;d.mode=mode;
  assert(d.iwx_scan_abort(&sc)==(mode==1?EWOULDBLOCK:mode==2?EINTR:ENXIO));
  if(mode==3)assert(sc.sc_flags&IWX_FLAG_SCAN_ABORTING);
 }
 iwx_softc sc;sc.sc_flags=IWX_FLAG_SCANNING;sc.sc_scan_active=true;
 AbortDriver d;d.current=&sc;assert(d.iwx_scan_abort(&sc)==0&&d.sent==0&&d.sleeps==0);
 sc.sc_flags=IWX_FLAG_SCANNING;sc.sc_use_mld_api=true;d.reply=2;
 assert(d.iwx_scan_abort(&sc)==EIO&&d.sleeps==0);
 puts("PASS scan abort: legacy/MLD terminal wait, NOT_FOUND, timeout/interruption, reset generation and unsent batch");
}
'''

code += r'''
static void channels(AirportItlwmSkywalkInterface&s){
 auto&ic=s.hal.ic;ic.ic_channels[5]={2432,5,false};setbit(ic.ic_chan_active,5);
 ic.ic_channels[200]={6215,53,true};setbit(ic.ic_chan_active,200);
 ic.ic_bgscan_start=submit_scan;
 ic.ic_newstate=[](ieee80211com*ic,int state,int){ic->ic_state=state;return submit_scan(ic);};
}
static void result(AirportItlwmSkywalkInterface&s,uint8_t id,unsigned ch,bool six,uint8_t payload){
 uint8_t bssid[6]{2,0,0,0,0,id},ssid[3]{'n','e','t'},ie[3]{0,1,payload};ieee80211_node node;
 s.postWCLScanResult(&node,bssid,ssid,3,AirportWCL::channelSpec20(ch,six?AirportWCL::ChannelBand::GHz6:AirportWCL::ChannelBand::GHz2),ch,six,ie,sizeof(ie),0);
}
static void cache_tests(){
 AirportItlwmSkywalkInterface s;active=&s;channels(s);AirportWCL::ScanRequest request{};
 assert(s.startWCLScan(request)==0);result(s,1,5,false,1);result(s,1,5,true,2);result(s,1,5,true,9);
 assert(s.wclScanResultCount==2);clock_ms=15000;s.inst.messages.clear();s.scanDone();assert(s.scanCompleted);s.completeWCLScan();
 assert(!s.scanPending&&s.wclScanResultCount==0&&allocations.empty());
 assert(s.inst.messages.size()==4&&s.inst.messages[0].kind==AirportWCL::ScanResult&&s.inst.messages[1].kind==AirportWCL::ScanResult);
 assert(s.inst.messages[0].time==15000&&s.inst.messages[1].bytes.back()==9&&s.inst.messages[2].kind==AirportWCL::ScanDone);
 assert(s.startWCLScan(request)==0);result(s,2,5,false,7);s.inst.messages.clear();s.finishWCLScan(kIOReturnAborted);
 assert(s.inst.messages.size()==2&&s.inst.messages[0].kind==AirportWCL::ScanDone&&allocations.empty());
 request.channelCount=1;setbit(request.channels6GHz,53);assert(s.startWCLScan(request)==0);
 result(s,3,5,false,1);assert(s.wclScanResultCount==0);result(s,3,53,true,2);assert(s.wclScanResultCount==1);
 s.finishWCLScan(kIOReturnAborted);assert(allocations.empty());
 assert(s.startWCLScan(AirportWCL::ScanRequest{})==0);
 result(s,4,5,false,1);fail_allocation=true;result(s,4,53,true,2);fail_allocation=false;assert(s.wclScanResultCount==1);
 for(unsigned i=5;i<110;i++)result(s,uint8_t(i),53,true,3);
 assert(s.wclScanResultCount==s.kWCLScanResultCopies);s.finishWCLScan(kIOReturnAborted);assert(allocations.empty());
 puts("PASS WCL cache: newest BSS payload, completion ordering/freshness, channel filtering, abort cleanup, allocation failure and capacity");
}
static void lifecycle_tests(){
 AirportItlwmSkywalkInterface s;active=&s;channels(s);AirportWCL::ScanRequest a{},b{};
 a.channelCount=b.channelCount=1;setbit(a.channels,5);setbit(b.channels6GHz,53);
 assert(s.startWCLScan(a)==0);old_channels=1;unsigned before=driver.aborts;
 clock_ms=12000;assert(s.startWCLScan(b)==0);assert(driver.aborts==before+1&&!s.scanCompleted);
 assert(!s.hal.ic.ic_wcl_scan_restart&&isset(s.hal.ic.ic_wcl_scan_channels6GHz,53)&&!isset(s.hal.ic.ic_wcl_scan_channels,5));
 assert((s.hal.ic.ic_flags&(IEEE80211_F_BGSCAN|IEEE80211_F_DISABLE_BG_AUTO_CONNECT))==(IEEE80211_F_BGSCAN|IEEE80211_F_DISABLE_BG_AUTO_CONNECT));
 assert(s.timer.timeout==20000);s.finishWCLScan(kIOReturnAborted);
 s.hal.ic.ic_if.if_flags=IFF_UP;assert(s.startWCLScan(a)==0&&s.scanPending&&s.scanDeferred);
 assert(s.timer.timeout==20000);s.completeWCLScan();assert(!s.scanPending&&!s.scanDeferred);
 iwx_softc transport;transport.sc_flags=IWX_FLAG_SCANNING;transport.sc_ic.ic_wcl_scan_restart=true;
 driver.fail_abort=true;unsigned sent=driver.sends;assert(driver.iwx_umac_scan(&transport,0)!=0&&driver.sends==sent&&transport.sc_ic.ic_wcl_scan_restart);
 driver.fail_abort=false;
 puts("PASS WCL lifecycle: replacement requests restart old scan, late completion ignored, deferred deadline and abort failure propagation");
}
int main(){cache_tests();lifecycle_tests();abort_tests();assert(allocations.empty());}
'''
(out/'wcl-scan-test.cpp').write_text(code, encoding='utf-8')
if os.name == 'nt':
    vswhere = Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio/Installer/vswhere.exe'
    vs = subprocess.check_output([str(vswhere), '-latest', '-products', '*', '-requires',
        'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'], text=True).strip()
    cmd = out/'run.cmd'
    cmd.write_text('@echo off\ncall "'+str(Path(vs)/'VC/Auxiliary/Build/vcvars64.bat')+'" >nul\n'
        'cl /nologo /std:c++20 /EHsc /W3 /Od /Zi /fsanitize=address /I"'+str(repo)+'" /Fe:wcl-scan-test.exe wcl-scan-test.cpp\n'
        'if errorlevel 1 exit /b %errorlevel%\nwcl-scan-test.exe\n', encoding='utf-8')
    result = subprocess.run(['cmd.exe', '/d', '/c', str(cmd)], cwd=out, capture_output=True)
else:
    cxx = os.environ.get('CXX') or shutil.which('clang++') or shutil.which('g++')
    subprocess.run([cxx, '-std=c++17', '-g', '-fsanitize=address,undefined', '-I'+str(repo),
        str(out/'wcl-scan-test.cpp'), '-o', str(out/'wcl-scan-test')], check=True)
    result = subprocess.run([str(out/'wcl-scan-test')], cwd=out, capture_output=True)
log = (result.stdout+result.stderr).decode('mbcs' if os.name == 'nt' else 'utf-8', errors='replace')
(out/'wcl-scan-test.log').write_text(log, encoding='utf-8')
print(log)
raise SystemExit(result.returncode)
