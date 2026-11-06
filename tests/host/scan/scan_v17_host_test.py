"""Execute production scan-v17 channel plans and wire requests."""
import os,re,shlex,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[3]
if not (root/'itlwm').is_dir():
    root=Path(os.environ['ITLWM_TEST_REPO'])
iwx=root/'itlwm/hal_iwx'
source=(iwx/'ItlIwxApi86.cpp').read_text(encoding='utf-8')
reg=(iwx/'if_iwxreg.h').read_text(encoding='utf-8')
api=(iwx/'if_iwxapi86.h').read_text(encoding='utf-8')
def declaration(name):
    start=reg.index('struct '+name+' {')
    return reg[start:reg.index('} __packed;',start)+11]+'\n'
def collect(name,done,parts):
    if name in done:return
    done.add(name);decl=declaration(name)
    for child in re.findall(r'struct (iwx_\w+)',decl)[1:]:collect(child,done,parts)
    parts.append(decl)
parts=[];done=set()
for name in ['iwx_scan_periodic_parms_v1','iwx_scan_probe_params_v4']:collect(name,done,parts)
start=source.index('int ItlIwx::\niwx_umac_scan_v17(')
function=source[start:source.index('\n}',start)+2]
constants='\n'.join(re.findall(r'^static constexpr[^\n]+;',source,re.M))
rx=(root/'itl80211/openbsd/net80211/ieee80211_input.c').read_text(encoding='utf-8')
start=rx.index('static void\nieee80211_collect_scan_rnr(')
rnr_functions=rx[start:rx.index('\n}',rx.index('void\nieee80211_seed_scan_rnr(',start))+2]

program=r"""
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <vector>
#define AIRPORT_WCL 1
#define __packed __attribute__((packed))
#define XYLog(...) ((void)0)
#define MIN(a,b) std::min<unsigned>((a),(b))
#define nitems(a) (sizeof(a)/sizeof(a[0]))
#define htole16(v) (v)
#define htole32(v) (v)
#define le16toh(v) (v)
#define le32toh(v) (v)
#define cpu_to_le16(v) (v)
#define isset(a,i) ((a)[(i)/8]&(1U<<((i)%8)))
#define setbit(a,i) ((a)[(i)/8]|=uint8_t(1U<<((i)%8)))
#define ETHER_ADDR_LEN 6
#define M_NOWAIT 1
#define M_WAITOK 2
#define M_ZERO 4
#define IWX_CMD_ASYNC 1U
using u8=uint8_t;using u_int8_t=uint8_t;
#include "AirportItlwm/WCL/WCL.hpp"
TYPES
#include "itlwm/hal_iwx/if_iwxapi86.h"
CONSTANTS
struct ieee80211_channel{unsigned ic_freq=0,ic_flags=0;uint8_t number=0;};
struct ieee80211_node {ieee80211_channel*ni_chan;uint8_t*ni_rsnie_tlv;size_t ni_rsnie_tlv_len;uint64_t ni_age_ts;};
struct ieee80211com {
    uint8_t ic_des_esslen=0,ic_des_essid[32]{},ic_des_bssid[6]{2};
    bool ic_wcl_scan_requested=true,ic_wcl_scan_active=false,ic_wcl_scan_restricted=true,ic_wcl_join_requested=false;
    uint32_t ic_wcl_scan_away_time_ms=0;
    uint8_t ic_wcl_scan_ssid_length=0,ic_wcl_scan_ssid[32]{};
    uint8_t ic_wcl_scan_channels[32]{},ic_wcl_scan_channels6GHz[32]{},ic_chan_active[32]{};
    uint8_t ic_wcl_scan_rnr_count=0,ic_wcl_scan_rnr_channel[8]{},ic_wcl_scan_rnr_bssid[8][6]{};
    uint32_t ic_wcl_scan_rnr_short_ssid[8]{};
    ieee80211_channel ic_channels[256]{};std::vector<ieee80211_node*>ic_tree;
};
struct properties {void setProperty(const char*,unsigned,unsigned){}void setProperty(const char*,const void*,size_t){}};
struct iwx_softc {
    ieee80211com sc_ic;properties pci,*sc_pcitag=&pci;
    int sc_scan_batch_sent=0,sc_scan_batch_pending=0,sc_scan_batch=0;
    unsigned sc_scan_unrestricted_fallback=0,sc_capa_n_scan_channels=67;
    uint16_t sc_scan_next_channel=1;
    uint8_t sc_ucode_api[32]{},sc_enabled_capa[32]{};
};
struct iwx_host_cmd {unsigned id,len[1];const void*data[1];unsigned flags;};
static uint8_t ieee80211_chan2number(ieee80211com*,ieee80211_channel*c){return c->number;}
static unsigned ieee80211_ieee2chanidx(ieee80211com*ic,unsigned channel,unsigned band){
    for(unsigned i=1;i<256;i++)if(ic->ic_channels[i].number==channel&&(ic->ic_channels[i].ic_flags&band))return i;
    return 0;
}
static uint64_t clock_ms=60000;
static uint64_t airport_up_time(){return clock_ms;}
#define RB_FOREACH(ni,tree,head) for(auto it=(head)->begin();it!=(head)->end()&&((ni=*it),true);++it)
RNR_FUNCTIONS
static unsigned iwx_cmd_id(unsigned c,unsigned g,unsigned v){return c|(g<<8)|(v<<16);}
static void*scan_alloc(size_t size,int,int){return std::calloc(1,size);}
class ItlIwx {public:
    std::vector<iwx_api86_scan_req>requests;
    int iwx_umac_scan_v17(iwx_softc*,int);
    int iwx_fill_probe_req(iwx_softc*,iwx_scan_probe_req*){return 0;}
    int iwx_send_cmd(iwx_softc*,iwx_host_cmd*cmd){
        assert(cmd->len[0]==sizeof(iwx_api86_scan_req));
        requests.push_back(*static_cast<const iwx_api86_scan_req*>(cmd->data[0]));return 0;
    }
};
#define malloc(size,type,flags) scan_alloc(size,type,flags)
FUNCTION
#undef malloc
static void populate(iwx_softc&s,bool legacy=false){
    auto&ic=s.sc_ic;
    for(unsigned n=0;n<59;n++){
        unsigned channel=1+n*4,index=196+n;
        ic.ic_channels[index]={5950+channel*5,IEEE80211_CHAN_6GHZ,uint8_t(channel)};
        setbit(ic.ic_chan_active,index);setbit(ic.ic_wcl_scan_channels6GHz,channel);
    }
    if(legacy){
        ic.ic_channels[1]={2412,IEEE80211_CHAN_2GHZ,1};setbit(ic.ic_chan_active,1);setbit(ic.ic_wcl_scan_channels,1);
        ic.ic_channels[36]={5180,IEEE80211_CHAN_5GHZ,36};setbit(ic.ic_chan_active,36);setbit(ic.ic_wcl_scan_channels,36);
    }
}
int main(){
    iwx_softc full;populate(full);ItlIwx driver;
    assert(driver.iwx_umac_scan_v17(&full,1)==0);
    auto&first=driver.requests.at(0).scan_params;
    assert(first.channel_params.count==59);
    assert(first.channel_params.channel_config[0].channel_num==1&&first.channel_params.channel_config[58].channel_num==233);
    assert(first.general_params.active_dwell[0]==10&&first.general_params.passive_dwell[1]==110);
    assert(first.general_params.max_out_of_time[0]==120&&first.general_params.suspend_time[0]==120);
    assert(full.sc_scan_next_channel>IEEE80211_CHAN_MAX);
    iwx_softc mixed;populate(mixed,true);ItlIwx combined;
    while(mixed.sc_scan_next_channel<=IEEE80211_CHAN_MAX)assert(combined.iwx_umac_scan_v17(&mixed,0)==0);
    assert(combined.requests.size()==2);
    assert(combined.requests[0].scan_params.channel_params.count==2&&combined.requests[1].scan_params.channel_params.count==59);
    iwx_softc limited;populate(limited);limited.sc_capa_n_scan_channels=6;ItlIwx chunks;unsigned total=0;
    while(limited.sc_scan_next_channel<=IEEE80211_CHAN_MAX)assert(chunks.iwx_umac_scan_v17(&limited,1)==0);
    for(auto&r:chunks.requests){assert(r.scan_params.channel_params.count<=6);total+=r.scan_params.channel_params.count;}
    assert(total==59&&chunks.requests.size()==10);
    iwx_softc active;populate(active);active.sc_ic.ic_wcl_scan_active=true;ItlIwx probes;
    assert(probes.iwx_umac_scan_v17(&active,1)==0);
    assert(probes.requests[0].scan_params.channel_params.count==15);
    iwx_softc cached;populate(cached,true);cached.sc_ic.ic_wcl_scan_active=true;
    std::vector<uint8_t>ies={0,3,'l','a','b',201,16,0,12,131,49,
        0,2,0,0,0,0,1,0x78,0x56,0x34,0x12,0x40};
    ieee80211_node recent{&cached.sc_ic.ic_channels[36],ies.data(),ies.size(),59000};
    cached.sc_ic.ic_tree={&recent};ieee80211_seed_scan_rnr(&cached.sc_ic);
    assert(cached.sc_ic.ic_wcl_scan_rnr_count==1&&cached.sc_ic.ic_wcl_scan_rnr_channel[0]==49);
    assert(cached.sc_ic.ic_wcl_scan_rnr_short_ssid[0]==0x12345678);
    ItlIwx known;
    while(cached.sc_scan_next_channel<=IEEE80211_CHAN_MAX)assert(known.iwx_umac_scan_v17(&cached,1)==0);
    assert(known.requests.size()==2&&known.requests.back().scan_params.channel_params.count==16);
    unsigned targets=0;
    for(unsigned i=0;i<known.requests.back().scan_params.channel_params.count;i++) {
        auto&target=known.requests.back().scan_params.channel_params.channel_config[i];
        assert(AirportWCL::is6GHzPsc(target.channel_num)||target.channel_num==49);
        if(target.channel_num==49){assert((target.flags&0x10001)==0x10001);targets++;}
    }
    assert(targets==1);
    clock_ms=90001;ieee80211_seed_scan_rnr(&cached.sc_ic);assert(cached.sc_ic.ic_wcl_scan_rnr_count==0);
    clock_ms=60000;recent.ni_rsnie_tlv_len=ies.size()-1;
    ieee80211_seed_scan_rnr(&cached.sc_ic);assert(cached.sc_ic.ic_wcl_scan_rnr_count==0);
    puts("PASS RNR cache: recent lower-band hints add only their non-PSC channels to active discovery; stale and truncated entries excluded");
    puts("PASS scan v17: passive full 6 GHz coverage, hardware channel capacity, two band phases, unchanged dwell/home timing and active PSC discovery");
}
""".replace('TYPES','\n'.join(parts)).replace('CONSTANTS',constants).replace('RNR_FUNCTIONS',rnr_functions).replace('FUNCTION',function)
definitions={}
for line in (reg+'\n'+'\n'.join((root/'itl80211/openbsd/net80211'/name).read_text(encoding='utf-8') for name in ['ieee80211.h','ieee80211_var.h','ieee80211_priv.h'])).replace('\\\n','').splitlines():
    match=re.match(r'#define\s+(\w+)',line)
    if match:definitions[match[1]]=line
    match=re.match(r'\s*([A-Z][A-Z0-9_]+)\s*=\s*([^,]+),',line)
    if match:definitions[match[1]]='#define '+match[1]+' '+match[2]
needed=set(re.findall(r'\b[A-Z][A-Z0-9_]+',program+api))
while True:
    more=set(re.findall(r'\b[A-Z][A-Z0-9_]+','\n'.join(definitions.get(n,'') for n in needed)))
    if more<=needed:break
    needed|=more
prefix='\n'.join(definitions[n] for n in sorted(needed) if n in definitions and n not in ['MIN','M_NOWAIT','M_WAITOK','M_ZERO'])
with tempfile.TemporaryDirectory(prefix='itlwm-scan-v17-') as tmp:
    source=Path(tmp)/'scan.cpp';binary=Path(tmp)/'scan-test'
    source.write_text(prefix+'\n'+program,encoding='utf-8')
    subprocess.run(shlex.split(os.environ.get('CXX','c++'))+['-std=c++17','-Wall','-Wextra','-Wno-unused-parameter','-Werror','-fsanitize=address,undefined','-I'+str(root),str(source),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
