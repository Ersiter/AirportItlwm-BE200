"""Exercise production HE/EHT state, MBSSID link commands and MCC policy."""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
net = root/'itl80211/openbsd/net80211'
iwx = root/'itlwm/hal_iwx'
headers = '\n'.join((net/name).read_text(encoding='utf-8') for name in
    ['ieee80211.h','ieee80211_var.h','ieee80211_node.h','ieee80211_crypto.h','ieee80211_priv.h','ieee80211_proto.h','ieee80211_ioctl.h'])
registers = (iwx/'if_iwxreg.h').read_text(encoding='utf-8')
mld_header = (iwx/'if_iwxmld.h').read_text(encoding='utf-8')
driver = (iwx/'ItlIwx.cpp').read_text(encoding='utf-8')
node = (net/'ieee80211_node.c').read_text(encoding='utf-8')
proto = (net/'ieee80211_proto.c').read_text(encoding='utf-8')
rx = (net/'ieee80211_input.c').read_text(encoding='utf-8')
mld = (iwx/'ItlIwxMld.cpp').read_text(encoding='utf-8')

def block(text, opening, declaration=False):
    start = text.index(opening)
    brace = text.index('{', start)
    depth = 1
    end = brace+1
    while depth:
        depth += (text[end]=='{')-(text[end]=='}')
        end += 1
    return text[start:text.index(';',end)+1] if declaration else text[start:end]

def function(text, name):
    match = re.search(r'(?m)^(?:static\s+)?(?:inline\s+)?[\w*]+(?: \w+::)?\n'+name+r'\(', text)
    assert match, name
    return block(text, match.group())

def macros_for(program):
    definitions = {}
    for line in (headers+'\n'+registers+'\n'+mld_header).replace('\\\n','').splitlines():
        match = re.match(r'#define\s+(\w+)',line)
        if match: definitions[match[1]]=line
    needed = set(re.findall(r'\b[A-Z][A-Z0-9_]+',program))
    while True:
        more = set(re.findall(r'\b[A-Z][A-Z0-9_]+', '\n'.join(definitions.get(n,'') for n in needed)))
        if more <= needed: break
        needed |= more
    return '\n'.join(definitions[n] for n in sorted(needed) if n in definitions)

node_header=(net/'ieee80211_node.h').read_text(encoding='utf-8')
flag_region=node_header[node_header.index('ni_flags;'):node_header.index('/* If not NULL, this function',node_header.index('ni_flags;'))]
flags = re.findall(r'^#define (IEEE80211_NODE_\w+)\s+(0x[0-9a-fA-F]+)\b',flag_region,re.M)
seen = {}
for name, value in flags:
    value = int(value,16)
    assert value not in seen, (name,seen.get(value),'node flag collision')
    seen[value]=name

prelude = r"""
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <string>
#include <vector>
#define __packed __attribute__((packed))
#define XYLog(...) ((void)0)
#define DPRINTFN(...) ((void)0)
#define nitems(a) (sizeof(a)/sizeof(a[0]))
#define BIT(n) (1U << (n))

#define le16toh(v) (v)
#define le32toh(v) (v)
#define htole16(v) (v)
#define htole32(v) (v)
#define hweight8(v) __builtin_popcount(unsigned(v))
#define DIV_ROUND_UP(v,d) (((v)+(d)-1)/(d))
#define KASSERT(v,m) assert(v)
using u_int=unsigned;using u_int8_t=uint8_t;using u_int16_t=uint16_t;
"""

types = '\n'.join(block(headers,'struct '+n+' {',True) for n in [
    'ieee80211_he_cap_elem','ieee80211_he_mcs_nss_supp','ieee80211_he_operation',
    'ieee80211_he_6ghz_oper','ieee80211_eht_cap_elem_fixed','ieee80211_eht_operation',
    'ieee80211_eht_operation_info'])
helpers = '\n'.join(function(headers,n) for n in ['ieee80211_he_mcs_nss_size',
    'ieee80211_he_ppe_size','ieee80211_he_oper_size','ieee80211_eht_mcs_nss_size',
    'ieee80211_eht_ppe_size','ieee80211_he_mcs_intersection'])
functions = '\n'.join(function(node,n) for n in ['ieee80211_setup_hecaps',
    'ieee80211_setup_heop','ieee80211_setup_he_6ghz_capa'])
functions += '\n'+function(rx,'ieee80211_update_eht_params')
functions += '\n'+function(proto,'ieee80211_he_supported')
functions += '\n'+function(proto,'ieee80211_he_negotiate')
functions += '\n'+function(mld,'iwx_mld_modify_link_fill')
functions += '\n'+block(driver,'static uint16_t rs_fw_he_ieee80211_mcs_to_rs_mcs(')
functions += '\n'+function(driver,'iwx_rs_fw_he_set_enabled_rates')
functions += '\n'+function(driver,'iwx_rs_fw_get_config_flags')
types += '\n'+block(registers,'struct iwx_ac_qos {',True)
types += '\n'+block(registers,'struct iwx_tlc_config_cmd_v4 {',True)
types += '\n'+block(mld_header,'struct iwx_mld_he_backoff_conf {',True)
types += '\n'+block(mld_header,'struct iwx_mld_link_config_cmd {',True)
program = r"""
struct ieee80211com;
struct ieee80211_channel {unsigned ic_flags=0;uint16_t ic_freq=0,ic_center_freq1=0,ic_center_freq2=0;uint8_t ic_reg_flags=0;};
struct ieee80211_node {
    ieee80211com*ni_ic=nullptr;ieee80211_channel*ni_chan=nullptr;
    uint32_t ni_flags=0,ni_he_oper_params=0,ni_rsnciphers=0,ni_he_txrate_kbps=0,ni_htcaps=0,ni_vhtcaps=0;
    uint16_t ni_he_oper_nss_set=0xffff,ni_he_6ghz_capa=0;
    ieee80211_he_cap_elem ni_he_cap_elem{};
    ieee80211_he_mcs_nss_supp ni_he_mcs_nss_supp{};
    uint8_t ni_ppe_thres[32]{},ni_he_optional[16]{},ni_he_mu_edca[13]{};
    bool ni_he_requested=false,ni_eht_requested=false;
    unsigned ni_he_tx_nss=0,ni_chw=IEEE80211_CHAN_WIDTH_20,ni_rx_nss=1;
    uint8_t ni_eht_oper_len=0,ni_eht_oper_width=0,ni_eht_ccfs0=0,ni_eht_ccfs1=0;
    uint16_t ni_eht_puncture=0,ni_eht_center_freq1=0;
    ieee80211_eht_cap_elem_fixed ni_eht_cap_elem{};
    uint8_t ni_eht_oper[16]{},ni_eht_mcs_nss[16]{},ni_eht_ppe_thres[32]{};
    size_t ni_eht_mcs_nss_len=0,ni_eht_ppe_len=0;
    uint16_t ni_htop1=0,ni_intval=100,ni_dtimperiod=1;
    uint8_t ni_mbssid_index=0,ni_mbssid_transmitted[6]{},ni_mld_link_id=0;
    bool ni_mld_valid=false;
};
struct ieee80211_edca_ac_params {int ac_ecwmin=4,ac_ecwmax=10,ac_aifsn=3,ac_txoplimit=0;};
struct ieee80211com {
    ieee80211_node*ic_bss=nullptr;unsigned ic_state=IEEE80211_S_SCAN;
    unsigned ic_flags=IEEE80211_F_HEON,ic_userflags=0,ic_modecaps=1U<<IEEE80211_MODE_11AX;
    ieee80211_he_cap_elem ic_he_cap_elem{};
    ieee80211_he_mcs_nss_supp ic_he_mcs_nss_supp{};
    ieee80211_edca_ac_params ic_edca_ac[4];
    unsigned ic_mld_link_count=0;struct {uint8_t local_addr[6]{};}ic_mld_links[2];
    uint8_t ic_myaddr[6]{2,1,2,3,4,5};
};
static int ieee80211_chan2number(ieee80211com*,ieee80211_channel*c){return(c->ic_freq-5950)/5;}
static int ieee80211_ieee2mhz(int ch,int){return 5950+5*ch;}
struct iwx_phy_ctxt {unsigned id=0;};
struct iwx_node {ieee80211_node in_ni;unsigned in_id=0;iwx_phy_ctxt*in_phyctxt=nullptr;};
struct iwx_softc {ieee80211com sc_ic;};
static unsigned iwx_num_of_ant(unsigned antennas){return __builtin_popcount(antennas);}
static unsigned iwx_fw_valid_tx_ant(iwx_softc*){return 3;}
static int iwx_mld_link_slot(ieee80211com*,ieee80211_node*){return 0;}
static void iwx_ack_rates(iwx_softc*,iwx_node*,int*c,int*o){*c=0;*o=0x15;}
class ItlIwx {public:void iwx_mld_modify_link_fill(iwx_softc*,iwx_node*,iwx_mld_link_config_cmd*,int,int);uint16_t iwx_rs_fw_get_config_flags(iwx_softc*,ieee80211_node*);};
FUNCTIONS
static void setup(iwx_softc&s,iwx_node&n,ieee80211_channel&c,iwx_phy_ctxt&phy){
    auto&ic=s.sc_ic;auto&ni=n.in_ni;ic.ic_bss=&ni;ni.ni_ic=&ic;ni.ni_chan=&c;n.in_phyctxt=&phy;
    c.ic_flags=IEEE80211_CHAN_6GHZ;c.ic_freq=6215;c.ic_center_freq1=c.ic_freq;
    ic.ic_he_cap_elem.phy_cap_info[0]=IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G|IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G;
    ic.ic_he_mcs_nss_supp={0xfffa,0xfffa,0xfffa,0xfffa,0xffff,0xffff};
    std::vector<uint8_t> cap(sizeof(ieee80211_he_cap_elem)+8);
    memcpy(cap.data(),&ic.ic_he_cap_elem,sizeof(ic.ic_he_cap_elem));
    memcpy(cap.data()+sizeof(ic.ic_he_cap_elem),&ic.ic_he_mcs_nss_supp,8);
    assert(ieee80211_setup_hecaps(&ni,cap.data(),cap.size()));
    uint8_t op[sizeof(ieee80211_he_operation)+sizeof(ieee80211_he_6ghz_oper)]{};
    uint32_t params=IEEE80211_HE_OPERATION_6GHZ_OP_INFO;uint16_t basic=0xfffc;
    memcpy(op,&params,4);memcpy(op+4,&basic,2);
    uint8_t oper[]={53,3,55,47,0};memcpy(op+6,oper,sizeof(oper));
    assert(ieee80211_setup_heop(&ni,op,sizeof(op)));
    ni.ni_flags|=IEEE80211_NODE_QOS;ni.ni_he_requested=true;
}
int main(){
    iwx_softc s;iwx_node n;ieee80211_channel c;iwx_phy_ctxt phy;setup(s,n,c,phy);
    auto&ni=n.in_ni;auto&ic=s.sc_ic;
    uint8_t he6[]={IEEE80211_ELEMID_EXTENSION,3,IEEE80211_ELEMID_EXT_HE_6GHZ_CAPA,0,0};
    assert(ieee80211_setup_he_6ghz_capa(&ni,he6,sizeof(he6)));
    ieee80211_update_eht_params(&ic,&ni,nullptr,nullptr);
    assert(ni.ni_flags&IEEE80211_NODE_HE6CAP);
    assert(!(ni.ni_flags&IEEE80211_NODE_EHTOP));
    assert(ieee80211_he_supported(&ic,&ni));
    for(unsigned width=0;width<4;++width){
        ni.ni_he_optional[1]=width;ni.ni_he_optional[2]=width?55:53;ni.ni_he_optional[3]=width==3?47:0;
        ieee80211_he_negotiate(&ic,&ni);
        assert(ni.ni_flags&IEEE80211_NODE_HE);
        const unsigned widths[]={IEEE80211_CHAN_WIDTH_20,IEEE80211_CHAN_WIDTH_40,IEEE80211_CHAN_WIDTH_80,IEEE80211_CHAN_WIDTH_160};
        assert(ni.ni_chw==widths[width]);
    }
    c.ic_reg_flags=IEEE80211_CHAN_NO_160MHZ;ieee80211_he_negotiate(&ic,&ni);
    assert(ni.ni_chw==IEEE80211_CHAN_WIDTH_80&&c.ic_center_freq1==6225);
    ni.ni_flags&=~IEEE80211_NODE_HE6CAP;ni.ni_flags|=IEEE80211_NODE_EHTOP;
    assert(!ieee80211_he_supported(&ic,&ni));
    ieee80211_setup_he_6ghz_capa(&ni,he6,sizeof(he6));
    uint8_t parent[]={2,0x11,0x22,0x33,0x44,0x50};memcpy(ni.ni_mbssid_transmitted,parent,6);ni.ni_mbssid_index=1;
    for(bool he:{false,true})for(int changes:{IWX_MLD_LINK_CONTEXT_MODIFY_ACTIVE,IWX_MLD_LINK_CONTEXT_MODIFY_HE_PARAMS}){
        if(he)ni.ni_flags|=IEEE80211_NODE_HE;else ni.ni_flags&=~IEEE80211_NODE_HE;
        iwx_mld_link_config_cmd cmd{};ItlIwx().iwx_mld_modify_link_fill(&s,&n,&cmd,changes,1);
        assert(memcmp(cmd.ref_bssid_addr,parent,6)==0&&cmd.bssid_index==1);
        assert(cmd.modify_mask==unsigned(changes));
    }
    static_assert(sizeof(iwx_mld_link_config_cmd)==208,"LINK v1 wire size");
    ic.ic_state=IEEE80211_S_RUN;ni.ni_eht_requested=true;ni.ni_flags|=IEEE80211_NODE_EHTCAP;
    uint8_t ehtop[]={IEEE80211_ELEMID_EXTENSION,9,IEEE80211_ELEMID_EXT_EHT_OPERATION,
        IEEE80211_EHT_OPER_INFO_PRESENT,0x22,0x22,0x22,0x22,IEEE80211_EHT_OPER_CHAN_WIDTH_320MHZ,31,63};
    ieee80211_update_eht_params(&ic,&ni,nullptr,ehtop);
    assert((ni.ni_flags&IEEE80211_NODE_EHTOP)&&ni.ni_eht_oper_len==8);
    ni.ni_eht_center_freq1=6265;ni.ni_eht_puncture=2;
    for(unsigned state:{IEEE80211_S_ASSOC,IEEE80211_S_RUN}){
        ic.ic_state=state;ieee80211_update_eht_params(&ic,&ni,nullptr,nullptr);
        assert(ni.ni_eht_oper_width==IEEE80211_EHT_OPER_CHAN_WIDTH_320MHZ);
        assert(ni.ni_eht_ccfs0==31&&ni.ni_eht_ccfs1==63&&ni.ni_eht_puncture==2&&ni.ni_eht_center_freq1==6265);
    }
    uint8_t shortop[]={IEEE80211_ELEMID_EXTENSION,1,IEEE80211_ELEMID_EXT_EHT_OPERATION};
    ieee80211_update_eht_params(&ic,&ni,nullptr,shortop);assert(ni.ni_eht_oper_len==8&&ni.ni_eht_puncture==2);
    ieee80211_update_eht_params(&ic,&ni,nullptr,ehtop);assert(ni.ni_eht_puncture==0);
    ic.ic_state=IEEE80211_S_SCAN;ieee80211_update_eht_params(&ic,&ni,nullptr,nullptr);
    assert(!(ni.ni_flags&IEEE80211_NODE_EHTOP)&&ni.ni_eht_oper_len==0);

    ni.ni_chw=IEEE80211_CHAN_WIDTH_160;ni.ni_rx_nss=2;
    ni.ni_he_cap_elem.phy_cap_info[1]|=IEEE80211_HE_PHY_CAP1_LDPC_CODING_IN_PAYLOAD;
    ieee80211_node secondary=ni;secondary.ni_chw=IEEE80211_CHAN_WIDTH_80;secondary.ni_rx_nss=1;
    secondary.ni_he_mcs_nss_supp.rx_mcs_80=0xfffc;
    iwx_tlc_config_cmd_v4 primary_rates{},secondary_rates{};
    iwx_rs_fw_he_set_enabled_rates(&s,&ni,&primary_rates);
    iwx_rs_fw_he_set_enabled_rates(&s,&secondary,&secondary_rates);
    ic.ic_state=IEEE80211_S_RUN;ni.ni_flags|=IEEE80211_NODE_HE;secondary.ni_flags|=IEEE80211_NODE_HE;
    secondary.ni_he_cap_elem.phy_cap_info[1]&=~IEEE80211_HE_PHY_CAP1_LDPC_CODING_IN_PAYLOAD;
    assert(ItlIwx().iwx_rs_fw_get_config_flags(&s,&ni)&IWX_TLC_MNG_CFG_FLAGS_LDPC_MSK);
    assert(!(ItlIwx().iwx_rs_fw_get_config_flags(&s,&secondary)&IWX_TLC_MNG_CFG_FLAGS_LDPC_MSK));
    assert(primary_rates.ht_rates[0][0]==0xfff&&primary_rates.ht_rates[1][1]==0xfff);
    assert(secondary_rates.ht_rates[0][0]==0xff&&secondary_rates.ht_rates[1][0]==0&&secondary_rates.ht_rates[0][1]==0);

    puts("PASS HE/EHT state: 6 GHz 20/40/80/160 MHz, regulatory narrowing, MBSSID LINK reference, retained live 320 MHz EHT operation and puncturing");
}
""".replace('FUNCTIONS',functions)
needed=set(re.findall(r'\b[A-Z][A-Z0-9_]+',types+helpers+program))
enums=[]
for match in re.finditer(r'(?m)^enum(?:\s+\w+)?\s*\{',headers+'\n'+mld_header+'\n'+registers):
    item=block((headers+'\n'+mld_header+'\n'+registers)[match.start():],match.group(),True)
    if needed.intersection(re.findall(r'\b[A-Z][A-Z0-9_]+',item)):
        enums.append(item)
enums='\n'.join(enums)
he_program=prelude+macros_for(types+helpers+program+enums)+'\n'+enums+'\n'+types+'\n'+helpers+'\n'+program

mcc_functions='\n'.join(function(driver,n) for n in ['iwx_valid_mcc','iwx_resolved_mcc','iwx_mcc_update','iwx_process_mcc_request'])
country = r"""
#define IC2IFP(ic) (&(ic)->ic_if)
#define DEVNAME(sc) "test"
#define IFF_RUNNING 0x40
#define IFF_DEBUG 0x4
struct _ifnet{unsigned if_flags=IFF_RUNNING;};
struct ieee80211com{_ifnet ic_if;unsigned ic_state=IEEE80211_S_SCAN;void(*ic_event_handler)(ieee80211com*,int,void*)=nullptr;};
struct iwx_softc {
    ieee80211com sc_ic;unsigned sc_flags=0;
    struct{bool lar_enabled=true;}sc_nvm;
    char sc_fw_mcc[3]="ZZ",sc_mcc_last[3]{},sc_mcc_override[3]{};
    uint16_t sc_fw_mcc_int=0;uint8_t sc_mcc_last_source=0;bool sc_mcc_last_valid=false;
};
struct Gate {bool inGate(){return true;}template<typename...T>int runAction(T...){std::abort();}};
using IOReturn=int;struct OSObject{};
class ItlIwx {public:
    std::string requested;unsigned source=0,requests=0;Gate gate;
    Gate*getMainWorkLoop(){return &gate;}Gate*getMainCommandGate(){return &gate;}
    void iwx_mcc_update(iwx_softc*,iwx_mcc_chub_notif*);
    int iwx_process_mcc_request(iwx_softc*,const char*,uint8_t);
    int iwx_send_update_mcc_cmd(iwx_softc*,const char*c,uint8_t s){requested=c;source=s;++requests;return 0;}
};
FUNCTIONS
int main(){
    assert(iwx_resolved_mcc("US")&&iwx_resolved_mcc("CN"));
    assert(!iwx_resolved_mcc("ZZ")&&!iwx_resolved_mcc("00")&&!iwx_resolved_mcc("us"));
    ItlIwx d;iwx_softc s;iwx_mcc_chub_notif n{};n.mcc=0x5553;n.source_id=IWX_MCC_SOURCE_WIFI;
    d.iwx_mcc_update(&s,&n);assert(s.sc_mcc_last_valid&&strcmp(s.sc_mcc_last,"US")==0);
    n.mcc=0x3030;n.source_id=IWX_MCC_SOURCE_DEFAULT;d.iwx_mcc_update(&s,&n);
    assert(strcmp(s.sc_fw_mcc,"00")==0&&strcmp(s.sc_mcc_last,"US")==0);
    assert(d.iwx_process_mcc_request(&s,"00",IWX_MCC_SOURCE_DEFAULT)==0);
    assert(d.requested=="US"&&d.source==IWX_MCC_SOURCE_WIFI);
    memcpy(s.sc_mcc_override,"CN",3);s.sc_ic.ic_state=IEEE80211_S_RUN;
    for(const char*c:{"US","00","ZZ"}){
        assert(d.iwx_process_mcc_request(&s,c,IWX_MCC_SOURCE_WIFI)==0);
        assert(d.requested=="CN"&&d.source==IWX_MCC_SOURCE_ME);
    }
    s.sc_mcc_override[0]=0;unsigned count=d.requests;
    assert(d.iwx_process_mcc_request(&s,"CN",IWX_MCC_SOURCE_WIFI)==0&&d.requests==count);
    s.sc_flags=IWX_FLAG_SHUTDOWN;assert(d.iwx_process_mcc_request(&s,"CN",IWX_MCC_SOURCE_ME)==ENXIO);
    puts("PASS MCC policy: retain resolved restore state, report actual world response, prioritize configured country over asynchronous hints, keep associated Wi-Fi hint guard");
}
""".replace('FUNCTIONS',mcc_functions)
country_types=block(registers,'struct iwx_mcc_chub_notif {',True)
country_enums=block(headers,'enum ieee80211_state {',True)
# The softc flags are in a separate HAL header.
headers+='\n'+(iwx/'if_iwxvar.h').read_text(encoding='utf-8')
mcc_program=prelude+macros_for(country)+'\n'+country_types+'\n'+country_enums+'\n'+country

native_source=(root/'AirportItlwm/AirportItlwmV2.cpp').read_text(encoding='utf-8')
native_functions='\n'.join(function(native_source,n) for n in ['getCOUNTRY_CODE','setCOUNTRY_CODE'])
native = r"""
#define AIRPORT_WCL 1
#define APPLE80211_VERSION 1
#define kIOReturnSuccess 0
#define kIOReturnError 1
#define kIOReturnBadArgument 2
#define IEEE80211_EVT_COUNTRY_CODE_UPDATE 1
struct OSObject{};
using IOReturn=int;
struct apple80211_country_code_data{unsigned version=0;uint8_t cc[3]{};};
struct ieee80211com{unsigned ic_state=IEEE80211_S_SCAN;};
struct HAL{
    char firmware[3]="00",requested[3]{};unsigned requests=0;ieee80211com ic;
    HAL*getDriverInfo(){return this;}HAL*getDriverController(){return this;}
    const char*getFirmwareCountryCode(){return firmware;}
    ieee80211com*get80211Controller(){return &ic;}
    bool setCountryCode(const char*c){memcpy(requested,c,2);++requests;return true;}
};
struct AirportItlwmSkywalkInterface{unsigned events=0;void handleWCLEvent(int,void*){++events;}};
struct Property{void setProperty(const char*,const char*){}};
class AirportItlwm{public:
    char geo_location_cc[3]{};HAL*fHalService;AirportItlwmSkywalkInterface*fNetIf;Property*pciNub;
    IOReturn getCOUNTRY_CODE(OSObject*,apple80211_country_code_data*);
    IOReturn setCOUNTRY_CODE(OSObject*,apple80211_country_code_data*);
};
FUNCTIONS
int main(){
    HAL h;AirportItlwmSkywalkInterface net;Property property;AirportItlwm a;
    a.fHalService=&h;a.fNetIf=&net;a.pciNub=&property;
    assert(a.setCOUNTRY_CODE(nullptr,nullptr)==kIOReturnBadArgument);
    apple80211_country_code_data d{};d.cc[0]='U';d.cc[1]='S';d.cc[2]=0x7f;
    assert(a.setCOUNTRY_CODE(nullptr,&d)==0&&strcmp(a.geo_location_cc,"US")==0);
    assert(h.requests==1&&net.events==1);
    d.cc[2]=0;assert(a.setCOUNTRY_CODE(nullptr,&d)==0&&net.events==1);
    unsigned count=h.requests;
    for(const char*c:{"00","ZZ","us","X0"}){
        memcpy(d.cc,c,2);assert(a.setCOUNTRY_CODE(nullptr,&d)==0);
        assert(h.requests==count&&net.events==1&&strcmp(a.geo_location_cc,"US")==0);
    }
    h.ic.ic_state=IEEE80211_S_RUN;memcpy(d.cc,"CN",3);a.setCOUNTRY_CODE(nullptr,&d);
    assert(h.requests==count&&net.events==2);
    memcpy(h.firmware,"US",3);a.getCOUNTRY_CODE(nullptr,&d);assert(memcmp(d.cc,"US",2)==0);
    memcpy(h.firmware,"00",3);a.getCOUNTRY_CODE(nullptr,&d);assert(memcmp(d.cc,"00",2)==0);
    memcpy(h.firmware,"ZZ",3);a.getCOUNTRY_CODE(nullptr,&d);assert(memcmp(d.cc,"CN",2)==0);
    puts("PASS native country boundary: two-byte hints, terminated storage, world/invalid input, association guard and effective firmware reporting");
}
""".replace('FUNCTIONS',native_functions)
native_program=prelude+country_enums+'\n'+native


# Exercise station filtering at the firmware TX-completion boundary.
tx_types='\n'.join(block(registers,'struct '+name+' {',True) for name in
    ['iwx_compressed_ba_tfd','iwx_compressed_ba_ratid','iwx_compressed_ba_notif'])
tx_function=function(driver,'iwx_rx_tx_ba_notif')
tx=r"""
using u8=uint8_t;using __le16=uint16_t;using __le32=uint32_t;
TYPES
struct ieee80211com{unsigned ic_state=IEEE80211_S_RUN;};
struct iwx_tx_ring{unsigned ring_count=256;};
struct iwx_softc{ieee80211com sc_ic;bool sc_use_mld_api=false;uint32_t sc_mld_active_sta_mask=0;unsigned sc_tx_timer=5;iwx_tx_ring txq[8];};
struct iwx_rx_data{};
struct iwx_rx_packet{size_t length=0;alignas(8) uint8_t data[256]{};};
static size_t iwx_rx_packet_payload_len(iwx_rx_packet*p){return p->length;}
class ItlIwx{public:
    std::vector<unsigned> completed;
    void iwx_rx_tx_ba_notif(iwx_softc*,iwx_rx_packet*,iwx_rx_data*);
    void iwx_ampdu_txq_advance(iwx_softc*s,iwx_tx_ring*r,int index){completed.push_back(unsigned(r-s->txq)*256+index);}
    void iwx_clear_oactive(iwx_softc*,iwx_tx_ring*){}
};
FUNCTION
int main(){
    ItlIwx driver;iwx_softc sc;iwx_rx_packet packet;
    auto*ba=reinterpret_cast<iwx_compressed_ba_notif*>(packet.data);
    packet.length=sizeof(*ba)+sizeof(ba->tfd[0]);ba->tfd_cnt=1;ba->tfd[0].q_num=2;ba->tfd[0].tfd_index=7;
    driver.iwx_rx_tx_ba_notif(&sc,&packet,nullptr);assert(driver.completed==std::vector<unsigned>{519});
    ba->sta_id=7;driver.iwx_rx_tx_ba_notif(&sc,&packet,nullptr);assert(driver.completed.size()==1);
    sc.sc_use_mld_api=true;sc.sc_mld_active_sta_mask=(1U<<7)|1;
    driver.iwx_rx_tx_ba_notif(&sc,&packet,nullptr);assert(driver.completed.size()==2);
    for(unsigned sta:{8,31,32,255}){ba->sta_id=sta;driver.iwx_rx_tx_ba_notif(&sc,&packet,nullptr);assert(driver.completed.size()==2);}
    ba->sta_id=7;--packet.length;driver.iwx_rx_tx_ba_notif(&sc,&packet,nullptr);assert(driver.completed.size()==2);
    ++packet.length;ba->tfd[0].q_num=8;driver.iwx_rx_tx_ba_notif(&sc,&packet,nullptr);assert(driver.completed.size()==2);
    ba->tfd[0].q_num=2;sc.sc_ic.ic_state=IEEE80211_S_SCAN;driver.iwx_rx_tx_ba_notif(&sc,&packet,nullptr);assert(driver.completed.size()==2);
    puts("PASS TX completion: primary and active secondary stations reclaim queues; inactive station, malformed payload and queue bounds rejected");
}
""".replace('TYPES',tx_types).replace('FUNCTION',tx_function)
tx_enum=block(registers,'enum iwx_ba_resp_flags {',True)
tx_program=prelude+macros_for(tx)+'\n'+country_enums+'\n'+tx_enum+'\n'+tx

with tempfile.TemporaryDirectory(prefix='itlwm-6ghz-state-') as folder:
    folder=Path(folder)
    for name,code in [('he_state',he_program),('mcc_policy',mcc_program),('native_country',native_program),('tx_completion',tx_program)]:
        path=folder/(name+'.cpp');path.write_text(code,encoding='utf-8')
        binary=folder/name
        subprocess.run(shlex.split(os.environ.get('CXX','c++'))+['-std=c++17','-g',
            '-Wall','-Wextra','-Wno-unused-parameter','-Werror','-fsanitize=address,undefined',
            str(path),'-o',str(binary)],check=True)
        subprocess.run([str(binary)],check=True)
