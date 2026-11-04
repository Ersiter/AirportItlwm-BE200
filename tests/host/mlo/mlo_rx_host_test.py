"""Build a host harness from the changed production functions."""
import re
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
temporary = tempfile.TemporaryDirectory(prefix='itlwm-mlo-rx-') if args.output is None else None
out = args.output.resolve() if args.output else Path(temporary.name)
out.mkdir(parents=True, exist_ok=True)
root = args.repo.resolve()
n=root/'itl80211/openbsd/net80211'
p=root/'itlwm/hal_iwx'
pae=(n/'ieee80211_pae_input.c').read_text(encoding='utf-8')
crypto=(n/'ieee80211_crypto.c').read_text(encoding='utf-8')
iwx=(p/'ItlIwx.cpp').read_text(encoding='utf-8')
mld=(p/'ItlIwxMld.cpp').read_text(encoding='utf-8')
def func(text,name,ret):
    start=text.index('\n'+name+'(')+1
    end=text.index('\n}',start)+2
    return ret+'\n'+text[start:end]+'\n'
def struct(text,name):
    start=text.index('struct '+name+' {')
    end=text.index('\n}',start)
    return text[start:text.index(';',end)+1]+'\n'
def enum(text,name):
    start=text.index('enum '+name+' {')
    return text[start:text.index('\n};',start)+3]+'\n'

code=r'''
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <functional>
#include <algorithm>
#ifdef _MSC_VER
#include <intrin.h>
#define __sync_synchronize() _ReadWriteBarrier()
#endif
using u_int=unsigned int;
using u_int8_t=uint8_t; using u_int16_t=uint16_t; using u_int64_t=uint64_t;
#define AIRPORT_WCL 1
#define XYLog(...) ((void)0)
#define DPRINTFN(...) ((void)0)
#define IEEE80211_NUM_TID 16
#define IEEE80211_GROUP_NKID 8
#define IEEE80211_MLD_MAX_LINKS 4
#define IEEE80211_ADDR_LEN 6
#define IEEE80211_OUI "\x00\x0f\xac"
#define IEEE80211_ADDR_EQ(a,b) (memcmp((a),(b),6)==0)
#define IEEE80211_IS_MULTICAST(a) ((a)[0]&1)
#define IEEE80211_ELEMID_VENDOR 221
#define IEEE80211_ELEMID_RSN 48
#define IEEE80211_ELEMID_RSNXE 244
#define IEEE80211_ELEMID_MMIE 76
#define IEEE80211_RSNXECAP_LENGTH_MASK 15
#define IEEE80211_F_RSNON 1
#define IEEE80211_NODE_MFP 1
#define IEEE80211_NODE_BEACON_PROT 2
#define IEEE80211_NODE_TXMGMTPROT 4
#define IEEE80211_NODE_RXMGMTPROT 8
#define IEEE80211_FC0_TYPE_MASK 12
#define IEEE80211_FC0_TYPE_MGT 0
#define IEEE80211_FC0_SUBTYPE_MASK 240
#define IEEE80211_FC0_SUBTYPE_BEACON 128
#define IEEE80211_MMIE_LEN 18
#define LE_READ_2(a) (uint16_t((a)[0])|(uint16_t((a)[1])<<8))
static uint64_t read6(const uint8_t*p) { uint64_t n=0; for(int i=5;i>=0;i--)n=(n<<8)|p[i];return n; }
#define LE_READ_6 read6
#define le16toh(a) (a)
#define htole32(a) (a)
#define htole64(a) (a)
#define nitems(a) (sizeof(a)/sizeof((a)[0]))
static void explicit_bzero(void*p,size_t n){memset(p,0,n);}
#define IEEE80211_NODE_HT 16
#define IEEE80211_NODE_HE 32
#define IEEE80211_C_TX_AMPDU 1
#define IEEE80211_M_STA 1
#define IEEE80211_PROTO_RSN 1
#define IEEE80211_RX_BA_MAX_WINSZ 256
#define IEEE80211_BA_MAX_WINSZ 64
#define IEEE80211_S_RUN 4
#define IEEE80211_BA_REQUESTED 1
#define IEEE80211_BA_AGREED 2
#define IEEE80211_F_BGSCAN 2
#define IEEE80211_F_DISABLE_BG_AUTO_CONNECT 4
#define IEEE80211_F_TX_MGMT_ONLY 8
#define IEEE80211_F_PBAR 16
#define IEEE80211_RSNCAP_PBAC 1
#define IEEE80211_HTCAP_DELAYEDBA 1
#define IEEE80211_ADDBA_TID_MASK 60
#define IEEE80211_ADDBA_TID_SHIFT 2
#define IEEE80211_ADDBA_BUFSZ_MASK 65472
#define IEEE80211_ADDBA_BUFSZ_SHIFT 6
#define IEEE80211_ADDBA_BA_POLICY 2
#define IEEE80211_ADDBA_AMSDU 1
#define IEEE80211_C_AMSDU_IN_AMPDU 2
#define IEEE80211_DUR_TU 1024
#define IEEE80211_SEND_ACTION(...) ((void)0)
#define DPRINTF(...) ((void)0)
#define SEQ_LT(a,b) ((((uint16_t)(a)-(uint16_t)(b))&0xfff)>2048)
struct ieee80211_node;
struct ieee80211_ba_buf{void*m;};
struct ieee80211_rx_ba{int ba_state{},ba_timeout_val{},ba_token{},ba_to{},ba_gap_to{},ba_gapwait{};uint16_t ba_winsize{},ba_params{},ba_winstart{},ba_winend{},ba_head{};ieee80211_ba_buf*ba_buf{};ieee80211_node*ba_ni{};};
'''
header=(n/'ieee80211_crypto.h').read_text(encoding='utf-8')
code+=enum(header,'ieee80211_cipher')+enum(header,'ieee80211_akm')
code+=struct(header,'ieee80211_key')
wire = (n/'ieee80211.h').read_text(encoding='utf-8')
kde_start = wire.rindex('enum {', 0, wire.index('IEEE80211_KDE_GTK'))
code += wire[kde_start:wire.index('\n};', kde_start) + 3] + '\n'
code += '#define __packed\n#define EAPOL_KEY_NONCE_LEN 32\n#define EAPOL_KEY_IV_LEN 16\n#define EAPOL_KEY_MIC_LEN 16\n#pragma pack(push,1)\n'
code += struct(wire, 'ieee80211_eapol_key') + struct(wire, 'ieee80211_ptk') + '#pragma pack(pop)\n'
code+=r'''
struct ieee80211_node {
  uint8_t ni_macaddr[6]{}, ni_mld_addr[6]{}; int ni_mld_valid{};
  unsigned ni_rsnakms{IEEE80211_AKM_SAE};
  unsigned ni_flags{};
  unsigned ni_rsnprotos{IEEE80211_PROTO_RSN};int ni_rsn_supp_state{};uint64_t ni_replaycnt{};
  int ni_port_valid{1},ni_rsncaps{};ieee80211_rx_ba ni_rx_ba[16];
  struct {struct {int mld; uint8_t ownaddr[6],peeraddr[6];}sae_auth;int sae_state{1};}ni_sae{};
  uint8_t *ni_rsnie{}, *ni_rsnxe{}; size_t ni_rsnxe_len{};
  ieee80211_cipher ni_rsncipher{IEEE80211_CIPHER_CCMP},ni_rsngroupcipher{IEEE80211_CIPHER_CCMP},ni_rsngroupmgmtcipher{IEEE80211_CIPHER_BIP};
  ieee80211_key ni_pairwise_key{};ieee80211_ptk ni_ptk{};
};
'''
code+=struct((n/'ieee80211_var.h').read_text(encoding='utf-8'),'ieee80211_mld_link_info')
code+=r'''
struct _ifnet {int if_flags{};};
struct ieee80211com {
  uint8_t ic_myaddr[6]{}, ic_wcl_local_mlo_addrs[4][6]{};
  bool ic_wcl_peer_is_mlo{}, ic_wcl_local_mlo_addrs_valid{};
  uint8_t ic_nonce[32]{};_ifnet ic_if; unsigned ic_caps{IEEE80211_C_TX_AMPDU};int ic_opmode{IEEE80211_M_STA};
  int ic_state{IEEE80211_S_RUN},ic_xflags{},ic_tid_noack{},ic_htcaps{};
  int(*ic_ampdu_rx_start)(ieee80211com*,ieee80211_node*,int){};
  struct{unsigned is_cmac_replays{};}ic_stats;
  ieee80211_node*ic_bss{}; unsigned ic_flags{IEEE80211_F_RSNON};
  ieee80211_mld_link_info ic_mld_links[4]{}; int ic_mld_link_count{};
  ieee80211_key ic_nw_keys[8]{}; int ic_beacon_prot{1},ic_mld_gmac{1},ic_def_txkey{},ic_igtk_kid{};
  int(*ic_set_key)(ieee80211com*,ieee80211_node*,ieee80211_key*);
  void(*ic_delete_key)(ieee80211com*,ieee80211_node*,ieee80211_key*);
};
static ieee80211_node*ieee80211_mld_primary_node(ieee80211com*ic,ieee80211_node*ni){return ni==ic->ic_bss||std::any_of(ic->ic_mld_links,ic->ic_mld_links+ic->ic_mld_link_count,[&](auto&l){return l.ni==ni&&l.assoc_accepted;})?ic->ic_bss:ni;}
'''
var=(n/'ieee80211_var.h').read_text(encoding='utf-8')
code+=func(var,'ieee80211_rsn_uses_mld','static inline int')
code+=func(var,'ieee80211_rsn_own_addr','static inline const uint8_t *')
code+=func(var,'ieee80211_rsn_peer_addr','static inline const uint8_t *')
code+=r'''
static void ieee80211_delete_key(ieee80211com*,ieee80211_node*,ieee80211_key*k){k->k_priv=nullptr;}
static int ieee80211_is_bip_cipher(ieee80211_cipher c){return c==IEEE80211_CIPHER_BIP||c==IEEE80211_CIPHER_BIP_GMAC_128||c==IEEE80211_CIPHER_BIP_GMAC_256;}
#pragma pack(push,1)
struct ieee80211_frame{uint8_t i_fc[2],i_dur[2],i_addr1[6],i_addr2[6],i_addr3[6],i_seq[2];};
#pragma pack(pop)
struct mbuf{std::vector<uint8_t>data;int id{};};using mbuf_t=mbuf*;
#define mtod(m,type) reinterpret_cast<type>((m)->data.data())
static size_t mbuf_len(mbuf_t m){return m->data.size();}
static void*mbuf_data(mbuf_t m){return m->data.data();}
static int ieee80211_get_hdrlen(const ieee80211_frame*){return 24;}
struct mbuf_list{std::vector<mbuf_t>q;};
#define MBUF_LIST_INITIALIZER() {}
static int purged=0;
static void ml_purge(mbuf_list*m){for(auto p:m->q){delete p;purged++;}m->q.clear();}
static mbuf_t ml_dequeue(mbuf_list*m){if(m->q.empty())return nullptr;auto p=m->q.front();m->q.erase(m->q.begin());return p;}
'''
code+=func((n/'ieee80211.h').read_text(encoding='utf-8'),'ieee80211_rsnxe_valid','static int')
code+=func((n/'ieee80211.h').read_text(encoding='utf-8'),'ieee80211_rsnxe_matches','static int')
code+=func(crypto,'ieee80211_cipher_keylen','static int')
code+=func(crypto,'ieee80211_cipher_mmie_len','static int')
code+=func(pae,'ieee80211_must_update_group_key','static int')
code+=func(pae,'ieee80211_reset_key_slot','static void')
start=pae.index('struct ieee80211_mlo_kdes {')
code+=pae[start:pae.index('\n#endif',start)]
code+=func(crypto,'ieee80211_mld_key_link','static ieee80211_mld_link_info *')
code+=func(crypto,'ieee80211_get_rxgroupkeys','static ieee80211_key *')
code+=func(crypto,'ieee80211_get_rxkey','static ieee80211_key *')
code+=func(crypto,'ieee80211_get_txkey','static ieee80211_key *')
code+=func(crypto,'ieee80211_mld_clear_groupkeys','static void')
code+=func((n/'ieee80211_output.c').read_text(encoding='utf-8'),'ieee80211_can_use_ampdu','static int')
code+=func((n/'ieee80211_pae_output.c').read_text(encoding='utf-8'),'ieee80211_add_mlo_mac_kde','static uint8_t *')
code+=r'''
#define IWX_DEVICE_FAMILY_AX210 1
#define IWX_DEVICE_FAMILY_BZ 2
#define IWX_RX_MQ_RING_COUNT 16
#define IWX_FLAG_STA_ACTIVE 1
#define IWX_FLAG_HW_ERR 2
#define IWX_DATA_PATH_GROUP 5
#define IWX_MLD_SEC_KEY_CMD 24
#define IWX_WIDE_ID(a,b) ((a)*256+(b))
#define IWX_FW_CTXT_ACTION_REMOVE 1
#define IWX_FW_CTXT_ACTION_ADD 0
#define IWX_HBUS_TARG_WRPTR 1
#define IWX_RFH_Q0_FRBDCB_WIDX_TRG 2
#define IWX_HBUS_TARG_WRPTR_RX_Q(a) 0
#define IWX_LEGACY_GROUP 0
#define IWX_FRAME_RELEASE 0xc3
#define RX_REORDER_BUF_TIMEOUT_MQ_USEC 100000
#define IEEE80211_RXI_SAME_SEQ 1
#define IEEE80211_RXI_HWDEC_SAME_PN 2
struct ieee80211_rxinfo{unsigned rxi_flags{};};
struct CTimeout {};
#ifdef _WIN32
struct timeval{long tv_sec,tv_usec;};
#else
#include <sys/time.h>
#endif
'''
var_header=(p/'if_iwxvar.h').read_text(encoding='utf-8')
for name in ['iwx_reorder_buffer','iwx_reorder_buf_entry','iwx_rxba_data']:
    code+=struct(var_header,name)
code+=r'''
template<class T>static void timeout_add_usec(T*,int){}
template<class T>static void timeout_del(T*){}
static void timeout_set(int*,void(*)(void*),void*){}
static void ieee80211_rx_ba_timeout(void*){}
static void ieee80211_input_ba_gap_timeout(void*){}
static void ieee80211_ba_move_window(ieee80211com*,ieee80211_node*,int,int,mbuf_list*){}
static void ieee80211_addba_req_refuse(ieee80211com*,ieee80211_node*,int){}
static void ieee80211_addba_req_accept(ieee80211com*,ieee80211_node*,int){}
static void*host_malloc(size_t n,int,int){return calloc(1,n);}
struct iwx_rx_packet{uint8_t data[4]{};size_t len{};};
static size_t iwx_rx_packet_payload_len(iwx_rx_packet*p){return p->len;}
#define SYNC_RESP_STRUCT(v,p,type) v=reinterpret_cast<type>((p)->data)
struct iwx_frame_release{uint8_t baid,reserved;uint16_t nssn;};
struct property{void setProperty(const char*,uint32_t,int){}};
struct iwx_rx_data{int id;};
struct iwx_rx_completion_desc_bz{uint16_t rbid;uint16_t flags;};
struct iwx_rb_status{uint16_t closed_rb_num;};
struct iwx_softc{
 iwx_rxba_data sc_rxba_data[8]{};
 ieee80211com sc_ic;int sc_generation{},sc_device_family{IWX_DEVICE_FAMILY_BZ};uint64_t sc_rx_service_cookie{};
 unsigned sc_flags{IWX_FLAG_STA_ACTIVE},sc_mld_sta_mask{3};uint8_t sc_mld_sta_ids[4]{0,1,2,3};
 property props,*sc_pcitag{&props};
 struct {unsigned cur{};void*stat{};struct{void*vaddr;}used_desc_dma{};iwx_rx_data data[IWX_RX_MQ_RING_COUNT];}rxq;
};
'''
code+=enum((p/'if_iwxmld.h').read_text(encoding='utf-8'),'iwx_mld_sec_key_flags')
code+='#define __packed\n#pragma pack(push,1)\n'+struct((p/'if_iwxmld.h').read_text(encoding='utf-8'),'iwx_mld_sec_key_cmd')+'#pragma pack(pop)\n'
code+=r'''
static iwx_softc*active_sc;
static std::vector<iwx_mld_sec_key_cmd>commands;
static bool fail_key=false;
static std::vector<int>events;
static int doorbells=0, recovery=0;
static std::function<void(iwx_softc*,int)>during_packet;
static std::function<void()>during_input;
static void write_reg(iwx_softc*,int,int val){events.push_back(1000+val);doorbells++;}
#define IWX_WRITE write_reg
static void if_input(_ifnet*,mbuf_list*ml){events.push_back(2000);ml_purge(ml);if(during_input)during_input();}
static int iwx_lookup_cmd_ver(iwx_softc*,int,int){return 1;}
static void iwx_mld_record_key_reject(iwx_softc*,ieee80211_node*,ieee80211_key*,int,const char*){}
static void iwx_schedule_recovery(iwx_softc*,const char*,int){recovery++;}
class ItlIwx{public:
 int iwx_mld_set_key(iwx_softc*,ieee80211_node*,ieee80211_key*,int);
 void iwx_notif_intr(iwx_softc*);
 int iwx_is_sn_less(uint16_t,uint16_t,uint16_t);
 void iwx_release_frames(iwx_softc*,ieee80211_node*,iwx_rxba_data*,iwx_reorder_buffer*,uint16_t,mbuf_list*);
 void release_notification(iwx_softc*,int,iwx_rx_packet*,mbuf_list*);
 void iwx_rx_frame(iwx_softc*sc,mbuf_t m,int,uint32_t,int,uint32_t,uint32_t,ieee80211_rxinfo*,mbuf_list*ml){ml->q.push_back(m);if(during_packet)during_packet(sc,m->id);}
 int iwx_send_cmd_pdu(iwx_softc*,int,int,size_t,const void*p){if(fail_key)return EIO;commands.push_back(*static_cast<const iwx_mld_sec_key_cmd*>(p));return 0;}
 void iwx_rx_pkt(iwx_softc*sc,iwx_rx_data*d,mbuf_list*ml){events.push_back(d->id);ml->q.push_back(new mbuf{{},d->id});if(during_packet)during_packet(sc,d->id);}
};
static ItlIwx driver;
static int set_key(ieee80211com*,ieee80211_node*ni,ieee80211_key*k){return driver.iwx_mld_set_key(active_sc,ni,k,0);}
static void delete_key(ieee80211com*,ieee80211_node*ni,ieee80211_key*k){assert(driver.iwx_mld_set_key(active_sc,ni,k,1)==0);}
'''
code+=func(mld,'iwx_mld_link_slot','static int')
code+=func(mld,'iwx_mld_set_key','int ItlIwx::')
code+=func(iwx,'iwx_notif_intr','void ItlIwx::')
code+=func(iwx,'iwx_is_sn_less','int ItlIwx::')
code+=func(iwx,'iwx_release_frames','void ItlIwx::')
code+=func(iwx,'iwx_check_mgmt_replay','static int')
code+='#define malloc host_malloc\n'+func((n/'ieee80211_input.c').read_text(encoding='utf-8'),'ieee80211_recv_addba_req','static void')+'#undef malloc\n'
start=iwx.index('            case IWX_WIDE_ID(IWX_LEGACY_GROUP, IWX_FRAME_RELEASE):')
end=iwx.index('            case IWX_WIDE_ID(IWX_LEGACY_GROUP, IWX_BAR_FRAME_RELEASE):',start)
code+='void ItlIwx::release_notification(iwx_softc*sc,int code,iwx_rx_packet*pkt,mbuf_list*ml){switch(code){\n'+iwx[start:end]+'default:break;}}\n'

code+=r'''
#define IEEE80211_PROTO_WPA 2
#define IEEE80211_WPAIE_MAXLEN 64
#define IEEE80211_RSNIE_MAXLEN 64
#define IEEE80211_RSNXEIE_MAXLEN 16
#define RSNA_SUPP_PTKNEGOTIATING 1
#define RNSA_SUPP_PTKDONE 2
#define SAE_STATE_ACCEPTED 1
#define IFF_DEBUG 1
#define MBUF_DONTWAIT 0
#define MT_DATA 0
#define IEEE80211_NODE_TXPROT 64
static void write_be(uint8_t*p,uint64_t v,int n){while(n){p[--n]=uint8_t(v);v>>=8;}}
#define BE_WRITE_2(p,v) write_be(p,v,2)
#define BE_WRITE_8(p,v) write_be(p,v,8)
static mbuf_t ieee80211_get_eapol_key(int,int,size_t n){return new mbuf{std::vector<uint8_t>(sizeof(ieee80211_eapol_key)+n)};}
static void mbuf_pkthdr_setlen(mbuf_t m,size_t n){m->data.resize(n);}
static void mbuf_setlen(mbuf_t m,size_t n){m->data.resize(n);}
static int ieee80211_node_allow_wpa3(ieee80211com*,ieee80211_node*n){return n->ni_rsnakms==IEEE80211_AKM_SAE;}
static uint8_t*ieee80211_add_rsn(uint8_t*p,ieee80211com*,ieee80211_node*n){memcpy(p,n->ni_rsnie,n->ni_rsnie[1]+2);return p+n->ni_rsnie[1]+2;}
static uint8_t*ieee80211_add_rsnxe(uint8_t*p,ieee80211com*,ieee80211_node*n){memcpy(p,n->ni_rsnxe,n->ni_rsnxe_len);return p+n->ni_rsnxe_len;}
static uint8_t*ieee80211_add_wpa(uint8_t*p,ieee80211com*,ieee80211_node*){return p;}
static int ieee80211_mark_eapol_noencrypt(mbuf_t){return 0;}
static void mbuf_freem(mbuf_t m){delete m;}
static std::vector<uint8_t>sent_eapol;
static int ieee80211_send_eapol_key(ieee80211com*,mbuf_t m,ieee80211_node*,const ieee80211_ptk*){sent_eapol=m->data;delete m;return 0;}
'''
code+=func((n/'ieee80211_pae_output.c').read_text(encoding='utf-8'),'ieee80211_send_4way_msg2','static int')
code+=func((n/'ieee80211_pae_output.c').read_text(encoding='utf-8'),'ieee80211_send_4way_msg4','static int')
code+=r'''
static void kde(std::vector<uint8_t>&v,int type,const std::vector<uint8_t>&body){v.insert(v.end(),{221,uint8_t(body.size()+4),0,15,172,uint8_t(type)});v.insert(v.end(),body.begin(),body.end());}
static std::vector<uint8_t>gtk(int id,int kid,int seed,int pn){std::vector<uint8_t>v(7+16,seed);v[0]=uint8_t((id<<4)|kid);for(int j=0;j<6;j++)v[1+j]=uint8_t(uint64_t(pn)>>(j*8));return v;}
static std::vector<uint8_t>igtk(int id,int kid,int seed,int pn){std::vector<uint8_t>v(9+16,seed);v[0]=kid;v[1]=0;for(int j=0;j<6;j++)v[2+j]=uint8_t(uint64_t(pn)>>(j*8));v[8]=id<<4;return v;}
struct fixture {
 iwx_softc sc{};ieee80211_node nodes[2]{};std::vector<uint8_t>rsn{48,2,1,0},rsnxe{244,1,32};
 fixture(){for(auto&ba:sc.sc_rxba_data)ba.baid=255;active_sc=&sc;auto&ic=sc.sc_ic;ic.ic_bss=&nodes[0];ic.ic_mld_link_count=2;ic.ic_set_key=set_key;ic.ic_delete_key=delete_key;
 for(int i=0;i<2;i++){auto&ni=nodes[i];ni.ni_flags=IEEE80211_NODE_MFP|IEEE80211_NODE_BEACON_PROT;ni.ni_macaddr[0]=2;ni.ni_macaddr[5]=20+i;ni.ni_rsnie=rsn.data();ni.ni_rsnxe=rsnxe.data();ni.ni_rsnxe_len=rsnxe.size();auto&l=ic.ic_mld_links[i];l.ni=&ni;l.ap_link_id=i?5:0;l.assoc_accepted=1;l.local_addr[0]=2;l.local_addr[5]=30+i;}
 nodes[0].ni_sae.sae_auth.mld=1;nodes[0].ni_sae.sae_auth.peeraddr[0]=2;nodes[0].ni_sae.sae_auth.peeraddr[5]=99;
 commands.clear();fail_key=false;
 }
 std::vector<uint8_t> initial(){std::vector<uint8_t>v;auto*p=nodes[0].ni_sae.sae_auth.peeraddr;kde(v,3,{p,p+6});for(int i=0;i<2;i++){int id=i?5:0;std::vector<uint8_t>b{uint8_t(id|0x30)};b.insert(b.end(),nodes[i].ni_macaddr,nodes[i].ni_macaddr+6);b.insert(b.end(),rsn.begin(),rsn.end());b.insert(b.end(),rsnxe.begin(),rsnxe.end());kde(v,19,b);kde(v,16,gtk(id,2,40+i,3));kde(v,17,igtk(id,4,60+i,4));kde(v,18,igtk(id,6,80+i,5));}return v;}
 bool valid(std::vector<uint8_t>&v,int initial=1){ieee80211_mlo_kdes k;return ieee80211_parse_mlo_kdes(&sc.sc_ic,v.data(),v.size(),&k)==0&&ieee80211_validate_mlo_keys(&sc.sc_ic,&nodes[0],&k,initial)==0;}
 void install(std::vector<uint8_t>&v){ieee80211_mlo_kdes k;assert(ieee80211_parse_mlo_kdes(&sc.sc_ic,v.data(),v.size(),&k)==0);assert(ieee80211_validate_mlo_keys(&sc.sc_ic,&nodes[0],&k,1)==0);assert(ieee80211_install_mlo_keys(&sc.sc_ic,&nodes[0],&k)==0);}
};
static void security_tests(){
 fixture f;auto v=f.initial();assert(f.valid(v));f.install(v);assert(commands.size()==6);
 for(int i=0;i<6;i++){assert(commands[i].u.add.sta_mask==unsigned(i<3?1:2));assert(commands[i].u.add.key_flags&IWX_MLD_SEC_KEY_FLAG_MCAST_KEY);assert(commands[i].u.add.rx_seq==unsigned(3+i%3));}
 auto&ic=f.sc.sc_ic;
 // Same key with a lower PN must preserve every TID and management PN.
 for(int i=0;i<2;i++){auto&l=ic.ic_mld_links[i];for(auto&pn:l.keys[2].k_rsc)pn=99;l.keys[4].k_mgmt_rsc=100;l.keys[6].k_mgmt_rsc=101;}
 f.install(v);assert(commands.size()==6);
 for(auto&l:ic.ic_mld_links){if(!l.assoc_accepted)continue;for(auto pn:l.keys[2].k_rsc)assert(pn==99);assert(l.keys[4].k_mgmt_rsc==100&&l.keys[6].k_mgmt_rsc==101);}
 // RX selects by transmitter even when both links use the same key ID.
 mbuf m{std::vector<uint8_t>(32)};auto*wh=mtod(&m,ieee80211_frame*);wh->i_fc[0]=8;wh->i_addr1[0]=1;m.data[27]=2<<6;
 for(int i=0;i<2;i++){memcpy(wh->i_addr2,f.nodes[i].ni_macaddr,6);auto*k=ieee80211_get_rxkey(&ic,&m,&f.nodes[0]);assert(k==&ic.ic_mld_links[i].keys[2]);assert(k->k_key[0]==40+i);}
 wh->i_addr2[5]=88;assert(ieee80211_get_rxkey(&ic,&m,&f.nodes[0])==nullptr);
 // Management PN is checked against the per-link KDE IPN after MIC validation.
 mbuf mgmt{std::vector<uint8_t>(42)};auto*mwh=mtod(&mgmt,ieee80211_frame*);mwh->i_fc[0]=128;mwh->i_addr1[0]=1;memcpy(mwh->i_addr2,f.nodes[1].ni_macaddr,6);mgmt.data[24]=76;mgmt.data[25]=16;mgmt.data[26]=6;mgmt.data[28]=102;
 auto*mk=ieee80211_get_rxkey(&ic,&mgmt,&f.nodes[0]);assert(mk==&ic.ic_mld_links[1].keys[6]);assert(iwx_check_mgmt_replay(&f.sc,&mgmt,mk)==0&&mk->k_mgmt_rsc==102);assert(iwx_check_mgmt_replay(&f.sc,&mgmt,mk)==1);mgmt.data[28]=100;assert(iwx_check_mgmt_replay(&f.sc,&mgmt,mk)==1&&mk->k_mgmt_rsc==102);assert(ic.ic_mld_links[0].keys[6].k_mgmt_rsc==101);
 // Subset group rekey changes only the addressed link.
 std::vector<uint8_t>r;kde(r,16,gtk(5,2,77,9));ieee80211_mlo_kdes k;assert(ieee80211_parse_mlo_kdes(&ic,r.data(),r.size(),&k)==0);assert(ieee80211_validate_mlo_keys(&ic,&f.nodes[0],&k,0)==0);assert(ieee80211_install_mlo_keys(&ic,&f.nodes[0],&k)==0);assert(commands.size()==7&&commands.back().u.add.sta_mask==2);assert(ic.ic_mld_links[0].keys[2].k_rsc[15]==99&&ic.ic_mld_links[1].keys[2].k_rsc[15]==9);
 // PTK remains shared across the MLD, install and removal use all stations.
 auto ptk=ic.ic_mld_links[0].keys[2];ptk.k_flags=0;assert(driver.iwx_mld_set_key(&f.sc,&f.nodes[0],&ptk,0)==0);assert(commands.back().u.add.sta_mask==3);
 ieee80211_mld_clear_groupkeys(&ic);assert(commands.size()==14);assert(commands.back().u.remove.sta_mask==2);for(auto&l:ic.ic_mld_links)for(auto&key:l.keys)assert(key.k_cipher==IEEE80211_CIPHER_NONE);
 // A failed install remains eligible for a retry.
 fail_key=true;assert(ieee80211_install_mlo_keys(&ic,&f.nodes[0],&k)==EIO);assert(ic.ic_mld_links[1].keys[2].k_cipher==IEEE80211_CIPHER_NONE);fail_key=false;assert(ieee80211_install_mlo_keys(&ic,&f.nodes[0],&k)==0);
 uint8_t tx[12]{};assert(ieee80211_add_mlo_mac_kde(tx,&ic,&f.nodes[0])==tx+12);assert(tx[0]==221&&tx[1]==10&&tx[5]==3);
 // Boundary and identity checks, including each byte truncation.
 fixture g;auto good=g.initial();for(size_t n=0;n<good.size();n++){auto x=good;x.resize(n);assert(!g.valid(x));}
 auto bad=good;bad[11]^=1;assert(!g.valid(bad));bad=good;bad[19]^=2;assert(!g.valid(bad));
 bad=good;kde(bad,16,gtk(0,2,4,0));assert(!g.valid(bad));
 bad=good;bad.insert(bad.end(),{221,0,0,0});assert(g.valid(bad));bad.back()=1;assert(!g.valid(bad));
 // Every parsed key has a validated key length before an install occurs.
 for(size_t i=0;i<good.size();){auto x=good;unsigned len=x[i+1];if(x[i+5]>=16&&x[i+5]<=18){x[i+1]--;assert(!g.valid(x));}i+=len+2;}
 std::puts("PASS MLO: MAC/Link KDE, two-link keys, subset rekey, RX selection, PN preservation, install failure, malformed input");
}
static void rx_tests(){
 iwx_softc sc;uint16_t hw=4;iwx_rx_completion_desc_bz desc[16]{};sc.rxq.stat=&hw;sc.rxq.used_desc_dma.vaddr=desc;
 for(int i=0;i<16;i++){desc[i].rbid=i;sc.rxq.data[i].id=i;}
 events.clear();doorbells=0;during_packet={};during_input=[&]{assert(doorbells==1);sc.sc_generation++;sc.rxq.cur=0;};driver.iwx_notif_intr(&sc);assert(events.back()==2000&&doorbells==1&&sc.rxq.cur==0);
 events.clear();doorbells=0;during_input={};during_packet=[&](iwx_softc*s,int){s->sc_generation++;s->rxq.cur=0;};driver.iwx_notif_intr(&sc);assert(doorbells==0&&sc.rxq.cur==0);
 // A nested service owns the new cursor; the older batch cannot publish it again.
 events.clear();doorbells=0;during_packet=[&](iwx_softc*s,int id){if(id==0){during_packet={};hw=5;driver.iwx_notif_intr(s);}};driver.iwx_notif_intr(&sc);assert(doorbells==1&&sc.rxq.cur==5);for(int i=0;i<5;i++)assert(std::count(events.begin(),events.end(),i)==1);
 sc.rxq.cur=0;desc[0].rbid=16;events.clear();doorbells=0;driver.iwx_notif_intr(&sc);assert(recovery==1&&doorbells==0);
 std::puts("PASS RX: credits before callback, reset generation, nested service cursor, invalid completion");
}
static void aggregation_tests(){
 fixture f;f.nodes[0].ni_flags=IEEE80211_NODE_HE;assert(ieee80211_can_use_ampdu(&f.sc.sc_ic,&f.nodes[0]));f.sc.sc_ic.ic_flags=0;assert(!ieee80211_can_use_ampdu(&f.sc.sc_ic,&f.nodes[0]));f.sc.sc_ic.ic_flags=IEEE80211_F_RSNON;f.nodes[0].ni_flags=0;assert(!ieee80211_can_use_ampdu(&f.sc.sc_ic,&f.nodes[0]));
 auto&rb=f.sc.sc_rxba_data[0];rb.baid=0;rb.reorder_buf.buf_size=256;rb.reorder_buf.head_sn=4000;rb.reorder_buf.num_stored=256;
 for(int sn=4000;sn<4256;sn++)rb.entries[sn%256].frames.q.push_back(new mbuf{{},sn&4095});
 mbuf_list ml;driver.iwx_release_frames(&f.sc,&f.nodes[0],&rb,&rb.reorder_buf,160,&ml);assert(rb.reorder_buf.head_sn==160&&rb.reorder_buf.num_stored==0&&ml.q.size()==256);for(int i=0;i<256;i++)assert(ml.q[i]->id==((4000+i)&4095));ml_purge(&ml);
 driver.iwx_release_frames(&f.sc,&f.nodes[0],&rb,&rb.reorder_buf,159,&ml);assert(rb.reorder_buf.head_sn==160);
 iwx_rx_packet pkt;pkt.data[0]=0;pkt.data[2]=161;
 for(size_t len=0;len<4;len++){pkt.len=len;driver.release_notification(&f.sc,IWX_FRAME_RELEASE,&pkt,&ml);assert(rb.reorder_buf.head_sn==160);}
 pkt.len=4;driver.release_notification(&f.sc,IWX_FRAME_RELEASE,&pkt,&ml);assert(rb.reorder_buf.head_sn==161);
 pkt.data[0]=8;pkt.data[2]=162;driver.release_notification(&f.sc,IWX_FRAME_RELEASE,&pkt,&ml);assert(rb.reorder_buf.head_sn==161);
 pkt.data[0]=1;driver.release_notification(&f.sc,IWX_FRAME_RELEASE,&pkt,&ml);assert(f.sc.sc_rxba_data[1].reorder_buf.head_sn==0);
 rb.reorder_buf.num_stored=1;rb.entries[161].frames.q.push_back(new mbuf{{},161});during_packet=[&](iwx_softc*s,int){s->sc_generation++;};driver.iwx_release_frames(&f.sc,&f.nodes[0],&rb,&rb.reorder_buf,162,&ml);assert(rb.reorder_buf.head_sn==161&&rb.reorder_buf.num_stored==1);during_packet={};ml_purge(&ml);
 // Feed real ADDBA request parsing, including a HE peer with no HT flag.
 for(unsigned flags:{unsigned(IEEE80211_NODE_HT),unsigned(IEEE80211_NODE_HE)})for(unsigned requested:{0u,1u,64u,256u,1023u}){
  fixture g;auto&ic=g.sc.sc_ic;g.nodes[0].ni_flags=flags;ic.ic_ampdu_rx_start=[](ieee80211com*,ieee80211_node*,int){return EBUSY;};mbuf request{std::vector<uint8_t>(33)};auto*params=request.data.data()+27;unsigned bits=(requested<<6)|2;params[0]=bits;params[1]=bits>>8;ieee80211_recv_addba_req(&ic,&request,&g.nodes[0]);auto&ba=g.nodes[0].ni_rx_ba[0];unsigned cap=flags==IEEE80211_NODE_HE?256:64;assert(ba.ba_state==IEEE80211_BA_REQUESTED&&ba.ba_winsize==(requested==0?cap:std::min(requested,cap)));assert(ba.ba_buf);ba.ba_buf[255].m=nullptr;free(ba.ba_buf);ba.ba_buf=nullptr;
 }
 std::puts("PASS aggregation: HE-only TX gate, open-network restriction, 256-frame reorder and sequence wrap, FRAME_RELEASE bounds and BAID");
}
static void eapol_output_tests(){
 fixture f;uint8_t replay[8]{0,0,0,0,0,0,0,9};ieee80211_ptk ptk{};auto&ic=f.sc.sc_ic;auto*ni=&f.nodes[0];
 assert(ieee80211_send_4way_msg2(&ic,ni,replay,&ptk)==0);assert(sent_eapol.size()==sizeof(ieee80211_eapol_key)+32);auto*p=sent_eapol.data()+sizeof(ieee80211_eapol_key);assert(memcmp(p,f.rsn.data(),4)==0&&memcmp(p+4,f.rsnxe.data(),3)==0);assert(p[7]==221&&p[8]==10&&p[12]==3&&memcmp(p+13,ni->ni_sae.sae_auth.ownaddr,6)==0);assert(p[19]==221&&p[20]==11&&p[24]==19&&p[25]==5&&memcmp(p+26,ic.ic_mld_links[1].local_addr,6)==0);
 assert(ieee80211_send_4way_msg4(&ic,ni)==0);assert(sent_eapol.size()==sizeof(ieee80211_eapol_key)+12);p=sent_eapol.data()+sizeof(ieee80211_eapol_key);assert(p[5]==3&&memcmp(p+6,ni->ni_sae.sae_auth.ownaddr,6)==0);
 ni->ni_sae.sae_auth.mld=0;assert(ieee80211_send_4way_msg2(&ic,ni,replay,&ptk)==0&&sent_eapol.size()==sizeof(ieee80211_eapol_key)+7);assert(ieee80211_send_4way_msg4(&ic,ni)==0&&sent_eapol.size()==sizeof(ieee80211_eapol_key));
 std::puts("PASS EAPOL TX: M2 MAC and requested Link KDE bytes, M4 MAC KDE, single-link frame lengths");
}
static void owe_mlo_tests(){
 fixture f;auto&ic=f.sc.sc_ic;auto*ni=&f.nodes[0];
 ni->ni_rsnakms=IEEE80211_AKM_OWE;ni->ni_sae.sae_auth.mld=0;
 ic.ic_wcl_peer_is_mlo=true;ic.ic_wcl_local_mlo_addrs_valid=true;ni->ni_mld_valid=1;
 memcpy(ni->ni_mld_addr,ni->ni_sae.sae_auth.peeraddr,6);
 ic.ic_wcl_local_mlo_addrs[0][0]=2;ic.ic_wcl_local_mlo_addrs[0][5]=71;
 assert(ieee80211_rsn_uses_mld(&ic,ni));
 assert(memcmp(ieee80211_rsn_peer_addr(&ic,ni),ni->ni_mld_addr,6)==0);
 assert(memcmp(ieee80211_rsn_own_addr(&ic,ni),ic.ic_wcl_local_mlo_addrs[0],6)==0);
 auto v=f.initial();assert(f.valid(v));f.install(v);assert(commands.size()==6);
 uint8_t replay[8]{};ieee80211_ptk ptk{};
 assert(ieee80211_send_4way_msg2(&ic,ni,replay,&ptk)==0);
 auto*p=sent_eapol.data()+sizeof(ieee80211_eapol_key);
 assert(sent_eapol.size()==sizeof(ieee80211_eapol_key)+29);
 assert(memcmp(p,f.rsn.data(),4)==0&&p[4]==221&&p[9]==3&&memcmp(p+10,ic.ic_wcl_local_mlo_addrs[0],6)==0);
 assert(ieee80211_send_4way_msg4(&ic,ni)==0&&sent_eapol.size()==sizeof(ieee80211_eapol_key)+12);
 ic.ic_wcl_peer_is_mlo=false;assert(!ieee80211_rsn_uses_mld(&ic,ni));
 assert(ieee80211_rsn_own_addr(&ic,ni)==ic.ic_myaddr&&ieee80211_rsn_peer_addr(&ic,ni)==ni->ni_macaddr);
 std::puts("PASS OWE MLO: MLD PTK identities, per-link group keys, M2/M4 KDEs without SAE RSNXE");
}
int main(){security_tests();rx_tests();aggregation_tests();eapol_output_tests();owe_mlo_tests();std::puts("All production-function tests passed");}
'''
target=out/'native-test.cpp'
target.write_text(code,encoding='utf-8')
if os.name == 'nt':
    vswhere = Path(os.environ['ProgramFiles(x86)']) / 'Microsoft Visual Studio/Installer/vswhere.exe'
    installation = subprocess.check_output([str(vswhere), '-latest', '-products', '*',
        '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
        '-property', 'installationPath'], text=True).strip()
    vcvars = Path(installation) / 'VC/Auxiliary/Build/vcvars64.bat'
    if not vcvars.is_file():
        raise RuntimeError('MSVC x64 build tools were not found')
    cmd = out / 'native-test.cmd'
    cmd.write_text('@echo off\ncall "' + str(vcvars) + '" >nul\n'
        'cl /nologo /std:c++17 /EHsc /W3 /Od /Zi /fsanitize=address /Fe:native-test.exe native-test.cpp\n'
        'if errorlevel 1 exit /b %errorlevel%\nnative-test.exe\n', encoding='utf-8')
    r = subprocess.run(['cmd.exe', '/d', '/c', str(cmd)], cwd=out, capture_output=True)
else:
    cxx = os.environ.get('CXX') or shutil.which('clang++') or shutil.which('g++')
    if not cxx:
        raise RuntimeError('Set CXX to a C++17 compiler')
    subprocess.run([cxx, '-std=c++17', '-g', '-fsanitize=address,undefined',
        '-fno-omit-frame-pointer', str(target), '-o', str(out/'native-test')], check=True)
    r = subprocess.run([str(out/'native-test')], cwd=out, capture_output=True)
log=(r.stdout+r.stderr).decode('utf-8' if os.name != 'nt' else 'mbcs',errors='replace')
(out/'native-test.log').write_text(log,encoding='utf-8')
print(log)
raise SystemExit(r.returncode)
