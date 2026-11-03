"""Check shipped firmware identities and production GL selection/PHY command bytes."""
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import shutil
import tempfile
from pathlib import Path

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[3])
parser.add_argument('--output',type=Path)
args=parser.parse_args()
root=args.repo.resolve()
temporary=tempfile.TemporaryDirectory(prefix='itlwm-gl92-') if args.output is None else None
out=args.output.resolve() if args.output else Path(temporary.name)
out.mkdir(parents=True,exist_ok=True)
iwx=(root/'itlwm/hal_iwx/ItlIwx.cpp').read_text(encoding='utf-8')
reg=(root/'itlwm/hal_iwx/if_iwxreg.h').read_text(encoding='utf-8')
unknown_definition=re.search(r'^#define IWX_FW_CMD_VER_UNKNOWN\s+\d+',reg,re.M).group()
unknown=int(unknown_definition.split()[2])

identities={
    86: ('6b1e8d640327ca05b33830499a8ac356d12973d3f3ae550e2d86bdf80a53d736',4,None),
    92: ('c7092f1f78676f9e9c2c4d12716401db2116b009c5d7c464e8387c5b1c645d6f',5,2),
}
report={}
for api,(sha,phy,link) in identities.items():
    data=(root/f'itlwm/firmware/iwlwifi-gl-c0-fm-c0-{api}.ucode').read_bytes()
    assert hashlib.sha256(data).hexdigest()==sha
    commands={};caps={};version=None;pos=88
    while pos<len(data):
        kind,size=struct.unpack_from('<II',data,pos);pos+=8
        payload=data[pos:pos+size];assert len(payload)==size
        if kind==48:
            assert size%4==0
            for off in range(0,size,4):
                cmd,group,cver,nver=struct.unpack_from('4B',payload,off)
                commands[group,cmd]=(cver,nver)
        elif kind==36:
            version=struct.unpack('<III',payload)
        elif kind==30:
            index,bits=struct.unpack('<II',payload);caps[index]=bits
        pos+=(size+3)&~3
    assert version[0]==api and commands[1,8][0]==phy
    assert commands.get((3,9),(None,))[0]==link
    assert caps[110//32]&(1<<(110%32))
    # Current station security, queue, BA and separate RX-chain control APIs.
    assert commands.get((3,0x0a),(unknown,))[0] in (1,2,unknown)
    for key,want in {(3,8):2,(5,0x18):1,(5,0x17):3,(5,0x16):2,(5,8):2}.items():
        assert commands[key][0]==want,(api,key,commands.get(key))
    report[api]={'version':version,'sha256':sha,'phy':phy,'link':link,'mld':True}
pnvm=root/'itlwm/firmware/iwlwifi-gl-c0-fm-c0-92.pnvm'
assert hashlib.sha256(pnvm.read_bytes()).hexdigest()=='c528e7d9daa76d51e4ab11ae0814ca6461ebe4fde7c07272cd26e583e11ea7c1'
(out/'firmware-identities.json').write_text(json.dumps(report,indent=2),encoding='utf-8')

def declaration(name,text=reg):
    start=text.index('struct '+name+' {')
    return text[start:text.index('} __packed;',start)+11]+'\n'

start=iwx.index('    sc->sc_fwname = sc->sc_cfg->fwname;')
selection=iwx[start:iwx.index('    XYLog("Found PCI dev',start)]
start=iwx.index('\niwx_phy_ctxt_cmd_v3(')+1
phy='int ItlIwx::\n'+iwx[start:iwx.index('\n}',start)+2]
start=iwx.index('    uint8_t phy_ver =',iwx.index('\niwx_phy_ctxt_cmd('))
end=iwx.index('chains_dynamic, action, apply_time);',start)+len('chains_dynamic, action, apply_time);')
dispatch=iwx[start:end]
code=unknown_definition+'\n'+r'''
#include <cassert>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <vector>
#define __packed
#define XYLog(...) ((void)0)
#define htole32(x) (x)
#define IWX_LONG_GROUP 1
#define IWX_DATA_PATH_GROUP 5
#define IWX_PHY_CONTEXT_CMD 8
#define IWX_FW_CTXT_ACTION_REMOVE 2
#define IWX_FW_CMD_ID_AND_COLOR(i,c) ((i)|((c)<<8))
#define IWX_PHY_BAND_5 0
#define IWX_PHY_BAND_24 1
#define IWX_PHY_BAND_6 2
#define IWX_PHY_RX_CHAIN_VALID_POS 1
#define IWX_PHY_RX_CHAIN_CNT_POS 10
#define IWX_PHY_RX_CHAIN_MIMO_CNT_POS 12
#define IWX_AC_NUM 4
#define IEEE80211_IS_CHAN_6GHZ(c) ((c)->band==6)
#define IEEE80211_IS_CHAN_2GHZ(c) ((c)->band==2)
PRODUCTION_BE_DEFINES
#include "itlwm/hal_iwx/iwx_be_config.h"
struct ieee80211_channel {unsigned number,band;};
struct ieee80211com {};
struct config {const char*fwname;};
static config iwl_be200_gl_c0_fm_c0_cfg{"iwlwifi-gl-c0-fm-c0-86.ucode"};
struct property {int api=0;void setProperty(const char*,int value,int){api=value;}};
struct iwx_softc {ieee80211com sc_ic;config*sc_cfg;const char*sc_fwname;property*sc_pcitag;int phy=4,rlc=2;IwxBE::Selection sc_be{};};
struct iwx_phy_ctxt {unsigned id,color;ieee80211_channel*channel;};
static int argument=0;
static bool PE_parse_boot_argn(const char*,void*p,size_t){if(!argument)return false;*(int*)p=argument;return true;}
static uint8_t iwx_lookup_cmd_ver(iwx_softc*s,int group,int){return group==1?s->phy:s->rlc;}
static unsigned ieee80211_chan2number(ieee80211com*,ieee80211_channel*c){return c->number;}
static unsigned iwx_lmac_id(iwx_softc*,ieee80211_channel*){return 1;}
static unsigned iwx_phy_context_width(ieee80211com*,iwx_phy_ctxt*){return 3;}
static unsigned iwx_phy_context_ctrl_pos(ieee80211com*,iwx_phy_ctxt*){return 2;}
static unsigned iwx_fw_valid_rx_ant(iwx_softc*){return 3;}
static unsigned iwx_num_of_ant(unsigned){return 2;}
static unsigned iwx_cmd_id(unsigned cmd,unsigned group,unsigned version){return cmd|(group<<8)|(version<<16);}
struct sent {unsigned id;std::vector<uint8_t>bytes;};
static std::vector<sent>commands;
static int sendError=0;
static int iwx_send_cmd_pdu(iwx_softc*,unsigned id,int,size_t size,const void*p){
 const auto*bytes=(const uint8_t*)p;commands.push_back({id,{bytes,bytes+size}});return sendError;
}
class ItlIwx {public:int iwx_phy_ctxt_cmd_v3(iwx_softc*,iwx_phy_ctxt*,uint8_t,uint8_t,uint32_t,uint32_t);
 int route(iwx_softc*,iwx_phy_ctxt*,uint8_t,uint8_t,uint32_t,uint32_t);};
'''
var=(root/'itlwm/hal_iwx/if_iwxvar.h').read_text(encoding='utf-8')
be_defines='\n'.join(line for line in var.replace('\\\n','').splitlines()
    if re.match(r'#define\s+(?:IWL_CFG_(?:MAC|RF)_TYPE_|CSR_HW_RFID_)',line))
code=code.replace('PRODUCTION_BE_DEFINES',be_defines)
mld=(root/'itlwm/hal_iwx/if_iwxmld.h').read_text(encoding='utf-8')
code+='#pragma pack(push,1)\n'+declaration('iwx_fw_channel_info')+declaration('iwx_phy_context_cmd')
code+=declaration('iwx_ac_qos')+declaration('iwx_mld_he_backoff_conf',mld)+declaration('iwx_mld_link_config_cmd',mld)
code+='#pragma pack(pop)\nstatic_assert(sizeof(iwx_mld_link_config_cmd)==208,"LINK v1/v2 ABI");\n'
code+='static_assert(offsetof(iwx_mld_link_config_cmd,ref_bssid_addr)==156,"reference BSSID ABI");\n'
code+='static_assert(offsetof(iwx_mld_link_config_cmd,bssid_index)==164,"BSSID index ABI");\n'
code+='static bool select(iwx_softc*sc){\n'+selection+'return true;\n}\n'+phy
code+='\nint ItlIwx::route(iwx_softc*sc,iwx_phy_ctxt*ctxt,uint8_t chains_static,uint8_t chains_dynamic,uint32_t action,uint32_t apply_time){\n'+dispatch+'\nreturn -42;\n}\n'
code+=r'''
int main(){
 property prop;iwx_softc sc{};sc.sc_cfg=&iwl_be200_gl_c0_fm_c0_cfg;sc.sc_pcitag=&prop;sc.sc_be.family=IwxBE::GL;
 for(int api:{0,86,92}){argument=api;assert(select(&sc));assert(sc.sc_be.max_api==unsigned(api));}
 argument=93;assert(!select(&sc));
 config other{"other.ucode"};sc.sc_cfg=&other;sc.sc_be.family=IwxBE::None;assert(select(&sc)&&strcmp(sc.sc_fwname,"other.ucode")==0);
 ItlIwx driver;ieee80211_channel channel{5,6};iwx_phy_ctxt ctxt{2,3,&channel};
 for(int version:{3,4,5}){sc.phy=version;sc.rlc=2;commands.clear();assert(driver.route(&sc,&ctxt,1,1,0,0)==0);assert(commands.size()==2&&commands[0].bytes.size()==32&&commands[1].bytes.size()==32);
  const auto&b=commands[0].bytes;assert(b[0]==2&&b[1]==3&&b[8]==5&&b[12]==2&&b[13]==3&&b[14]==2&&b[16]==1);
  uint32_t word;memcpy(&word,b.data()+20,4);assert(word==(version==3?0x2806u:0u));memcpy(&word,commands[1].bytes.data()+4,4);assert(word==0x2806u);
 }
 sc.phy=5;commands.clear();assert(driver.route(&sc,&ctxt,1,1,IWX_FW_CTXT_ACTION_REMOVE,0)==0&&commands.size()==1);
 commands.clear();sendError=5;assert(driver.route(&sc,&ctxt,1,1,0,0)==5&&commands.size()==1);sendError=0;
 sc.rlc=0;commands.clear();assert(driver.route(&sc,&ctxt,1,1,0,0)==0&&commands.size()==1);
 std::puts("PASS GL86/GL92: production firmware selector and PHY v3/v4/v5 dispatch/32-byte wire layout, separate RLC, removal and errors");
}
'''
(out/'gl92-test.cpp').write_text(code,encoding='utf-8')
if os.name == 'nt':
    vswhere=Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio/Installer/vswhere.exe'
    vs=subprocess.check_output([str(vswhere),'-latest','-products','*','-requires',
        'Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],text=True).strip()
    cmd=out/'run.cmd'
    cmd.write_text('@echo off\ncall "'+str(Path(vs)/'VC/Auxiliary/Build/vcvars64.bat')+'" >nul\n'
        'cl /nologo /std:c++17 /EHsc /W3 /Od /Zi /fsanitize=address /I"'+str(root)+'" /Fe:gl92-test.exe gl92-test.cpp\n'
        'if errorlevel 1 exit /b %errorlevel%\ngl92-test.exe\n',encoding='utf-8')
    result=subprocess.run(['cmd.exe','/d','/c',str(cmd)],cwd=out,capture_output=True)
else:
    compiler=os.environ.get('CXX') or shutil.which('clang++') or shutil.which('c++')
    subprocess.run([compiler,'-std=c++17','-g','-fsanitize=address,undefined',
        '-I'+str(root),str(out/'gl92-test.cpp'),'-o',str(out/'gl92-test')],check=True)
    result=subprocess.run([str(out/'gl92-test')],cwd=out,capture_output=True)
log=(result.stdout+result.stderr).decode('mbcs' if os.name=='nt' else 'utf-8',errors='replace')
(out/'gl92-test.log').write_text(log,encoding='utf-8')
print(log)
raise SystemExit(result.returncode)