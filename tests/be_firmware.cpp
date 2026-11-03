#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <vector>
#include "hardware-defs.h"
#include "itlwm/hal_iwx/iwx_be_config.h"

#define XYLog(...) ((void)0)
#define isset(a,b) ((a)[(b)/8] & (1U<<((b)%8)))
struct Property {
    std::map<std::string,std::string> values;
    void setProperty(const char *key,const char *value){values[key]=value;}
    void setProperty(const char *key,uint64_t value,unsigned){values[key]=std::to_string(value);}
} property;
struct iwx_fw_info {int fw_status=IWX_FW_STATUS_NONE;bool allocated=false;};
struct iwx_softc {
    IwxBE::Selection sc_be{};
    iwx_fw_info sc_fw;
    const char *sc_fwname="legacy.ucode";
    unsigned sc_hw_rev=(IWL_CFG_MAC_TYPE_GL<<4)|(2<<2);
    unsigned sc_hw_rf_id=(IWL_CFG_RF_TYPE_FM<<12)|(2<<8),sc_fw_api=0;
    uint8_t sc_enabled_capa[32]{};
    Property *sc_pcitag=&property;
    unsigned cnvi=(1U<<24)|0x900,crf=(2U<<24)|0x910,otp=0;
    bool locked=false,lockAvailable=true,badABI92=false,wrongAPI92=false;
    int parseError92=0,legacyResult=0;
    unsigned parsed=0,nicReads=0;
};
static std::set<std::string> resources;
static std::vector<std::string> attempted;
static void *getFWDescByName(const char *name){attempted.push_back(name);return resources.count(name)?(void*)1:nullptr;}
static bool iwx_nic_lock(iwx_softc*s){s->locked=s->lockAvailable;return s->locked;}
static void iwx_nic_unlock(iwx_softc*s){assert(s->locked);s->locked=false;}
static unsigned iwx_read_prph(iwx_softc*s,unsigned address){
    assert(s->locked);++s->nicReads;
    switch(address){
    case GEN3_UMAC_PRPH_OFFSET+IWX_WFPM_CTRL_REG:return 0;
    case GEN3_UMAC_PRPH_OFFSET+IWX_CNVI_AUX_MISC_CHIP:return s->cnvi;
    case IWX_SD_REG_VER_GEN2:return s->crf;
    case GEN3_UMAC_PRPH_OFFSET+IWX_WFPM_OTP_CFG1_ADDR:return s->otp;
    default:assert(false);return 0;
    }
}
static void iwx_write_prph(iwx_softc*s,unsigned address,unsigned value){
    assert(s->locked&&address==GEN3_UMAC_PRPH_OFFSET+IWX_WFPM_CTRL_REG&&value==0x80000000);
}
static void iwx_fw_info_free(iwx_fw_info*fw){fw->allocated=false;}
static unsigned iwx_lookup_cmd_ver(iwx_softc*s,unsigned group,unsigned cmd){
    if(group==1&&cmd==8)return s->badABI92&&s->sc_be.selected_api==92?6:5;
    if(group==3&&cmd==9)return s->sc_be.selected_api==86?IWX_FW_CMD_VER_UNKNOWN:2;
    if(group==3&&cmd==8)return 2;
    if(group==3&&cmd==0x0a)return IWX_FW_CMD_VER_UNKNOWN;
    if(group==5&&cmd==0x18)return 1;
    if(group==5&&cmd==0x17)return 3;
    if(group==5&&(cmd==0x16||cmd==8))return 2;
    return 0xff;
}
static unsigned iwx_read_umac_prph(iwx_softc*s,unsigned address){return iwx_read_prph(s,GEN3_UMAC_PRPH_OFFSET+address);}
static void iwx_write_umac_prph(iwx_softc*s,unsigned address,unsigned value){iwx_write_prph(s,GEN3_UMAC_PRPH_OFFSET+address,value);}
class ItlIwx {public:
    unsigned iwx_lookup_cmd_ver(iwx_softc*s,unsigned group,unsigned cmd){return ::iwx_lookup_cmd_ver(s,group,cmd);}
    int iwx_read_firmware(iwx_softc*);
    int iwx_read_firmware_file(iwx_softc*s){
        if(s->sc_be.family==IwxBE::None)return s->legacyResult;
        assert(!s->sc_fw.allocated);
        ++s->parsed;
        if(s->sc_be.selected_api==92&&s->parseError92)return s->parseError92;
        s->sc_fw.allocated=true;s->sc_fw.fw_status=IWX_FW_STATUS_DONE;
        s->sc_fw_api=s->sc_be.selected_api+(s->wrongAPI92&&s->sc_be.selected_api==92?1:0);
        s->sc_enabled_capa[IWX_UCODE_TLV_CAPA_MLD_API_SUPPORT/8]|=1U<<(IWX_UCODE_TLV_CAPA_MLD_API_SUPPORT%8);
        return 0;
    }
};
#include "loader.inc"

static iwx_softc state(IwxBE::Family family=IwxBE::GL){
    resources.clear();attempted.clear();property.values.clear();
    iwx_softc s;s.sc_be.family=family;
    if(family==IwxBE::BZ)s.sc_hw_rev=IWL_CFG_MAC_TYPE_BZ<<4;
    return s;
}
static void addPair(IwxBE::Selection selection,unsigned index){
    assert(IwxBE::candidate(selection,index));resources.insert(selection.firmware);resources.insert(selection.pnvm);
}
static void prepareGL(iwx_softc&s){
    assert(IwxBE::makePrefix(s.sc_be,IWL_CFG_MAC_TYPE_GL,2,s.sc_hw_rf_id));
}

int main(int argc,char**argv){
    if(argc>1&&strcmp(argv[1],"--abi")==0){
        assert(argc==13);unsigned input[11];for(int i=0;i<11;++i)input[i]=unsigned(atoi(argv[i+2]));
        auto lookup=[&](unsigned group,unsigned cmd)->unsigned{
            if(group==1&&cmd==8)return input[2];if(group==3&&cmd==9)return input[3];
            if(group==3&&cmd==8)return input[4];if(group==3&&cmd==0x0a)return input[5];
            if(group==5&&cmd==0x18)return input[6];if(group==5&&cmd==0x17)return input[7];
            if(group==5&&cmd==0x16)return input[8];if(group==5&&cmd==8)return input[9];
            return 0xff;
        };
        assert(IwxBE::compatible(input[0],input[1]!=0,lookup)==(input[10]!=0));return 0;
    }
    for(unsigned device:{0x272b,0xa840,0x7740,0x4d40})assert(IwxBE::pciFamily(device)!=IwxBE::None);
    for(unsigned device:{0x2725,0x2729,0xe440,0xffff})assert(IwxBE::pciFamily(device)==IwxBE::None);
    assert(!IwxBE::macMatches(IwxBE::GL,IWL_CFG_MAC_TYPE_BZ));
    assert(!IwxBE::macMatches(IwxBE::BZ,IWL_CFG_MAC_TYPE_GL));
    assert(IwxBE::bzStep(IWL_CFG_MAC_TYPE_BZ,0x930)==1);
    assert(IwxBE::bzStep(IWL_CFG_MAC_TYPE_BZ,0x900)==0);
    assert(IwxBE::bzStep(IWL_CFG_MAC_TYPE_BZ_W,0)==1);
    assert(IwxBE::mappedRF((2U<<24)|0x910,0,0)==((IWL_CFG_RF_TYPE_FM<<12)|(2<<8)));
    assert((IwxBE::mappedRF(0x410,1U<<19,1U<<4)&0x30000000)==0x30000000);
    assert(IwxBE::mappedRF(0xfff,0,0)==0);

    ItlIwx driver;
    {
        auto s=state();prepareGL(s);assert(IwxBE::apiAt(s.sc_be,0)==86&&IwxBE::apiAt(s.sc_be,1)==0);
        addPair(s.sc_be,0);assert(driver.iwx_read_firmware(&s)==0&&s.sc_fw_api==86);
        assert(property.values["AirportItlwm-PNVMName"]=="iwlwifi-gl-c0-fm-c0.pnvm");
    }
    for(int failure:{0,1,2,3,4}){
        auto s=state();s.sc_be.max_api=92;prepareGL(s);addPair(s.sc_be,0);addPair(s.sc_be,1);
        if(failure==1)resources.erase("iwlwifi-gl-c0-fm-c0-92.ucode");
        if(failure==2)resources.erase("iwlwifi-gl-c0-fm-c0-92.pnvm");
        if(failure==3)s.badABI92=true;
        if(failure==4)s.wrongAPI92=true;
        assert(driver.iwx_read_firmware(&s)==0&&s.sc_fw_api==(failure?86U:92U));
        assert(property.values["AirportItlwm-FirmwareAPI"]==(failure?"86":"92"));
        assert(property.values["AirportItlwm-FirmwareCandidateIndex"]==(failure?"1":"0"));
        assert(s.sc_fw.allocated&&s.sc_fw.fw_status==IWX_FW_STATUS_DONE);
    }
    {
        auto s=state();s.sc_be.max_api=92;prepareGL(s);addPair(s.sc_be,0);addPair(s.sc_be,1);s.parseError92=EINVAL;
        assert(driver.iwx_read_firmware(&s)==0&&s.parsed==2&&s.sc_fw_api==86);
    }
    {
        auto s=state();s.sc_be.max_api=92;prepareGL(s);addPair(s.sc_be,0);addPair(s.sc_be,1);s.parseError92=ENOMEM;
        assert(driver.iwx_read_firmware(&s)==ENOMEM&&s.parsed==1);
    }
    {
        auto s=state();s.sc_be.max_api=92;assert(driver.iwx_read_firmware(&s)==ENOENT&&s.parsed==0);
        assert(property.values.count("AirportItlwm-FirmwareAPI")==0);
    }
    {
        auto s=state();s.sc_be.max_api=92;prepareGL(s);addPair(s.sc_be,0);s.badABI92=true;
        assert(driver.iwx_read_firmware(&s)==ENOTSUP&&!s.sc_fw.allocated);
        assert(s.sc_fw.fw_status==IWX_FW_STATUS_NONE&&property.values.count("AirportItlwm-FirmwareAPI")==0);
    }
    {
        auto s=state(IwxBE::BZ);s.sc_hw_rev=IWL_CFG_MAC_TYPE_BZ_W<<4;s.cnvi=0x900;
        assert(IwxBE::makePrefix(s.sc_be,IWL_CFG_MAC_TYPE_BZ_W,1,s.sc_hw_rf_id));addPair(s.sc_be,0);
        assert(driver.iwx_read_firmware(&s)==0&&strcmp(s.sc_be.prefix,"iwlwifi-bz-b0-fm-c0")==0);
    }
    {
        auto s=state();s.sc_hw_rf_id|=1U<<28;assert(driver.iwx_read_firmware(&s)==ENOTSUP&&s.parsed==0);
    }
    {
        auto s=state();s.sc_fw.fw_status=IWX_FW_STATUS_INPROGRESS;
        assert(driver.iwx_read_firmware(&s)==EBUSY&&s.parsed==0);
    }
    {
        auto s=state();s.sc_hw_rev=(IWL_CFG_MAC_TYPE_GL<<4)|(1<<2);
        s.sc_hw_rf_id=(IWL_CFG_RF_TYPE_FM<<12)|(1<<8);
        assert(IwxBE::makePrefix(s.sc_be,IWL_CFG_MAC_TYPE_GL,1,s.sc_hw_rf_id));
        assert(IwxBE::apiAt(s.sc_be,0)==92&&IwxBE::apiAt(s.sc_be,1)==86);
        addPair(s.sc_be,1);
        assert(driver.iwx_read_firmware(&s)==0&&s.sc_fw_api==86);
        assert(strcmp(s.sc_be.firmware,"iwlwifi-gl-b0-fm-b0-86.ucode")==0);
    }
    for(unsigned rf:{unsigned(IWL_CFG_RF_TYPE_FM),unsigned(IWL_CFG_RF_TYPE_GF)}){
        auto s=state(IwxBE::BZ);s.sc_hw_rf_id=(rf<<12)|((rf==IWL_CFG_RF_TYPE_FM?2:0)<<8);
        assert(IwxBE::makePrefix(s.sc_be,IWL_CFG_MAC_TYPE_BZ,1,s.sc_hw_rf_id));addPair(s.sc_be,0);
        assert(driver.iwx_read_firmware(&s)==0&&s.sc_fw_api==92&&s.nicReads==2&&!s.locked);
        assert(IWX_CSR_HW_REV_STEP(s.sc_hw_rev)==1&&IwxBE::apiAt(s.sc_be,1)==0);
    }
    {
        auto s=state(IwxBE::BZ);s.sc_hw_rf_id=0;
        IwxBE::Selection selection{};selection.family=IwxBE::BZ;
        assert(IwxBE::makePrefix(selection,IWL_CFG_MAC_TYPE_BZ,1,(IWL_CFG_RF_TYPE_FM<<12)|(2<<8)));addPair(selection,0);
        assert(driver.iwx_read_firmware(&s)==0&&s.nicReads==4&&s.sc_fw_api==92&&!s.locked);
    }
    {
        auto s=state(IwxBE::BZ);s.lockAvailable=false;
        assert(driver.iwx_read_firmware(&s)==EBUSY&&s.nicReads==0);
    }
    {
        auto s=state(IwxBE::None);s.legacyResult=37;
        assert(driver.iwx_read_firmware(&s)==37&&attempted.empty());
    }
    puts("PASS BE family: GL/BZ hardware identity, stepping, RF mapping, paired PNVM, descending adapted API candidates, missing resources, ABI rejection, parser errors and legacy path");
}
