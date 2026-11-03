"""Validate BE firmware pairs and execute production hardware selection/loading on the host."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
temporary = tempfile.TemporaryDirectory(prefix='itlwm-be-family-') if args.output is None else None
out = args.output.resolve() if args.output else Path(temporary.name)
out.mkdir(parents=True, exist_ok=True)
source = (root/'itlwm/hal_iwx/ItlIwx.cpp').read_text(encoding='utf-8')
headers = '\n'.join((root/'itlwm/hal_iwx'/name).read_text(encoding='utf-8')
    for name in ('if_iwxvar.h', 'if_iwxreg.h', 'if_iwxmld.h'))
names = {'IWL_CFG_MAC_TYPE_GL','IWL_CFG_MAC_TYPE_BZ','IWL_CFG_MAC_TYPE_BZ_W',
    'IWL_CFG_RF_TYPE_FM','IWL_CFG_RF_TYPE_GF','CSR_HW_RFID_TYPE','CSR_HW_RFID_STEP',
    'CSR_HW_RFID_IS_CDB','CSR_HW_REV_TYPE','IWX_CSR_HW_REV_STEP','GEN3_UMAC_PRPH_OFFSET',
    'IWX_WFPM_CTRL_REG','IWX_CNVI_AUX_MISC_CHIP','IWX_SD_REG_VER_GEN2','IWX_WFPM_OTP_CFG1_ADDR',
    'IWX_FW_STATUS_NONE','IWX_FW_STATUS_INPROGRESS','IWX_FW_STATUS_DONE','IWX_FW_CMD_VER_UNKNOWN',
    'IWX_UCODE_TLV_CAPA_MLD_API_SUPPORT'}
definitions = {}
for line in headers.replace('\\\n','').splitlines():
    match = re.match(r'#define\s+(\w+)',line)
    if match and match[1] in names:
        definitions[match[1]]=line
assert definitions.keys()==names, names-definitions.keys()
(out/'hardware-defs.h').write_text('\n'.join(definitions.values())+'\n',encoding='utf-8')
start=source.index('\niwx_read_firmware(struct')+1
end=source.index('\n}',start)+2
(out/'loader.inc').write_text('int ItlIwx::\n'+source[start:end]+'\n',encoding='utf-8')
test=root/'tests/be_firmware.cpp'
if os.name=='nt':
    vswhere=Path(os.environ['ProgramFiles(x86)'])/'Microsoft Visual Studio/Installer/vswhere.exe'
    vs=subprocess.check_output([str(vswhere),'-latest','-products','*','-requires',
        'Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],text=True).strip()
    command=out/'compile.cmd'
    command.write_text('@echo off\ncall "'+str(Path(vs)/'VC/Auxiliary/Build/vcvars64.bat')+'" >nul\n'
        'cl /nologo /std:c++17 /EHsc /W3 /Od /Zi /fsanitize=address /I"'+str(root)+'" /I"'+str(out)+'" /Fe:be-test.exe "'+str(test)+'"\n',encoding='utf-8')
    subprocess.run(['cmd.exe','/d','/c',str(command)],cwd=out,check=True)
    tools=(Path(vs)/'VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt').read_text().strip()
    runtime=Path(vs)/'VC/Tools/MSVC'/tools/'bin/Hostx64/x64'
    os.environ['PATH']=str(runtime)+os.pathsep+os.environ['PATH']
    binary=out/'be-test.exe'
else:
    binary=out/'be-test'
    compiler=os.environ.get('CXX') or shutil.which('clang++') or shutil.which('c++')
    subprocess.run([compiler,'-std=c++17','-g','-Wall','-Wextra','-Werror',
        '-fsanitize=address,undefined','-I'+str(root),'-I'+str(out),str(test),'-o',str(binary)],check=True)
subprocess.run([str(binary)],check=True)

manifest=json.loads((root/'tests/be_firmware.json').read_text(encoding='utf-8'))
firmware=root/'itlwm/firmware'
for item in manifest:
    data=(firmware/item['name']).read_bytes()
    assert hashlib.sha256(data).hexdigest()==item['sha256'],item['name']
    if not item['name'].endswith('.ucode'):
        continue
    commands={};capabilities={};version=None;pos=88
    while pos<len(data):
        kind,size=struct.unpack_from('<II',data,pos);pos+=8
        body=data[pos:pos+size];assert len(body)==size
        if kind==48:
            assert size%4==0
            for offset in range(0,size,4):
                cmd,group,command,notification=struct.unpack_from('4B',body,offset)
                commands[group,cmd]=command
        elif kind==36:
            version=struct.unpack('<III',body)
        elif kind==30:
            index,bits=struct.unpack('<II',body);capabilities[index]=bits
        pos+=(size+3)&~3
    api=item['api'];assert version[0]==api
    assert (firmware/item['pnvm']).is_file()
    unknown=int(definitions['IWX_FW_CMD_VER_UNKNOWN'].split()[2],0)
    values=[commands.get(key,unknown) for key in [(1,8),(3,9),(3,8),(3,0x0a),(5,0x18),(5,0x17),(5,0x16),(5,8)]]
    mld=bool(capabilities.get(110//32,0)&(1<<(110%32)))
    inputs=[api,int(mld),*values]
    subprocess.run([str(binary),'--abi',*map(str,inputs), '1'],check=True)
    for index in [0,1,2,3,4,5,6,7,8,9]:
        invalid=inputs.copy();invalid[index]=0 if index==1 else 254
        subprocess.run([str(binary),'--abi',*map(str,invalid),'0'],check=True)
    print(item['name']+': hash, firmware API, paired PNVM and production command ABI passed',flush=True)

for platform in ['Info.plist','Sequoia-Info.plist']:
    info=plistlib.loads((root/'AirportItlwm/WCL'/platform).read_bytes())
    matching=' '.join(str(personality.get('IOPCIMatch','')) for personality in info['IOKitPersonalities'].values())
    for device in ['272b','a840','7740','4d40']:
        assert '0x'+device+'8086' in matching.lower(),(platform,device)
        assert re.search(r'IWL_PCI_DEVICE\(0x'+device+r', PCI_ANY_ID, iwl_(?:gl|bz)_trans_cfg\)',source)
print('PASS paired platform personalities and BE transport PCI table')
