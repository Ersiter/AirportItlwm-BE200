"""Run production OWE/P-256/PTK/MIC code against independent cryptography vectors."""
import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[3])
p.add_argument('--output', type=Path)
a = p.parse_args()
root = a.repo.resolve()
tmp = tempfile.TemporaryDirectory(prefix='itlwm-owe-') if a.output is None else None
out = a.output.resolve() if a.output else Path(tmp.name)
out.mkdir(parents=True, exist_ok=True)
n = root/'itl80211/openbsd/net80211'
c = root/'itl80211/openbsd/crypto'
def read(path): return path.read_text(encoding='utf-8')
def func(text, name, ret):
    start = text.index('\n'+name+'(')+1
    return ret+'\n'+text[start:text.index('\n}', start)+2]+'\n'
def struct(text, name):
    start = text.index('struct '+name+' {')
    end = text.index('\n}', start)
    return text[start:text.index(';', end)+1]+'\n'
def enum(text, name):
    start = text.index('enum '+name+' {')
    return text[start:text.index('\n};', start)+3]+'\n'

compat = r'''
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#ifdef _MSC_VER
#include <intrin.h>
#define __attribute__(x)
#define __packed
#define bswap32 _byteswap_ulong
#define bswap64 _byteswap_uint64
#define _OSSwapInt32 _byteswap_ulong
#define _OSSwapInt64 _byteswap_uint64
#endif
#define BYTE_ORDER 1234
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
typedef unsigned int u_int;
typedef uint8_t u_int8_t; typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t; typedef uint64_t u_int64_t;
typedef uint8_t u_char;
typedef char *caddr_t;
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define NBBY 8
#define htole16(x) (x)
#define bzero(p,n) memset(p,0,n)
#define bcopy(a,b,n) memmove(b,a,n)
#define MIN(a,b) ((a)<(b)?(a):(b))
#define XYLog(...) ((void)0)
#define LE_READ_2(p) (uint16_t((p)[0]) | (uint16_t((p)[1])<<8))
#define BE_READ_2(p) (uint16_t((p)[1]) | (uint16_t((p)[0])<<8))
#define LE_WRITE_2(p,x) do{(p)[0]=(x)&255;(p)[1]=((x)>>8)&255;}while(0)
#define BE_WRITE_2(p,x) do{(p)[1]=(x)&255;(p)[0]=((x)>>8)&255;}while(0)
#define be32toh bswap32
#define be64toh bswap64
#define htobe32 bswap32
#define htobe64 bswap64
inline void explicit_bzero(void*p,size_t n){volatile uint8_t*q=(volatile uint8_t*)p;while(n--)*q++=0;}
void arc4random_buf(void*,size_t);
inline int timingsafe_bcmp(const void*a,const void*b,size_t n){const uint8_t*x=(const uint8_t*)a,*y=(const uint8_t*)b;uint8_t r=0;while(n--)r|=*x++^*y++;return r;}
'''
(out/'compat.h').write_text(compat, encoding='utf-8')
for file in ['types.h','sys/systm.h','sys/time.h','sys/param.h','sys/_endian.h','sys/endian.h','IOKit/IOLib.h']:
    dest=out/'shim'/file
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text('#include "compat.h"\n',encoding='utf-8')

crypto = read(n/'ieee80211_crypto.c')
header = read(n/'ieee80211_crypto.h')
wire = read(n/'ieee80211.h')
node = read(n/'ieee80211_node.h')
constants = '\n'.join(line for line in wire.splitlines() if line.startswith('#define EAPOL_KEY_') or line.startswith('#define IEEE80211_PMKID_LEN'))
constants += '\n#define IEEE80211_ADDR_LEN 6\n#define IEEE80211_PMK_LEN 32\n'
constants += '\n'.join(line for line in node.splitlines() if line.startswith('#define IEEE80211_OWE_'))
constants += '\n#define IEEE80211_NODE_PMK 0x0100\n#define IEEE80211_NODE_PMKID 0x0200\n'
for name in ['IEEE80211_ELEMID_EXTENSION','IEEE80211_ELEMID_EXT_OWE_DH_PARAM']:
    constants += '#define '+name+' '+re.search(name+r'\s*=\s*(\d+)',wire).group(1)+'\n'
code = '#include "compat.h"\n#include <vector>\n#include <cstdio>\n'
code += '#include <crypto/md5.h>\n#include <crypto/sha1.h>\n#include <crypto/sha2.h>\n#include <crypto/hmac.h>\n#include <crypto/aes.h>\n#include <crypto/cmac.h>\n#include <crypto/ec_p256_m31.h>\n'
code += '#include <crypto/key_wrap.h>\n#include <crypto/arc4.h>\n'
code += '#include "AirportItlwm/WCL/WCL.hpp"\n'+constants+'\n'
code += enum(header,'ieee80211_akm')+func(header,'ieee80211_is_sha256_akm','static inline int')
code += struct(node,'ieee80211_owe')
code += 'struct ieee80211_node {ieee80211_owe ni_owe{};uint8_t ni_pmk[32]{},ni_pmkid[16]{};unsigned ni_flags{};};\n'
code += '#pragma pack(push,1)\n'+struct(wire,'ieee80211_ptk')+struct(wire,'ieee80211_eapol_key')+'#pragma pack(pop)\n'
code += r'''
static std::vector<uint8_t> random_bytes;
static size_t random_cursor;
void arc4random_buf(void*p,size_t n){assert(random_cursor+n<=random_bytes.size());memcpy(p,random_bytes.data()+random_cursor,n);random_cursor+=n;}
static std::vector<uint8_t> unhex(const char*s){std::vector<uint8_t>v;while(*s){unsigned b;assert(sscanf(s,"%2x",&b)==1);v.push_back(b);s+=2;}return v;}
static bool zero(const void*p,size_t n){const uint8_t*q=(const uint8_t*)p;while(n--)if(*q++)return false;return true;}
static void seed(const std::vector<uint8_t>&v){random_bytes=v;random_cursor=0;}
static void eq(const uint8_t*p,const char*s){auto v=unhex(s);assert(memcmp(p,v.data(),v.size())==0);}
'''
for name,ret in [('ieee80211_owe_prepare','int'),('ieee80211_owe_process_response','int'),('ieee80211_prf','void'),('ieee80211_kdf','void'),('ieee80211_derive_ptk','void')]:
    code += func(crypto,name,ret)
start=crypto.index('typedef union _ANY_CTX {')
code+=crypto[start:crypto.index('} ANY_CTX;',start)+len('} ANY_CTX;')]+'\n'
code+=func(crypto,'ieee80211_eapol_key_mic','void')
code+=func(crypto,'ieee80211_eapol_key_check_mic','int')
code+=func(crypto,'ieee80211_eapol_key_decrypt','int')
# Use the actual association encoder block so the x-only key and IE length are checked.
output=read(n/'ieee80211_output.c')
start=output.index('    if (ni->ni_rsnakms == IEEE80211_AKM_OWE) {',output.index('\nieee80211_get_assoc_req('))
end=output.index('\n    }',start)+6
code+='static uint8_t* encode(uint8_t*frm,ieee80211_node*ni){\n'
code+=output[start:end].replace('ni->ni_rsnakms == IEEE80211_AKM_OWE','true')+'\nreturn frm;}\n'

code+='int main(){\n'
order=int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',16)
scalars=[1,2,order-1]+[int.from_bytes(hashlib.sha256(f'OWE-vector-{i}'.encode()).digest(),'big')%(order-1)+1 for i in range(5)]
# Include a leading-zero public x coordinate to verify fixed-width encoding.
scalars += [next(i for i in range(1,2048) if ec.derive_private_key(i,ec.SECP256R1()).public_key().public_numbers().x < 2**248)]
for index,scalar in enumerate(scalars):
    client=ec.derive_private_key(scalar,ec.SECP256R1())
    ap=ec.derive_private_key(0x123456789abcdef+index,ec.SECP256R1())
    public=client.public_key().public_numbers().x.to_bytes(32,'big')
    peer=ap.public_key().public_numbers().x.to_bytes(32,'big')
    shared=client.exchange(ec.ECDH(),ap.public_key())
    salt=public+peer+b'\x13\x00'
    prk=hmac.digest(salt,shared,'sha256')
    pmk=hmac.digest(prk,b'OWE Key Generation\x01','sha256')
    pmkid=hashlib.sha256(public+peer).digest()[:16]
    req=b'\xff\x23\x20\x13\x00'+public
    resp=b'\xff\x23\x20\x13\x00'+peer
    code+=' {ieee80211_node ni;\n'
    code+=f'seed(unhex("{scalar.to_bytes(32,"big").hex()}"));assert(ieee80211_owe_prepare(&ni)==0);eq(ni.ni_owe.public_key,"{public.hex()}");\n'
    code+=f'uint8_t frame[37];assert(encode(frame,&ni)==frame+37);eq(frame,"{req.hex()}");\n'
    code+=f'auto resp=unhex("{resp.hex()}");assert(ieee80211_owe_process_response(&ni,resp.data(),resp.size())==0);eq(ni.ni_pmk,"{pmk.hex()}");eq(ni.ni_pmkid,"{pmkid.hex()}");\n'
    code+='assert(ni.ni_owe.state==2&&zero(ni.ni_owe.private_key,32)&&(ni.ni_flags&IEEE80211_NODE_PMK));\n'
    aa=bytes.fromhex('020000000001'); spa=bytes.fromhex('020000000002')
    anonce=bytes(range(32)); snonce=bytes(range(32,64))
    context=aa+spa+anonce+snonce
    material=b''.join(hmac.digest(pmk,i.to_bytes(2,'little')+b'Pairwise key expansion'+context+(384).to_bytes(2,'little'),'sha256') for i in [1,2])[:48]
    code+=f'ieee80211_ptk ptk{{}};auto aa=unhex("{aa.hex()}"),spa=unhex("{spa.hex()}"),an=unhex("{anonce.hex()}"),sn=unhex("{snonce.hex()}");ieee80211_derive_ptk(IEEE80211_AKM_OWE,ni.ni_pmk,aa.data(),spa.data(),an.data(),sn.data(),&ptk);eq((const uint8_t*)&ptk,"{material.hex()}");\n'
    # RFC 8110 group 19: HMAC-SHA-256-128 over the complete EAPOL frame.
    eapol=bytearray(99); eapol[0]=2;eapol[1]=3;eapol[2:4]=(95).to_bytes(2,'big');eapol[4]=2;eapol[5:7]=(0x108).to_bytes(2,'big')
    eapol[17:49]=snonce
    mic=hmac.digest(material[:16],bytes(eapol),'sha256')[:16]
    code+=f'auto packet=unhex("{eapol.hex()}");auto*key=(ieee80211_eapol_key*)packet.data();ieee80211_eapol_key_mic(key,ptk.kck,IEEE80211_AKM_OWE);eq(key->mic,"{mic.hex()}");\n'
    code+='assert(ieee80211_eapol_key_check_mic(key,ptk.kck,IEEE80211_AKM_OWE)==0);packet[17]^=1;assert(ieee80211_eapol_key_check_mic(key,ptk.kck,IEEE80211_AKM_OWE)!=0);\n'
    # The same descriptor version selects AES-CMAC for SAE.
    cmac=CMAC(algorithms.AES(material[:16]));cmac.update(bytes(eapol));sae_mic=cmac.finalize()
    code+=f'packet=unhex("{eapol.hex()}");key=(ieee80211_eapol_key*)packet.data();ieee80211_eapol_key_mic(key,ptk.kck,IEEE80211_AKM_SAE);eq(key->mic,"{sae_mic.hex()}");\n'
    keydata=bytes.fromhex('dd16000fac010100')+bytes(range(16))
    wrapped=aes_key_wrap(material[16:32],keydata)
    encrypted=bytearray(eapol); encrypted[97:99]=len(wrapped).to_bytes(2,'big')
    encrypted+=wrapped
    code+=f'auto encrypted=unhex("{encrypted.hex()}");key=(ieee80211_eapol_key*)encrypted.data();assert(ieee80211_eapol_key_decrypt(key,ptk.kek)==0);eq((const uint8_t*)(key+1),"{keydata.hex()}");\n'
    encrypted[-1]^=1
    code+=f'auto corrupted=unhex("{encrypted.hex()}");assert(ieee80211_eapol_key_decrypt((ieee80211_eapol_key*)corrupted.data(),ptk.kek)!=0);}}\n'

code+=r'''
 {ieee80211_node ni;std::vector<uint8_t>invalid(64,0);auto valid=unhex("0000000000000000000000000000000000000000000000000000000000000001");
 auto order=unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");invalid.insert(invalid.end(),order.begin(),order.end());invalid.insert(invalid.end(),valid.begin(),valid.end());seed(invalid);assert(ieee80211_owe_prepare(&ni)==0&&random_cursor==128);
 seed(std::vector<uint8_t>(3200));assert(ieee80211_owe_prepare(&ni)!=0&&zero(&ni.ni_owe,sizeof(ni.ni_owe)));}
 auto valid=unhex("ff232013006b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
 std::vector<std::vector<uint8_t>> bad;
 for(size_t len=0;len<valid.size();len++)bad.emplace_back(valid.begin(),valid.begin()+len);
 auto wronggroup=valid;wronggroup[3]=20;bad.push_back(wronggroup);
 auto duplicate=valid;duplicate.insert(duplicate.end(),valid.begin(),valid.end());bad.push_back(duplicate);
 auto trailing=valid;trailing.push_back(0);bad.push_back(trailing);
 for(auto x:{"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff","ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","0000000000000000000000000000000000000000000000000000000000000001"}){auto b=valid;auto p=unhex(x);memcpy(b.data()+5,p.data(),32);bad.push_back(b);}
 for(auto&b:bad){ieee80211_node ni;seed(unhex("0000000000000000000000000000000000000000000000000000000000000002"));assert(ieee80211_owe_prepare(&ni)==0);memset(ni.ni_pmk,0xaa,32);assert(ieee80211_owe_process_response(&ni,b.data(),b.size())!=0);assert(zero(&ni.ni_owe,sizeof(ni.ni_owe))&&zero(ni.ni_pmk,32)&&!(ni.ni_flags&IEEE80211_NODE_PMK));}
 {ieee80211_node ni;assert(ieee80211_owe_process_response(&ni,valid.data(),valid.size())!=0);seed(unhex("0000000000000000000000000000000000000000000000000000000000000002"));assert(ieee80211_owe_prepare(&ni)==0);auto extra=unhex("00016101018c");extra.insert(extra.end(),valid.begin(),valid.end());assert(ieee80211_owe_process_response(&ni,extra.data(),extra.size())==0);}
 AirportWCL::JoinRequest j{};j.lowerAuth=1;
 auto rsn=unhex("30140100000fac040100000fac040100000fac12c000");j.rsnLength=rsn.size();memcpy(j.rsn,rsn.data(),rsn.size());
 assert(AirportWCL::classifyLegacyAuth(j)==AirportWCL::LegacyAuth::EnhancedOpen);
 j.keyLength=1;assert(AirportWCL::classifyLegacyAuth(j)==AirportWCL::LegacyAuth::Invalid);j.keyLength=0;
 j.upperAuth=8;assert(AirportWCL::classifyLegacyAuth(j)==AirportWCL::LegacyAuth::Invalid);j.upperAuth=0;
 for(size_t len=1;len<rsn.size();len++){j.rsnLength=len;assert(AirportWCL::classifyLegacyAuth(j)==AirportWCL::LegacyAuth::Invalid);}
 j.rsnLength=rsn.size();j.rsn[7]=2;assert(AirportWCL::classifyLegacyAuth(j)==AirportWCL::LegacyAuth::Invalid);
 j.rsnLength=0;assert(AirportWCL::classifyLegacyAuth(j)==AirportWCL::LegacyAuth::Open);
 std::puts("PASS OWE: independent P-256/PMK/PMKID/PTK/OWE HMAC-SHA-256-128/SAE CMAC/AES-unwrap vectors, x-only association encoding, scalar rejection, malformed DH and WCL security classification");
}
'''
(out/'owe-test.cpp').write_text(code,encoding='utf-8')
# MSVC rejects C99 compound literals in this C++ dependency. Normalize only
# those two zero-array expressions; all curve arithmetic stays unchanged.
curve=read(c/'ec_p256_m31.c')
assert curve.count('(const uint32_t[9]){0}') == 2
curve=curve.replace('(const uint32_t[9]){0}', 'host_zero')
curve='static const unsigned int host_zero[9] = {};\n'+curve
(out/'curve.cpp').write_text(curve,encoding='utf-8')
sources=[out/'owe-test.cpp',out/'curve.cpp']+[c/(f+'.c') for f in ['i31','sha2','sha1','md5','hmac','aes','cmac','key_wrap','arc4']]
if os.name=='nt':
    vswhere=Path(os.environ.get('ProgramFiles(x86)',r'C:\Program Files (x86)'))/'Microsoft Visual Studio/Installer/vswhere.exe'
    vs=subprocess.check_output([str(vswhere),'-latest','-products','*','-requires','Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],text=True).strip()
    vcvars=Path(vs)/'VC/Auxiliary/Build/vcvars64.bat'
    command='cl /nologo /TP /std:c++17 /EHsc /W3 /Od /Zi /fsanitize=address /FIcompat.h /I. /Ishim '
    command+=' '.join('/I"'+str(x)+'"' for x in [root,root/'itl80211/openbsd'])+' /Fe:owe-test.exe '
    command+=' '.join('"'+str(x)+'"' for x in sources)
    script=out/'run.cmd'
    script.write_text('@echo off\ncall "'+str(vcvars)+'" >nul\n'+command+'\nif errorlevel 1 exit /b %errorlevel%\nowe-test.exe\n',encoding='utf-8')
    result=subprocess.run(['cmd.exe','/d','/c',str(script)],cwd=out,capture_output=True)
else:
    raise RuntimeError('This harness currently targets the Windows MSVC development host')
print(result.stdout.decode('utf-8',errors='replace'))
print(result.stderr.decode('utf-8',errors='replace'))
if result.returncode: raise SystemExit(result.returncode)
if tmp: tmp.cleanup()
