"""Check patch boundaries and compile the actual opt-in expression."""
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

source = (Path(sys.argv[1])/'BrcmPatchRAM/BlueToolFixup.cpp').read_text()
def array(name):
    body = re.search(name+r'\[\]\s*=\s*\{([^}]+)}',source).group(1)
    return bytes(int(value,16) for value in re.findall(r'0x[0-9A-Fa-f]+',body))
original,patched = array('kBE200StoredKeyOriginal'),array('kBE200StoredKeyPatched')
assert len(original) == len(patched) == 8
assert [i for i,(a,b) in enumerate(zip(original,patched)) if a != b] == [4,5]
assert original[2:4] == patched[2:4] == b'\x0d\x0c'
assert patched[4:6] == b'\xff\xff'
page = bytes(0x150)+original+bytes(4096-0x150-8)
changed = page.replace(original,patched)
assert len(changed) == 4096 and [i for i,(a,b) in enumerate(zip(page,changed)) if a != b] == [0x154,0x155]
assert original not in changed
other = original[:2]+b'\x03\x0c'+original[4:]
assert other.replace(original,patched) == other
truncated = original[:-1]
assert truncated.replace(original,patched) == truncated
expression = re.search(r'shouldPatchBE200StoredKey = (getKernelVersion\(\).*?);',source,re.S).group(1)
program = '''#include <cstdio>
#include <cstring>
namespace KernelVersion { enum { Tahoe = 25 }; }
int majorVersion, minorVersion; bool argument;
int getKernelVersion() { return majorVersion; }
int getKernelMinorVersion() { return minorVersion; }
bool checkKernelArgument(const char *arg) { return argument && std::strcmp(arg,"-btlfxbe200key") == 0; }
int main() {
    for (majorVersion = 24; majorVersion <= 26; ++majorVersion)
        for (minorVersion = 3; minorVersion <= 5; ++minorVersion)
            for (int enabled = 0; enabled <= 1; ++enabled) {
                argument = enabled;
                bool actual = EXPRESSION;
                bool expected = majorVersion == 25 && minorVersion == 4 && enabled;
                if (actual != expected) return 1;
            }
    std::puts("18 version/opt-in combinations passed; descriptor changes only two capability bytes");
}
'''.replace('EXPRESSION',expression)
with tempfile.TemporaryDirectory(prefix='bt-key-test-') as directory:
    directory = Path(directory)
    test,binary = directory/'gate.cpp',directory/'gate'
    test.write_text(program)
    subprocess.run(shlex.split(os.environ.get('CXX','c++'))+['-std=c++14','-Wall','-Wextra','-Werror',str(test),'-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
