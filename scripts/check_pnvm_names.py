"""Resolve the driver's generated PNVM names against actual firmware resources."""
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
header = (root / 'itl80211/linux/kernel.h').read_text()
source = (root / 'itlwm/hal_iwx/ItlIwx.cpp').read_text()
function = re.search(r'static inline const char \*reverse_strchr\(.*?\n}', header, re.S).group()
start = source.index('    strlcpy(fwname_copy, sc->sc_fwname')
end = source.index('    fwData = getFWDescByName(pnvm_name);', start)
fragment = source[start:end]
program = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef __APPLE__
static size_t strlcpy(char *dest, const char *src, size_t capacity) {
    size_t length = strlen(src);
    if (capacity) {
        size_t copied = length < capacity - 1 ? length : capacity - 1;
        memcpy(dest, src, copied);
        dest[copied] = 0;
    }
    return length;
}
#endif
FUNCTION
#define strrchr(x, y) reverse_strchr((x), (y))
static void require(int success, const char *message) {
    if (!success) { fprintf(stderr, "%s\n", message); exit(1); }
}
int main(int argc, char **argv) {
    require(argc == 2, "expected a firmware name or --search-contract");
    if (strcmp(argv[1], "--search-contract") == 0) {
        const char *text = "-a--";
        const char *empty = "";
        require(strrchr(text, '-') == text + 3, "last separator mismatch");
        require(strrchr(text, 'a') == text + 1, "single match mismatch");
        require(strrchr(text, 'z') == NULL, "absent character returned a pointer");
        require(strrchr(text, 0) == text + 4, "terminating NUL mismatch");
        require(strrchr(empty, '-') == NULL, "empty string returned a match");
        require(strrchr(empty, 0) == empty, "empty string terminating NUL mismatch");
        puts("separator search contract passed");
        return 0;
    }
    struct pci_property {
        char value[64] = {};
        void setProperty(const char *key, const char *name) {
            require(strcmp(key, "AirportItlwm-PNVMName") == 0, "PNVM property key mismatch");
            snprintf(value, sizeof(value), "%s", name);
        }
    } property;
    struct { const char *sc_fwname; pci_property *sc_pcitag; }
        state = {argv[1], &property}, *sc = &state;
    char fwname_copy[64], pnvm_name[64];
    const char *find;
FRAGMENT
    require(strcmp(property.value, pnvm_name) == 0, "PNVM diagnostic mismatch");
    puts(pnvm_name);
    return 0;
out:
    return 1;
}
'''.replace('FUNCTION', function).replace('FRAGMENT', fragment)

with tempfile.TemporaryDirectory(prefix='itlwm-pnvm-name-') as folder:
    folder = Path(folder)
    test, binary = folder / 'name.cpp', folder / 'name'
    test.write_text(program)
    subprocess.run(shlex.split(os.environ.get('CXX', 'c++')) + [
        '-std=c++17', '-Wall', '-Wextra', str(test), '-o', str(binary)
    ], check=True)
    firmware_names = set(re.findall(r'"(iwlwifi-[^"]+\.ucode)"', source))
    resources = sorted((root / 'itlwm/firmware').glob('*.pnvm'))
    assert any(path.name == 'iwlwifi-gl-c0-fm-c0.pnvm' for path in resources)
    def expected_resource(name):
        if name == 'iwlwifi-gl-c0-fm-c0-92.ucode':
            return 'iwlwifi-gl-c0-fm-c0-92.pnvm'
        return name.rsplit('-', 1)[0] + '.pnvm'
    assert 'iwlwifi-gl-c0-fm-c0-92.ucode' in firmware_names
    assert any(path.name == 'iwlwifi-gl-c0-fm-c0-92.pnvm' for path in resources)
    for resource in resources:
        candidates = [name for name in firmware_names if expected_resource(name) == resource.name]
        assert candidates, f'no configured firmware for {resource.name}'
        for firmware in candidates:
            generated = subprocess.check_output([str(binary), firmware], text=True).strip()
            assert generated == resource.name, f'{firmware}: generated {generated}, expected {resource.name}'
            assert (resource.parent / generated).is_file(), f'missing resource: {generated}'
            print(f'{firmware} -> {generated}: resource found', flush=True)
    subprocess.run([str(binary), '--search-contract'], check=True)
