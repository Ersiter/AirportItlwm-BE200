"""Apply the opt-in stored-key compatibility experiment to pinned BlueToolFixup."""
import hashlib
import sys
from pathlib import Path

path = Path(sys.argv[1])/'BrcmPatchRAM/BlueToolFixup.cpp'
source = path.read_text(encoding='utf-8')
canonical = source.encode('utf-8')
assert hashlib.sha1(b'blob '+str(len(canonical)).encode()+b'\0'+canonical).hexdigest() == 'e592e66e8541ebbb01b7d84cfde133836d3b3dc3'

def replace(old,new):
    global source
    assert source.count(old) == 1, f'upstream patch anchor mismatch: {old}'
    source = source.replace(old,new)

replace('static bool shouldPatchBoardId = false;', '''// Tahoe 25.4 / 25E246 command descriptor: require an unavailable capability
// for Read Stored Link Key, using bluetoothd's existing nonfatal local fallback.
static const uint8_t kBE200StoredKeyOriginal[] = {0x02, 0x00, 0x0D, 0x0C, 0x20, 0x06, 0x07, 0x00};
static const uint8_t kBE200StoredKeyPatched[]  = {0x02, 0x00, 0x0D, 0x0C, 0xFF, 0xFF, 0x07, 0x00};
static bool shouldPatchBE200StoredKey = false;

static bool shouldPatchBoardId = false;''')
replace('''        else if (strcmp(path + dirLength, "bluetoothd") == 0) {''','''        else if (strcmp(path + dirLength, "bluetoothd") == 0) {
            if (shouldPatchBE200StoredKey && KernelPatcher::findAndReplace(const_cast<void *>(data), PAGE_SIZE,
                kBE200StoredKeyOriginal, sizeof(kBE200StoredKeyOriginal), kBE200StoredKeyPatched, sizeof(kBE200StoredKeyPatched)))
                SYSLOG(MODULE_SHORT, "BE200 stored-key descriptor patched for native unsupported-command fallback");''')
replace('''        if (getKernelVersion() >= KernelVersion::Sonoma) {''','''        shouldPatchBE200StoredKey = getKernelVersion() == KernelVersion::Tahoe &&
            getKernelMinorVersion() == 4 && checkKernelArgument("-btlfxbe200key");
        if (shouldPatchBE200StoredKey)
            SYSLOG(MODULE_SHORT, "BE200 stored-key compatibility experiment enabled for Darwin25.4");
        if (getKernelVersion() >= KernelVersion::Sonoma) {''')
path.write_text(source,encoding='utf-8',newline='\n')
print('Applied opt-in BlueToolFixup stored-key descriptor correction to pinned source')
