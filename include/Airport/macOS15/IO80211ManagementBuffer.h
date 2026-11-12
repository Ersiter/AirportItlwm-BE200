//
//  IO80211ManagementBuffer.h
//  AirportItlwm
//
//  macOS 15 (Sequoia) views of IO80211's management frame buffers, as the AWDL receive path uses them.
//  IO80211Buffer has no virtual methods of its own on Sequoia: returnBuffer, getCapacity, setLength and
//  getBytesNoCopy are ordinary exports. IO80211BufferPool::getBuffer is virtual, slot 0x118 as on macOS 26.
//
#pragma once
#include <libkern/c++/OSObject.h>
class IO80211Buffer : public OSObject {
    IO80211Buffer();
public:
    void returnBuffer();                                 // __ZN13IO80211Buffer12returnBufferEv
    size_t getCapacity() const;                          // __ZNK13IO80211Buffer11getCapacityEv
    void setLength(size_t);                              // __ZN13IO80211Buffer9setLengthEm
    void *getBytesNoCopy();                              // __ZN13IO80211Buffer14getBytesNoCopyEv
};
class IO80211BufferPool : public OSObject {
    IO80211BufferPool();
public:
    virtual IO80211Buffer *getBuffer();                  // 0x118
};
class IO80211Controller;
class IO80211VirtualInterface;
extern "C" IO80211BufferPool *itlGetMgmtFramePool(IO80211Controller*)
    __asm__("__ZN17IO80211Controller16getMgmtFramePoolEv");
// This overload consumes the pool-buffer lease on every path: it returns the
// buffer itself or transfers it to the peer manager. Do not return it twice.
extern "C" void itlSubmitMgmtFrame(IO80211VirtualInterface*, IO80211Buffer*, unsigned int, void*, unsigned long)
    __asm__("__ZN23IO80211VirtualInterface11bpfTapInputEP13IO80211BufferjPvm");
