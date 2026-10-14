#!/usr/bin/env python3
"""Expose Tahoe's public MSI-X API in the pinned MacKernelSDK header."""

import hashlib
from pathlib import Path

header = Path(__file__).resolve().parent.parent / "MacKernelSDK/Headers/IOKit/pci/IOPCIDevice.h"
original = header.read_bytes()
expected = "64a32261140503d1b332dd67ab656d3f79e946f223a730ad739b81fe5bb5ae3a"
if hashlib.sha256(original).hexdigest() != expected:
    raise SystemExit("Unexpected pinned IOPCIDevice.h; refusing to change its virtual layout")

text = original.decode("utf-8")
padding = "    OSMetaClassDeclareReservedUnused(IOPCIDevice,  3);"
api = """    OSMetaClassDeclareReservedUsed(IOPCIDevice,  3);
    virtual IOReturn configureInterrupts(UInt32 interruptType,
                                        UInt32 numRequired,
                                        UInt32 numRequested,
                                        IOOptionBits options);"""
interrupt = "    kIOInterruptTypePCIMessaged = 0x00010000"
if text.count(padding) != 1 or text.count(interrupt) != 1:
    raise SystemExit("Pinned SDK declaration anchors are not unique")
text = text.replace(padding, api).replace(
    interrupt,
    interrupt + ",\n    kIOInterruptTypePCIMessagedX = 0x00020000",
)
header.write_bytes(text.encode("utf-8"))
print("Exposed public IOPCIDevice::configureInterrupts at reserved slot 3 for Tahoe")
