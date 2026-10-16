# BE200 stored link key compatibility experiment

The target is USB8087:0036 on x86_64 macOS Tahoe26.4 / Darwin25.4.0, build25E246.
Its first controller initialization fails at Read Stored Link Key (opcode0x0c0d).
Later failures while selecting an internal controller are a consequence.

The captured bluetoothd x86_64 UUID is118BC7BF-203C-37B8-B20F-C7F09C4DA707.
Static execution of its actual command API shows that an unavailable capability
descriptor returns local unsupported-command status628 before encoding a request.
The initialization caller already treats this local failure as nonfatal. An
asynchronous controller failure instead reaches a callback that aborts initialization.

This experiment patches the eight-byte descriptor for opcode0x0c0d, changing only
its required-capability field from0x0620 to0xffff. It leaves HCI responses, key
contents, other command descriptors and controller error callbacks untouched.
It does not change the system executable on disk or disable general validation;
it extends BlueToolFixup's existing in-memory page patch mechanism.

The patch requires the explicit boot argument `-btlfxbe200key` and Darwin25.4.
The byte signature was checked against the captured25E246 x86_64 executable.
This is an experiment for this BE200 machine, not general Bluetooth compatibility.
Other builds, hardware and runtime page application remain unverified. Removing
the argument disables the extra patch. Do not install two copies of BlueToolFixup.

Builds use [BrcmPatchRAM](https://github.com/acidanthera/BrcmPatchRAM) commit
65389020769837e92e9fb939bac34bd9a3e25bb2, preserving its BSD3-Clause license and
existing behavior. The Lilu1.7.2 Debug SDK is a pinned build dependency; it does
not replace the installed Lilu. The manual Bluetooth workflow builds only
BlueToolFixup x86_64. No captured Apple executable or runtime logs are published.

The first hardware success criterion is no fatal Stored Keys initialization
failure and a Bluetooth controller that remains powered on. Discovery, pairing,
encrypted reconnection and persistence across reboot require separate observation.
Builds and static tests cannot establish those outcomes.
