"""Compile the production power request and adapter enable paths on the host."""
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = (root / "AirportItlwm/AirportItlwmV2.cpp").read_text()


def definition(opening):
    start = source.index(opening)
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


enable = definition("IOReturn AirportItlwm::enable(IO80211SkywalkInterface *netif)")
set_power = definition("IOReturn AirportItlwm::\nsetPOWER(")
enable_adapter = definition("IOReturn AirportItlwm::enableAdapter(")

program = r'''
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#define AIRPORT_WCL 1
#define IFF_UP 0x1
#define IFF_RUNNING 0x40
#define kIOReturnSuccess 0
#define kIOReturnError -1
#define kIOReturnNotReady -2
#define kPowerStateOff 0
#define kPowerStateOn 1
#define kWatchDogTimerPeriod 30000
#define XYLog(...) do {} while (0)
#define IOLog(...) do {} while (0)
#define super IO80211ControllerV2
using IOReturn = int;
using IONetworkInterface = void;
struct OSObject {};
struct IO80211SkywalkInterface {};
struct FakeDevice {
    std::map<std::string, uint32_t> values;
    void setProperty(const char *key, uint32_t value, int) { values[key] = value; }
};
struct apple80211_power_data { uint32_t num_radios; uint32_t power_state[4]; };
struct FakeIfnet { uint32_t if_flags; };
struct FakeAc { FakeIfnet ac_if; };
struct FakeController { FakeAc ic_ac{}; bool ic_wcl_mac_reconfig{}; };
struct FakeHal {
    FakeController controller{};
    int enableResult = kIOReturnSuccess;
    int enableCalls = 0;
    FakeController *get80211Controller() { return &controller; }
    int enable(void *) { ++enableCalls; return enableResult; }
};
struct FakeTimer {
    int timeout = 0;
    int enableCalls = 0;
    void setTimeoutMS(int ms) { timeout = ms; }
    void enable() { ++enableCalls; }
};
class IO80211ControllerV2 {
public:
    int superEnableCalls = 0;
    int superEnableResult = kIOReturnSuccess;
    int enable(IO80211SkywalkInterface *) { ++superEnableCalls; return superEnableResult; }
};
class AirportItlwm : public IO80211ControllerV2 {
public:
    IOReturn enable(IO80211SkywalkInterface *);
    IOReturn setPOWER(OSObject *, apple80211_power_data *);
    IOReturn enableAdapter(void *);
    void changePowerStateToPriv(int) {}
    void disableAdapter(void *) { ++disableCalls; }
    FakeDevice *pciNub{};
    FakeHal *fHalService{};
    FakeTimer *watchdogTimer{};
    void *bsdInterface{};
    int power_state{};
    FakeTimer * _fCommandGate{};
    int disableCalls{};
};
static void net80211_ifstats(FakeController *) {}
ENABLE_ADAPTER
SET_POWER
ENABLE
static void require(bool condition, const char *name) {
    if (!condition) { std::cerr << "FAILED: " << name << '\n'; std::exit(1); }
}
static uint32_t value(const FakeDevice &device, const char *key) {
    auto item = device.values.find(key);
    return item == device.values.end() ? UINT32_MAX : item->second;
}
static void reset(AirportItlwm &driver, FakeDevice &device, FakeHal &hal, FakeTimer &timer) {
    device.values.clear();
    driver.pciNub = &device; driver.fHalService = &hal; driver.watchdogTimer = &timer;
    driver._fCommandGate = &timer;
    driver.power_state = 0; driver.disableCalls = 0;
    driver.superEnableCalls = 0; driver.superEnableResult = kIOReturnSuccess;
    hal.enableCalls = timer.enableCalls = timer.timeout = 0;
    hal.controller.ic_ac.ac_if.if_flags = 0;
    hal.controller.ic_wcl_mac_reconfig = false;
    hal.enableResult = kIOReturnSuccess;
}
int main() {
    FakeDevice device; FakeHal hal; FakeTimer timer; AirportItlwm driver;
    reset(driver, device, hal, timer);
    apple80211_power_data off{4, {0,0,0,0}};
    driver.power_state = 1;
    hal.controller.ic_ac.ac_if.if_flags = IFF_UP | IFF_RUNNING;
    require(driver.setPOWER(nullptr, &off) == kIOReturnSuccess, "power off result");
    require(value(device, "AirportItlwm-PowerSetSeen") == 1, "power seen");
    require(value(device, "AirportItlwm-PowerRequestRadioCount") == 4, "radio count captured");
    require(value(device, "AirportItlwm-PowerRequestState0") == 0, "power state captured");
    require(value(device, "AirportItlwm-PowerEnableAttempted") == 0, "power off skips enable");
    require(driver.power_state == 0 && driver.disableCalls == 1 && hal.enableCalls == 0,
            "power off behavior preserved");

    reset(driver, device, hal, timer);
    apple80211_power_data on{1, {1,0,0,0}};
    hal.enableResult = kIOReturnNotReady;
    require(driver.setPOWER(nullptr, &on) == kIOReturnSuccess, "power ioctl preserves success return");
    require(value(device, "AirportItlwm-PowerEnableAttempted") == 1, "enable attempt captured");
    require(value(device, "AirportItlwm-PowerEnableAdapterResult") == uint32_t(kIOReturnNotReady),
            "HAL enable error captured");
    require(value(device, "AirportItlwm-EnableAdapterHALResult") == uint32_t(kIOReturnNotReady),
            "HAL result captured at adapter boundary");
    require(driver.power_state == 1 && hal.enableCalls == 1 && timer.enableCalls == 0,
            "power-on behavior and async limitation");

    reset(driver, device, hal, timer);
    hal.controller.ic_ac.ac_if.if_flags = IFF_RUNNING;
    require(driver.setPOWER(nullptr, &on) == kIOReturnSuccess, "already-running power request");
    require(value(device, "AirportItlwm-PowerEnableAttempted") == 0 &&
            value(device, "AirportItlwm-PowerEnableAdapterResult") == UINT32_MAX,
            "skipped adapter enable remains distinguishable");
    require(hal.enableCalls == 0, "already-running path skips adapter enable");

    reset(driver, device, hal, timer);
    IO80211SkywalkInterface interface;
    require(driver.enable(&interface) == kIOReturnSuccess, "interface enable with radio off");
    require(value(device, "AirportItlwm-InterfaceEnableSeen") == 1 &&
            value(device, "AirportItlwm-InterfaceEnableAttempted") == 0 &&
            value(device, "AirportItlwm-InterfaceEnableResult") == UINT32_MAX &&
            value(device, "AirportItlwm-InterfaceSuperEnableResult") == kIOReturnSuccess,
            "interface enable off-state captured");
    require(hal.enableCalls == 0, "interface enable off-state skips adapter");

    reset(driver, device, hal, timer);
    driver.power_state = 1;
    driver.superEnableResult = kIOReturnNotReady;
    require(driver.enable(&interface) == kIOReturnSuccess, "interface enable on");
    require(value(device, "AirportItlwm-InterfaceEnableAttempted") == 1 &&
            value(device, "AirportItlwm-InterfaceEnableResult") == kIOReturnSuccess &&
            value(device, "AirportItlwm-InterfaceSuperEnableResult") == uint32_t(kIOReturnNotReady),
            "interface adapter result captured");
    require(hal.enableCalls == 1 && timer.enableCalls == 2, "interface enable behavior");

    reset(driver, device, hal, timer);
    require(driver.setPOWER(nullptr, nullptr) == kIOReturnError, "null power request");
    require(value(device, "AirportItlwm-PowerSetSeen") == 1 &&
            value(device, "AirportItlwm-PowerRequestRadioCount") == UINT32_MAX &&
            value(device, "AirportItlwm-PowerRequestState0") == UINT32_MAX,
            "null request resets fields to pending");
    std::cout << "production power/enable paths: 6 cases passed\n";
}
'''.replace("ENABLE_ADAPTER", enable_adapter).replace("SET_POWER", set_power).replace("ENABLE", enable)

with tempfile.TemporaryDirectory(prefix="itlwm-startup-power-") as folder:
    folder = Path(folder)
    test = folder / "startup_power.cpp"
    test.write_text(program)
    binary = folder / "startup_power"
    subprocess.run(shlex.split(os.environ.get("CXX", "c++")) + [
        "-std=c++14", "-Wall", "-Wextra", "-Wno-unused-parameter", "-Werror", str(test), "-o", str(binary)
    ], check=True)
    subprocess.run([str(binary)], check=True)
