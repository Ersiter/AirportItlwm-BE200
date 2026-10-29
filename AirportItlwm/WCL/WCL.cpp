//
//  WCL.cpp
//  AirportItlwm
//
//  Created by laobamac on 2026/10/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#ifdef AIRPORT_WCL
#include "../AirportItlwmV2.hpp"
#include "../AirportItlwmSkywalkInterface.hpp"
#include <kern/thread_call.h>
#include <kern/clock.h>
#include <net80211/ieee80211_node.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_priv.h>
#include <sys/_mbuf.h>
#include <crypto/sha1.h>

extern IOCommandGate *_fCommandGate;

static AirportWCL::ChannelBand wclChannelBand(const ieee80211_channel *channel)
{
    return IEEE80211_IS_CHAN_6GHZ(channel) ? AirportWCL::ChannelBand::GHz6 :
        (IEEE80211_IS_CHAN_5GHZ(channel) ? AirportWCL::ChannelBand::GHz5 :
            AirportWCL::ChannelBand::GHz2);
}

static void clearWCLSAE(ieee80211com *ic)
{
	++ic->ic_sae_generation;
    explicit_bzero(ic->ic_sae_pt, sizeof(ic->ic_sae_pt));
    explicit_bzero(ic->ic_sae_pwe, sizeof(ic->ic_sae_pwe));
    explicit_bzero(ic->ic_sae_password, sizeof(ic->ic_sae_password));
    ic->ic_sae_password_len = 0;
    ic->ic_sae_pt_valid = ic->ic_sae_pwe_valid = 0;
    ic->ic_sae_defer_active = 0;
    ic->ic_xflags &= ~IEEE80211_F_SAE_PWE;
}

enum { WCL_USER_EAPOL_DEFER, WCL_USER_EAPOL_SET_LINK, WCL_USER_EAPOL_TAKE, WCL_USER_EAPOL_PURGE, WCL_USER_EAPOL_INPUT_RESULT };

struct WCLUserEapolInputResult {
    uint32_t count;
    int status;
};

void AirportItlwmSkywalkInterface::publishWCLAuthDiagnostic(const char *event, mbuf_t packet)
{
    if (!instance || !instance->pciNub)
        return;
    uint32_t packetLength = packet ? static_cast<uint32_t>(mbuf_pkthdr_len(packet)) : 0;
    uint8_t ethernet[14] = {};
    uint8_t eapol[6] = {};
    if (packetLength >= sizeof(ethernet))
        mbuf_copydata(packet, 0, sizeof(ethernet), ethernet);
    if (packetLength >= 16)
        mbuf_copydata(packet, 14, 2, eapol);
    if (packetLength >= 18)
        mbuf_copydata(packet, 16, 2, eapol + 2);
    if (packetLength >= 20)
        mbuf_copydata(packet, 18, 2, eapol + 4);
    uint8_t packetType = packetLength >= 16 ? eapol[1] : 0xff;
    uint8_t eapCode = packetType == 0 && packetLength >= 20 ? eapol[4] : 0xff;
    uint8_t eapIdentifier = packetType == 0 && packetLength >= 20 ? eapol[5] : 0xff;
    uint16_t eapolLength = packetLength >= 18 ? (uint16_t(eapol[2]) << 8) | eapol[3] : 0;
    auto ic = fHalService ? fHalService->get80211Controller() : nullptr;
    char value[1024];
    snprintf(value, sizeof(value),
        "seq=%u join_attempt=%u event=%s ic_state=%u assoc=%u first_beacon=%u native_link_ready=%u user_eapol_gate_ready=%u user_eapol_queued=%u wcl_link_up=%u assoc_events=%u first_beacon_events=%u link_events=%u join_timeouts=%u join_timeout_ms=%u user_eapol_rx_deferred=%u user_eapol_rx_delivered=%u user_eapol_rx_dropped=%u user_eapol_rx_direct=%u user_eapol_gate_drops=%u user_eapol_len=%u user_eapol_type=%u eap_code=%u eap_id=%u auth_rx=%u sae_rx=%u sae_token_retries=%u sae_commit_retries=%u sae_confirm_replays=%u sae_failures=%u sae_last_seq=%u sae_last_status=%u sae_last_rx_state=%u sae_state=%u bssid=%02x:%02x:%02x:%02x:%02x:%02x src=%02x:%02x:%02x:%02x:%02x:%02x dst=%02x:%02x:%02x:%02x:%02x:%02x",
        ++wclAuthDiagnosticSequence, ic ? ic->ic_wcl_join_attempt : 0, event,
        ic ? static_cast<unsigned>(ic->ic_state) : UINT32_MAX,
        unsigned(assocNotified), unsigned(firstBeaconNotified), unsigned(wclNativeLinkReady),
        unsigned(wclUserEapolReady), wclUserEapolCount, unsigned(portAuthorized),
        wclAssociationEvents, wclFirstBeaconEvents, wclLinkEvents,
        wclJoinTimeoutEvents, wclJoinTimeoutMS, wclEapolRxDeferred,
        wclEapolRxDelivered, wclEapolRxDropped, wclEapolRxDirect, wclEapolRxGateDrops,
        unsigned(eapolLength), unsigned(packetType), unsigned(eapCode), unsigned(eapIdentifier),
        ic ? ic->ic_wcl_auth_rx_count : 0, ic ? ic->ic_wcl_sae_rx_count : 0,
        ic ? ic->ic_wcl_sae_token_retries : 0,
        ic ? ic->ic_wcl_sae_commit_retries : 0,
        ic ? ic->ic_wcl_sae_confirm_replays : 0,
        ic ? ic->ic_wcl_sae_failures : 0,
        ic ? ic->ic_wcl_sae_last_seq : 0, ic ? ic->ic_wcl_sae_last_status : 0,
        ic ? ic->ic_wcl_sae_last_state : 0,
        ic && ic->ic_bss ? ic->ic_bss->ni_sae.sae_state : 0,
        joinBSSID[0], joinBSSID[1], joinBSSID[2], joinBSSID[3], joinBSSID[4], joinBSSID[5],
        ethernet[6], ethernet[7], ethernet[8], ethernet[9], ethernet[10], ethernet[11],
        ethernet[0], ethernet[1], ethernet[2], ethernet[3], ethernet[4], ethernet[5]);
    instance->pciNub->setProperty("AirportItlwm-WCLAuthDiagnostic", value);
}

IOReturn AirportItlwmSkywalkInterface::wclUserEapolGated(
    OSObject *, void *arg0, void *arg1, void *arg2, void *arg3)
{
    auto self = static_cast<AirportItlwmSkywalkInterface *>(arg0);
    switch (uintptr_t(arg1)) {
        case WCL_USER_EAPOL_DEFER: {
            auto consumed = static_cast<bool *>(arg3);
            *consumed = false;
            mbuf_t packet = static_cast<mbuf_t>(arg2);
            if (self->wclStopping) {
                ++self->wclEapolRxDropped;
                self->publishWCLAuthDiagnostic("rx-drop-stopping", packet);
                mbuf_freem(packet);
                *consumed = true;
                return kIOReturnSuccess;
            }
            if (!self->fHalService->get80211Controller()->ic_wcl_enterprise || self->wclUserEapolReady) {
                ++self->wclEapolRxDirect;
                self->publishWCLAuthDiagnostic("rx-direct", packet);
                return kIOReturnSuccess;
            }
            if (self->wclUserEapolCount >= 32) {
                ++self->wclEapolRxDropped;
                self->publishWCLAuthDiagnostic("rx-drop-queue-full", packet);
                mbuf_freem(packet);
                *consumed = true;
                return kIOReturnSuccess;
            }
            mbuf_setnextpkt(packet, nullptr);
            if (self->wclUserEapolTail)
                mbuf_setnextpkt(self->wclUserEapolTail, packet);
            else
                self->wclUserEapolHead = packet;
            self->wclUserEapolTail = packet;
            ++self->wclUserEapolCount;
            ++self->wclEapolRxDeferred;
            self->publishWCLAuthDiagnostic("rx-deferred", packet);
            *consumed = true;
            return kIOReturnSuccess;
        }
        case WCL_USER_EAPOL_SET_LINK:
            self->wclNativeLinkReady = uintptr_t(arg2) != 0;
            self->wclUserEapolReady = false;
            if (!self->wclNativeLinkReady) {
                mbuf_t packet = self->wclUserEapolHead;
                self->wclEapolRxDropped += self->wclUserEapolCount;
                self->wclUserEapolHead = self->wclUserEapolTail = nullptr;
                self->wclUserEapolCount = 0;
                while (packet) {
                    mbuf_t next = mbuf_nextpkt(packet);
                    mbuf_setnextpkt(packet, nullptr);
                    mbuf_freem(packet);
                    packet = next;
                }
            }
            self->publishWCLAuthDiagnostic(self->wclNativeLinkReady ? "native-link-ready" : "native-link-down");
            return kIOReturnSuccess;
        case WCL_USER_EAPOL_TAKE: {
            auto batch = static_cast<mbuf_t *>(arg2);
            auto done = static_cast<bool *>(arg3);
            *batch = nullptr;
            *done = false;
            if (self->wclStopping || !self->wclNativeLinkReady) {
                *done = true;
                return kIOReturnSuccess;
            }
            *batch = self->wclUserEapolHead;
            self->wclUserEapolHead = self->wclUserEapolTail = nullptr;
            self->wclUserEapolCount = 0;
            if (!*batch) {
                self->wclUserEapolReady = true;
                *done = true;
                self->publishWCLAuthDiagnostic("rx-gate-open");
            }
            return kIOReturnSuccess;
        }
        case WCL_USER_EAPOL_PURGE: {
            mbuf_t packet = self->wclUserEapolHead;
            self->wclEapolRxDropped += self->wclUserEapolCount;
            self->wclUserEapolHead = self->wclUserEapolTail = nullptr;
            self->wclUserEapolCount = 0;
            self->wclNativeLinkReady = self->wclUserEapolReady = false;
            while (packet) {
                mbuf_t next = mbuf_nextpkt(packet);
                mbuf_setnextpkt(packet, nullptr);
                mbuf_freem(packet);
                packet = next;
            }
            self->publishWCLAuthDiagnostic("rx-purge");
            return kIOReturnSuccess;
        }
        case WCL_USER_EAPOL_INPUT_RESULT: {
            auto result = static_cast<WCLUserEapolInputResult *>(arg2);
            if (result->status == 0)
                self->wclEapolRxDelivered += result->count;
            else
                self->wclEapolRxDropped += result->count;
            self->publishWCLAuthDiagnostic(result->status == 0 ? "rx-delivered" : "rx-if_input-failed");
            return kIOReturnSuccess;
        }
    }
    return kIOReturnUnsupported;
}

bool AirportItlwmSkywalkInterface::deferWCLUserEapol(
    ieee80211com *, mbuf_t packet, void *arg)
{
    auto self = static_cast<AirportItlwmSkywalkInterface *>(arg);
    bool consumed = false;
    IOReturn status = _fCommandGate ? _fCommandGate->runAction(wclUserEapolGated, self,
        reinterpret_cast<void *>(WCL_USER_EAPOL_DEFER), packet, &consumed) : kIOReturnNotReady;
    if (self->instance && self->instance->pciNub)
        self->instance->pciNub->setProperty("AirportItlwm-WCLEapolRxGateStatus", status, 32);
    if (status == kIOReturnSuccess)
        return consumed;
    __sync_add_and_fetch(&self->wclEapolRxGateDrops, 1);
    if (self->instance && self->instance->pciNub)
        self->instance->pciNub->setProperty("AirportItlwm-WCLEapolRxGateDrops", self->wclEapolRxGateDrops, 32);
    mbuf_freem(packet);
    return true;
}

void AirportItlwmSkywalkInterface::setWCLNativeLinkReady(bool ready)
{
    if (_fCommandGate)
        _fCommandGate->runAction(wclUserEapolGated, this,
            reinterpret_cast<void *>(WCL_USER_EAPOL_SET_LINK),
            reinterpret_cast<void *>(uintptr_t(ready)));
}

void AirportItlwmSkywalkInterface::releaseWCLUserEapol()
{
    while (_fCommandGate) {
        mbuf_t batch = nullptr;
        bool done = false;
        if (_fCommandGate->runAction(wclUserEapolGated, this,
                reinterpret_cast<void *>(WCL_USER_EAPOL_TAKE), &batch, &done) != kIOReturnSuccess)
            return;
        if (done)
            return;
        WCLUserEapolInputResult result = {};
        struct mbuf_list packets = MBUF_LIST_INITIALIZER();
        while (batch) {
            mbuf_t next = mbuf_nextpkt(batch);
            mbuf_setnextpkt(batch, nullptr);
            ml_enqueue(&packets, batch);
            ++result.count;
            batch = next;
        }
        result.status = if_input(&fHalService->get80211Controller()->ic_if, &packets);
        if (result.status != 0)
            ml_purge(&packets);
        _fCommandGate->runAction(wclUserEapolGated, this,
            reinterpret_cast<void *>(WCL_USER_EAPOL_INPUT_RESULT), &result);
    }
}

void AirportItlwmSkywalkInterface::purgeWCLUserEapol()
{
    if (_fCommandGate)
        _fCommandGate->runAction(wclUserEapolGated, this,
            reinterpret_cast<void *>(WCL_USER_EAPOL_PURGE));
}

struct AirportItlwmSkywalkInterface::CountryUpdate {
    AirportItlwmSkywalkInterface *interface;
    AirportItlwm *controller;
    IOCommandGate *gate;
    IO80211WorkQueue *queue;
    thread_call_t call;
};

void AirportItlwmSkywalkInterface::deferWCLCountryUpdate()
{
    auto queue = instance->getWorkQueue();
    if (wclStopping || !_fCommandGate || !queue)
        return;
    auto update = static_cast<CountryUpdate *>(IOMalloc(sizeof(CountryUpdate)));
    if (!update)
        return;
    update->call = thread_call_allocate(wclCountryUpdateThread, update);
    if (!update->call) {
        IOFree(update, sizeof(*update));
        return;
    }
    update->interface = this;
    update->controller = instance;
    update->gate = _fCommandGate;
    update->queue = queue;
    retain();
    instance->retain();
    update->gate->retain();
    queue->retain();
    thread_call_enter(update->call);
}

void AirportItlwmSkywalkInterface::wclCountryUpdateThread(void *arg, void *)
{
    auto update = static_cast<CountryUpdate *>(arg);
    // Native country notifications synchronously query WCL. Holding the gate
    // is necessary, but executing on the driver's workloop thread is forbidden.
    update->gate->runAction(wclCountryUpdateGated, update);
    thread_call_free(update->call);
    update->interface->release();
    update->controller->release();
    update->gate->release();
    update->queue->release();
    IOFree(update, sizeof(*update));
}

IOReturn AirportItlwmSkywalkInterface::wclCountryUpdateGated(
    OSObject *, void *arg, void *, void *, void *)
{
    auto update = static_cast<CountryUpdate *>(arg);
    if (update->interface->wclStopping)
        return kIOReturnNotReady;
    if (!update->queue->inGate() || update->queue->onThread())
        return kIOReturnNotPermitted;
    update->interface->postMessage(APPLE80211_M_COUNTRY_CODE_CHANGED, nullptr, 0, false);
    return kIOReturnSuccess;
}

bool AirportItlwmSkywalkInterface::initWCL()
{
#if __IO80211_TARGET != __MAC_15_2
    auto ic = fHalService->get80211Controller();
    ic->ic_wcl_defer_user_eapol = deferWCLUserEapol;
    ic->ic_wcl_user_eapol_arg = this;
#endif
    joinTimer = IOTimerEventSource::timerEventSource(this, wclJoinTimeout);
    if (!joinTimer)
        return false;
    if (instance->getWorkQueue()->addEventSource(joinTimer) != kIOReturnSuccess)
        return false;
    wclEapolSource = IOTimerEventSource::timerEventSource(this, wclUserEapolAction);
    if (!wclEapolSource ||
        instance->getWorkQueue()->addEventSource(wclEapolSource) != kIOReturnSuccess)
        return false;
    instance->pciNub->setProperty("AirportItlwm-WCLEapolRxGateStatus", UINT32_MAX, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLEapolRxGateDrops", static_cast<uint64_t>(0), 32);
    instance->pciNub->setProperty("AirportItlwm-WCLAuthBssidQueryStatus", UINT32_MAX, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLAuthBssidMatchesJoin", UINT32_MAX, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLAuthCurrentBssid", "not-queried");
    publishWCLAuthDiagnostic("driver-ready");
    return true;
}

void AirportItlwmSkywalkInterface::wclUserEapolAction(OSObject *owner, IOTimerEventSource *)
{
    auto self = OSDynamicCast(AirportItlwmSkywalkInterface, owner);
    if (self && !self->wclStopping)
        self->releaseWCLUserEapol();
}

void AirportItlwmSkywalkInterface::stopWCL()
{
    // Pending country tasks must observe shutdown under the same gate.
    if (_fCommandGate)
        _fCommandGate->runAction(stopWCLGated, this);
    wclStopping = true;
    if (fHalService) {
        auto ic = fHalService->get80211Controller();
        ic->ic_wcl_defer_user_eapol = nullptr;
        ic->ic_wcl_user_eapol_arg = nullptr;
    }
    if (joinTimer) {
        joinTimer->cancelTimeout();
        if (joinTimer->getWorkLoop())
            joinTimer->getWorkLoop()->removeEventSource(joinTimer);
        OSSafeReleaseNULL(joinTimer);
    }
    if (wclEapolSource) {
        wclEapolSource->cancelTimeout();
        if (wclEapolSource->getWorkLoop())
            wclEapolSource->getWorkLoop()->removeEventSource(wclEapolSource);
        OSSafeReleaseNULL(wclEapolSource);
    }
    if (scanSource)
        scanSource->cancelTimeout();
    scanPending = joinPending = false;
    joinDeferred = false;
    explicit_bzero(&deferredJoin, sizeof(deferredJoin));
    explicit_bzero(&wclDerivedCredential, sizeof(wclDerivedCredential));
    if (fHalService) {
        ieee80211com *ic = fHalService->get80211Controller();
        ic->ic_wcl_join_requested = false;
        ic->ic_wcl_scan_requested = false;
        explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
        clearWCLSAE(ic);
    }
    purgeWCLUserEapol();
}

IOReturn AirportItlwmSkywalkInterface::stopWCLGated(
    OSObject *, void *arg, void *, void *, void *)
{
    auto self = static_cast<AirportItlwmSkywalkInterface *>(arg);
    self->portAuthorized = false;
    self->updateWCLLinkQuality(true);
    self->wclStopping = true;
    if (self->fHalService) {
        auto ic = self->fHalService->get80211Controller();
        ic->ic_wcl_defer_user_eapol = nullptr;
        ic->ic_wcl_user_eapol_arg = nullptr;
    }
    return kIOReturnSuccess;
}

void AirportItlwmSkywalkInterface::updateWCLLinkQuality(bool force)
{
    if (_fCommandGate)
        _fCommandGate->runAction(updateWCLLinkQualityGated, this,
                                reinterpret_cast<void *>(uintptr_t(force)));
}

IOReturn AirportItlwmSkywalkInterface::updateWCLLinkQualityGated(
    OSObject *, void *arg0, void *arg1, void *, void *)
{
    auto self = static_cast<AirportItlwmSkywalkInterface *>(arg0);
    if (self->wclStopping || !self->fHalService)
        return kIOReturnNotReady;
    auto queue = self->instance->getWorkQueue();
    if (!queue || !queue->inGate())
        return kIOReturnNotPermitted;
    auto interface = self->mExpansionData ? self->getBSDInterface() : nullptr;
    if (!interface) {
        self->wclLinkQualityInterface = nullptr;
        self->wclReportedLinkQuality = -2;
        return kIOReturnNotReady;
    }
    auto ic = self->fHalService->get80211Controller();
    int quality = -2;
    if (self->portAuthorized && self->linkState() == kIO80211NetworkLinkUp &&
        (ifnet_flags(interface) & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING) &&
        ic && ic->ic_state == IEEE80211_S_RUN && ic->ic_bss &&
        IEEE80211_ADDR_EQ(ic->ic_bss->ni_bssid, self->joinBSSID)) {
        int rssi = IWM_MIN_DBM + ic->ic_bss->ni_rssi;
        quality = rssi >= -70 ? 100 : (rssi >= -85 ? 50 : 20);
    }
    if (arg1 || quality != self->wclReportedLinkQuality ||
        interface != self->wclLinkQualityInterface) {
        self->setLQM(static_cast<unsigned long long>(static_cast<long long>(quality)));
        self->wclReportedLinkQuality = quality;
        self->wclLinkQualityInterface = interface;
    }
    return kIOReturnSuccess;
}

void AirportItlwmSkywalkInterface::free()
{
    if (joinTimer || wclEapolSource)
        stopWCL();
    IO80211InfraProtocol::free();
}

IOReturn AirportItlwmSkywalkInterface::wclCommand(OSObject *, void *a0, void *a1, void *a2, void *)
{
    auto self = static_cast<AirportItlwmSkywalkInterface *>(a0);
    if (self->wclStopping)
        return kIOReturnNotReady;
    switch (uintptr_t(a1)) {
        case 13: return self->copyWCLChannels(a2);
        case 14: return self->copyWCLTrafficCounters(a2);
        case 15:
            return self->fHalService->setScanHomeAwayTime(
                AirportWCL::read32(static_cast<const uint8_t *>(a2)));
        case 12:
            self->handleWCLEvent(int(uintptr_t(a2)), nullptr);
            return kIOReturnSuccess;
        case 11:
            self->clearWCLPMKSA();
            self->clearWCLDerivedCredential();
            return kIOReturnSuccess;
        case 8: return self->installWCLKey(static_cast<apple80211_key *>(a2));
        case 9: return self->accessWCLRSN(static_cast<apple80211_rsn_ie_data *>(a2), true);
        case 10: return self->accessWCLRSN(static_cast<apple80211_rsn_ie_data *>(a2), false);
        case 0: return self->beginWCLScan(static_cast<apple80211ScanRequest *>(a2));
        case 1: return self->beginWCLJoin(static_cast<apple80211AssocCandidates *>(a2));
        case 2: return self->abortWCLJoin();
        case 3: return self->leaveWCLNetwork();
        case 6: return self->copyWCLExtendedBss(a2);
        case 7:
            if (!a2 || !self->wclBssValid || !self->wclAssociatedBeacons)
                return kIOReturnNotReady;
            memcpy(a2, self->wclBeaconInfo, sizeof(self->wclBeaconInfo));
            return kIOReturnSuccess;
        case 5:
            if (!a2 || !self->wclBssValid)
                return kIOReturnNotReady;
            memcpy(a2, self->wclBssInfo, sizeof(self->wclBssInfo));
            return kIOReturnSuccess;
        case 4:
            self->finishWCLScan(kIOReturnAborted);
            return kIOReturnSuccess;
    }
    return kIOReturnUnsupported;
}

IOReturn AirportItlwmSkywalkInterface::setWCL_SCAN_REQ(apple80211ScanRequest *request)
{
    return _fCommandGate->runAction(wclCommand, this, nullptr, request);
}

IOReturn AirportItlwmSkywalkInterface::setWCL_SCAN_ABORT(void *)
{
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(4));
}

IOReturn AirportItlwmSkywalkInterface::setWCL_ASSOCIATE(apple80211AssocCandidates *request)
{
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(1), request);
}

#if __IO80211_TARGET == __MAC_15_2
IOReturn AirportItlwmSkywalkInterface::setWCL_JOIN_ABORT(void *)
#else
IOReturn AirportItlwmSkywalkInterface::setWCL_JOIN_ABORT(apple80211_wcl_abort_join *)
#endif
{
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(2));
}

IOReturn AirportItlwmSkywalkInterface::setWCL_LEAVE_NETWORK(apple80211_leave_network *)
{
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(3));
}

IOReturn AirportItlwmSkywalkInterface::beginWCLScan(apple80211ScanRequest *request)
{
    instance->pciNub->setProperty("AirportItlwm-WCLScanRequests", ++wclScanRequests, 32);
    AirportWCL::ScanRequest scan;
    if (!AirportWCL::decodeScan(request, 0x1550, scan)) {
        instance->pciNub->setProperty("AirportItlwm-WCLScanExit", "decode");
        return kIOReturnBadArgument;
    }
    instance->pciNub->setProperty("AirportItlwm-WCLScanChannelCount", scan.channelCount, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLScanType", scan.type, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLScanSsidLength", scan.ssidLength, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLChannelCodecVersion", 2, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLScanLegacyMap", scan.channels, sizeof(scan.channels));
    instance->pciNub->setProperty("AirportItlwm-WCLScan6GHzMap", scan.channels6GHz, sizeof(scan.channels6GHz));
    ieee80211com *ic = fHalService->get80211Controller();
    if (!(ic->ic_if.if_flags & IFF_RUNNING)) {
        instance->pciNub->setProperty("AirportItlwm-WCLScanExit", "not-running");
        return kIOReturnNotReady;
    }
    if (scanPending || joinPending || (ic->ic_flags & IEEE80211_F_BGSCAN)) {
        instance->pciNub->setProperty("AirportItlwm-WCLScanExit", "busy");
        return kIOReturnBusy;
    }
    if (ic->ic_state == IEEE80211_S_AUTH || ic->ic_state == IEEE80211_S_ASSOC) {
        instance->pciNub->setProperty("AirportItlwm-WCLScanExit", "busy-auth");
        return kIOReturnBusy;
    }
    uint8_t mappedChannels[sizeof(ic->ic_wcl_scan_channels)] = {};
    uint8_t mappedChannels6GHz[sizeof(ic->ic_wcl_scan_channels6GHz)] = {};
    unsigned mappedCount = 0, mapped6GHz = 0;
    for (unsigned index = 1; index <= IEEE80211_CHAN_MAX; ++index) {
        const auto channel = &ic->ic_channels[index];
        if (!channel->ic_freq || !isset(ic->ic_chan_active, index))
            continue;
        bool sixGHz = IEEE80211_IS_CHAN_6GHZ(channel);
        if (!AirportWCL::scanChannelSelected(sixGHz ? scan.channels6GHz : scan.channels,
                scan.channelCount != 0, ieee80211_chan2number(ic, channel)))
            continue;
        const unsigned channelNumber = ieee80211_chan2number(ic, channel);
        auto mapped = sixGHz ? mappedChannels6GHz : mappedChannels;
        setbit(mapped, channelNumber);
        ++mappedCount;
        if (sixGHz)
            ++mapped6GHz;
    }
    instance->pciNub->setProperty("AirportItlwm-WCLScanMappedChannels", mappedCount, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLScanMapped6GHz", mapped6GHz, 32);
    if (!mappedCount) {
        instance->pciNub->setProperty("AirportItlwm-WCLScanExit", "no-channels");
        return kIOReturnUnsupported;
    }
    scanPending = true;
    scanCompleted = false;
    ic->ic_wcl_scan_requested = true;
    ic->ic_wcl_scan_active = scan.type != 2;
    ic->ic_wcl_scan_ssid_length = scan.type == 2 ? 0 : scan.ssidLength;
    memcpy(ic->ic_wcl_scan_ssid, scan.ssid, sizeof(scan.ssid));
    ic->ic_wcl_scan_restricted = scan.channelCount != 0;
    memcpy(ic->ic_wcl_scan_channels, mappedChannels, sizeof(mappedChannels));
    memcpy(ic->ic_wcl_scan_channels6GHz, mappedChannels6GHz, sizeof(mappedChannels6GHz));
    scanSource->setTimeoutMS(20000);
    if (ic->ic_state == IEEE80211_S_RUN) {
        ieee80211_begin_cache_bgscan(&ic->ic_if);
        if (!(ic->ic_flags & IEEE80211_F_BGSCAN)) {
            scanPending = false;
            ic->ic_wcl_scan_requested = false;
            scanSource->cancelTimeout();
            instance->pciNub->setProperty("AirportItlwm-WCLScanExit", "bgscan-unavailable");
            return kIOReturnBusy;
        }
    } else {
        int error = ic->ic_newstate(ic, IEEE80211_S_SCAN, -1);
        if (error) {
            scanPending = false;
            ic->ic_wcl_scan_requested = false;
            scanSource->cancelTimeout();
            instance->pciNub->setProperty("AirportItlwm-WCLScanExit", "newstate-error");
            return kIOReturnError;
        }
    }
    instance->pciNub->setProperty("AirportItlwm-WCLScanExit", "accepted");
    return kIOReturnSuccess;
}

void AirportItlwmSkywalkInterface::finishWCLScan(IOReturn status)
{
    if (!scanPending)
        return;
    scanPending = false;
    scanCompleted = false;
    scanSource->cancelTimeout();
    fHalService->get80211Controller()->ic_wcl_scan_requested = false;
    instance->pciNub->setProperty("AirportItlwm-WCLScanDoneCount", ++wclScanDoneCount, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLScanDoneStatus", uint32_t(status), 32);
    char statusKey[64];
    snprintf(statusKey, sizeof(statusKey), "AirportItlwm-WCLScanDoneStatusCount-%08x", uint32_t(status));
    auto count = OSDynamicCast(OSNumber, instance->pciNub->getProperty(statusKey));
    instance->pciNub->setProperty(statusKey, count ? count->unsigned32BitValue() + 1 : 1, 32);
    instance->postMessage(this, AirportWCL::ScanDone, &status, sizeof(status), true);
    // The legacy scan-complete notification still drives airportd's result
    // fetch on Tahoe; without it the cached results never reach the UI.
    uint32_t legacyScanDone = 0;
    this->postMessage(APPLE80211_M_SCAN_DONE, &legacyScanDone,
                      sizeof(legacyScanDone), false);
}

void AirportItlwmSkywalkInterface::completeWCLScan()
{
    if (!wclStopping)
        finishWCLScan(scanCompleted ? kIOReturnSuccess : kIOReturnTimeout);
}

void AirportItlwmSkywalkInterface::publishWCLBeacon(const ieee80211_node *node, const uint8_t *ies, size_t length)
{
    instance->pciNub->setProperty("AirportItlwm-WCLBeaconEvents", ++wclBeaconEvents, 32);
    size_t iePrefix = AirportWCL::validIEPrefix(ies, length);
    instance->pciNub->setProperty("AirportItlwm-WCLBeaconRawIELength", (uint32_t)length, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLBeaconIEPrefix", (uint32_t)iePrefix, 32);
    if (!node || node->ni_esslen > 32 || !iePrefix) {
        instance->pciNub->setProperty("AirportItlwm-WCLBeaconDrops", ++wclBeaconDrops, 32);
        instance->pciNub->setProperty("AirportItlwm-WCLBeaconDropReason",
                                      !node ? "node" : (node->ni_esslen > 32 ? "ssid" : "ies"));
        return;
    }
    length = iePrefix;
    ieee80211com *ic = fHalService->get80211Controller();
    if (!node->ni_chan || node->ni_chan == IEEE80211_CHAN_ANYC) {
        instance->pciNub->setProperty("AirportItlwm-WCLBeaconDrops", ++wclBeaconDrops, 32);
        instance->pciNub->setProperty("AirportItlwm-WCLBeaconDropReason", "chan");
        return;
    }
    unsigned channel = ieee80211_chan2number(ic, node->ni_chan);
    uint16_t spec = AirportWCL::channelSpec20(channel, wclChannelBand(node->ni_chan));
    if (!spec) {
        instance->pciNub->setProperty("AirportItlwm-WCLBeaconDrops", ++wclBeaconDrops, 32);
        instance->pciNub->setProperty("AirportItlwm-WCLBeaconDropReason", "chan");
        return;
    }
    instance->pciNub->setProperty("AirportItlwm-WCLScanResults", ++wclScanResults, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLScanLastChannel", channel, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLScanLastBand",
        IEEE80211_IS_CHAN_6GHZ(node->ni_chan) ? 6 :
            (IEEE80211_IS_CHAN_5GHZ(node->ni_chan) ? 5 : 2), 32);
    {
        size_t ssidLength = node->ni_esslen > sizeof(wclResultRing[0].ssid) ?
            sizeof(wclResultRing[0].ssid) : node->ni_esslen;
        uint32_t slotIndex = wclResultRingNext & 3;
        auto &slot = wclResultRing[slotIndex];
        memset(&slot, 0, sizeof(slot));
        memcpy(slot.ssid, node->ni_essid, ssidLength);
        slot.ssidLength = uint8_t(ssidLength);
        slot.channel = uint8_t(channel);
        slot.rssi = IWM_MIN_DBM + node->ni_rssi;
        char text[48], key[32];
        snprintf(text, sizeof(text), "%.*s|%04x|%d", int(ssidLength), node->ni_essid,
                 spec, slot.rssi);
        snprintf(key, sizeof(key), "AirportItlwm-WCLResult%u", slotIndex);
        instance->pciNub->setProperty(key, text);
        wclResultRingNext = uint8_t((slotIndex + 1) & 3);
    }
    size_t size = sizeof(AirportWCL::BeaconMetadata) + length;
    auto metadata = static_cast<AirportWCL::BeaconMetadata *>(IOMalloc(size));
    if (!metadata)
        return;
    *metadata = {};
    metadata->ieLength = uint32_t(length);
    metadata->channelSpec = spec;
    metadata->channel = channel;
    metadata->ssidLength = node->ni_esslen;
    memcpy(metadata->ssid, node->ni_essid, node->ni_esslen);
    memcpy(metadata->bssid, node->ni_bssid, 6);
    metadata->rssi = IWM_MIN_DBM + node->ni_rssi;
    metadata->interval = node->ni_intval;
    metadata->capability = node->ni_capinfo;
    metadata->flags = AirportWCL::SSIDPresent | AirportWCL::RSSIValid;
    memcpy(metadata + 1, ies, length);
    size_t messageSize = sizeof(*metadata) + metadata->ieLength;
    if (assocNotified && IEEE80211_ADDR_EQ(node->ni_bssid, joinBSSID)) {
        wclBssValid = messageSize <= sizeof(wclBssInfo);
        if (wclBssValid) {
            bzero(wclBssInfo, sizeof(wclBssInfo));
            memcpy(wclBssInfo, metadata, messageSize);
        }
    }
    IOReturn scanResultStatus = instance->postMessage(this, AirportWCL::ScanResult,
                                                       metadata, messageSize, true);
    instance->pciNub->setProperty("AirportItlwm-WCLScanResultPostStatus",
                                  uint32_t(scanResultStatus), 32);
    IOFree(metadata, size);
}

void AirportItlwmSkywalkInterface::clearWCLPMKSA()
{
    auto ic = fHalService->get80211Controller();
    ieee80211_pmk *pmk;
    while ((pmk = TAILQ_FIRST(&ic->ic_pmksa))) {
        TAILQ_REMOVE(&ic->ic_pmksa, pmk, pmk_next);
        explicit_bzero(pmk, sizeof(*pmk));
        ::free(pmk);
    }
}

void AirportItlwmSkywalkInterface::clearWCLDerivedCredential()
{
    explicit_bzero(&wclDerivedCredential, sizeof(wclDerivedCredential));
}

IOReturn AirportItlwmSkywalkInterface::setCLEAR_PMKSA_CACHE(void *)
{
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(11));
}

IOReturn AirportItlwmSkywalkInterface::installWCLKey(apple80211_key *key)
{
    static_assert(sizeof(apple80211_key) == 0x94, "WCL cipher key layout");
    if (!key || !AirportWCL::validCipherKey(key->key_cipher_type, key->key_len,
            key->key_flags, key->key_index, key->key_rsc_len))
        return kIOReturnBadArgument;
    auto ic = fHalService->get80211Controller();
    auto ni = ic->ic_bss;
    if (!ic->ic_wcl_enterprise || !ni || ic->ic_state != IEEE80211_S_RUN)
        return kIOReturnNotReady;
    if (key->key_cipher_type == APPLE80211_CIPHER_PMK ||
        key->key_cipher_type == APPLE80211_CIPHER_PMKSA ||
        key->key_cipher_type == APPLE80211_CIPHER_MSK) {
        // WCL's native user-client rejects PTK/GTK, and delivers a PMK/MSK
        // instead. Use the existing net80211 four-way/group-key handshake.
        if (!ieee80211_is_8021x_akm((enum ieee80211_akm)ni->ni_rsnakms))
            return kIOReturnBadArgument;
        uint8_t any = 0;
        for (auto byte : key->key_ea.octet) any |= byte;
        if (any && !IEEE80211_ADDR_EQ(key->key_ea.octet, ni->ni_bssid))
            return kIOReturnBadArgument;
        auto pmk = ieee80211_pmksa_add(ic, (enum ieee80211_akm)ni->ni_rsnakms,
                                     ni->ni_macaddr, key->key, 0);
        IOReturn result = pmk ? kIOReturnSuccess : kIOReturnNoMemory;
        return result;
    }
    return kIOReturnUnsupported;
}

IOReturn AirportItlwmSkywalkInterface::accessWCLRSN(apple80211_rsn_ie_data *data, bool write)
{
    if (!data) return kIOReturnBadArgument;
    auto ic = fHalService->get80211Controller();
    if (write) {
        if (!AirportWCL::validRSNOverride(data->ie, data->len))
            return kIOReturnBadArgument;
        // net80211 constructs negotiated IEs for its own key handshake.
        return kIOReturnUnsupported;

    }
    const uint8_t *ie = ic->ic_bss ? ic->ic_bss->ni_rsnie : nullptr;
    if (!ie) return kIOReturnNotReady;
    size_t length = size_t(ie[1]) + 2;
    if (length > sizeof(data->ie)) return kIOReturnBadArgument;
    bzero(data, sizeof(*data));
    data->version = APPLE80211_VERSION;
    data->len = length;
    memcpy(data->ie, ie, length);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::beginWCLJoin(apple80211AssocCandidates *request)
{
    instance->pciNub->setProperty("AirportItlwm-WCLJoinRequests", ++wclJoinRequests, 32);
    AirportWCL::JoinRequest join;
    if (!AirportWCL::decodeJoin(request, 0x2cc, join)) {
        explicit_bzero(&join, sizeof(join));
        instance->pciNub->setProperty("AirportItlwm-WCLJoinExit", "decode");
        return kIOReturnBadArgument;
    }
    instance->pciNub->setProperty("AirportItlwm-WCLJoinSsidLength", join.ssidLength, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLJoinLowerAuth", join.lowerAuth, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLJoinUpperAuth", join.upperAuth, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLJoinKeyLength", join.keyLength, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLJoinKeyCipher", join.keyCipher, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLJoinRsnLength", join.rsnLength, 32);
    return startWCLJoin(join);
}

IOReturn AirportItlwmSkywalkInterface::startWCLJoin(AirportWCL::JoinRequest &join)
{
    auto auth = AirportWCL::classifyLegacyAuth(join);
    auto credentialKind = auth == AirportWCL::LegacyAuth::Personal ?
        AirportWCL::DerivedCredentialKind::Personal : AirportWCL::DerivedCredentialKind::SAE;
    bool derivedCredential = (auth == AirportWCL::LegacyAuth::Personal && join.keyCipher == 10) ||
        auth == AirportWCL::LegacyAuth::PersonalSAE;
    bool cachedCredential = derivedCredential && AirportWCL::matchesDerivedCredential(
        wclDerivedCredential, credentialKind, join.ssid, join.ssidLength,
        join.key, join.keyLength);
    if (!cachedCredential)
        clearWCLDerivedCredential();
    instance->pciNub->setProperty("AirportItlwm-WCLJoinAuthClass",
        auth == AirportWCL::LegacyAuth::Open ? "open" :
        auth == AirportWCL::LegacyAuth::Wep ? "wep" :
        auth == AirportWCL::LegacyAuth::Personal ? "personal" :
        auth == AirportWCL::LegacyAuth::PersonalSAE ? "sae" :
        auth == AirportWCL::LegacyAuth::Enterprise ? "enterprise" : "invalid");
    bool personal = auth == AirportWCL::LegacyAuth::Personal;
    bool sae = auth == AirportWCL::LegacyAuth::PersonalSAE;
    bool enterprise = auth == AirportWCL::LegacyAuth::Enterprise;
    bool supported = auth != AirportWCL::LegacyAuth::Invalid;
    ieee80211com *ic = fHalService->get80211Controller();
    purgeWCLUserEapol();
    // Applying a private MAC restarts firmware asynchronously. WCL can issue
    // the association before that restart has completed; keep one request
    // until the HAL reports READY rather than making the user retry it.
    if (supported && !joinPending && ic->ic_wcl_mac_reconfig &&
        (ic->ic_if.if_flags & IFF_UP)) {
        deferredJoin = join;
        memcpy(joinBSSID, join.bssid, sizeof(joinBSSID));
        explicit_bzero(&join, sizeof(join));
        joinDeferred = joinPending = true;
        joinTimer->setTimeoutMS(30000);
        wclJoinTimeoutMS = 30000;
        publishWCLAuthDiagnostic("join-deferred");
        instance->pciNub->setProperty("AirportItlwm-WCLJoinExit", "deferred");
        return kIOReturnSuccess;
    }
    if (!supported || !(ic->ic_if.if_flags & IFF_RUNNING) || joinPending || scanPending) {
        instance->pciNub->setProperty("AirportItlwm-WCLJoinExit",
            !supported ? "unsupported" : (!(ic->ic_if.if_flags & IFF_RUNNING) ? "not-running" :
                                          (joinPending ? "join-busy" : "scan-busy")));
        explicit_bzero(&join, sizeof(join));
        return !supported ? kIOReturnUnsupported : kIOReturnBusy;
    }
    unsigned joinChannel = 0;
    AirportWCL::ChannelBand joinBand = AirportWCL::ChannelBand::GHz2;
    if (!AirportWCL::decodeChannelSpec20(join.channelSpec, joinChannel, joinBand)) {
        instance->pciNub->setProperty("AirportItlwm-WCLJoinExit", "channel");
        clearWCLDerivedCredential();
        explicit_bzero(&join, sizeof(join));
        return kIOReturnBadArgument;
    }
    uint8_t joinChannels[sizeof(ic->ic_wcl_scan_channels)] = {};
    uint8_t joinChannels6GHz[sizeof(ic->ic_wcl_scan_channels6GHz)] = {};
    unsigned mappedJoinChannels = 0;
    for (unsigned index = 1; index <= IEEE80211_CHAN_MAX; ++index) {
        const auto channel = &ic->ic_channels[index];
        if (!channel->ic_freq || !isset(ic->ic_chan_active, index))
            continue;
        if (!IEEE80211_IS_CHAN_6GHZ(channel) && !IEEE80211_IS_CHAN_5GHZ(channel) &&
            !IEEE80211_IS_CHAN_2GHZ(channel))
            continue;
        auto band = IEEE80211_IS_CHAN_6GHZ(channel) ? AirportWCL::ChannelBand::GHz6 :
            IEEE80211_IS_CHAN_5GHZ(channel) ? AirportWCL::ChannelBand::GHz5 :
            AirportWCL::ChannelBand::GHz2;
        if (band != joinBand || ieee80211_chan2number(ic, channel) != joinChannel)
            continue;
        auto mapped = band == AirportWCL::ChannelBand::GHz6 ?
            joinChannels6GHz : joinChannels;
        setbit(mapped, joinChannel);
        ++mappedJoinChannels;
    }
    if (!mappedJoinChannels) {
        instance->pciNub->setProperty("AirportItlwm-WCLJoinExit", "channel");
        clearWCLDerivedCredential();
        explicit_bzero(&join, sizeof(join));
        return kIOReturnUnsupported;
    }
    if (ic->ic_state == IEEE80211_S_RUN || ic->ic_state == IEEE80211_S_AUTH || ic->ic_state == IEEE80211_S_ASSOC)
        leaveWCLNetwork();
    ieee80211_disable_rsn(ic);
    ieee80211_disable_wep(ic);
    explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
    clearWCLSAE(ic);
    clearWCLPMKSA();
    ic->ic_flags &= ~(IEEE80211_F_AUTO_JOIN | IEEE80211_F_PSK);
    ic->ic_wcl_enterprise = enterprise;

    if (personal || sae || enterprise) {
        ieee80211_wpaparams wpa = {};
        wpa.i_enabled = 1;
        if (join.upperAuth & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA_PSK))
            wpa.i_protos |= IEEE80211_WPA_PROTO_WPA1;
        if (join.upperAuth & (APPLE80211_AUTHTYPE_WPA2 | APPLE80211_AUTHTYPE_WPA2_PSK |
                              APPLE80211_AUTHTYPE_SHA256_PSK | APPLE80211_AUTHTYPE_SHA256_8021X))
            wpa.i_protos |= IEEE80211_WPA_PROTO_WPA2;
        if (sae)
            wpa.i_protos |= IEEE80211_WPA_PROTO_WPA2;
        if (join.upperAuth & (APPLE80211_AUTHTYPE_WPA_PSK | APPLE80211_AUTHTYPE_WPA2_PSK))
            wpa.i_akms |= IEEE80211_WPA_AKM_PSK;
        if (join.upperAuth & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA2))
            wpa.i_akms |= IEEE80211_WPA_AKM_8021X;
        if (join.upperAuth & APPLE80211_AUTHTYPE_SHA256_PSK)
            wpa.i_akms |= IEEE80211_WPA_AKM_SHA256_PSK;
        if (join.upperAuth & APPLE80211_AUTHTYPE_SHA256_8021X)
            wpa.i_akms |= IEEE80211_WPA_AKM_SHA256_8021X;
        if (sae)
            wpa.i_akms |= IEEE80211_WPA_AKM_SAE;
        wpa.i_ciphers = IEEE80211_WPA_CIPHER_CCMP | IEEE80211_WPA_CIPHER_TKIP;
        if (sae)
            wpa.i_ciphers = IEEE80211_WPA_CIPHER_CCMP;
        if (join.rsnLength >= 8 && join.rsn[0] == IEEE80211_ELEMID_RSN &&
            join.rsn[4] == 0 && join.rsn[5] == 0x0f && join.rsn[6] == 0xac) {
            if (join.rsn[7] == 2) wpa.i_groupcipher = IEEE80211_WPA_CIPHER_TKIP;
            if (join.rsn[7] == 4) wpa.i_groupcipher = IEEE80211_WPA_CIPHER_CCMP;
        }
        int error = ieee80211_ioctl_setwpaparms(ic, &wpa);
        if (error && error != ENETRESET) {
            instance->pciNub->setProperty("AirportItlwm-WCLJoinExit", "rsn-parameters");
            clearWCLSAE(ic);
            clearWCLDerivedCredential();
            explicit_bzero(&join, sizeof(join));
            return kIOReturnBadArgument;
        }
        if (sae) {
            if (cachedCredential) {
                memcpy(ic->ic_sae_pt, wclDerivedCredential.result, sizeof(ic->ic_sae_pt));
            } else if (ieee80211_sae_password_to_pt(ic->ic_sae_pt, join.key,
                join.keyLength, join.ssid, join.ssidLength) != 0) {
                instance->pciNub->setProperty("AirportItlwm-WCLJoinExit", "sae-pt");
                clearWCLSAE(ic);
                clearWCLDerivedCredential();
                explicit_bzero(&join, sizeof(join));
                return kIOReturnBadArgument;
            } else {
                wclDerivedCredential.valid = 1;
                wclDerivedCredential.kind = credentialKind;
                wclDerivedCredential.ssidLength = join.ssidLength;
                wclDerivedCredential.credentialLength = join.keyLength;
                wclDerivedCredential.resultLength = sizeof(ic->ic_sae_pt);
                memcpy(wclDerivedCredential.ssid, join.ssid, join.ssidLength);
                memcpy(wclDerivedCredential.credential, join.key, join.keyLength);
                memcpy(wclDerivedCredential.result, ic->ic_sae_pt, sizeof(ic->ic_sae_pt));
            }
            memcpy(ic->ic_sae_password, join.key, join.keyLength);
            ic->ic_sae_password_len = join.keyLength;
            ic->ic_sae_pt_valid = 1;
        }
        if (personal) {
            if (join.keyCipher == 10) {
                if (cachedCredential) {
                    memcpy(ic->ic_psk, wclDerivedCredential.result, sizeof(ic->ic_psk));
                } else {
                    join.key[join.keyLength] = 0;
                    if (pbkdf2_sha1(reinterpret_cast<const char *>(join.key), join.ssid,
                            join.ssidLength, 4096, ic->ic_psk, sizeof(ic->ic_psk)) != 0) {
                        explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
                        clearWCLDerivedCredential();
                        explicit_bzero(&join, sizeof(join));
                        return kIOReturnBadArgument;
                    }
                    wclDerivedCredential.valid = 1;
                    wclDerivedCredential.kind = credentialKind;
                    wclDerivedCredential.ssidLength = join.ssidLength;
                    wclDerivedCredential.credentialLength = join.keyLength;
                    wclDerivedCredential.resultLength = sizeof(ic->ic_psk);
                    memcpy(wclDerivedCredential.ssid, join.ssid, join.ssidLength);
                    memcpy(wclDerivedCredential.credential, join.key, join.keyLength);
                    memcpy(wclDerivedCredential.result, ic->ic_psk, sizeof(ic->ic_psk));
                }
            } else {
                memcpy(ic->ic_psk, join.key, sizeof(ic->ic_psk));
            }
            ic->ic_flags |= IEEE80211_F_PSK;
        } else if (!sae && join.keyLength == IEEE80211_PMK_LEN) {
            bool cached = true;
            if (join.upperAuth & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA2))
                cached = ieee80211_pmksa_add(ic, IEEE80211_AKM_8021X, join.bssid, join.key, 0) != nullptr;
            if (cached && (join.upperAuth & APPLE80211_AUTHTYPE_SHA256_8021X))
                cached = ieee80211_pmksa_add(ic, IEEE80211_AKM_SHA256_8021X, join.bssid, join.key, 0) != nullptr;
            if (!cached) {
                clearWCLPMKSA();
                explicit_bzero(&join, sizeof(join));
                return kIOReturnNoMemory;
            }
        }
    } else if (auth == AirportWCL::LegacyAuth::Wep) {
        ieee80211_nwkey keys = {};
        keys.i_wepon = IEEE80211_NWKEY_WEP;
        keys.i_defkid = join.keyIndex + 1;
        keys.i_key[join.keyIndex].i_keylen = join.keyLength;
        keys.i_key[join.keyIndex].i_keydat = join.key;
        int error = ieee80211_ioctl_setnwkeys(ic, &keys);
        if (error && error != ENETRESET) {
            explicit_bzero(&join, sizeof(join));
            return kIOReturnBadArgument;
        }
    }
    ic->ic_des_esslen = join.ssidLength;
    memcpy(ic->ic_des_essid, join.ssid, sizeof(ic->ic_des_essid));
    memcpy(ic->ic_des_bssid, join.bssid, 6);
    memcpy(joinBSSID, join.bssid, 6);
    ic->ic_flags |= IEEE80211_F_DESBSSID;
    ic->ic_wcl_peer_is_mlo = join.peerIsMlo;
    if (join.peerIsMlo)
        memcpy(ic->ic_wcl_peer_mld_addr, join.peerMldAddress, sizeof(ic->ic_wcl_peer_mld_addr));
    else
        bzero(ic->ic_wcl_peer_mld_addr, sizeof(ic->ic_wcl_peer_mld_addr));
    ic->ic_wcl_scan_restricted = true;
    memcpy(ic->ic_wcl_scan_channels, joinChannels, sizeof(joinChannels));
    memcpy(ic->ic_wcl_scan_channels6GHz, joinChannels6GHz, sizeof(joinChannels6GHz));
    ic->ic_wcl_join_attempt = wclJoinRequests;
    ic->ic_wcl_auth_rx_count = ic->ic_wcl_sae_rx_count = 0;
    ic->ic_wcl_sae_token_retries = 0;
    ic->ic_wcl_sae_commit_retries = ic->ic_wcl_sae_confirm_replays = 0;
    ic->ic_wcl_sae_failures = 0;
    wclEapolRxDeferred = wclEapolRxDelivered = wclEapolRxDropped = 0;
    wclEapolRxDirect = wclEapolRxGateDrops = 0;
    ic->ic_wcl_sae_last_seq = ic->ic_wcl_sae_last_status = 0;
    ic->ic_wcl_sae_last_state = 0;
    ic->ic_wcl_join_requested = true;
    ic->ic_wcl_scan_requested = false;
    current_authtype_lower = join.lowerAuth;
    current_authtype_upper = join.upperAuth;
    explicit_bzero(&join, sizeof(join));
    wclBssValid = false;
    joinPending = true;
    assocNotified = firstBeaconNotified = portAuthorized = false;
    wclAssociatedBeacons = 0;
    bzero(wclBeaconInfo, sizeof(wclBeaconInfo));
    disassocIsVoluntary = false;
    joinTimer->setTimeoutMS(30000);
    wclJoinTimeoutMS = 30000;
    if (ic->ic_newstate(ic, IEEE80211_S_SCAN, -1)) {
        joinPending = false;
        joinTimer->cancelTimeout();
        ic->ic_wcl_join_requested = false;
        clearWCLPMKSA();
        ic->ic_wcl_enterprise = false;
        explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
        clearWCLSAE(ic);
        clearWCLDerivedCredential();
        instance->pciNub->setProperty("AirportItlwm-WCLJoinExit", "newstate-error");
        return kIOReturnError;
    }
    instance->pciNub->setProperty("AirportItlwm-WCLJoinExit", "started");
    publishWCLAuthDiagnostic("join-started");
    return kIOReturnSuccess;
}

void AirportItlwmSkywalkInterface::resumeWCLJoin()
{
    if (!joinDeferred || wclStopping)
        return;
    AirportWCL::JoinRequest join = deferredJoin;
    explicit_bzero(&deferredJoin, sizeof(deferredJoin));
    joinDeferred = joinPending = false;
    joinTimer->cancelTimeout();
    IOReturn status = startWCLJoin(join);
    explicit_bzero(&join, sizeof(join));
    if (status != kIOReturnSuccess) {
        joinPending = true;
        finishWCLJoin(1, 0, status);
    }
}

void AirportItlwmSkywalkInterface::finishWCLJoin(uint16_t status, uint16_t reason, IOReturn driverStatus)
{
    if (!joinPending)
        return;
    AirportWCL::ConnectionEvent event = {};
    event.status = status;
    event.reason = reason;
    memcpy(event.peers[0].bssid, joinBSSID, 6);
    event.peers[0].driverStatus = driverStatus;
    joinPending = false;
    joinDeferred = false;
    explicit_bzero(&deferredJoin, sizeof(deferredJoin));
    joinTimer->cancelTimeout();
    publishWCLAuthDiagnostic(status ? "join-failed" : "join-succeeded");
    instance->postMessage(this, AirportWCL::ConnectComplete, &event, sizeof(event), true);
    if (status) {
        purgeWCLUserEapol();
        portAuthorized = false;
        updateWCLLinkQuality(true);
        clearWCLDerivedCredential();
        ieee80211com *ic = fHalService->get80211Controller();
        ic->ic_wcl_join_requested = false;
        ic->ic_wcl_peer_is_mlo = false;
        bzero(ic->ic_wcl_peer_mld_addr, sizeof(ic->ic_wcl_peer_mld_addr));
        clearWCLPMKSA();
        ic->ic_wcl_enterprise = false;
        explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
        clearWCLSAE(ic);
    }
}

void AirportItlwmSkywalkInterface::wclJoinTimeout(OSObject *owner, IOTimerEventSource *)
{
    auto self = OSDynamicCast(AirportItlwmSkywalkInterface, owner);
    if (self && !self->wclStopping) {
        ++self->wclJoinTimeoutEvents;
        self->publishWCLAuthDiagnostic("join-timeout");
        self->finishWCLJoin(1, 1004, kIOReturnTimeout);
        self->leaveWCLNetwork();
    }
}

IOReturn AirportItlwmSkywalkInterface::leaveWCLNetwork()
{
    ieee80211com *ic = fHalService->get80211Controller();
#ifdef __PRIVATE_SPI__
    if (instance->bsdInterface) {
        instance->bsdInterface->stopOutputThread();
        instance->bsdInterface->flushOutputQueue();
    }
#endif
    ifq_flush(&ic->ic_if.if_snd);
    purgeWCLUserEapol();
    portAuthorized = false;
    updateWCLLinkQuality(true);
    joinPending = false;
    joinDeferred = false;
    explicit_bzero(&deferredJoin, sizeof(deferredJoin));
    joinTimer->cancelTimeout();
    ic->ic_wcl_join_requested = false;
    ic->ic_wcl_peer_is_mlo = false;
    bzero(ic->ic_wcl_peer_mld_addr, sizeof(ic->ic_wcl_peer_mld_addr));
    wclAssociatedBeacons = 0;
    wclBssValid = false;
    disassocIsVoluntary = true;
    ic->ic_deauth_reason = IEEE80211_REASON_AUTH_LEAVE;
    if (ic->ic_state > IEEE80211_S_SCAN)
        ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
    ieee80211_disable_rsn(ic);
    ieee80211_disable_wep(ic);
    explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
    clearWCLSAE(ic);
    clearWCLPMKSA();
    ic->ic_wcl_enterprise = false;
    ic->ic_flags &= ~(IEEE80211_F_PSK | IEEE80211_F_DESBSSID);
    ic->ic_des_esslen = 0;
    bzero(ic->ic_des_essid, sizeof(ic->ic_des_essid));
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::abortWCLJoin()
{
    leaveWCLNetwork();
    instance->postMessage(this, AirportWCL::JoinAbortComplete, nullptr, 0, true);
    return kIOReturnSuccess;
}

void AirportItlwmSkywalkInterface::handleWCLLink(bool up)
{
    if (wclStopping)
        return;
    portAuthorized = up;
    ++wclLinkEvents;
    publishWCLAuthDiagnostic(up ? "controlled-port-link-up" : "controlled-port-link-down");
#if __IO80211_TARGET == __MAC_26_0
    if (up && (fHalService->get80211Controller()->ic_flags & IEEE80211_F_RSNON)) {
        AirportWCL::SupplicantEvent event = {};
        event.version = 1;
        // PostOffice clears WCL's handshake deadline and notifies IO80211RSNDone.
        IOReturn status = instance->postMessage(this, AirportWCL::Supplicant,
            &event, sizeof(event), true);
        instance->pciNub->setProperty("AirportItlwm-WCLRSNDonePostResult", status, 32);
    }
#endif
    if (!up && wclLinkIndicated) {
        AirportWCL::LinkStatusEvent event = {};
        memcpy(event.bssid, joinBSSID, sizeof(event.bssid));
        event.reason = 255;
        wclLinkIndicated = false;
        wclBssValid = false;
        instance->postMessage(this, AirportWCL::LinkStatus, &event, sizeof(event), true);
    }
    if (up && joinPending && firstBeaconNotified)
        finishWCLJoin(0, 0, kIOReturnSuccess);
    updateWCLLinkQuality(true);
}

void AirportItlwmSkywalkInterface::handleWCLEvent(int code, void *data)
{
    if (wclStopping)
        return;
    bool lifecycleEvent = code == IEEE80211_EVT_DRIVER_RESET_BEGIN ||
        code == IEEE80211_EVT_DRIVER_READY || code == IEEE80211_EVT_DRIVER_STOPPED;
    if (lifecycleEvent) {
        instance->pciNub->setProperty("AirportItlwm-WCLLifecycleEventSeen", 1, 32);
        instance->pciNub->setProperty("AirportItlwm-WCLLifecycleEventCode", code, 32);
        instance->pciNub->setProperty("AirportItlwm-WCLLifecycleEventProcessed", static_cast<uint64_t>(0), 32);
        instance->pciNub->setProperty("AirportItlwm-WCLLifecycleGateDispatchResult", UINT32_MAX, 32);
        if (code == IEEE80211_EVT_DRIVER_RESET_BEGIN) {
            instance->pciNub->setProperty("AirportItlwm-WCLReadyEventSeen", static_cast<uint64_t>(0), 32);
            instance->pciNub->setProperty("AirportItlwm-WCLReadyEventProcessed", static_cast<uint64_t>(0), 32);
        } else if (code == IEEE80211_EVT_DRIVER_READY) {
            instance->pciNub->setProperty("AirportItlwm-WCLReadyEventSeen", 1, 32);
            instance->pciNub->setProperty("AirportItlwm-WCLReadyEventProcessed", static_cast<uint64_t>(0), 32);
        }
        instance->pciNub->setProperty("AirportItlwm-WCLMacReconfig", UINT32_MAX, 32);
        instance->pciNub->setProperty("AirportItlwm-WCLMacReconfigConsumed", UINT32_MAX, 32);
        instance->pciNub->setProperty("AirportItlwm-WCLResetPostAttempted", static_cast<uint64_t>(0), 32);
        instance->pciNub->setProperty("AirportItlwm-WCLResetPostResult", UINT32_MAX, 32);
        instance->pciNub->setProperty("AirportItlwm-WCLDriverAvailablePostAttempted", static_cast<uint64_t>(0), 32);
        instance->pciNub->setProperty("AirportItlwm-WCLDriverAvailable", UINT32_MAX, 32);
        instance->pciNub->setProperty("AirportItlwm-WCLDriverAvailableReason", UINT32_MAX, 32);
        instance->pciNub->setProperty("AirportItlwm-WCLDriverAvailablePostResult", UINT32_MAX, 32);
    }
    // Firmware initialization runs on systq, outside the native PostOffice gate.
    // Serialize only lifecycle notifications; never run synchronous WCL ioctls here.
    if ((code == IEEE80211_EVT_DRIVER_RESET_BEGIN || code == IEEE80211_EVT_DRIVER_READY ||
         code == IEEE80211_EVT_DRIVER_STOPPED) && !instance->getWorkQueue()->inGate()) {
        IOReturn status = _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(12),
                                                   reinterpret_cast<void *>(uintptr_t(code)));
        instance->pciNub->setProperty("AirportItlwm-WCLLifecycleGateDispatchResult", status, 32);
        return;
    }
    if (lifecycleEvent)
        instance->pciNub->setProperty("AirportItlwm-WCLLifecycleEventProcessed", 1, 32);
    if (code == IEEE80211_EVT_DRIVER_READY)
        instance->pciNub->setProperty("AirportItlwm-WCLReadyEventProcessed", 1, 32);
    ieee80211com *ic = fHalService->get80211Controller();
    switch (code) {
        case IEEE80211_EVT_COUNTRY_CODE_UPDATE:
            if (data)
                memcpy(instance->geo_location_cc, data, sizeof(instance->geo_location_cc));
            deferWCLCountryUpdate();
            break;
        case IEEE80211_EVT_DRIVER_RESET_BEGIN: {
            purgeWCLUserEapol();
            portAuthorized = false;
            updateWCLLinkQuality(true);
            instance->pciNub->setProperty("AirportItlwm-WCLMacReconfig", ic->ic_wcl_mac_reconfig, 32);
            if (ic->ic_wcl_mac_reconfig) {
                // Consume at reset entry, not at READY: the READY that follows
                // this restart is the only completion signal, and skipping it
                // left WCL without a driver-available notification.
                AirportWCL::consumeMacReconfiguration(ic->ic_wcl_mac_reconfig, true);
                instance->pciNub->setProperty("AirportItlwm-WCLMacReconfigConsumed", 1, 32);
                break;
            }
            uint32_t reset = 0; // Native resetInterfacesBegin.
            instance->pciNub->setProperty("AirportItlwm-WCLResetPostAttempted", 1, 32);
            IOReturn status = instance->postMessage(this, AirportWCL::ResetInterface, &reset, sizeof(reset), true);
            instance->pciNub->setProperty("AirportItlwm-WCLResetPostResult", status, 32);
            break;
        }
        case IEEE80211_EVT_DRIVER_READY:
        case IEEE80211_EVT_DRIVER_STOPPED: {
            bool ready = code == IEEE80211_EVT_DRIVER_READY;
            if (!ready) {
                purgeWCLUserEapol();
                finishWCLScan(ic->ic_wcl_mac_reconfig ? kIOReturnAborted : kIOReturnOffline);
                finishWCLJoin(1, 0, kIOReturnOffline);
                portAuthorized = false;
                updateWCLLinkQuality(true);
                ic->ic_wcl_join_requested = false;
                clearWCLPMKSA();
                ic->ic_wcl_enterprise = false;
                explicit_bzero(ic->ic_psk, sizeof(ic->ic_psk));
                clearWCLSAE(ic);
            }
            // An address application is requested by WCL itself, not a new
            // adapter reset. Replaying firmware-load events here rotates the
            // scan MAC again and recursively restarts the card.
            instance->pciNub->setProperty("AirportItlwm-WCLMacReconfig", ic->ic_wcl_mac_reconfig, 32);
            bool consumedMacReconfig = AirportWCL::consumeMacReconfiguration(ic->ic_wcl_mac_reconfig, ready);
            instance->pciNub->setProperty("AirportItlwm-WCLMacReconfigConsumed", consumedMacReconfig, 32);
            if (consumedMacReconfig) {
                if (ready)
                    resumeWCLJoin();
                break;
            }
            if (ready) {
                uint32_t reset = 1; // Native resetInterfacesComplete, only after HAL success.
                instance->pciNub->setProperty("AirportItlwm-WCLResetPostAttempted", 1, 32);
                IOReturn status = instance->postMessage(this, AirportWCL::ResetInterface, &reset, sizeof(reset), true);
                instance->pciNub->setProperty("AirportItlwm-WCLResetPostResult", status, 32);
            }
            AirportWCL::DriverAvailability event = {};
            event.version = 3;
            event.available = ready;
            event.reason = ready ? 0xe0821803 : 0xe0821804;
            instance->pciNub->setProperty("AirportItlwm-WCLDriverAvailablePostAttempted", 1, 32);
            instance->pciNub->setProperty("AirportItlwm-WCLDriverAvailable", event.available, 32);
            instance->pciNub->setProperty("AirportItlwm-WCLDriverAvailableReason", event.reason, 32);
            IOReturn status = instance->postMessage(this, AirportWCL::DriverAvailable, &event, sizeof(event), true);
            instance->pciNub->setProperty("AirportItlwm-WCLDriverAvailablePostResult", status, 32);
            if (ready)
                resumeWCLJoin();
            break;
        }
        case IEEE80211_EVT_BEACON: {
            auto beacon = static_cast<ieee80211_beacon_event *>(data);
            if (!beacon)
                break;
            // Retain the actual associated beacon, including its advancing TSF.
            // WCL polls BEACON_INFO to distinguish fresh reception from a stale BSS.
            if (assocNotified && (joinPending || portAuthorized) &&
                IEEE80211_ADDR_EQ(beacon->node->ni_bssid, joinBSSID) &&
                beacon->frame && beacon->frame_length >= 36 &&
                beacon->frame_length <= 0x800 &&
                (beacon->frame[0] & 0xfc) == IEEE80211_FC0_SUBTYPE_BEACON) {
                uint32_t length = uint32_t(beacon->frame_length);
                bzero(wclBeaconInfo, sizeof(wclBeaconInfo));
                memcpy(wclBeaconInfo, &length, sizeof(length));
                memcpy(wclBeaconInfo + 4, beacon->frame, length);
                ++wclAssociatedBeacons;
                ++wclLqmBeacons;
                // WCL has no legacy LQMData instance at createLQMData().
                // Send the snapshot consumed by WCL instead of legacy 227/229.
                if (portAuthorized && (wclLqmBeacons % 8 == 0)) {
#if __IO80211_TARGET == __MAC_15_2
                    apple80211_rssi_data rssi = {};
                    if (getRSSI(&rssi) == kIOReturnSuccess) {
                        AirportWCL::SequoiaLqmUpdate update = {};
                        update.rssiValid = 1;
                        update.rssi = rssi.aggregate_rssi;
                        instance->postMessage(this, AirportWCL::LqmUpdate,
                            &update, sizeof(update), true);
                    }
#else
                    AirportWCL::LqmBeaconUpdate update;
                    if (AirportWCL::makeBeaconUpdate(
                            wclLqmBeacons - wclLqmReportedBeacons, update)) {
                        instance->postMessage(this, AirportWCL::LqmUpdate,
                            &update, sizeof(update), true);
                        wclLqmReportedBeacons = wclLqmBeacons;
                    }
#endif
                    updateWCLLinkQuality();
                }
            }
            if (scanPending || joinPending || ic->ic_state == IEEE80211_S_SCAN ||
                (portAuthorized && IEEE80211_ADDR_EQ(beacon->node->ni_bssid, joinBSSID)))
                publishWCLBeacon(beacon->node, beacon->ies, beacon->length);
            if (joinPending && assocNotified && !firstBeaconNotified &&
                IEEE80211_ADDR_EQ(beacon->node->ni_bssid, joinBSSID)) {
                AirportWCL::FirstBeaconEvent event = {};
                memcpy(event.peer.bssid, joinBSSID, 6);
                if (!wclBssValid)
                    break;
                firstBeaconNotified = true;
                ++wclFirstBeaconEvents;
                publishWCLAuthDiagnostic("first-associated-beacon");
                AirportWCL::LinkStatusEvent link = {};
                memcpy(link.bssid, joinBSSID, sizeof(link.bssid));
                link.up = 1;
                link.reason = 255;
                wclLinkIndicated = true;
                instance->postMessage(this, AirportWCL::LinkStatus, &link, sizeof(link), true);
                instance->postMessage(this, AirportWCL::FirstBeacon, &event, sizeof(event), true);
                if (portAuthorized)
                    finishWCLJoin(0, 0, kIOReturnSuccess);
            }
            break;
        }
        case IEEE80211_EVT_SCAN_DONE:
            if (scanPending) {
                scanCompleted = true;
                scanSource->setTimeoutMS(0);
            }
            break;
        case IEEE80211_EVT_STA_ASSOC_DONE:
            if (joinPending && !assocNotified) {
                AirportWCL::AssociationEvent event = {};
                event.status = ic->ic_assoc_status;
                memcpy(event.bssid, joinBSSID, 6);
                event.mlo = ic->ic_wcl_peer_is_mlo;
                if (event.mlo)
                    memcpy(event.mloData, ic->ic_wcl_peer_mld_addr,
                        sizeof(ic->ic_wcl_peer_mld_addr));
                event.driverStatus = event.status ? kIOReturnError : kIOReturnSuccess;
                assocNotified = !event.status;
                ++wclAssociationEvents;
                if (assocNotified && ic->ic_wcl_enterprise) {
                    joinTimer->setTimeoutMS(60000);
                    wclJoinTimeoutMS = 60000;
                }
                publishWCLAuthDiagnostic(event.status ? "association-failed" : "association-complete");
                instance->postMessage(this, AirportWCL::AssocComplete, &event, sizeof(event), true);
                if (event.status)
                    finishWCLJoin(event.status, 0, kIOReturnError);
            }
            break;
        case IEEE80211_EVT_STA_DEAUTH: {
            purgeWCLUserEapol();
            portAuthorized = false;
            updateWCLLinkQuality(true);
            AirportWCL::DeauthEvent event = {};
            event.reason = ic->ic_deauth_reason;
            if (ic->ic_bss)
                memcpy(event.bssid, ic->ic_bss->ni_bssid, 6);
            instance->postMessage(this, AirportWCL::Deauth, &event, sizeof(event), true);
            finishWCLJoin(1, event.reason, kIOReturnOffline);
            break;
        }
        default: break;
    }
}

IOReturn AirportItlwmSkywalkInterface::getWCL_VALID_CHANNEL_COUNT(unsigned long *count)
{
    if (!count)
        return kIOReturnBadArgument;
    *count = 0;
    ieee80211com *ic = fHalService->get80211Controller();
    for (unsigned i = 1; i < IEEE80211_CHAN_MAX; ++i)
        if (isset(ic->ic_chan_active, i))
            ++*count;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::setWCL_LINK_STATE_UPDATE(apple80211_wcl_update_link_state *data)
{
    if (!data)
        return kIOReturnBadArgument;
#if __IO80211_TARGET == __MAC_15_2
    const auto bytes = reinterpret_cast<const uint8_t *>(data);
    if (bytes[6]) {
        if (bytes[8])
            setCurrentApAddress(reinterpret_cast<ether_addr *>(data));
        if (bytes[7])
            setLinkState(kIO80211NetworkLinkUp, 0, false, 0);
    } else {
        uint32_t debounce = AirportWCL::read32(bytes + 12);
        setCurrentApAddress(nullptr);
        setLinkState(kIO80211NetworkLinkDown, 0, debounce != 0, debounce);
    }
    IOReturn status = kIOReturnSuccess;
#else
    IOReturn status = IO80211InfraInterface::setWCL_LINK_STATE_UPDATE(data);
#ifdef __PRIVATE_SPI__
    if (status == kIOReturnSuccess) {
        // Native byte 6 is association; byte 7/linkState waits for authorization.
        const bool isAssociated = reinterpret_cast<const uint8_t *>(data)[6] != 0;
        if (instance->bsdInterface) {
            if (isAssociated)
                instance->bsdInterface->startOutputThread();
            else {
                instance->bsdInterface->stopOutputThread();
                instance->bsdInterface->flushOutputQueue();
            }
        }
        if (!isAssociated) {
            setWCLNativeLinkReady(false);
        } else if (instance->bsdInterface) {
            auto ic = fHalService->get80211Controller();
            apple80211_bssid_data bssid = {};
            if (ic->ic_wcl_enterprise) {
                IOReturn bssidStatus = getBSSID(&bssid);
                bool bssidMatchesJoin = bssidStatus == kIOReturnSuccess &&
                    memcmp(bssid.bssid.octet, joinBSSID, sizeof(joinBSSID)) == 0;
                instance->pciNub->setProperty("AirportItlwm-WCLAuthBssidQueryStatus", bssidStatus, 32);
                instance->pciNub->setProperty("AirportItlwm-WCLAuthBssidMatchesJoin", bssidMatchesJoin, 32);
                char currentBssid[18];
                if (bssidStatus == kIOReturnSuccess) {
                    snprintf(currentBssid, sizeof(currentBssid), "%02x:%02x:%02x:%02x:%02x:%02x",
                        bssid.bssid.octet[0], bssid.bssid.octet[1], bssid.bssid.octet[2],
                        bssid.bssid.octet[3], bssid.bssid.octet[4], bssid.bssid.octet[5]);
                } else {
                    strlcpy(currentBssid, "unavailable", sizeof(currentBssid));
                }
                instance->pciNub->setProperty("AirportItlwm-WCLAuthCurrentBssid", currentBssid);
                if (bssidMatchesJoin) {
                    setWCLNativeLinkReady(true);
                    if (wclEapolSource)
                        wclEapolSource->setTimeoutMS(0);
                }
            }
        }
    }
#endif
#endif
    if (status == kIOReturnSuccess)
        updateWCLLinkQuality(true);
    if (status == kIOReturnSuccess && linkState() == kIO80211NetworkLinkUp) {
        auto ic = fHalService->get80211Controller();
        apple80211_bssid_data bssid = {};
        if (ic->ic_wcl_peer_is_mlo &&
            getBSSID(&bssid) == kIOReturnSuccess &&
            ieee80211_mld_set_active_link_by_bssid(ic,
                bssid.bssid.octet) == 0 &&
            ic->ic_wcl_update_mld_active_link)
            ic->ic_wcl_update_mld_active_link(ic,
                ic->ic_wcl_active_mld_link);
    }
    return status;
}

IOReturn AirportItlwmSkywalkInterface::getWCL_BSS_INFO(apple80211_beacon_msg *data)
{
    if (!data)
        return kIOReturnBadArgument;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(5), data);
}

IOReturn AirportItlwmSkywalkInterface::getWCL_EXTENDED_BSS_INFO(apple80211_extended_bss_info *data)
{
    if (!data)
        return kIOReturnBadArgument;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(6), data);
}

IOReturn AirportItlwmSkywalkInterface::copyWCLExtendedBss(void *data)
{
    ieee80211com *ic = fHalService->get80211Controller();
    if (!data || !ic->ic_bss || ic->ic_state != IEEE80211_S_RUN)
        return kIOReturnNotReady;
    static_assert(sizeof(apple80211_rate_set_data) == 0xbc, "Extended BSS rates size");
    static_assert(sizeof(apple80211_mcs_index_set_data) == 0x10, "Extended BSS MCS size");
    auto bytes = static_cast<uint8_t *>(data);
#if __IO80211_TARGET == __MAC_15_2
    bzero(bytes, 0x1e0);
#else
    bzero(bytes, 0x214);
#endif
    IOReturn status = getRATE_SET(reinterpret_cast<apple80211_rate_set_data *>(bytes));
    if (status)
        return status;
    status = getMCS_INDEX_SET(reinterpret_cast<apple80211_mcs_index_set_data *>(bytes + 0xbc));
    if (status)
        return status;
    apple80211_vht_mcs_index_set_data vht = {};
    vht.version = APPLE80211_VERSION;
    vht.mcs_map = 0xffff;
    if (ic->ic_bss->ni_flags & IEEE80211_NODE_VHT)
        vht.mcs_map = ic->ic_bss->ni_vht_mcsinfo.tx_mcs_map;
    memcpy(bytes + 0xcc, &vht, sizeof(vht));
    // Native updateMCSSet uses version + a 16-bit HE MCS/NSS map (8 bytes).
    uint32_t heVersion = APPLE80211_VERSION;
    uint16_t heMap = 0xffff;
    if (ic->ic_bss->ni_flags & IEEE80211_NODE_HE) {
        bool wide = ic->ic_bss->ni_chw == IEEE80211_CHAN_WIDTH_160;
        heMap = htole16(ieee80211_he_mcs_intersection(
            le16toh(wide ? ic->ic_he_mcs_nss_supp.rx_mcs_160 : ic->ic_he_mcs_nss_supp.rx_mcs_80),
            le16toh(wide ? ic->ic_bss->ni_he_mcs_nss_supp.tx_mcs_160 : ic->ic_bss->ni_he_mcs_nss_supp.tx_mcs_80)));
    }
    memcpy(bytes + 0xd4, &heVersion, sizeof(heVersion));
    memcpy(bytes + 0xd8, &heMap, sizeof(heMap));
    if (ic->ic_flags & IEEE80211_F_RSNON)
#if __IO80211_TARGET == __MAC_15_2
        ieee80211_add_rsn(bytes + 0xdd, ic, ic->ic_bss);
#else
        ieee80211_add_rsn(bytes + 0x113, ic, ic->ic_bss);
#endif
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::setWCL_UPDATE_FAST_LANE(apple80211_fastlane *data)
{
    if (!data)
        return kIOReturnBadArgument;
    const auto bytes = reinterpret_cast<const uint8_t *>(data);
    return (bytes[0] || bytes[1]) ? kIOReturnUnsupported : kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getWCL_LOW_LATENCY_INFO(apple80211_low_latency_info *data)
{
    if (!data)
        return kIOReturnBadArgument;
    // No low-latency or P2P session is implemented by this adapter.
    bzero(data, 4);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::getWCL_CHANNELS_INFO(apple80211ChannelInfo *data)
{
    if (!data)
        return kIOReturnBadArgument;
    auto info = reinterpret_cast<AirportWCL::ChannelInfo *>(data);
    bzero(info, sizeof(*info));
    ieee80211com *ic = fHalService->get80211Controller();
    for (unsigned i = 1; i <= IEEE80211_CHAN_MAX && info->count < 400; ++i) {
        if (!isset(ic->ic_chan_active, i))
            continue;
        const ieee80211_channel *channel = &ic->ic_channels[i];
        unsigned number = ieee80211_chan2number(ic, channel);
        uint16_t spec = AirportWCL::channelSpec20(number, wclChannelBand(channel));
        if (!spec)
            continue;
        auto &entry = info->channels[info->count++];
        entry.channel = number;
        entry.channelSpec = spec;
        if (IEEE80211_IS_CHAN_6GHZ(channel))
            info->supports6GHz = 1;
        if (channel->ic_flags & IEEE80211_CHAN_DFS)
            entry.flags |= 2;
        if (channel->ic_flags & IEEE80211_CHAN_PASSIVE)
            entry.flags |= 4;
    }
    instance->pciNub->setProperty("AirportItlwm-WCLChannelsInfo", info->count, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLChannels6GHz", info->supports6GHz, 32);
    apple80211_country_code_data country = {};
    if (instance->getCOUNTRY_CODE(static_cast<OSObject *>(this), &country) == kIOReturnSuccess)
        memcpy(info->country, country.cc, 3);
    return info->count ? kIOReturnSuccess : kIOReturnNotReady;
}

IOReturn AirportItlwmSkywalkInterface::getCHANNELS_INFO(apple80211_channels_info *data)
{
    if (!data)
        return kIOReturnBadArgument;
    if (!_fCommandGate)
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(13), data);
}

IOReturn AirportItlwmSkywalkInterface::copyWCLChannels(void *data)
{
    auto info = static_cast<AirportWCL::NativeChannelInfo *>(data);
    bzero(info, sizeof(*info));
    info->version = APPLE80211_VERSION;
    ieee80211com *ic = fHalService->get80211Controller();
    for (unsigned i = 1; i <= IEEE80211_CHAN_MAX; ++i) {
        const ieee80211_channel *channel = &ic->ic_channels[i];
        if (!isset(ic->ic_chan_active, i) || !channel->ic_freq)
            continue;
        AirportWCL::appendChannel(*info, ieee80211_chan2number(ic, channel), wclChannelBand(channel),
            channel->ic_flags & IEEE80211_CHAN_DFS,
            channel->ic_flags & IEEE80211_CHAN_PASSIVE,
            !(channel->ic_reg_flags & IEEE80211_CHAN_NO_40MHZ) &&
                (IEEE80211_IS_CHAN_HT40(channel) || IEEE80211_IS_CHAN_VHT40(channel)),
            !(channel->ic_reg_flags & IEEE80211_CHAN_NO_80MHZ) &&
                (IEEE80211_IS_CHAN_VHT80(channel) || IEEE80211_IS_CHAN_6GHZ(channel)));
    }
    apple80211_country_code_data country = {};
    if (instance->getCOUNTRY_CODE(static_cast<OSObject *>(this), &country) == kIOReturnSuccess)
        memcpy(info->country, country.cc, sizeof(country.cc));
    instance->pciNub->setProperty("AirportItlwm-WCLNativeChannelsVersion", info->version, 32);
    instance->pciNub->setProperty("AirportItlwm-WCLNativeChannelsInfo", info->count, 32);
    return info->count ? kIOReturnSuccess : kIOReturnNotReady;
}

IOReturn AirportItlwmSkywalkInterface::getWCL_TRAFFIC_COUNTERS(apple80211_wcl_traffic_counters *data)
{
    if (!data)
        return kIOReturnBadArgument;
    if (!_fCommandGate)
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(14), data);
}

IOReturn AirportItlwmSkywalkInterface::copyWCLTrafficCounters(void *data)
{
    ieee80211com *ic = fHalService->get80211Controller();
    uint64_t timestamp;
    absolutetime_to_nanoseconds(mach_absolute_time(), &timestamp);
    const auto counters = AirportWCL::makeTrafficCounters(
        ic->ic_wcl_tx_packets, ic->ic_wcl_rx_packets, timestamp);
    memcpy(data, &counters, sizeof(counters));
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::setWCL_SET_SCAN_HOME_AWAY_TIME(scanHomeAndAwayTime *data)
{
    if (!data)
        return kIOReturnBadArgument;
    if (!_fCommandGate)
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(15), data);
}
#endif

#ifdef AIRPORT_WCL
IOReturn AirportItlwmSkywalkInterface::getBEACON_INFO(apple80211_beacon_info_t *data)
{
    if (!_fCommandGate || !data)
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(7), data);
}
#endif
