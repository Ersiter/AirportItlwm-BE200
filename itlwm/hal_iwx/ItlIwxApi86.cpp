/*
 * Copyright (C) 2020  钟先耀
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifdef AIRPORT_WCL
#include "../../AirportItlwm/WCL/WCL.hpp"
#endif
#include "ItlIwx.hpp"
#include "if_iwxapi86.h"
#include <net80211/ieee80211_priv.h>

static constexpr uint8_t IWL_SCAN_DWELL_ACTIVE = 10;
static constexpr uint8_t IWL_SCAN_DWELL_PASSIVE = 110;
static constexpr uint8_t IWL_SCAN_NUM_OF_FRAGS = 3;
static constexpr uint8_t IWX_SCAN_ADWELL_DEFAULT_N_APS_SOCIAL = 10;
static constexpr uint8_t IWX_SCAN_ADWELL_DEFAULT_LB_N_APS = 2;
static constexpr uint8_t IWX_SCAN_ADWELL_DEFAULT_HB_N_APS = 8;
static constexpr uint16_t IWX_SCAN_ADWELL_MAX_BUDGET_DIRECTED_SCAN = 100;
static constexpr uint16_t IWX_SCAN_ADWELL_MAX_BUDGET_FULL_SCAN = 300;
static constexpr uint8_t IWX_SCAN_ADWELL_N_APS_GO_FRIENDLY = 10;
static constexpr uint8_t IWX_SCAN_ADWELL_N_APS_SOCIAL_CHS = 2;

int ItlIwx::
iwx_umac_scan_v17(struct iwx_softc *sc, int bgscan)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = &sc->sc_ic;
    int scanSSIDLength = ic->ic_des_esslen;
    const uint8_t *scanSSID = ic->ic_des_essid;
    bool scanActive = scanSSIDLength != 0 && !bgscan;
#ifdef AIRPORT_WCL
    scanActive = AirportWCL::scanUsesProbes(ic->ic_wcl_scan_requested,
        ic->ic_wcl_scan_active);
    if (ic->ic_wcl_scan_requested) {
        scanSSIDLength = ic->ic_wcl_scan_ssid_length;
        scanSSID = ic->ic_wcl_scan_ssid;
    }
#endif
    int err = 0, async = bgscan;
    struct iwx_api86_scan_req *req;
    size_t req_len;
    uint16_t gen_flags = 0;
    struct iwx_api86_scan_general *general_params;
    struct iwx_api86_scan_channels *cp;
    const uint32_t timeout = bgscan ?  htole32(120) : htole32(0);
#ifdef AIRPORT_WCL
    const auto timing = AirportWCL::scanTiming(ic->ic_wcl_scan_away_time_ms, bgscan,
        isset(sc->sc_ucode_api, IWX_UCODE_TLV_API_FRAGMENTED_SCAN));
    const uint32_t maxOut = htole32(timing.maxOutTU);
#else
    const uint32_t maxOut = timeout;
#endif
    struct iwx_host_cmd hcmd = {
        .id = iwx_cmd_id(IWX_SCAN_REQ_UMAC, IWX_LONG_GROUP, 0),
        .len = { 0, },
        .data = { NULL, },
        .flags = 0,
    };
    
    req_len = sizeof(*req);
    req = (struct iwx_api86_scan_req *)malloc(req_len, 0,
                                             (async ? M_NOWAIT : M_WAITOK) | M_ZERO);
    if (req == NULL)
        return ENOMEM;
    
    hcmd.len[0] = (uint16_t)req_len;
    hcmd.data[0] = (void *)req;
    hcmd.flags |= async ? IWX_CMD_ASYNC : 0;
    
    general_params = &req->scan_params.general_params;
    
    req->ooc_priority = htole32(IWX_SCAN_PRIORITY_EXT_6);
    
    if (!scanActive)
        gen_flags |= IWX_UMAC_SCAN_GEN_FLAGS_V2_FORCE_PASSIVE;
    
    gen_flags |= IWX_UMAC_SCAN_GEN_FLAGS_V2_PASS_ALL |
    IWX_UMAC_SCAN_GEN_FLAGS_V2_ADAPTIVE_DWELL;
    
#ifdef AIRPORT_WCL
    if (timing.fragmented) {
        gen_flags |= IWX_UMAC_SCAN_GEN_FLAGS_V2_FRAGMENTED_LMAC1;
        general_params->num_of_fragments[IWX_SCAN_LB_LMAC_IDX] = IWL_SCAN_NUM_OF_FRAGS;
        if (isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_CDB_SUPPORT)) {
            gen_flags |= IWX_UMAC_SCAN_GEN_FLAGS_V2_FRAGMENTED_LMAC2;
            general_params->num_of_fragments[IWX_SCAN_HB_LMAC_IDX] = IWL_SCAN_NUM_OF_FRAGS;
        }
    }
#endif
    req->scan_params.general_params.flags = htole16(gen_flags);
    
    general_params->adwell_default_social_chn =
        IWX_SCAN_ADWELL_DEFAULT_N_APS_SOCIAL;
    general_params->adwell_default_2g = IWX_SCAN_ADWELL_DEFAULT_LB_N_APS;
    general_params->adwell_default_5g = IWX_SCAN_ADWELL_DEFAULT_HB_N_APS;
    if (scanActive && scanSSIDLength != 0)
        general_params->adwell_max_budget =
            cpu_to_le16(IWX_SCAN_ADWELL_MAX_BUDGET_DIRECTED_SCAN);
    else
        general_params->adwell_max_budget =
            cpu_to_le16(IWX_SCAN_ADWELL_MAX_BUDGET_FULL_SCAN);
    
    general_params->scan_priority = htole32(IWX_SCAN_PRIORITY_EXT_6);
    general_params->max_out_of_time[IWX_SCAN_LB_LMAC_IDX] =
        maxOut;
    general_params->suspend_time[IWX_SCAN_LB_LMAC_IDX] =
        timeout;
    
    if (isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_CDB_SUPPORT)) {
        general_params->max_out_of_time[IWX_SCAN_HB_LMAC_IDX] = maxOut;
        general_params->suspend_time[IWX_SCAN_HB_LMAC_IDX] = timeout;
    }

    general_params->active_dwell[IWX_SCAN_LB_LMAC_IDX] = IWL_SCAN_DWELL_ACTIVE;
    general_params->passive_dwell[IWX_SCAN_LB_LMAC_IDX] = IWL_SCAN_DWELL_PASSIVE;
    general_params->active_dwell[IWX_SCAN_HB_LMAC_IDX] = IWL_SCAN_DWELL_ACTIVE;
    general_params->passive_dwell[IWX_SCAN_HB_LMAC_IDX] = IWL_SCAN_DWELL_PASSIVE;
    
    /* Specify the scan plan: We'll do one iteration. */
    req->scan_params.periodic_params.schedule[0].interval = 0;
    req->scan_params.periodic_params.schedule[0].iter_count = 1;
    
    err = iwx_fill_probe_req(sc, &req->scan_params.probe_params.preq);
    if (err) {
        ::free(req);
        return err;
    }
    if (scanActive) {
        req->scan_params.probe_params.direct_scan[0].id = IEEE80211_ELEMID_SSID;
        req->scan_params.probe_params.direct_scan[0].len = scanSSIDLength;
        memcpy(req->scan_params.probe_params.direct_scan[0].ssid, scanSSID,
               scanSSIDLength);
    }
    
    cp = &req->scan_params.channel_params;
    
    cp->flags = IWX_SCAN_CHANNEL_FLAG_ENABLE_CHAN_ORDER;
    for (auto c = &ic->ic_channels[1];
         c <= &ic->ic_channels[IEEE80211_CHAN_MAX] &&
         cp->count < nitems(cp->channel_config) &&
         cp->count < sc->sc_capa_n_scan_channels; c++) {
        if (!IEEE80211_IS_CHAN_2GHZ(c) && !IEEE80211_IS_CHAN_5GHZ(c))
            continue;
#ifdef AIRPORT_WCL
        if (!AirportWCL::scanChannelSelected(ic->ic_wcl_scan_channels,
                ic->ic_wcl_scan_requested && ic->ic_wcl_scan_restricted,
                ieee80211_chan2ieee(ic, c)))
            continue;
#endif
        auto channel = &cp->channel_config[cp->count++];
        uint32_t channelFlags =
            (IEEE80211_IS_CHAN_2GHZ(c) ? IWX_PHY_BAND_24 : IWX_PHY_BAND_5) << 30;
#ifdef AIRPORT_WCL
        if (AirportWCL::probeChannel(scanActive,
                c->ic_flags & IEEE80211_CHAN_PASSIVE,
                c->ic_flags & IEEE80211_CHAN_DFS))
#else
        if (scanActive && !bgscan)
#endif
            channelFlags |= 1;
        channel->flags = htole32(channelFlags);
        channel->channel_num = ieee80211_mhz2ieee(c->ic_freq, 0);
        channel->psd_20 = 0x80;
        channel->iter_count = 1;
    }
    cp->n_aps_override[0] = IWX_SCAN_ADWELL_N_APS_GO_FRIENDLY;
    cp->n_aps_override[1] = IWX_SCAN_ADWELL_N_APS_SOCIAL_CHS;
    
    err = iwx_send_cmd(sc, &hcmd);
    ::free(req);
    return err;
}
