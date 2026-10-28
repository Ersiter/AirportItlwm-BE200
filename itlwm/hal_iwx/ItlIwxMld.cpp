/*	$OpenBSD: if_iwx.c,v 1.230 2026/09/19 19:36:42 stsp Exp $	*/

/*
 * Copyright (c) 2014, 2016 genua gmbh <info@genua.de>
 *   Author: Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2014 Fixup Software Ltd.
 * Copyright (c) 2017, 2019, 2020 Stefan Sperling <stsp@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*-
 * Based on BSD-licensed source modules in the Linux iwlwifi driver,
 * which were used as the reference documentation for this implementation.
 *
 ******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2017 Intel Deutschland GmbH
 * Copyright(c) 2018 - 2019 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * BSD LICENSE
 *
 * Copyright(c) 2017 Intel Deutschland GmbH
 * Copyright(c) 2018 - 2019 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************
 */

/*-
 * Copyright (c) 2007-2010 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

// Single-link command paths adapted from OpenBSD if_iwx.c revision 1.230.
#include "ItlIwx.hpp"
#include "if_iwxmld.h"
#include <net80211/ieee80211_priv.h>
#include <libkern/c++/OSNumber.h>

static uint8_t
iwx_mld_he_ppe_value(const uint8_t *ppe, unsigned bit)
{
    unsigned value = ppe[bit / 8] >> (bit % 8);
    if (bit % 8 > 5)
        value |= unsigned(ppe[bit / 8 + 1]) << (8 - bit % 8);
    return value & 7;
}

static void
iwx_mld_record_state_failure(struct iwx_softc *sc, const char *operation,
    const char *stage, int error, uint32_t command, int detail)
{
    if (sc->sc_flags & IWX_FLAG_SHUTDOWN)
        return;
    OSNumber *failure_generation = OSDynamicCast(OSNumber,
        sc->sc_pcitag->getProperty("AirportItlwm-MLDStateFailureGeneration"));
    if (failure_generation &&
        failure_generation->unsigned32BitValue() == (uint32_t)sc->sc_generation)
        return;

    char value[192];
    snprintf(value, sizeof(value),
        "operation=%s stage=%s error=%d cmd=0x%08x detail=%d gen=%d",
        operation, stage, error, command, detail, sc->sc_generation);
    sc->sc_pcitag->setProperty("AirportItlwm-MLDStateFailure", value);
    sc->sc_pcitag->setProperty("AirportItlwm-MLDStateFailureGeneration",
        sc->sc_generation, 32);
}

static void
iwx_mld_record_key_reject(struct iwx_softc *sc, struct ieee80211_node *ni,
    struct ieee80211_key *key, int remove, const char *reason)
{
    char detail[160];
    snprintf(detail, sizeof(detail),
        "reason=%s remove=%d cipher=%d len=%d key_id=%d flags=0x%x node=%d",
        reason, remove, key->k_cipher, key->k_len, key->k_id,
        key->k_flags, ni != NULL);
    sc->sc_pcitag->setProperty("AirportItlwm-MLDKeyReject", reason);
    sc->sc_pcitag->setProperty("AirportItlwm-MLDKeyRejectDetail", detail);
}

static int
iwx_mld_link_slot(struct ieee80211com *ic, struct ieee80211_node *ni)
{
    if (ni == ic->ic_bss)
        return 0;
    for (int i = 0; i < ic->ic_mld_link_count; i++)
        if (ic->ic_mld_links[i].ni == ni)
            return i;
    return -1;
}

static void
iwx_mld_limit_link_resources(struct iwx_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    int max_links = IWX_NUM_PHY_CTX;

    if (max_links > IWX_MLD_MAX_LINKS)
        max_links = IWX_MLD_MAX_LINKS;
    if (sc->sc_capa_num_stations <= IWX_MONITOR_STA_ID + 1)
        max_links = 1;
    else if (max_links > sc->sc_capa_num_stations - IWX_MONITOR_STA_ID)
        max_links = sc->sc_capa_num_stations - IWX_MONITOR_STA_ID;

    while (ic->ic_mld_link_count > max_links) {
        struct ieee80211_mld_link_info *link =
            &ic->ic_mld_links[ic->ic_mld_link_count - 1];
        if (link->ni != NULL)
            ieee80211_release_node(ic, link->ni);
        memset(link, 0, sizeof(*link));
        ic->ic_mld_link_count--;
    }

    memset(sc->sc_mld_sta_ids, 0xff, sizeof(sc->sc_mld_sta_ids));
    sc->sc_mld_sta_ids[0] = IWX_STATION_ID;
    if (ic->ic_mld_link_count != 0) {
        for (int i = 1; i < ic->ic_mld_link_count; i++)
            sc->sc_mld_sta_ids[i] = IWX_MONITOR_STA_ID + i;
    }
    sc->sc_mld_sta_mask = 0;
    sc->sc_mld_active_sta_mask = 0;
    sc->sc_mld_active_links = 1;
    sc->sc_mld_primary_link = 0;
    sc->sc_mld_emlsr_active = 0;
    sc->sc_mld_tx_link_seq = 0;
    ic->ic_wcl_active_mld_link = 0;
}

static int
iwx_mld_modify_queue_sta_mask(ItlIwx *that, struct iwx_softc *sc, int tid,
    uint32_t old_mask, uint32_t new_mask)
{
    struct iwx_mld_scd_queue_cfg_cmd cmd = {};

    if (that->iwx_lookup_cmd_ver(sc, IWX_DATA_PATH_GROUP,
        IWX_MLD_SCD_QUEUE_CONFIG_CMD) != 3)
        return ENOTSUP;
    cmd.operation = htole32(IWX_MLD_SCD_QUEUE_MODIFY);
    cmd.u.modify.old_sta_mask = htole32(old_mask);
    cmd.u.modify.tid = htole32(tid);
    cmd.u.modify.new_sta_mask = htole32(new_mask);
    return that->iwx_send_cmd_pdu(sc,
        IWX_WIDE_ID(IWX_DATA_PATH_GROUP, IWX_MLD_SCD_QUEUE_CONFIG_CMD),
        0, sizeof(cmd), &cmd);
}

static int
iwx_mld_update_queue_sta_mask(ItlIwx *that, struct iwx_softc *sc,
    uint32_t old_mask, uint32_t new_mask)
{
    uint16_t modified = 0;
    int err;

    for (int tid = 0; tid <= IWX_MGMT_TID; tid++) {
        if (!(sc->sc_mld_txq_tidmask & (1U << tid)))
            continue;
        err = iwx_mld_modify_queue_sta_mask(that, sc, tid, old_mask, new_mask);
        if (err) {
            for (int undo = tid - 1; undo >= 0; undo--)
                if (modified & (1U << undo))
                    iwx_mld_modify_queue_sta_mask(that, sc, undo,
                        new_mask, old_mask);
            return err;
        }
        modified |= 1U << tid;
    }
    return 0;
}

static int
iwx_mld_modify_rx_baid_sta_mask(struct iwx_softc *sc, uint32_t new_mask)
{
    uint32_t modified = 0;
    uint32_t old_masks[IWX_MAX_BAID] = {};
    int err;

    for (int i = 0; i < nitems(sc->sc_rxba_data); i++) {
        struct iwx_rxba_data *rxba = &sc->sc_rxba_data[i];
        struct iwx_mld_rx_baid_cfg_cmd cmd = {};

        if (rxba->baid == IWX_RX_REORDER_DATA_INVALID_BAID ||
            rxba->sta_mask == new_mask)
            continue;
        cmd.action = htole32(IWX_MLD_RX_BAID_MODIFY);
        cmd.modify.old_sta_id_mask = htole32(rxba->sta_mask);
        cmd.modify.new_sta_id_mask = htole32(new_mask);
        cmd.modify.tid = htole32(rxba->tid);
        ItlIwx *that = container_of(sc, ItlIwx, com);
        err = that->iwx_send_cmd_pdu(sc,
            IWX_WIDE_ID(IWX_DATA_PATH_GROUP, IWX_MLD_RX_BAID_CONFIG_CMD),
            0, sizeof(cmd), &cmd);
        if (err) {
            for (int undo = i - 1; undo >= 0; undo--) {
                struct iwx_rxba_data *old = &sc->sc_rxba_data[undo];
                struct iwx_mld_rx_baid_cfg_cmd undo_cmd = {};

                if (!(modified & (1U << undo)))
                    continue;
                undo_cmd.action = htole32(IWX_MLD_RX_BAID_MODIFY);
                undo_cmd.modify.old_sta_id_mask = htole32(old->sta_mask);
                undo_cmd.modify.new_sta_id_mask = htole32(old_masks[undo]);
                undo_cmd.modify.tid = htole32(old->tid);
                if (!that->iwx_send_cmd_pdu(sc,
                    IWX_WIDE_ID(IWX_DATA_PATH_GROUP,
                        IWX_MLD_RX_BAID_CONFIG_CMD),
                    0, sizeof(undo_cmd), &undo_cmd))
                    old->sta_mask = old_masks[undo];
            }
            return err;
        }
        old_masks[i] = rxba->sta_mask;
        rxba->sta_mask = new_mask;
        modified |= 1U << i;
    }
    return 0;
}

static int
iwx_mld_set_fw_link_active(ItlIwx *that, struct iwx_softc *sc, int link_slot,
    int active)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = link_slot == 0 ? ic->ic_bss :
        (link_slot < ic->ic_mld_link_count ? ic->ic_mld_links[link_slot].ni : NULL);
    struct iwx_mld_link_config_cmd cmd = {};

    if (ni == NULL || !(sc->sc_mld_link_active & (1U << link_slot)))
        return EINVAL;
    that->iwx_mld_modify_link_fill(sc, (struct iwx_node *)ni, &cmd,
        IWX_MLD_LINK_CONTEXT_MODIFY_ACTIVE, active);
    return that->iwx_send_cmd_pdu(sc,
        IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_LINK_CONFIG_CMD),
        0, sizeof(cmd), &cmd);
}

int ItlIwx::
iwx_mld_update_active_links(struct iwx_softc *sc, uint8_t link_mask,
    uint8_t primary_link, bool emlsr_active)
{
    struct ieee80211com *ic = &sc->sc_ic;
    uint8_t configured_links = 1;
    uint8_t old_links = sc->sc_mld_active_links;
    uint32_t old_sta_mask = sc->sc_mld_active_sta_mask;
    uint32_t new_sta_mask = 0;
    uint8_t added, removed, added_done = 0, removed_done = 0;
    bool baid_updated = false, queue_updated = false;
    int err;

    if (!(sc->sc_flags & IWX_FLAG_STA_ACTIVE) ||
        ic->ic_state != IEEE80211_S_RUN || !sc->sc_mld_sta_mask)
        return ENXIO;
    if (!link_mask || primary_link >= IWX_MLD_MAX_LINKS ||
        !(link_mask & (1U << primary_link)) ||
        __builtin_popcount((unsigned)link_mask) > 2 ||
        (emlsr_active &&
            __builtin_popcount((unsigned)link_mask) != 2))
        return EINVAL;
    for (int i = 1; i < ic->ic_mld_link_count; i++)
        if (ic->ic_mld_links[i].assoc_accepted &&
            ic->ic_mld_links[i].ni != NULL &&
            sc->sc_mld_sta_ids[i] != 0xff &&
            (sc->sc_mld_sta_mask & (1U << sc->sc_mld_sta_ids[i])))
            configured_links |= 1U << i;
    if (!link_mask || (link_mask & ~configured_links))
        return EINVAL;
    for (int i = 0; i < IWX_MLD_MAX_LINKS; i++) {
        uint8_t sta_id = sc->sc_mld_sta_ids[i];
        if ((link_mask & (1U << i)) && sta_id != 0xff &&
            (sc->sc_mld_sta_mask & (1U << sta_id)))
            new_sta_mask |= 1U << sta_id;
    }
    if (!new_sta_mask)
        return EINVAL;
    if (link_mask == old_links && new_sta_mask == old_sta_mask) {
        sc->sc_mld_primary_link = primary_link;
        sc->sc_mld_emlsr_active = emlsr_active;
        return 0;
    }

    added = link_mask & ~old_links;
    removed = old_links & ~link_mask;
    for (int i = 0; i < IWX_MLD_MAX_LINKS; i++) {
        if (!(added & (1U << i)))
            continue;
        err = iwx_mld_set_fw_link_active(this, sc, i, 1);
        if (err)
            goto rollback_added;
        added_done |= 1U << i;
    }
    err = iwx_mld_modify_rx_baid_sta_mask(sc, new_sta_mask);
    if (err) {
        iwx_mld_record_state_failure(sc, "mld-link-update", "rx-baid-mask",
            err, IWX_WIDE_ID(IWX_DATA_PATH_GROUP,
                IWX_MLD_RX_BAID_CONFIG_CMD), -1);
        goto rollback_added;
    }
    baid_updated = old_sta_mask != new_sta_mask;
    if (old_sta_mask != new_sta_mask) {
        err = iwx_mld_update_queue_sta_mask(this, sc,
            old_sta_mask, new_sta_mask);
        if (err) {
            iwx_mld_record_state_failure(sc, "mld-link-update", "tx-queue-mask",
                err, IWX_WIDE_ID(IWX_DATA_PATH_GROUP,
                    IWX_MLD_SCD_QUEUE_CONFIG_CMD), -1);
            goto rollback_added;
        }
        queue_updated = true;
    }
    for (int i = 0; i < IWX_MLD_MAX_LINKS; i++) {
        if (!(removed & (1U << i)))
            continue;
        err = iwx_mld_set_fw_link_active(this, sc, i, 0);
        if (err) {
            for (int undo = 0; undo < IWX_MLD_MAX_LINKS; undo++)
                if (removed_done & (1U << undo))
                    iwx_mld_set_fw_link_active(this, sc, undo, 1);
            iwx_mld_record_state_failure(sc, "mld-link-update", "link-deactivate",
                err, IWX_WIDE_ID(IWX_MAC_CONF_GROUP,
                    IWX_MLD_LINK_CONFIG_CMD), i);
            goto rollback_added;
        }
        removed_done |= 1U << i;
    }
    sc->sc_mld_active_links = link_mask;
    sc->sc_mld_active_sta_mask = new_sta_mask;
    sc->sc_mld_primary_link = primary_link;
    sc->sc_mld_emlsr_active = emlsr_active;
    return 0;

rollback_added:
    if (queue_updated)
        iwx_mld_update_queue_sta_mask(this, sc, new_sta_mask, old_sta_mask);
    if (baid_updated)
        iwx_mld_modify_rx_baid_sta_mask(sc, old_sta_mask);
    for (int undo = 0; undo < IWX_MLD_MAX_LINKS; undo++)
        if (added_done & (1U << undo))
            iwx_mld_set_fw_link_active(this, sc, undo, 0);
    return err;
}

#ifdef AIRPORT_WCL
static bool
iwx_mld_emlsr_link_usable(struct ieee80211_node *ni)
{
    int rssi_threshold;

    switch (ni->ni_chw) {
    case IEEE80211_CHAN_WIDTH_20_NOHT:
    case IEEE80211_CHAN_WIDTH_20:
    case IEEE80211_CHAN_WIDTH_320:
        rssi_threshold = -67;
        break;
    case IEEE80211_CHAN_WIDTH_40:
        rssi_threshold = -64;
        break;
    case IEEE80211_CHAN_WIDTH_80:
        rssi_threshold = -61;
        break;
    case IEEE80211_CHAN_WIDTH_160:
        rssi_threshold = -58;
        break;
    default:
        return false;
    }

    return (int)ni->ni_rssi + IWX_MIN_DBM >= rssi_threshold;
}

uint8_t ItlIwx::
iwx_mld_select_emlsr_links(struct iwx_softc *sc, uint8_t *primary_link)
{
    struct ieee80211com *ic = &sc->sc_ic;
    uint8_t best_links = 0;
    int best_min_rssi = -129, best_total_rssi = -258;

    if (!ic->ic_mld_emlsr_supported || !ic->ic_mld_emlsr_peer_supported ||
        ic->ic_mld_link_count < 2 || primary_link == NULL)
        return 0;

    for (int i = 0; i < ic->ic_mld_link_count; i++) {
        struct ieee80211_mld_link_info *a = &ic->ic_mld_links[i];
        struct ieee80211_node *ni_a = a->ni;
        uint8_t sta_a = sc->sc_mld_sta_ids[i];
        int band_a;

        if (ni_a == NULL || ni_a->ni_chan == NULL || sta_a == 0xff ||
            !(sc->sc_mld_sta_mask & (1U << sta_a)) ||
            (i != 0 && !a->assoc_accepted))
            continue;
        band_a = IEEE80211_IS_CHAN_2GHZ(ni_a->ni_chan) ? 2 :
            (IEEE80211_IS_CHAN_6GHZ(ni_a->ni_chan) ? 6 :
            (IEEE80211_IS_CHAN_5GHZ(ni_a->ni_chan) ? 5 : 0));
        if (!band_a || !iwx_mld_emlsr_link_usable(ni_a))
            continue;

        for (int j = i + 1; j < ic->ic_mld_link_count; j++) {
            struct ieee80211_mld_link_info *b = &ic->ic_mld_links[j];
            struct ieee80211_node *ni_b = b->ni;
            uint8_t sta_b = sc->sc_mld_sta_ids[j];
            int band_b, min_rssi, total_rssi;

            if (ni_b == NULL || ni_b->ni_chan == NULL || sta_b == 0xff ||
                !(sc->sc_mld_sta_mask & (1U << sta_b)) ||
                !b->assoc_accepted)
                continue;
            band_b = IEEE80211_IS_CHAN_2GHZ(ni_b->ni_chan) ? 2 :
                (IEEE80211_IS_CHAN_6GHZ(ni_b->ni_chan) ? 6 :
                (IEEE80211_IS_CHAN_5GHZ(ni_b->ni_chan) ? 5 : 0));
            if (!band_b || band_a == band_b ||
                ni_a->ni_chw != ni_b->ni_chw ||
                !iwx_mld_emlsr_link_usable(ni_b))
                continue;

            min_rssi = MIN(ni_a->ni_rssi, ni_b->ni_rssi);
            total_rssi = ni_a->ni_rssi + ni_b->ni_rssi;
            if (!best_links || min_rssi > best_min_rssi ||
                (min_rssi == best_min_rssi && total_rssi > best_total_rssi)) {
                best_links = (1U << i) | (1U << j);
                *primary_link = ni_a->ni_rssi >= ni_b->ni_rssi ? i : j;
                best_min_rssi = min_rssi;
                best_total_rssi = total_rssi;
            }
        }
    }
    return best_links;
}
#endif

void ItlIwx::
iwx_mld_active_link_task(void *arg)
{
    struct iwx_softc *sc = (struct iwx_softc *)arg;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    uint8_t links, primary_link, emlsr_active, disconnect, pending;
    int generation, err;

    if (!that->getMainWorkLoop()->inGate()) {
        that->getMainCommandGate()->runAction(
            [](OSObject *, void *arg0, void *, void *, void *) -> IOReturn {
                iwx_mld_active_link_task(arg0);
                return kIOReturnSuccess;
            }, arg);
        return;
    }
    int s = splnet();
    pending = sc->sc_mld_link_update_pending;
    links = sc->sc_mld_pending_links;
    primary_link = sc->sc_mld_pending_primary_link;
    emlsr_active = sc->sc_mld_pending_emlsr;
    disconnect = sc->sc_mld_disconnect_pending;
    generation = sc->sc_mld_pending_generation;
    sc->sc_mld_link_update_pending = 0;
    sc->sc_mld_disconnect_pending = 0;
    splx(s);
    if (!pending || generation != sc->sc_generation ||
        (sc->sc_flags & IWX_FLAG_SHUTDOWN))
        return;

    err = that->iwx_mld_update_active_links(sc, links, primary_link,
        emlsr_active);
    if (err && err != ENXIO) {
        iwx_mld_record_state_failure(sc, "mld-link-update", "apply-active-set",
            err, IWX_WIDE_ID(IWX_MAC_CONF_GROUP,
                IWX_MLD_LINK_CONFIG_CMD), links);
        disconnect = 1;
    }
    if (disconnect)
        that->iwx_newstate(&sc->sc_ic, IEEE80211_S_SCAN, 0);
}

void ItlIwx::
iwx_mld_modify_link_fill(struct iwx_softc *sc, struct iwx_node *in,
    struct iwx_mld_link_config_cmd *cmd, int changes, int active)
{
#define IWX_EXP2(x)    ((1 << (x)) - 1)    /* CWmin = 2^ECWmin - 1 */
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = &in->in_ni;
    int cck_ack_rates, ofdm_ack_rates;
    int i;
    uint32_t flags = 0;

    int link_slot = iwx_mld_link_slot(ic, ni);
    cmd->link_id = htole32(link_slot);
    cmd->mac_id = htole32(in->in_id);
    KASSERT(in->in_phyctxt, "MLD link requires a PHY context");
    cmd->phy_id = htole32(in->in_phyctxt->id);
    IEEE80211_ADDR_COPY(cmd->local_link_addr,
        ic->ic_mld_link_count != 0 ? ic->ic_mld_links[link_slot].local_addr :
            ic->ic_myaddr);
    cmd->active = htole32(active);

    iwx_ack_rates(sc, in, &cck_ack_rates, &ofdm_ack_rates);
    cmd->cck_rates = htole32(cck_ack_rates);
    cmd->ofdm_rates = htole32(ofdm_ack_rates);
    cmd->cck_short_preamble
        = htole32((ic->ic_flags & IEEE80211_F_SHPREAMBLE) ? 1 : 0);
    cmd->short_slot
        = htole32((ic->ic_flags & IEEE80211_F_SHSLOT) ? 1 : 0);

    for (i = 0; i < EDCA_NUM_AC; i++) {
        struct ieee80211_edca_ac_params *ac = &ic->ic_edca_ac[i];
        int txf;

        static const uint8_t bz_fifo[] = { 1, 0, 2, 3 };
        txf = bz_fifo[i];

        cmd->ac[txf].cw_min = htole16(IWX_EXP2(ac->ac_ecwmin));
        cmd->ac[txf].cw_max = htole16(IWX_EXP2(ac->ac_ecwmax));
        cmd->ac[txf].aifsn = ac->ac_aifsn;
        cmd->ac[txf].fifos_mask = (1 << txf);
        cmd->ac[txf].edca_txop = htole16(ac->ac_txoplimit * 32);
    }
    if (ni->ni_flags & IEEE80211_NODE_QOS)
        cmd->qos_flags |= htole32(IWX_MAC_QOS_FLG_UPDATE_EDCA);

    if (ni->ni_flags & IEEE80211_NODE_HT) {
        enum ieee80211_htprot htprot =
            (enum ieee80211_htprot)(ni->ni_htop1 & IEEE80211_HTOP1_PROT_MASK);
        switch (htprot) {
        case IEEE80211_HTPROT_NONE:
            break;
        case IEEE80211_HTPROT_NONMEMBER:
        case IEEE80211_HTPROT_NONHT_MIXED:
            cmd->protection_flags |=
                htole32(IWX_MLD_LINK_PROT_FLG_HT_PROT |
                    IWX_MLD_LINK_PROT_FLG_FAT_PROT);
            break;
        case IEEE80211_HTPROT_20MHZ:
            if (ni->ni_chw == IEEE80211_CHAN_WIDTH_40) {
                cmd->protection_flags |=
                    htole32(IWX_MLD_LINK_PROT_FLG_HT_PROT |
                        IWX_MLD_LINK_PROT_FLG_FAT_PROT);
            }
            break;
        default:
            break;
        }

        cmd->qos_flags |= htole32(IWX_MAC_QOS_FLG_TGN);
    }
    if (ic->ic_flags & IEEE80211_F_USEPROT)
        cmd->protection_flags |= htole32(IWX_MLD_LINK_PROT_FLG_TGG_PROTECT);

    if ((changes & IWX_MLD_LINK_CONTEXT_MODIFY_HE_PARAMS) &&
        (ni->ni_flags & IEEE80211_NODE_HE)) {
        uint32_t he_op = ni->ni_he_oper_params;
        cmd->htc_trig_based_pkt_ext = he_op &
            IEEE80211_HE_OPERATION_DFLT_PE_DURATION_MASK;
        cmd->frame_time_rts_th = htole16((he_op &
            IEEE80211_HE_OPERATION_RTS_THRESHOLD_MASK) >>
            IEEE80211_HE_OPERATION_RTS_THRESHOLD_OFFSET);
        cmd->bss_color = (he_op & IEEE80211_HE_OPERATION_BSS_COLOR_MASK) >>
            IEEE80211_HE_OPERATION_BSS_COLOR_OFFSET;
        if (he_op & IEEE80211_HE_OPERATION_BSS_COLOR_DISABLED)
            flags |= IWX_MLD_LINK_FLG_BSS_COLOR_DIS;
        if (ni->ni_flags & IEEE80211_NODE_HE_MU_EDCA) {
            static const uint8_t bz_fifo[] = { 1, 0, 2, 3 };
            flags |= IWX_MLD_LINK_FLG_MU_EDCA_CW;
            for (i = 0; i < 4; i++) {
                const uint8_t *rec = ni->ni_he_mu_edca + 1 + 3 * i;
                uint8_t fw_ac = bz_fifo[i];
                cmd->trig_based_txf[fw_ac].cwmin = htole16(rec[1] & 0x0f);
                cmd->trig_based_txf[fw_ac].cwmax = htole16(rec[1] >> 4);
                cmd->trig_based_txf[fw_ac].aifsn = htole16(rec[0] & 0x0f);
                cmd->trig_based_txf[fw_ac].mu_time = htole16(rec[2]);
            }
        }
    }
    if (changes & IWX_MLD_LINK_CONTEXT_MODIFY_EHT_PARAMS)
        cmd->puncture_mask = htole16(ni->ni_eht_puncture);

    cmd->bi = htole32(ni->ni_intval);
    cmd->dtim_interval = htole32(ni->ni_intval * ni->ni_dtimperiod);

    cmd->modify_mask = htole32(changes);
    cmd->flags = htole32(flags);
    cmd->flags_mask = 0;
    cmd->spec_link_id = ni->ni_mld_valid ? ni->ni_mld_link_id : 0;
    cmd->listen_lmac = 0;
    cmd->action = htole32(IWX_FW_CTXT_ACTION_MODIFY);
#undef IWX_EXP2
}


int ItlIwx::
iwx_mld_add_sta_cmd(struct iwx_softc *sc, struct iwx_node *in, int update)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_mld_link_config_cmd link_cmd;
    struct iwx_mld_sta_cfg_cmd_v2 sta_cmd;
    int cmd_ver;
    size_t cmd_size;
    uint32_t aggsize, mpdu_dens;
    const uint32_t max_aggsize = (IWX_STA_FLG_MAX_AGG_SIZE_4M >>
            IWX_STA_FLG_MAX_AGG_SIZE_SHIFT);
    int err, changes, link_slot, sta_id;
    uint32_t old_sta_mask, new_sta_mask;
    uint32_t old_active_sta_mask, new_active_sta_mask;

    cmd_ver = iwx_lookup_cmd_ver(sc, IWX_MAC_CONF_GROUP,
        IWX_MLD_STA_CONFIG_CMD);
    switch (cmd_ver) {
    case 2:
        cmd_size = sizeof(sta_cmd);
        break;
    case 1:
    case IWX_FW_CMD_VER_UNKNOWN:
        /* v1 is a shorter variant of v2 */
        cmd_size = sizeof(struct iwx_mld_mvm_sta_cfg_cmd);
        break;
    default:
        printf("%s: unsupported STA_CONFIG_CMD version %d\n",
            sc->sc_dev.dv_xname, cmd_ver);
        return ENOTSUP;
    }

    if (ic->ic_opmode != IEEE80211_M_STA)
        return ENOTSUP;
    if ((in->in_ni.ni_flags & IEEE80211_NODE_HE) &&
        (in->in_ni.ni_flags & (IEEE80211_NODE_HECAP | IEEE80211_NODE_HEOP)) !=
            (IEEE80211_NODE_HECAP | IEEE80211_NODE_HEOP))
        return EINVAL;

    link_slot = iwx_mld_link_slot(ic, &in->in_ni);
    if (link_slot < 0 || link_slot >= IWX_MLD_MAX_LINKS ||
        sc->sc_mld_sta_ids[link_slot] == 0xff)
        return ENOSPC;
    sta_id = sc->sc_mld_sta_ids[link_slot];

    if (!update && !(sc->sc_mld_link_active & (1U << link_slot))) {
        memset(&link_cmd, 0, sizeof(link_cmd));
        link_cmd.link_id = htole32(link_slot);
        link_cmd.mac_id = htole32(in->in_id);
        link_cmd.spec_link_id = in->in_ni.ni_mld_valid ?
            in->in_ni.ni_mld_link_id : 0;
        if (in->in_phyctxt)
            link_cmd.phy_id = htole32(in->in_phyctxt->id);
        else
            link_cmd.phy_id = htole32(IWX_FW_CTXT_INVALID);
        IEEE80211_ADDR_COPY(link_cmd.local_link_addr,
            ic->ic_mld_link_count != 0 ?
                ic->ic_mld_links[link_slot].local_addr : ic->ic_myaddr);
        link_cmd.listen_lmac = 0;
        link_cmd.action = IWX_FW_CTXT_ACTION_ADD;

        sc->sc_pcitag->setProperty("AirportItlwm-MLDLinkAddRequest", &link_cmd, sizeof(link_cmd));
        err = iwx_send_cmd_pdu(sc,
            IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_LINK_CONFIG_CMD),
            0, sizeof(link_cmd), &link_cmd);
        if (err)
            return err;
        sc->sc_mld_link_active |= 1U << link_slot;
    }

    changes = IWX_MLD_LINK_CONTEXT_MODIFY_ACTIVE;
    changes |= IWX_MLD_LINK_CONTEXT_MODIFY_RATES_INFO;
    if (update || link_slot != 0) {
        changes |= IWX_MLD_LINK_CONTEXT_MODIFY_PROTECT_FLAGS;
        changes |= IWX_MLD_LINK_CONTEXT_MODIFY_QOS_PARAMS;
        changes |= IWX_MLD_LINK_CONTEXT_MODIFY_BEACON_TIMING;
        if (in->in_ni.ni_flags & IEEE80211_NODE_HE)
            changes |= IWX_MLD_LINK_CONTEXT_MODIFY_HE_PARAMS;
    }
    if (in->in_ni.ni_flags & IEEE80211_NODE_EHTOP)
        changes |= IWX_MLD_LINK_CONTEXT_MODIFY_EHT_PARAMS;

    memset(&link_cmd, 0, sizeof(link_cmd));
    iwx_mld_modify_link_fill(sc, in, &link_cmd, changes,
        !!(sc->sc_mld_active_links & (1U << link_slot)));
    sc->sc_pcitag->setProperty("AirportItlwm-MLDLinkModifyRequest", &link_cmd, sizeof(link_cmd));
    err = iwx_send_cmd_pdu(sc,
        IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_LINK_CONFIG_CMD),
        0, sizeof(link_cmd), &link_cmd);
    if (err)
        return err;

    memset(&sta_cmd, 0, sizeof(sta_cmd));
    sta_cmd.sta_id = htole32(sta_id);
    sta_cmd.station_type = htole32(IWX_STA_LINK);
    sta_cmd.link_id = htole32(link_slot);
    IEEE80211_ADDR_COPY(sta_cmd.peer_mld_address,
        ic->ic_wcl_peer_is_mlo ? ic->ic_wcl_peer_mld_addr : in->in_macaddr);
    IEEE80211_ADDR_COPY(sta_cmd.peer_link_address, in->in_macaddr);
    sta_cmd.assoc_id = htole32(IEEE80211_AID(in->in_ni.ni_associd));
    if ((in->in_ni.ni_flags & IEEE80211_NODE_MFP) ||
        !in->in_ni.ni_port_valid)
        sta_cmd.mfp = htole32(1);

    const int is_6ghz = IEEE80211_IS_CHAN_6GHZ(in->in_ni.ni_chan);
    if ((in->in_ni.ni_flags & IEEE80211_NODE_HT) ||
        (is_6ghz && (in->in_ni.ni_flags &
            (IEEE80211_NODE_HE | IEEE80211_NODE_EHT)))) {
        if (iwx_mimo_enabled(sc) && in->in_ni.ni_rx_nss > 1)
            sta_cmd.mimo = htole32(1);

        if (is_6ghz) {
            mpdu_dens = in->in_ni.ni_he_6ghz_capa &
                IEEE80211_HE_6GHZ_CAP_MIN_MPDU_START;
            aggsize = (in->in_ni.ni_he_6ghz_capa &
                IEEE80211_HE_6GHZ_CAP_MAX_AMPDU_LEN_EXP) >> 3;
        } else {
            mpdu_dens = (in->in_ni.ni_ampdu_param &
                IEEE80211_AMPDU_PARAM_SS) >> 2;

            if (in->in_ni.ni_flags & IEEE80211_NODE_VHT) {
                aggsize = (in->in_ni.ni_vhtcaps &
                    IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK) >>
                    IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT;
            } else {
                aggsize = (in->in_ni.ni_ampdu_param &
                    IEEE80211_AMPDU_PARAM_LE);
            }
        }
        if (in->in_ni.ni_flags & IEEE80211_NODE_HE)
            aggsize += (in->in_ni.ni_he_cap_elem.mac_cap_info[3] &
                IEEE80211_HE_MAC_CAP3_MAX_AMPDU_LEN_EXP_MASK) >>
                IEEE80211_HE_MAC_CAP3_MAX_AMPDU_LEN_EXP_SHIFT;
        if (in->in_ni.ni_flags & IEEE80211_NODE_EHT)
            aggsize += in->in_ni.ni_eht_cap_elem.mac_cap_info[1] & 0x01;
        if (aggsize > max_aggsize)
            aggsize = max_aggsize;

        sta_cmd.tx_ampdu_spacing = htole32(mpdu_dens);
        sta_cmd.tx_ampdu_max_size = htole32(aggsize);
    }

    if (in->in_ni.ni_flags & IEEE80211_NODE_HE) {
        const uint8_t *mac = in->in_ni.ni_he_cap_elem.mac_cap_info;
        uint32_t htc = (mac[0] & IEEE80211_HE_MAC_CAP0_HTC_HE) ? 1 : 0;
        uint8_t link_adaptation =
            (((mac[2] & IEEE80211_HE_MAC_CAP2_LINK_ADAPTATION) << 1) |
            ((mac[1] & IEEE80211_HE_MAC_CAP1_LINK_ADAPTATION) >> 7));

        if (link_adaptation == 2)
            htc |= 2U << 1;
        else if (link_adaptation == 3)
            htc |= 3U << 1;
        if (mac[2] & IEEE80211_HE_MAC_CAP2_BSR)
            htc |= 1U << 4;
        if (mac[3] & IEEE80211_HE_MAC_CAP3_OMI_CONTROL)
            htc |= 1U << 5;
        if (mac[4] & IEEE80211_HE_MAC_CAP4_BQR)
            htc |= 1U << 6;
        sta_cmd.htc_flags = htole32(htc);
        sta_cmd.ack_enabled = htole32(
            (mac[2] & IEEE80211_HE_MAC_CAP2_ACK_EN) ? 1 : 0);

        memset(&sta_cmd.pkt_ext, 7, sizeof(sta_cmd.pkt_ext));
        if (in->in_ni.ni_he_cap_elem.phy_cap_info[6] &
            IEEE80211_HE_PHY_CAP6_PPE_THRESHOLD_PRESENT) {
            unsigned nss = (in->in_ni.ni_ppe_thres[0] & 7) + 1;
            unsigned mask = (in->in_ni.ni_ppe_thres[0] >> 3) & 15;
            unsigned bit = 7;
            for (unsigned ss = 0; ss < nss && ss < 2; ss++) {
                for (unsigned bw = 0; bw < 4; bw++) {
                    if (!(mask & (1U << bw)))
                        continue;
                    sta_cmd.pkt_ext.pkt_ext_qam_th[ss][bw][1] =
                        iwx_mld_he_ppe_value(in->in_ni.ni_ppe_thres, bit);
                    sta_cmd.pkt_ext.pkt_ext_qam_th[ss][bw][0] =
                        iwx_mld_he_ppe_value(in->in_ni.ni_ppe_thres, bit + 3);
                    bit += 6;
                }
            }
        } else {
            unsigned padding =
                (in->in_ni.ni_he_cap_elem.phy_cap_info[9] >> 6) & 3;
            if (padding != 3) {
                for (unsigned ss = 0; ss < 2; ss++)
                    for (unsigned bw = 0; bw < 4; bw++) {
                        sta_cmd.pkt_ext.pkt_ext_qam_th[ss][bw][0] =
                            padding == 1 ? 0 : 7;
                        sta_cmd.pkt_ext.pkt_ext_qam_th[ss][bw][1] =
                            padding == 2 ? 0 : 7;
                    }
            }
        }
    }

    sc->sc_pcitag->setProperty("AirportItlwm-MLDStationRequestGeneration", sc->sc_generation, 32);
    sc->sc_pcitag->setProperty("AirportItlwm-MLDStationRequest", &sta_cmd, cmd_size);
    err = iwx_send_cmd_pdu(sc,
        IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_STA_CONFIG_CMD),
        0, cmd_size, &sta_cmd);
    if (!err) {
        old_sta_mask = sc->sc_mld_sta_mask;
        new_sta_mask = old_sta_mask | (1U << sta_id);
        sc->sc_mld_sta_mask = new_sta_mask;
        old_active_sta_mask = sc->sc_mld_active_sta_mask;
        new_active_sta_mask = old_active_sta_mask;
        if (sc->sc_mld_active_links & (1U << link_slot))
            new_active_sta_mask |= 1U << sta_id;
        if (old_active_sta_mask != new_active_sta_mask) {
            err = iwx_mld_update_queue_sta_mask(this, sc,
                old_active_sta_mask, new_active_sta_mask);
            if (err)
                return err;
            sc->sc_mld_active_sta_mask = new_active_sta_mask;
        }
        sc->sc_flags |= IWX_FLAG_STA_ACTIVE;
    }
    return err;
}


int ItlIwx::
iwx_mld_mac_ctxt_cmd(struct iwx_softc *sc, struct iwx_node *in,
    uint32_t action, int assoc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = &in->in_ni;
    struct iwx_mld_mac_config_cmd cmd;

    if (ic->ic_opmode != IEEE80211_M_STA)
        return ENOTSUP;
    if (iwx_lookup_cmd_ver(sc, IWX_MAC_CONF_GROUP,
        IWX_MLD_MAC_CONFIG_CMD) != 2)
        return ENOTSUP;
    memset(&cmd, 0, sizeof(cmd));
    cmd.id_and_color = htole32(in->in_id);
    cmd.action = htole32(action);

    if (action == IWX_FW_CTXT_ACTION_REMOVE) {
        return iwx_send_cmd_pdu(sc,
            IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_MAC_CONFIG_CMD),
            0, sizeof(cmd), &cmd);
    }

    cmd.mac_type = htole32(IWX_FW_MAC_TYPE_BSS_STA);
    IEEE80211_ADDR_COPY(cmd.local_mld_addr, ic->ic_myaddr);
    if (ic->ic_flags & IEEE80211_F_HEON) {
        cmd.he_support = htole16(1);
        cmd.nic_not_ack_enabled = htole32(
            (ic->ic_he_cap_elem.mac_cap_info[2] &
                IEEE80211_HE_MAC_CAP2_ACK_EN) ? 0 : 1);
        if (ic->ic_wcl_peer_is_mlo || (ni->ni_flags & IEEE80211_NODE_EHT))
            cmd.eht_support = htole32(1);
    }
    cmd.client.assoc_id = htole16(IEEE80211_AID(ni->ni_associd));
    if (ni->ni_mld_valid) {
        uint16_t timeout = (ni->ni_mld_eml_capa &
            IEEE80211_EML_CAP_TRANSITION_TIMEOUT) >>
            IEEE80211_EML_CAP_TRANSITION_TIMEOUT_SHIFT;
        if (timeout > IEEE80211_EML_CAP_TRANSITION_TIMEOUT_64TU)
            timeout = IEEE80211_EML_CAP_TRANSITION_TIMEOUT_64TU;
        cmd.client.esr_transition_timeout = timeout;
        cmd.client.medium_sync_delay = htole16(ni->ni_mld_med_sync_delay);
    }
    cmd.client.is_assoc = assoc ? 1 : 0;

    cmd.filter_flags = htole32(IWX_MLD_MAC_CFG_FILTER_ACCEPT_GRP);
    if (!assoc || !ni->ni_associd || !ni->ni_dtimperiod) {
        /*
         * Allow beacons to pass through as long as we are not
         * associated or we do not have dtim period information.
         */
        cmd.filter_flags |= htole32(IWX_MLD_MAC_CFG_FILTER_ACCEPT_BEACON);
    }

    return iwx_send_cmd_pdu(sc,
        IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_MAC_CONFIG_CMD),
        0, sizeof(cmd), &cmd);
}

int ItlIwx::
iwx_mld_queue_cmd(struct iwx_softc *sc, uint32_t sta_mask, int tid, int remove,
    uint32_t num_slots, uint64_t tfd_addr, uint64_t bc_addr,
    uint16_t *qid, uint16_t *write_pointer)
{
    struct iwx_mld_scd_queue_cfg_cmd cmd;
    struct iwx_host_cmd hcmd = {
        .id = IWX_WIDE_ID(IWX_DATA_PATH_GROUP, IWX_MLD_SCD_QUEUE_CONFIG_CMD),
        .flags = IWX_CMD_WANT_RESP,
        .resp_pkt_len = sizeof(struct iwx_rx_packet) + sizeof(struct iwx_tx_queue_cfg_rsp),
    };
    int err;

    if (iwx_lookup_cmd_ver(sc, IWX_DATA_PATH_GROUP,
        IWX_MLD_SCD_QUEUE_CONFIG_CMD) != 3) {
        return ENOTSUP;
    }
    if (!sta_mask || tid < 0 || tid > IWX_MGMT_TID)
        return EINVAL;
    if (!remove && (!num_slots || (num_slots & (num_slots - 1))))
        return EINVAL;

    memset(&cmd, 0, sizeof(cmd));
    if (remove) {
        cmd.operation = htole32(IWX_MLD_SCD_QUEUE_REMOVE);
        cmd.u.remove.sta_mask = htole32(sta_mask);
        cmd.u.remove.tid = htole32(tid);
    } else {
        cmd.operation = htole32(IWX_MLD_SCD_QUEUE_ADD);
        cmd.u.add.sta_mask = htole32(sta_mask);
        cmd.u.add.tid = tid;
        cmd.u.add.cb_size = htole32(IWX_TFD_QUEUE_CB_SIZE(num_slots));
        cmd.u.add.tfdq_dram_addr = htole64(tfd_addr);
        cmd.u.add.bc_dram_addr = htole64(bc_addr);
    }
    hcmd.len[0] = sizeof(cmd);
    hcmd.data[0] = &cmd;
    if (remove) {
        /* REMOVE waits for command completion, not an ADD allocation reply. */
        hcmd.flags = 0;
        hcmd.resp_pkt_len = 0;
    }
    sc->sc_pcitag->setProperty("AirportItlwm-MLDQueueRequestGeneration", sc->sc_generation, 32);
    sc->sc_pcitag->setProperty("AirportItlwm-MLDQueueRequest", &cmd, sizeof(cmd));
    err = iwx_send_cmd(sc, &hcmd);
    if (err)
        return err;
    if (remove) {
        sc->sc_mld_txq_tidmask &= ~(1U << tid);
        return 0;
    }

    struct iwx_rx_packet *pkt = hcmd.resp_pkt;
    if (!pkt || (pkt->hdr.group_id & IWX_CMD_FAILED_MSK) ||
        iwx_rx_packet_payload_len(pkt) != sizeof(struct iwx_tx_queue_cfg_rsp)) {
        err = EIO;
    } else {
        struct iwx_tx_queue_cfg_rsp *resp = (struct iwx_tx_queue_cfg_rsp *)pkt->data;
        *qid = le16toh(resp->queue_number);
        *write_pointer = le16toh(resp->write_pointer);
        sc->sc_mld_txq_tidmask |= (1U << tid);
    }
    if (err) {
        sc->sc_pcitag->setProperty("AirportItlwm-MLDQueueFailureRequest", &cmd, sizeof(cmd));
        sc->sc_pcitag->setProperty("AirportItlwm-MLDQueueFailureCommand", hcmd.id, 32);
        sc->sc_pcitag->setProperty("AirportItlwm-MLDQueueFailureGeneration", sc->sc_generation, 32);
        sc->sc_pcitag->setProperty("AirportItlwm-MLDQueueFailurePayloadLength",
            pkt ? iwx_rx_packet_payload_len(pkt) : UINT32_MAX, 32);
        sc->sc_pcitag->setProperty("AirportItlwm-MLDQueueFailureStatus",
            pkt && iwx_rx_packet_payload_len(pkt) == sizeof(struct iwx_tx_queue_cfg_rsp) ?
                le16toh(((struct iwx_tx_queue_cfg_rsp *)pkt->data)->flags) : UINT32_MAX, 32);
        if (pkt && iwx_rx_packet_payload_len(pkt) == sizeof(struct iwx_tx_queue_cfg_rsp))
            sc->sc_pcitag->setProperty("AirportItlwm-MLDQueueFailureResponse", pkt->data, sizeof(struct iwx_tx_queue_cfg_rsp));
    }
    iwx_free_resp(sc, &hcmd);
    return err;
}

int ItlIwx::
iwx_mld_set_key(struct iwx_softc *sc, struct ieee80211_node *ni,
    struct ieee80211_key *k, int remove)
{
    struct iwx_mld_sec_key_cmd cmd;
    uint32_t flags = 0;
    int is_igtk = (k->k_flags & IEEE80211_KEY_IGTK) != 0;
    int is_bigtk = (k->k_flags & IEEE80211_KEY_BIGTK) != 0;
    int mgmt_key = is_igtk || is_bigtk;
    int err;

    if (iwx_lookup_cmd_ver(sc, IWX_DATA_PATH_GROUP, IWX_MLD_SEC_KEY_CMD) != 1) {
        iwx_mld_record_key_reject(sc, ni, k, remove, "cmd-version");
        return ENOTSUP;
    }
    if (mgmt_key) {
        if ((is_igtk && is_bigtk) ||
            (is_igtk && (k->k_id < 4 || k->k_id > 5)) ||
            (is_bigtk && ((!remove && !sc->sc_ic.ic_beacon_prot) ||
                k->k_id < 6 || k->k_id > 7))) {
            iwx_mld_record_key_reject(sc, ni, k, remove, "mgmt-key-id");
            return ENOTSUP;
        }
        switch (k->k_cipher) {
        case IEEE80211_CIPHER_BIP:
            if (k->k_len != 16)
                break;
            flags |= IWX_MLD_SEC_KEY_FLAG_CIPHER_CCMP;
            break;
        case IEEE80211_CIPHER_BIP_GMAC_128:
            if (!sc->sc_ic.ic_mld_gmac || k->k_len != 16)
                break;
            flags |= IWX_MLD_SEC_KEY_FLAG_CIPHER_GCMP;
            break;
        case IEEE80211_CIPHER_BIP_GMAC_256:
            if (!sc->sc_ic.ic_mld_gmac || k->k_len != 32)
                break;
            flags |= IWX_MLD_SEC_KEY_FLAG_CIPHER_GCMP |
                IWX_MLD_SEC_KEY_FLAG_KEY_SIZE;
            break;
        default:
            iwx_mld_record_key_reject(sc, ni, k, remove, "mgmt-cipher");
            return ENOTSUP;
        }
        if (!(flags & IWX_MLD_SEC_KEY_FLAG_CIPHER_MASK)) {
            iwx_mld_record_key_reject(sc, ni, k, remove, "mgmt-key-size");
            return ENOTSUP;
        }
    } else if (k->k_cipher == IEEE80211_CIPHER_CCMP && k->k_len == 16) {
        flags |= IWX_MLD_SEC_KEY_FLAG_CIPHER_CCMP;
    } else {
        iwx_mld_record_key_reject(sc, ni, k, remove, "cipher");
        return ENOTSUP;
    }
    if (!(sc->sc_flags & IWX_FLAG_STA_ACTIVE))
        return remove ? 0 : ENXIO;
    if (!sc->sc_mld_sta_mask)
        return remove ? 0 : ENXIO;
    if (mgmt_key || (k->k_flags & IEEE80211_KEY_GROUP))
        flags |= IWX_MLD_SEC_KEY_FLAG_MCAST_KEY;
    if (mgmt_key || (k->k_flags & IEEE80211_KEY_GROUP))
        flags |= IWX_MLD_SEC_KEY_FLAG_NO_TX;
    if (is_igtk ||
        (!mgmt_key && !(k->k_flags & IEEE80211_KEY_GROUP) && ni &&
         (ni->ni_flags & IEEE80211_NODE_MFP)))
        flags |= IWX_MLD_SEC_KEY_FLAG_MFP;
    memset(&cmd, 0, sizeof(cmd));
    cmd.action = htole32(remove ? IWX_FW_CTXT_ACTION_REMOVE : IWX_FW_CTXT_ACTION_ADD);
    if (remove) {
        cmd.u.remove.sta_mask = htole32(sc->sc_mld_sta_mask);
        cmd.u.remove.key_id = htole32(k->k_id);
        cmd.u.remove.key_flags = htole32(flags);
    } else {
        cmd.u.add.sta_mask = htole32(sc->sc_mld_sta_mask);
        cmd.u.add.key_id = htole32(k->k_id);
        cmd.u.add.key_flags = htole32(flags);
        cmd.u.add.tx_seq = htole64(k->k_tsc);
        memcpy(cmd.u.add.key, k->k_key, k->k_len);
    }

    // Complete the command before EAPOL code marks the port valid.
    err = iwx_send_cmd_pdu(sc,
        IWX_WIDE_ID(IWX_DATA_PATH_GROUP, IWX_MLD_SEC_KEY_CMD),
        0, sizeof(cmd), &cmd);
    if (err)
        return err;
    if (!remove) {
        sc->sc_pcitag->setProperty("AirportItlwm-MLDKeyInstalled",
            ((uint32_t)(k->k_flags & IEEE80211_KEY_GROUP) << 16) | k->k_id, 32);
    }
    if (!remove && (k->k_flags & IEEE80211_KEY_GROUP))
        sc->sc_ic.ic_def_txkey = k->k_id;
    return 0;
}

int ItlIwx::
iwx_mld_rm_sta_cmd(struct iwx_softc *sc, struct iwx_node *in)
{
    struct iwx_mld_mvm_remove_sta_cmd sta_cmd;
    struct iwx_mld_link_config_cmd link_cmd;
    struct ieee80211com *ic = &sc->sc_ic;
    int err;
    int generation = sc->sc_generation;
    int version = iwx_lookup_cmd_ver(sc, IWX_MAC_CONF_GROUP, IWX_MLD_STA_REMOVE_CMD);
    if (version != 1 && version != IWX_FW_CMD_VER_UNKNOWN) {
        iwx_mld_record_state_failure(sc, "deauth", "station-remove-version",
            ENOTSUP, IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_STA_REMOVE_CMD), -1);
        return ENOTSUP;
    }

    if (sc->sc_flags & IWX_FLAG_STA_ACTIVE) {
        err = iwx_flush_sta(sc, in);
        if (err) {
            iwx_mld_record_state_failure(sc, "deauth", "station-tx-flush",
                err, IWX_TXPATH_FLUSH, -1);
            return err;
        }
        for (int i = 1; i < IWX_MLD_MAX_LINKS; i++) {
            uint8_t sta_id = sc->sc_mld_sta_ids[i];
            if (sta_id == 0xff || !(sc->sc_mld_sta_mask & (1U << sta_id)))
                continue;
            err = iwx_flush_sta_tids(sc, sta_id, 0xffff);
            if (err) {
                iwx_mld_record_state_failure(sc, "deauth", "link-tx-flush",
                    err, IWX_TXPATH_FLUSH, i);
                return err;
            }
        }
        AbsoluteTime deadline;
        clock_interval_to_deadline(1, kSecondScale,
            reinterpret_cast<uint64_t *>(&deadline));
        auto wait_txq = [&](uint16_t qid) {
            if (qid == IWX_INVALID_QUEUE || qid >= nitems(sc->txq))
                return 0;
            struct iwx_tx_ring *ring = &sc->txq[qid];
            while (ring->queued != 0) {
                int result = getMainCommandGate()->commandSleep(
                    &ring->queued, deadline, THREAD_UNINT);
                if (generation != sc->sc_generation)
                    return ENXIO;
                if (result != THREAD_AWAKENED && ring->queued != 0)
                    return result == THREAD_TIMED_OUT ? EWOULDBLOCK : EINTR;
            }
            return 0;
        };
        err = wait_txq(sc->first_data_qid);
        for (int tid = 0; !err && tid < IWX_MAX_TID_COUNT; tid++)
            err = wait_txq(sc->sc_tid_data[tid].qid);
        if (err) {
            iwx_mld_record_state_failure(sc, "deauth", "station-tx-drain",
                err, IWX_TXPATH_FLUSH, -1);
            return err;
        }
        for (int tid = 0; tid <= IWX_MGMT_TID; tid++) {
            if (!(sc->sc_mld_txq_tidmask & (1U << tid)))
                continue;
            err = iwx_mld_queue_cmd(sc, sc->sc_mld_sta_mask, tid, 1, 0, 0, 0, NULL, NULL);
            if (err) {
                iwx_mld_record_state_failure(sc, "deauth", "station-queue-remove",
                    err, IWX_WIDE_ID(IWX_DATA_PATH_GROUP,
                        IWX_MLD_SCD_QUEUE_CONFIG_CMD), tid);
                return err;
            }
        }
        for (int i = 0; i < IEEE80211_GROUP_NKID; i++) {
            struct ieee80211_key *key = &sc->sc_ic.ic_nw_keys[i];
            if (key->k_cipher != IEEE80211_CIPHER_CCMP &&
                !ieee80211_is_bip_cipher(key->k_cipher))
                continue;
            err = iwx_mld_set_key(sc, &in->in_ni, key, 1);
            if (err) {
                iwx_mld_record_state_failure(sc, "deauth", "group-key-remove",
                    err, IWX_WIDE_ID(IWX_DATA_PATH_GROUP, IWX_MLD_SEC_KEY_CMD), i);
                return err;
            }
            if (ieee80211_is_bip_cipher(key->k_cipher))
                ieee80211_delete_key(&sc->sc_ic, &in->in_ni, key);
            explicit_bzero(key, sizeof(*key));
        }
        struct ieee80211_key *key = &in->in_ni.ni_pairwise_key;
        if (key->k_cipher == IEEE80211_CIPHER_CCMP) {
            err = iwx_mld_set_key(sc, &in->in_ni, key, 1);
            if (err) {
                iwx_mld_record_state_failure(sc, "deauth", "pairwise-key-remove",
                    err, IWX_WIDE_ID(IWX_DATA_PATH_GROUP, IWX_MLD_SEC_KEY_CMD), -1);
                return err;
            }
            explicit_bzero(key, sizeof(*key));
        }
        for (int i = 0; i < IWX_MLD_MAX_LINKS; i++) {
            uint8_t sta_id = sc->sc_mld_sta_ids[i];
            if (sta_id == 0xff || !(sc->sc_mld_sta_mask & (1U << sta_id)))
                continue;
            memset(&sta_cmd, 0, sizeof(sta_cmd));
            sta_cmd.sta_id = htole32(sta_id);
            err = iwx_send_cmd_pdu(sc,
                IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_STA_REMOVE_CMD),
                0, sizeof(sta_cmd), &sta_cmd);
            if (err) {
                iwx_mld_record_state_failure(sc, "deauth", "station-remove",
                    err, IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_STA_REMOVE_CMD), i);
                return err;
            }
            sc->sc_mld_sta_mask &= ~(1U << sta_id);
        }
        sc->sc_flags &= ~IWX_FLAG_STA_ACTIVE;
    }
    // The primary firmware slot exists even when non-MLO discovery reports zero links.
    for (int i = IWX_MLD_MAX_LINKS - 1; i >= 0; i--) {
        struct ieee80211_node *ni;
        struct iwx_node *linkin;
        if (!(sc->sc_mld_link_active & (1U << i)))
            continue;
        ni = i == 0 ? &in->in_ni :
            (i < ic->ic_mld_link_count ? ic->ic_mld_links[i].ni : NULL);
        if (ni == NULL)
            return EINVAL;
        linkin = (struct iwx_node *)ni;
        memset(&link_cmd, 0, sizeof(link_cmd));
        iwx_mld_modify_link_fill(sc, linkin, &link_cmd,
            IWX_MLD_LINK_CONTEXT_MODIFY_ACTIVE, 0);
        err = iwx_send_cmd_pdu(sc,
            IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_LINK_CONFIG_CMD),
            0, sizeof(link_cmd), &link_cmd);
        if (err)
            return err;
        memset(&link_cmd, 0, sizeof(link_cmd));
        link_cmd.action = htole32(IWX_FW_CTXT_ACTION_REMOVE);
        link_cmd.link_id = htole32(i);
        link_cmd.spec_link_id = ni->ni_mld_valid ? ni->ni_mld_link_id : 0;
        link_cmd.phy_id = htole32(IWX_FW_CTXT_INVALID);
        err = iwx_send_cmd_pdu(sc,
            IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_LINK_CONFIG_CMD),
            0, sizeof(link_cmd), &link_cmd);
        if (err)
            return err;
        sc->sc_mld_link_active &= ~(1U << i);
    }
    sc->sc_mld_sta_mask = 0;
    sc->sc_mld_active_sta_mask = 0;
    sc->sc_mld_active_links = 0;
    sc->sc_mld_primary_link = 0;
    sc->sc_mld_emlsr_active = 0;
    sc->sc_mld_tx_link_seq = 0;
    sc->sc_mld_txq_tidmask = 0;
    return 0;
}

int ItlIwx::
iwx_mld_auth(struct iwx_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_node *in = (struct iwx_node *)ic->ic_bss;
    int err, cleanup_err;
    int generation = sc->sc_generation;
    uint32_t duration;
    const char *stage = "preconditions";
    auto record_error = [&](int error) {
        sc->sc_pcitag->setProperty("AirportItlwm-MLDAuthFailureStage", stage);
        sc->sc_pcitag->setProperty("AirportItlwm-MLDAuthFailureError", error, 32);
        sc->sc_pcitag->setProperty("AirportItlwm-MLDAuthFailureGeneration", generation, 32);
    };
    int link_version = iwx_lookup_cmd_ver(sc, IWX_MAC_CONF_GROUP, IWX_MLD_LINK_CONFIG_CMD);

    if (ic->ic_opmode != IEEE80211_M_STA ||
        (link_version != 1 && link_version != IWX_FW_CMD_VER_UNKNOWN) ||
        !isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD)) {
        record_error(ENOTSUP);
        return ENOTSUP;
    }
    if (sc->sc_mld_phy_active || (sc->sc_flags & IWX_FLAG_MAC_ACTIVE)) {
        record_error(EBUSY);
        return EBUSY;
    }

#ifdef AIRPORT_WCL
    ieee80211_mld_discover_links(ic, &in->in_ni);
#endif
    iwx_mld_limit_link_resources(sc);
    sc->sc_mld_link_active = 0;
    sc->sc_mld_phy_active = 0;
    sc->sc_mld_active_links = 1;
    sc->sc_mld_active_sta_mask = 0;
    sc->sc_mld_primary_link = 0;
    sc->sc_mld_emlsr_active = 0;
    sc->sc_mld_tx_link_seq = 0;
    sc->sc_mld_txq_tidmask = 0;
    for (int i = 0; i < IWX_NUM_PHY_CTX; i++) {
        sc->sc_phyctxt[i].id = i;
        sc->sc_phyctxt[i].mld_config_valid = 0;
    }

    in->in_ni.ni_chw = IEEE80211_CHAN_WIDTH_20_NOHT;
    in->in_ni.ni_flags &= ~(IEEE80211_NODE_HT | IEEE80211_NODE_QOS |
        IEEE80211_NODE_HT_SGI20 | IEEE80211_NODE_HT_SGI40 |
        IEEE80211_NODE_VHT | IEEE80211_NODE_VHT_SGI80 |
        IEEE80211_NODE_VHT_SGI160 | IEEE80211_NODE_HE |
        IEEE80211_NODE_EHT);
    in->in_phyctxt = &sc->sc_phyctxt[0];
    in->in_phyctxt->channel = in->in_ni.ni_chan;
    in->in_phyctxt->mld_width = in->in_ni.ni_chw;
    in->in_phyctxt->mld_center_freq = in->in_ni.ni_chan->ic_center_freq1;
    in->in_phyctxt->mld_config_valid = 1;
    IEEE80211_ADDR_COPY(in->in_macaddr, in->in_ni.ni_macaddr);
    stage = "phy-context-add";
    err = iwx_phy_ctxt_cmd(sc, in->in_phyctxt, 1, 1, IWX_FW_CTXT_ACTION_ADD, 0);
    if (err) {
        record_error(err);
        return err;
    }
    sc->sc_mld_phy_active |= 1U;
    stage = "mac-context-add";
    err = iwx_mld_mac_ctxt_cmd(sc, in, IWX_FW_CTXT_ACTION_ADD, 0);
    if (err)
        goto fail;
    sc->sc_flags |= IWX_FLAG_MAC_ACTIVE;
    stage = "station-link-add";
    err = iwx_mld_add_sta_cmd(sc, in, 0);
    if (err)
        goto fail;
    stage = "management-queue-enable";
    err = iwx_enable_mgmt_queue(sc);
    if (err)
        goto fail;
    duration = in->in_ni.ni_intval ? in->in_ni.ni_intval * 9 : 900;
    stage = "session-protection";
    err = iwx_schedule_protect_session(sc, in, duration);
    if (err)
        goto fail;
    sc->sc_flags |= IWX_FLAG_TE_ACTIVE;
    return 0;

fail:
    record_error(err);
    if (generation == sc->sc_generation) {
        cleanup_err = iwx_mld_deauth(sc);
        if (cleanup_err)
            XYLog("%s: MLD AUTH cleanup failed (%d), original error %d\n",
                sc->sc_dev.dv_xname, cleanup_err, err);
    }
    return err;
}

int ItlIwx::
iwx_mld_run(struct iwx_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_node *in = (struct iwx_node *)ic->ic_bss;
    int err;
    int chains = iwx_mimo_enabled(sc) ? 2 : 1;

    if (ic->ic_opmode != IEEE80211_M_STA ||
        in->in_ni.ni_chw == IEEE80211_CHAN_WIDTH_80P80)
        return ENOTSUP;
    in->in_phyctxt->mld_width = in->in_ni.ni_chw;
    in->in_phyctxt->mld_center_freq = in->in_ni.ni_eht_center_freq1 ?
        in->in_ni.ni_eht_center_freq1 : in->in_ni.ni_chan->ic_center_freq1;
    err = iwx_phy_ctxt_update(sc, in->in_phyctxt, in->in_ni.ni_chan,
        chains, chains, 0);
    if (err)
        return err;
    sc->sc_mld_active_links = 1;
    err = iwx_mld_add_sta_cmd(sc, in, 1);
    if (err)
        return err;
    for (int i = 1; i < ic->ic_mld_link_count; i++) {
        struct ieee80211_mld_link_info *link = &ic->ic_mld_links[i];
        struct iwx_node *linkin;

        if (!link->assoc_accepted)
            continue;
        if (link->ni == NULL || link->assoc_id == 0 || link->ni->ni_chan == NULL)
            return EINVAL;
        linkin = (struct iwx_node *)link->ni;
        linkin->in_id = in->in_id;
        linkin->in_color = in->in_color;
        IEEE80211_ADDR_COPY(linkin->in_macaddr, linkin->in_ni.ni_macaddr);
        linkin->in_phyctxt = &sc->sc_phyctxt[i];
        linkin->in_phyctxt->id = i;
        linkin->in_phyctxt->channel = linkin->in_ni.ni_chan;
        linkin->in_phyctxt->mld_width = linkin->in_ni.ni_chw;
        linkin->in_phyctxt->mld_center_freq = linkin->in_ni.ni_eht_center_freq1 ?
            linkin->in_ni.ni_eht_center_freq1 :
                linkin->in_ni.ni_chan->ic_center_freq1;
        linkin->in_phyctxt->mld_config_valid = 1;
        err = iwx_phy_ctxt_cmd(sc, linkin->in_phyctxt, chains, chains,
            IWX_FW_CTXT_ACTION_ADD, 0);
        if (err)
            return err;
        sc->sc_mld_phy_active |= 1U << i;
        err = iwx_mld_add_sta_cmd(sc, linkin, 0);
        if (err)
            return err;
    }
    err = iwx_mld_mac_ctxt_cmd(sc, in, IWX_FW_CTXT_ACTION_MODIFY, 1);
    if (err)
        return err;
    err = iwx_allow_mcast(sc);
    if (err)
        return err;
    err = iwx_power_update_device(sc);
    if (err)
        return err;
    err = iwx_power_mac_update_mode(sc, in);
    if (err)
        return err;
    for (int i = 1; i < ic->ic_mld_link_count; i++) {
        struct ieee80211_mld_link_info *link = &ic->ic_mld_links[i];
        if (!link->assoc_accepted)
            continue;
        err = iwx_rs_init(sc, (struct iwx_node *)link->ni, true);
        if (err)
            return err;
    }
    in->in_ni.ni_txrate = 0;
    in->in_ni.ni_txmcs = 0;
    return iwx_rs_init(sc, in, true);
}

int ItlIwx::
iwx_mld_run_stop(struct iwx_softc *sc)
{
    struct iwx_node *in = (struct iwx_node *)sc->sc_ic.ic_bss;
    int err = iwx_flush_sta(sc, in);
    if (err) {
        iwx_mld_record_state_failure(sc, "run-stop", "tx-flush", err,
            IWX_TXPATH_FLUSH, -1);
        return err;
    }
    for (int i = 0; i < nitems(sc->sc_rxba_data); i++) {
        struct iwx_rxba_data *rxba = &sc->sc_rxba_data[i];
        if (rxba->baid == IWX_RX_REORDER_DATA_INVALID_BAID)
            continue;
        err = iwx_sta_rx_agg(sc, &in->in_ni, rxba->tid, 0, 0, 0, 0);
        if (err) {
            iwx_mld_record_state_failure(sc, "run-stop", "rx-ba-stop", err,
                IWX_WIDE_ID(IWX_DATA_PATH_GROUP, IWX_MLD_RX_BAID_CONFIG_CMD),
                rxba->tid);
            return err;
        }
    }
    for (int i = 1; i < sc->sc_ic.ic_mld_link_count; i++) {
        struct ieee80211_mld_link_info *link = &sc->sc_ic.ic_mld_links[i];
        if (!link->assoc_accepted || link->ni == NULL)
            continue;
        err = iwx_flush_sta_tids(sc, sc->sc_mld_sta_ids[i], 0xffff);
        if (err) {
            iwx_mld_record_state_failure(sc, "run-stop", "link-tx-flush", err,
                IWX_TXPATH_FLUSH, i);
            return err;
        }
    }
    err = iwx_mld_mac_ctxt_cmd(sc, in, IWX_FW_CTXT_ACTION_MODIFY, 0);
    if (err)
        iwx_mld_record_state_failure(sc, "run-stop", "mac-deactivate", err,
            IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_MAC_CONFIG_CMD), -1);
    return err;
}

int ItlIwx::
iwx_mld_deauth(struct iwx_softc *sc)
{
    struct iwx_node *in = (struct iwx_node *)sc->sc_ic.ic_bss;
    int err;
    int generation = sc->sc_generation;
    if (sc->sc_flags & IWX_FLAG_TE_ACTIVE) {
        err = iwx_cancel_session_protection(sc, in);
        if (err) {
            iwx_mld_record_state_failure(sc, "deauth", "protection-cancel",
                err, IWX_TIME_EVENT_CMD, -1);
            return err;
        }
        sc->sc_flags &= ~IWX_FLAG_TE_ACTIVE;
    }
    err = iwx_mld_rm_sta_cmd(sc, in);
    if (err)
        return err;
    if (generation != sc->sc_generation)
        return ENXIO;
    if (sc->sc_flags & IWX_FLAG_MAC_ACTIVE) {
        err = iwx_mld_mac_ctxt_cmd(sc, in, IWX_FW_CTXT_ACTION_REMOVE, 0);
        if (err) {
            iwx_mld_record_state_failure(sc, "deauth", "mac-remove", err,
                IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_MAC_CONFIG_CMD), -1);
            return err;
        }
        sc->sc_flags &= ~IWX_FLAG_MAC_ACTIVE;
    }
    for (int i = IWX_NUM_PHY_CTX - 1; i >= 0; i--) {
        if (!(sc->sc_mld_phy_active & (1U << i)))
            continue;
        err = iwx_phy_ctxt_cmd(sc, &sc->sc_phyctxt[i], 1, 1,
            IWX_FW_CTXT_ACTION_REMOVE, 0);
        if (err) {
            iwx_mld_record_state_failure(sc, "deauth", "phy-remove", err,
                IWX_PHY_CONTEXT_CMD, i);
            return err;
        }
        sc->sc_mld_phy_active &= ~(1U << i);
    }
    sc->sc_rx_ba_sessions = 0;
    sc->ba_rx.start_tidmask = 0;
    sc->ba_rx.stop_tidmask = 0;
    sc->ba_tx.start_tidmask = 0;
    sc->ba_tx.stop_tidmask = 0;
#ifdef AIRPORT_WCL
    ieee80211_mld_clear_links(&sc->sc_ic);
#endif
    return 0;
}


