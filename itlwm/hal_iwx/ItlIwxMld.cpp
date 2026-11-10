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
iwx_mld_log_failure(struct iwx_softc *sc, const char *operation,
    const char *stage, int error, uint32_t command, int detail)
{
    if (sc->sc_flags & IWX_FLAG_SHUTDOWN)
        return;
    XYLog("%s: %s failed at %s: error=%d cmd=0x%08x detail=%d\n",
        __FUNCTION__, operation, stage, error, command, detail);
}

static void
iwx_mld_log_key_reject(struct ieee80211_key *key, int remove, const char *reason)
{
    XYLog("%s: rejected key %s (%s): cipher=%d len=%d id=%d flags=0x%x\n",
        __FUNCTION__, remove ? "removal" : "install", reason, key->k_cipher,
        key->k_len, key->k_id, key->k_flags);
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
        ic->ic_wcl_active_mld_link = primary_link;
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
        iwx_mld_log_failure(sc, "mld-link-update", "rx-baid-mask",
            err, IWX_WIDE_ID(IWX_DATA_PATH_GROUP,
                IWX_MLD_RX_BAID_CONFIG_CMD), -1);
        goto rollback_added;
    }
    baid_updated = old_sta_mask != new_sta_mask;
    if (old_sta_mask != new_sta_mask) {
        err = iwx_mld_update_queue_sta_mask(this, sc,
            old_sta_mask, new_sta_mask);
        if (err) {
            iwx_mld_log_failure(sc, "mld-link-update", "tx-queue-mask",
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
            iwx_mld_log_failure(sc, "mld-link-update", "link-deactivate",
                err, IWX_WIDE_ID(IWX_MAC_CONF_GROUP,
                    IWX_MLD_LINK_CONFIG_CMD), i);
            goto rollback_added;
        }
        removed_done |= 1U << i;
    }
    XYLog("%s: active links 0x%x -> 0x%x, primary %u, EMLSR %d\n", __FUNCTION__,
        old_links, link_mask, primary_link, emlsr_active);
    sc->sc_mld_active_links = link_mask;
    sc->sc_mld_active_sta_mask = new_sta_mask;
    sc->sc_mld_primary_link = primary_link;
    sc->sc_mld_emlsr_active = emlsr_active;
    ic->ic_wcl_active_mld_link = primary_link;
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

static int
iwx_mld_width_mhz(const struct ieee80211_node *ni)
{
    switch (ni->ni_chw) {
    case IEEE80211_CHAN_WIDTH_20_NOHT:
    case IEEE80211_CHAN_WIDTH_20: return 20;
    case IEEE80211_CHAN_WIDTH_40: return 40;
    case IEEE80211_CHAN_WIDTH_80: return 80;
    case IEEE80211_CHAN_WIDTH_160: return 160;
    case IEEE80211_CHAN_WIDTH_320: return 320;
    }
    return -1;
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

/*
 * EMLSR policy, after iwlmld (mld/mlo.c, mld/link.c, mld/stats.c). The firmware
 * never recommends entering EMLSR; the driver decides, once the traffic is
 * worth it, from scan data on every link that is at most five seconds old, and
 * leaves again when the pair stops paying off.
 *
 * Differences from iwlmld: low RSSI uses the firmware's per-link beacon
 * statistics; the channel load of an inactive link comes from its BSS Load
 * element or the per-band default; the 6 GHz beacon RSSI correction is the
 * fixed 4 dB iwlmld falls back to. The secondary-link usage exit is left out:
 * received frames are not attributed to a link. Any link may be active, the
 * one WCL joined included or not; macOS is told about the active one through
 * ieee80211_mld_active_node().
 */
#define IWX_MLD_TPT_WINDOW_SEC           5
#define IWX_MLD_ENTER_EMLSR_TPT_THRESH   400
#define IWX_MLD_EXIT_EMLSR_CHAN_LOAD     2   /* percent */
#define IWX_MLD_LOW_RSSI_THRESH          (-72)
#define IWX_MLD_TRIGGER_LINK_SEL_SEC     30
#define IWX_MLD_PREVENT_EMLSR_TIMEOUT    400
#define IWX_MLD_EMLSR_PREVENT_SHORT      300
#define IWX_MLD_EMLSR_PREVENT_LONG       600
#define IWX_MLD_MLO_SCAN_MAX_AGE_SEC     5
#define IWX_MLD_SCALE_FACTOR             256
#define IWX_MLD_PERCENT_TO_255(p)        ((p) * 256 / 100)

enum {
    IWX_MLD_EMLSR_BLOCKED_TPT        = (1U << 0),
    IWX_MLD_EMLSR_BLOCKED_PREVENTION = (1U << 1),
};

enum {
    IWX_MLD_TASK_TICK   = (1U << 0),
    IWX_MLD_TASK_SELECT = (1U << 1),
};

static const char *
iwx_mld_emlsr_exit_name(int reason)
{
    switch (reason) {
    case IWX_MLD_EMLSR_EXIT_BLOCK: return "BLOCK";
    case IWX_MLD_EMLSR_EXIT_FAIL_ENTRY: return "FAIL_ENTRY";
    case IWX_MLD_EMLSR_EXIT_LOW_RSSI: return "LOW_RSSI";
    case IWX_MLD_EMLSR_EXIT_LINK_USAGE: return "LINK_USAGE";
    case IWX_MLD_EMLSR_EXIT_CHAN_LOAD: return "CHAN_LOAD";
    case IWX_MLD_EMLSR_EXIT_FW_REQUEST: return "FW_REQUEST";
    }
    return "?";
}

static uint32_t
iwx_mld_uptime(void)
{
    struct timeval tv;

    getmicrouptime(&tv);
    return (uint32_t)tv.tv_sec;
}

struct iwx_mld_rssi_to_grade {
    int8_t rssi[2];     /* 2.4 GHz, 5/6 GHz */
    uint16_t grade;
};
#define IWX_RSSI_GRADE_LB(_lb, _hb, _grade) { { _lb, _hb }, _grade }
#define IWX_RSSI_GRADE(_rssi, _grade) IWX_RSSI_GRADE_LB(_rssi, _rssi, _grade)

/* iwlmld rssi_to_grade_*mhz tables, sorted by increasing RSSI. */
static const struct iwx_mld_rssi_to_grade iwx_rssi_to_grade_20[] = {
    IWX_RSSI_GRADE_LB(-94, -95, 9), IWX_RSSI_GRADE_LB(-92, -93, 17),
    IWX_RSSI_GRADE_LB(-90, -90, 34), IWX_RSSI_GRADE_LB(-87, -87, 52),
    IWX_RSSI_GRADE_LB(-83, -84, 69), IWX_RSSI_GRADE_LB(-79, -80, 103),
    IWX_RSSI_GRADE_LB(-75, -75, 137), IWX_RSSI_GRADE_LB(-72, -73, 155),
    IWX_RSSI_GRADE_LB(-70, -71, 172), IWX_RSSI_GRADE_LB(-67, -68, 206),
    IWX_RSSI_GRADE_LB(-64, -65, 230), IWX_RSSI_GRADE_LB(-59, -60, 258),
    IWX_RSSI_GRADE_LB(-57, -58, 287), IWX_RSSI_GRADE_LB(-52, -53, 310),
    IWX_RSSI_GRADE_LB(-50, -50, 345),
};
static const struct iwx_mld_rssi_to_grade iwx_rssi_to_grade_40[] = {
    IWX_RSSI_GRADE_LB(-95, -95, 9), IWX_RSSI_GRADE_LB(-93, -93, 17),
    IWX_RSSI_GRADE_LB(-91, -92, 18), IWX_RSSI_GRADE_LB(-89, -90, 34),
    IWX_RSSI_GRADE_LB(-87, -87, 68), IWX_RSSI_GRADE_LB(-84, -84, 104),
    IWX_RSSI_GRADE_LB(-80, -81, 138), IWX_RSSI_GRADE_LB(-77, -77, 206),
    IWX_RSSI_GRADE_LB(-72, -72, 274), IWX_RSSI_GRADE_LB(-69, -70, 310),
    IWX_RSSI_GRADE_LB(-67, -68, 344), IWX_RSSI_GRADE_LB(-64, -65, 412),
    IWX_RSSI_GRADE_LB(-61, -62, 460), IWX_RSSI_GRADE_LB(-56, -57, 516),
    IWX_RSSI_GRADE_LB(-54, -55, 574), IWX_RSSI_GRADE_LB(-49, -50, 620),
    IWX_RSSI_GRADE_LB(-46, -47, 690),
};
static const struct iwx_mld_rssi_to_grade iwx_rssi_to_grade_80[] = {
    IWX_RSSI_GRADE(-95, 9), IWX_RSSI_GRADE(-93, 17), IWX_RSSI_GRADE(-92, 18),
    IWX_RSSI_GRADE(-90, 34), IWX_RSSI_GRADE(-89, 36), IWX_RSSI_GRADE(-87, 68),
    IWX_RSSI_GRADE(-83, 136), IWX_RSSI_GRADE(-80, 208), IWX_RSSI_GRADE(-77, 276),
    IWX_RSSI_GRADE(-74, 412), IWX_RSSI_GRADE(-69, 548), IWX_RSSI_GRADE(-67, 620),
    IWX_RSSI_GRADE(-66, 688), IWX_RSSI_GRADE(-61, 824), IWX_RSSI_GRADE(-59, 920),
    IWX_RSSI_GRADE(-54, 1032), IWX_RSSI_GRADE(-52, 1148),
    IWX_RSSI_GRADE(-47, 1240), IWX_RSSI_GRADE(-44, 1380),
};
static const struct iwx_mld_rssi_to_grade iwx_rssi_to_grade_160[] = {
    IWX_RSSI_GRADE(-95, 9), IWX_RSSI_GRADE(-93, 17), IWX_RSSI_GRADE(-92, 18),
    IWX_RSSI_GRADE(-90, 34), IWX_RSSI_GRADE(-89, 36), IWX_RSSI_GRADE(-87, 68),
    IWX_RSSI_GRADE(-86, 72), IWX_RSSI_GRADE(-84, 136), IWX_RSSI_GRADE(-81, 272),
    IWX_RSSI_GRADE(-78, 416), IWX_RSSI_GRADE(-75, 552), IWX_RSSI_GRADE(-71, 824),
    IWX_RSSI_GRADE(-67, 1096), IWX_RSSI_GRADE(-65, 1240),
    IWX_RSSI_GRADE(-63, 1376), IWX_RSSI_GRADE(-59, 1648),
    IWX_RSSI_GRADE(-57, 1840), IWX_RSSI_GRADE(-52, 2064),
    IWX_RSSI_GRADE(-50, 2296), IWX_RSSI_GRADE(-46, 2480),
    IWX_RSSI_GRADE(-42, 2760),
};
static const struct iwx_mld_rssi_to_grade iwx_rssi_to_grade_320[] = {
    IWX_RSSI_GRADE(-95, 9), IWX_RSSI_GRADE(-93, 17), IWX_RSSI_GRADE(-92, 18),
    IWX_RSSI_GRADE(-90, 34), IWX_RSSI_GRADE(-89, 36), IWX_RSSI_GRADE(-87, 68),
    IWX_RSSI_GRADE(-86, 72), IWX_RSSI_GRADE(-84, 136), IWX_RSSI_GRADE(-83, 144),
    IWX_RSSI_GRADE(-81, 272), IWX_RSSI_GRADE(-78, 544), IWX_RSSI_GRADE(-75, 832),
    IWX_RSSI_GRADE(-72, 1104), IWX_RSSI_GRADE(-69, 1648),
    IWX_RSSI_GRADE(-64, 2192), IWX_RSSI_GRADE(-62, 2480),
    IWX_RSSI_GRADE(-61, 2752), IWX_RSSI_GRADE(-57, 3296),
    IWX_RSSI_GRADE(-55, 3680), IWX_RSSI_GRADE(-50, 4128),
    IWX_RSSI_GRADE(-47, 4592), IWX_RSSI_GRADE(-43, 4960),
    IWX_RSSI_GRADE(-40, 5520),
};

static struct ieee80211_node *
iwx_mld_link_node(struct iwx_softc *sc, int slot)
{
    struct ieee80211com *ic = &sc->sc_ic;

    if (slot == 0)
        return ic->ic_bss;
    if (slot >= ic->ic_mld_link_count || !ic->ic_mld_links[slot].assoc_accepted)
        return NULL;
    return ic->ic_mld_links[slot].ni;
}

/* Channel load caused by others, 0..256, as iwl_mld_get_chan_load(). */
static unsigned int
iwx_mld_get_chan_load(struct iwx_softc *sc, int slot,
    const struct ieee80211_node *ni)
{
    unsigned int load;

    if (ni->ni_chan_util >= 0) {
        unsigned int by_us = 0;

        load = (unsigned int)ni->ni_chan_util;
        if (slot < IWX_NUM_PHY_CTX && (sc->sc_mld_active_links & (1U << slot)))
            by_us = IWX_MLD_PERCENT_TO_255(sc->sc_mld_phy_load_by_us[slot]);
        if (by_us <= load)
            load -= by_us;
        return load;
    }
    /* No BSS Load element: the defaults of iwl_mld_get_default_chan_load(). */
    return IWX_MLD_PERCENT_TO_255(IEEE80211_IS_CHAN_2GHZ(ni->ni_chan) ? 30 :
        IEEE80211_IS_CHAN_5GHZ(ni->ni_chan) ? 15 : 0);
}

/* iwl_mld_get_link_grade() */
static unsigned int
iwx_mld_get_link_grade(struct iwx_softc *sc, int slot)
{
    const struct ieee80211_node *ni = iwx_mld_link_node(sc, slot);
    const struct iwx_mld_rssi_to_grade *table;
    int width, size, idx, rssi;
    unsigned int grade;

    if (ni == NULL || ni->ni_chan == NULL || (width = iwx_mld_width_mhz(ni)) < 0)
        return 0;
    switch (width) {
    case 20: table = iwx_rssi_to_grade_20; size = nitems(iwx_rssi_to_grade_20); break;
    case 40: table = iwx_rssi_to_grade_40; size = nitems(iwx_rssi_to_grade_40); break;
    case 80: table = iwx_rssi_to_grade_80; size = nitems(iwx_rssi_to_grade_80); break;
    case 160: table = iwx_rssi_to_grade_160; size = nitems(iwx_rssi_to_grade_160); break;
    default: table = iwx_rssi_to_grade_320; size = nitems(iwx_rssi_to_grade_320); break;
    }
    rssi = ni->ni_rssi ? (int)ni->ni_rssi + IWX_MIN_DBM : 0;
    /* Beacons on 6 GHz arrive weaker than data; iwlmld's default is +4 dB. */
    if (rssi && IEEE80211_IS_CHAN_6GHZ(ni->ni_chan))
        rssi += 4;
    idx = IEEE80211_IS_CHAN_2GHZ(ni->ni_chan) ? 0 : 1;
    if (!rssi)
        rssi = table[0].rssi[idx];
    grade = table[size - 1].grade;
    for (int i = 0; i < size; i++) {
        if (rssi > table[i].rssi[idx])
            continue;
        grade = table[i].grade;
        break;
    }
    grade = grade * (IWX_MLD_SCALE_FACTOR -
        iwx_mld_get_chan_load(sc, slot, ni)) / IWX_MLD_SCALE_FACTOR;
    /* iwl_mld_apply_puncturing_penalty(): a link of 80 MHz or more loses its punctured share. */
    if (width >= 80 && ni->ni_eht_puncture) {
        unsigned int n_subchannels = width / 20;
        unsigned int n_punctured = __builtin_popcount(
            ni->ni_eht_puncture & ((1U << n_subchannels) - 1));

        grade = grade * (n_subchannels - n_punctured) / n_subchannels;
    }
    return grade;
}

/* iwl_mld_get_min_chan_load_thresh() */
static unsigned int
iwx_mld_min_chan_load_thresh(const struct ieee80211_node *ni)
{
    switch (iwx_mld_width_mhz(ni)) {
    case 320:
    case 160: return 5;
    case 80: return 7;
    }
    return 10;
}

/*
 * iwl_mld_emlsr_pair_state() and iwl_mld_channel_load_allows_emlsr(): the two
 * links must be on different bands (5 GHz low and high channels excepted),
 * and the primary channel busy enough, or the secondary link wide enough
 * relative to it, to be worth the switching.
 */
static bool
iwx_mld_emlsr_pair_allowed(struct iwx_softc *sc, int a, int b)
{
    const struct ieee80211_node *na = iwx_mld_link_node(sc, a);
    const struct ieee80211_node *nb = iwx_mld_link_node(sc, b);
    int bw_a, bw_b;
    unsigned int load_percent;

    if (na == NULL || nb == NULL || na->ni_chan == NULL || nb->ni_chan == NULL)
        return false;
    bw_a = iwx_mld_width_mhz(na);
    bw_b = iwx_mld_width_mhz(nb);
    if (bw_a < 0 || bw_b < 0)
        return false;
    if ((na->ni_chan->ic_flags & (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_5GHZ |
        IEEE80211_CHAN_6GHZ)) == (nb->ni_chan->ic_flags &
        (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_6GHZ))) {
        const struct ieee80211_node *low = na, *high = nb;
        int low_bw = bw_a, high_bw = bw_b;

        if (low->ni_chan->ic_freq > high->ni_chan->ic_freq) {
            low = nb; high = na; low_bw = bw_b; high_bw = bw_a;
        }
        if (!IEEE80211_IS_CHAN_5GHZ(na->ni_chan) ||
            low->ni_chan->ic_center_freq1 + low_bw / 2 > 5330 ||
            high->ni_chan->ic_center_freq1 - high_bw / 2 < 5490)
            return false;
    }
    /* Only the primary link's measured load counts, so it has to be on the air. */
    if (a >= IWX_NUM_PHY_CTX || !(sc->sc_mld_active_links & (1U << a)))
        return false;
    load_percent = sc->sc_mld_phy_load[a];
    if (load_percent < iwx_mld_min_chan_load_thresh(na))
        return false;
    if (bw_a <= bw_b)
        return true;
    switch (bw_a / bw_b) {
    case 2: return load_percent > 25;
    case 4: return load_percent > 40;
    case 8:
    case 16: return load_percent > 50;
    }
    return false;
}

/*
 * _iwl_mld_select_links(): pick the links to keep active: the best single link,
 * or an EMLSR pair when EMLSR is not blocked and the pair is worth at least as
 * much. Returns the mask and the primary link; *emlsr tells whether it is a pair.
 */
uint8_t ItlIwx::
iwx_mld_select_links(struct iwx_softc *sc, uint8_t *primary, bool *emlsr)
{
    struct ieee80211com *ic = &sc->sc_ic;
    const int count = MIN(ic->ic_mld_link_count, IWX_MLD_MAX_LINKS);
    unsigned int grade[IWX_MLD_MAX_LINKS] = {};
    unsigned int max_grade = 0;
    int best = -1;
    uint8_t links;

    *emlsr = false;
    for (int i = 0; i < count; i++) {
        uint8_t sta = sc->sc_mld_sta_ids[i];

        if (sta == 0xff || !(sc->sc_mld_sta_mask & (1U << sta)))
            continue;
        grade[i] = iwx_mld_get_link_grade(sc, i);
        if (grade[i] > max_grade) {
            max_grade = grade[i];
            best = i;
        }
    }
    if (best < 0) {
        *primary = sc->sc_mld_primary_link;
        return sc->sc_mld_active_links;
    }
    *primary = best;
    links = 1U << best;
    if (sc->sc_mld_emlsr_blocked)
        return links;

    for (int a = 0; a < count; a++) {
        for (int b = a + 1; b < count; b++) {
            unsigned int pair_grade;
            int pri = grade[b] > grade[a] ? b : a;
            int sec = pri == a ? b : a;

            if (!grade[a] || !grade[b] ||
                !iwx_mld_emlsr_link_usable(iwx_mld_link_node(sc, a)) ||
                !iwx_mld_emlsr_link_usable(iwx_mld_link_node(sc, b)) ||
                !iwx_mld_emlsr_pair_allowed(sc, pri, sec))
                continue;
            /* The more the primary link is loaded, the more EMLSR is worth. */
            pair_grade = grade[pri] + grade[sec] *
                iwx_mld_get_chan_load(sc, pri, iwx_mld_link_node(sc, pri)) /
                IWX_MLD_SCALE_FACTOR;
            if (pair_grade < max_grade)
                continue;
            max_grade = pair_grade;
            links = (1U << a) | (1U << b);
            *primary = pri;
            *emlsr = true;
        }
    }
    XYLog("%s: grades %u/%u/%u, selected links 0x%x primary %u%s\n", __FUNCTION__,
        grade[0], grade[1], grade[2], links, *primary, *emlsr ? " (EMLSR)" : "");
    return links;
}

/* iwl_mld_check_emlsr_prevention() */
void ItlIwx::
iwx_mld_note_emlsr_exit(struct iwx_softc *sc, int reason)
{
    uint32_t now = iwx_mld_uptime(), delay;

    if (now > sc->sc_mld_emlsr_last_exit + IWX_MLD_PREVENT_EMLSR_TIMEOUT ||
        sc->sc_mld_emlsr_exit_reason != reason)
        sc->sc_mld_emlsr_exit_repeat = 0;
    sc->sc_mld_emlsr_exit_reason = reason;
    sc->sc_mld_emlsr_last_exit = now;
    sc->sc_mld_emlsr_exit_repeat++;
    if (reason == IWX_MLD_EMLSR_EXIT_BLOCK)
        return;
    delay = IWX_MLD_TRIGGER_LINK_SEL_SEC;
    if (sc->sc_mld_emlsr_exit_repeat > 1 &&
        (reason == IWX_MLD_EMLSR_EXIT_LINK_USAGE ||
         reason == IWX_MLD_EMLSR_EXIT_FW_REQUEST))
        delay = sc->sc_mld_emlsr_exit_repeat == 2 ?
            IWX_MLD_EMLSR_PREVENT_SHORT : IWX_MLD_EMLSR_PREVENT_LONG;
    sc->sc_mld_emlsr_blocked |= IWX_MLD_EMLSR_BLOCKED_PREVENTION;
    sc->sc_mld_emlsr_prevent_until = now + delay;
    XYLog("%s: preventing EMLSR for %u s after exit %s\n", __FUNCTION__, delay,
        iwx_mld_emlsr_exit_name(reason));
}

/* iwl_mld_exit_emlsr(): keep the better of the two links, the primary one on a tie. */
void ItlIwx::
iwx_mld_exit_emlsr(struct iwx_softc *sc, int reason)
{
    uint8_t keep = sc->sc_mld_primary_link;
    unsigned int keep_grade;

    if (!sc->sc_mld_emlsr_active)
        return;
    keep_grade = iwx_mld_get_link_grade(sc, keep);
    for (int i = 0; i < IWX_MLD_MAX_LINKS; i++) {
        unsigned int grade;

        if (!(sc->sc_mld_active_links & (1U << i)))
            continue;
        grade = iwx_mld_get_link_grade(sc, i);
        if (grade > keep_grade) {
            keep_grade = grade;
            keep = i;
        }
    }
    XYLog("%s: leaving EMLSR, reason %s, keeping link %u\n", __FUNCTION__,
        iwx_mld_emlsr_exit_name(reason), keep);
    iwx_mld_schedule_active_links(sc, 1U << keep, keep, false, false);
    iwx_mld_note_emlsr_exit(sc, reason);
    /* The channel statistics are not valid while in EMLSR. */
    memset(sc->sc_mld_phy_load, 0, sizeof(sc->sc_mld_phy_load));
}

/*
 * iwl_mld_int_mlo_scan(): hear every other link again. Selecting links is
 * done from the scan completion.
 */
bool ItlIwx::
iwx_mld_mlo_scan(struct iwx_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;

    if (ic->ic_state != IEEE80211_S_RUN || (ic->ic_flags & IEEE80211_F_BGSCAN) ||
        (sc->sc_flags & (IWX_FLAG_SCANNING | IWX_FLAG_BGSCAN | IWX_FLAG_SHUTDOWN)) ||
        ic->ic_mgt_timer != 0 || ic->ic_bgscan_start == NULL)
        return false;
    memset(sc->sc_scan_mlo_chans, 0, sizeof(sc->sc_scan_mlo_chans));
    for (int i = 1; i < ic->ic_mld_link_count; i++) {
        const struct ieee80211_node *ni = iwx_mld_link_node(sc, i);

        if (ni != NULL && ni->ni_chan != NULL)
            setbit(sc->sc_scan_mlo_chans, ni->ni_chan - ic->ic_channels);
    }
    sc->sc_scan_mlo = 1;
    ic->ic_flags |= IEEE80211_F_DISABLE_BG_AUTO_CONNECT;
    if (ic->ic_bgscan_start(ic) != 0) {
        sc->sc_scan_mlo = 0;
        ic->ic_flags &= ~IEEE80211_F_DISABLE_BG_AUTO_CONNECT;
        return false;
    }
    ic->ic_flags |= IEEE80211_F_BGSCAN | IEEE80211_F_DISABLE_BG_AUTO_CONNECT;
    return true;
}

void ItlIwx::
iwx_mld_mlo_scan_done(struct iwx_softc *sc)
{
    sc->sc_mld_mlo_scan_time = iwx_mld_uptime();
    __atomic_fetch_or(&sc->sc_mld_task_flags, IWX_MLD_TASK_SELECT, __ATOMIC_RELAXED);
    iwx_add_task(sc, sc->sc_nswq, &sc->mld_tpt_task);
}

/*
 * _iwl_mld_select_links(): apply what iwx_mld_select_links() chose, from scan
 * data that is at most five seconds old; start a scan first when it is not.
 */
void ItlIwx::
iwx_mld_apply_link_selection(struct iwx_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    uint8_t links, primary;
    bool emlsr;

    if (!ic->ic_bss->ni_port_valid || ic->ic_mld_link_count < 2)
        return;
    if (iwx_mld_uptime() > sc->sc_mld_mlo_scan_time + IWX_MLD_MLO_SCAN_MAX_AGE_SEC ||
        !sc->sc_mld_mlo_scan_time) {
        iwx_mld_mlo_scan(sc);
        return;
    }
    links = iwx_mld_select_links(sc, &primary, &emlsr);
    if (sc->sc_mld_emlsr_active ||
        (links == sc->sc_mld_active_links && primary == sc->sc_mld_primary_link))
        return;
    iwx_mld_schedule_active_links(sc, links, primary, emlsr, false);
    sc->sc_mld_pending_soft = 1;
}

int ItlIwx::
iwx_mld_request_periodic_stats(struct iwx_softc *sc, bool enable)
{
    struct iwx_system_statistics_cmd cmd = {};

    cmd.cfg_mask = htole32(enable ? 0 : IWX_STATS_CFG_FLG_DISABLE_NTFY_MSK);
    cmd.config_time_sec = htole32(enable ? IWX_MLD_TPT_WINDOW_SEC : 0);
    cmd.type_id_mask = htole32(enable ? IWX_STATS_NTFY_TYPE_ID_OPER |
        IWX_STATS_NTFY_TYPE_ID_OPER_PART1 : 0);
    return iwx_send_cmd_pdu(sc, IWX_WIDE_ID(IWX_SYSTEM_GROUP,
        IWX_SYSTEM_STATISTICS_CMD), 0, sizeof(cmd), &cmd);
}

/*
 * iwl_mld_handle_stats_oper_notif(): per-PHY channel load and per-link
 * beacon energy. The per-PHY entry grew with each notification version.
 */
void ItlIwx::
iwx_mld_handle_stats_oper_notif(struct iwx_softc *sc, struct iwx_rx_packet *pkt)
{
    uint8_t version = iwx_lookup_notif_ver(sc, IWX_STATISTICS_GROUP,
        IWX_STATISTICS_OPER_NOTIF);
    size_t phy_size, length = iwx_rx_packet_payload_len(pkt);
    const uint8_t *data = pkt->data;
    const size_t links_offset = 4;
    const size_t phy_offset = links_offset + IWX_FW_MAX_LINKS * IWX_STATS_PER_LINK_SIZE;

    if (version == IWX_FW_CMD_VER_UNKNOWN || version <= 3)
        phy_size = IWX_STATS_PER_PHY_SIZE_V1;
    else if (version == 4)
        phy_size = IWX_STATS_PER_PHY_SIZE_V2;
    else
        phy_size = IWX_STATS_PER_PHY_SIZE_V3;
    if (length != phy_offset + IWX_STATS_MAX_PHY_OPERATIONAL * phy_size +
        IWX_STATION_COUNT * sizeof(uint32_t))
        return;

    for (int phy = 0; phy < IWX_STATS_MAX_PHY_OPERATIONAL; phy++) {
        const uint8_t *entry = data + phy_offset + phy * phy_size;
        uint32_t by_us = le32toh(*(const uint32_t *)(entry + 4));
        uint32_t not_by_us = le32toh(*(const uint32_t *)(entry + 8));

        if (not_by_us == IWX_STATS_UNKNOWN_CHANNEL_LOAD || not_by_us > 100 ||
            sc->sc_mld_emlsr_active)
            continue;
        sc->sc_mld_phy_load_by_us[phy] = by_us;
        /* Weight the old value by one half, as iwlmld does. */
        sc->sc_mld_phy_load[phy] = (not_by_us >> 1) +
            (sc->sc_mld_phy_load[phy] >> 1);
    }
    for (int link = 0; link < IWX_FW_MAX_LINKS; link++) {
        const uint8_t *entry = data + links_offset + link * IWX_STATS_PER_LINK_SIZE;

        sc->sc_mld_link_energy[link] = (uint8_t)MIN(le32toh(
            *(const uint32_t *)(entry + 12)), 255);
    }
}

/* Arm the traffic window and the statistics when the association is an MLO one. */
void ItlIwx::
iwx_mld_emlsr_start(struct iwx_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    int accepted = 0;

    for (int i = 1; i < ic->ic_mld_link_count; i++)
        accepted += ic->ic_mld_links[i].assoc_accepted;
    if (!ic->ic_wcl_peer_is_mlo || !ic->ic_mld_emlsr_supported ||
        !ic->ic_mld_emlsr_peer_supported || !accepted ||
        CSR_HW_RFID_IS_CDB(sc->sc_hw_rf_id))
        return;
    sc->sc_mld_emlsr_blocked = IWX_MLD_EMLSR_BLOCKED_TPT;
    sc->sc_mld_emlsr_exit_repeat = 0;
    sc->sc_mld_emlsr_last_exit = 0;
    sc->sc_mld_emlsr_prevent_until = 0;
    sc->sc_mld_mlo_scan_time = 0;
    sc->sc_mld_retry_ticks = 0;
    sc->sc_mld_task_flags = 0;
    sc->sc_mld_tpt_tx = sc->sc_mld_tpt_rx = 0;
    for (int i = 0; i < 4; i++) {
        sc->sc_mld_tpt_tx += ic->ic_wcl_tx_packets[i];
        sc->sc_mld_tpt_rx += ic->ic_wcl_rx_packets[i];
    }
    memset(sc->sc_mld_phy_load, 0, sizeof(sc->sc_mld_phy_load));
    memset(sc->sc_mld_phy_load_by_us, 0, sizeof(sc->sc_mld_phy_load_by_us));
    memset(sc->sc_mld_link_energy, 0, sizeof(sc->sc_mld_link_energy));
    if (iwx_mld_request_periodic_stats(sc, true) != 0)
        XYLog("%s: could not request statistics\n", __FUNCTION__);
    sc->sc_mld_emlsr_enabled = 1;
    timeout_add_sec(&sc->sc_mld_tpt_timer, IWX_MLD_TPT_WINDOW_SEC);
}

void ItlIwx::
iwx_mld_emlsr_stop(struct iwx_softc *sc)
{
    sc->sc_mld_emlsr_enabled = 0;
    timeout_del(&sc->sc_mld_tpt_timer);
    iwx_del_task(sc, sc->sc_nswq, &sc->mld_tpt_task);
    sc->sc_mld_task_flags = 0;
    sc->sc_scan_mlo = 0;
}

void ItlIwx::
iwx_mld_tpt_timer(void *arg)
{
    struct iwx_softc *sc = (struct iwx_softc *)arg;
    ItlIwx *that = container_of(sc, ItlIwx, com);

    if (!sc->sc_mld_emlsr_enabled)
        return;
    __atomic_fetch_or(&sc->sc_mld_task_flags, IWX_MLD_TASK_TICK, __ATOMIC_RELAXED);
    that->iwx_add_task(sc, sc->sc_nswq, &sc->mld_tpt_task);
}

/*
 * iwl_mld_emlsr_check_tpt() and the checks iwlmld makes on its statistics: the
 * traffic window gates EMLSR, an unblock starts the scan that selects links,
 * and an active pair leaves when it stops paying off.
 */
void ItlIwx::
iwx_mld_tpt_task(void *arg)
{
    struct iwx_softc *sc = (struct iwx_softc *)arg;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    struct ieee80211com *ic = &sc->sc_ic;
    uint32_t flags, now, tx = 0, rx = 0;
    bool unblocked = false;

    if (!that->getMainWorkLoop()->inGate()) {
        that->getMainCommandGate()->runAction(
            [](OSObject *, void *arg0, void *, void *, void *) -> IOReturn {
                iwx_mld_tpt_task(arg0);
                return kIOReturnSuccess;
            }, arg);
        return;
    }
    flags = __atomic_exchange_n(&sc->sc_mld_task_flags, 0, __ATOMIC_RELAXED);
    if (!sc->sc_mld_emlsr_enabled || ic->ic_state != IEEE80211_S_RUN ||
        (sc->sc_flags & IWX_FLAG_SHUTDOWN))
        return;
    if (flags & IWX_MLD_TASK_SELECT)
        that->iwx_mld_apply_link_selection(sc);
    if (!(flags & IWX_MLD_TASK_TICK))
        return;

    timeout_add_sec(&sc->sc_mld_tpt_timer, IWX_MLD_TPT_WINDOW_SEC);
    now = iwx_mld_uptime();
    for (int i = 0; i < 4; i++) {
        tx += ic->ic_wcl_tx_packets[i];
        rx += ic->ic_wcl_rx_packets[i];
    }
    uint32_t window_tx = tx - sc->sc_mld_tpt_tx, window_rx = rx - sc->sc_mld_tpt_rx;
    sc->sc_mld_tpt_tx = tx;
    sc->sc_mld_tpt_rx = rx;
    if (!ic->ic_bss->ni_port_valid)
        return;

    if ((sc->sc_mld_emlsr_blocked & IWX_MLD_EMLSR_BLOCKED_PREVENTION) &&
        now >= sc->sc_mld_emlsr_prevent_until) {
        sc->sc_mld_emlsr_blocked &= ~IWX_MLD_EMLSR_BLOCKED_PREVENTION;
        unblocked = true;
    }
    if (sc->sc_mld_emlsr_blocked & IWX_MLD_EMLSR_BLOCKED_TPT) {
        if (window_tx >= IWX_MLD_ENTER_EMLSR_TPT_THRESH ||
            window_rx >= IWX_MLD_ENTER_EMLSR_TPT_THRESH) {
            sc->sc_mld_emlsr_blocked &= ~IWX_MLD_EMLSR_BLOCKED_TPT;
            unblocked = true;
        }
    } else if (window_tx < IWX_MLD_ENTER_EMLSR_TPT_THRESH &&
        window_rx < IWX_MLD_ENTER_EMLSR_TPT_THRESH) {
        sc->sc_mld_emlsr_blocked |= IWX_MLD_EMLSR_BLOCKED_TPT;
        iwx_mld_exit_emlsr(sc, IWX_MLD_EMLSR_EXIT_BLOCK);
        return;
    } else if (sc->sc_mld_emlsr_active) {
        /* Primary channel nearly idle, or one of the links too weak. */
        const struct ieee80211_node *primary =
            iwx_mld_link_node(sc, sc->sc_mld_primary_link);

        if (primary != NULL && primary->ni_chan_util >= 0 &&
            (unsigned int)primary->ni_chan_util <
            IWX_MLD_PERCENT_TO_255(IWX_MLD_EXIT_EMLSR_CHAN_LOAD)) {
            iwx_mld_exit_emlsr(sc, IWX_MLD_EMLSR_EXIT_CHAN_LOAD);
            return;
        }
        for (int i = 0; i < IWX_MLD_MAX_LINKS; i++) {
            if ((sc->sc_mld_active_links & (1U << i)) && sc->sc_mld_link_energy[i] &&
                -(int)sc->sc_mld_link_energy[i] < IWX_MLD_LOW_RSSI_THRESH) {
                iwx_mld_exit_emlsr(sc, IWX_MLD_EMLSR_EXIT_LOW_RSSI);
                return;
            }
        }
    }
    if (unblocked) {
        sc->sc_mld_retry_ticks = 0;
        that->iwx_mld_apply_link_selection(sc);
    } else if (!sc->sc_mld_emlsr_blocked && !sc->sc_mld_emlsr_active &&
        ++sc->sc_mld_retry_ticks >= IWX_MLD_TRIGGER_LINK_SEL_SEC / IWX_MLD_TPT_WINDOW_SEC) {
        /* Conditions change without a notification; look again now and then. */
        sc->sc_mld_retry_ticks = 0;
        that->iwx_mld_apply_link_selection(sc);
    }
}
#endif

bool ItlIwx::
iwx_mld_associated_channels_valid(struct iwx_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    auto channelValidForNode = [&](struct ieee80211_node *ni) {
        if (ni == NULL || ni->ni_chan == NULL)
            return false;
        int index = ieee80211_chan2ieee(ic, ni->ni_chan);
        if (index <= 0 || index > IEEE80211_CHAN_MAX)
            return false;
        struct ieee80211_channel *channel = &ic->ic_channels[index];
        if (!channel->ic_freq || !channel->ic_flags)
            return false;
        uint8_t restrictions = channel->ic_reg_flags;
        if ((ni->ni_flags & IEEE80211_NODE_HE) &&
            (restrictions & IEEE80211_CHAN_NO_HE))
            return false;
        if ((ni->ni_flags & IEEE80211_NODE_EHT) &&
            (restrictions & IEEE80211_CHAN_NO_EHT))
            return false;
        switch (ni->ni_chw) {
        case IEEE80211_CHAN_WIDTH_20_NOHT:
        case IEEE80211_CHAN_WIDTH_20:
            return true;
        case IEEE80211_CHAN_WIDTH_40:
            return !(restrictions & IEEE80211_CHAN_NO_40MHZ);
        case IEEE80211_CHAN_WIDTH_80:
            return !(restrictions & IEEE80211_CHAN_NO_80MHZ);
        case IEEE80211_CHAN_WIDTH_80P80:
        case IEEE80211_CHAN_WIDTH_160:
            return !(restrictions & IEEE80211_CHAN_NO_160MHZ);
        case IEEE80211_CHAN_WIDTH_320:
            return !(restrictions & IEEE80211_CHAN_NO_320MHZ);
        default:
            return false;
        }
    };
    if (!channelValidForNode(ic->ic_bss))
        return false;
    if (sc->sc_use_mld_api) {
        for (int i = 1; i < ic->ic_mld_link_count; i++) {
            struct ieee80211_mld_link_info *link = &ic->ic_mld_links[i];
            if (link->assoc_accepted &&
                !channelValidForNode(link->ni))
                return false;
        }
    }
    return true;
}

/*
 * Whether the channel the link sits on still exists, without judging what that
 * channel is allowed to do. A regulatory answer can narrow a channel after the
 * link is up; that is a reason to run narrower, not a reason to drop a working
 * connection.
 */
bool ItlIwx::
iwx_mld_associated_channel_usable(struct iwx_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    auto usable = [&](struct ieee80211_node *ni) {
        if (ni == NULL || ni->ni_chan == NULL)
            return false;
        int index = ieee80211_chan2ieee(ic, ni->ni_chan);
        if (index <= 0 || index > IEEE80211_CHAN_MAX)
            return false;
        struct ieee80211_channel *channel = &ic->ic_channels[index];
        return channel->ic_freq != 0 && channel->ic_flags != 0;
    };
    if (!usable(ic->ic_bss))
        return false;
    if (sc->sc_use_mld_api) {
        for (int i = 1; i < ic->ic_mld_link_count; i++) {
            struct ieee80211_mld_link_info *link = &ic->ic_mld_links[i];
            if (link->assoc_accepted && !usable(link->ni))
                return false;
        }
    }
    return true;
}

void ItlIwx::
iwx_mld_schedule_active_links(struct iwx_softc *sc, uint8_t links,
    uint8_t primary_link, bool emlsr_active, bool disconnect)
{
    ItlIwx *that = container_of(sc, ItlIwx, com);
    int s = splnet();

#ifdef AIRPORT_WCL
    if (sc->sc_ic.ic_wcl_peer_is_mlo) {
        uint8_t allowed = ieee80211_ttlm_allowed_links(&sc->sc_ic);
        links &= allowed;
        if (!links && allowed)
            links = allowed & -allowed;
        if (links && !(links & (1U << primary_link)))
            primary_link = __builtin_ctz((unsigned)links);
        emlsr_active = emlsr_active && __builtin_popcount((unsigned)links) == 2;
    }
#endif
    sc->sc_mld_pending_links = links;
    sc->sc_mld_pending_primary_link = primary_link;
    sc->sc_mld_pending_emlsr = emlsr_active;
    sc->sc_mld_disconnect_pending = disconnect;
    sc->sc_mld_pending_soft = 0;
    sc->sc_mld_link_update_pending = 1;
    sc->sc_mld_pending_generation = sc->sc_generation;
    splx(s);
    that->iwx_add_task(sc, sc->sc_nswq, &sc->mld_link_task);
}

#ifdef AIRPORT_WCL
void ItlIwx::
iwx_ttlm_schedule(struct ieee80211com *ic)
{
    struct iwx_softc *sc = (struct iwx_softc *)ic->ic_softc;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    if (!(sc->sc_flags & IWX_FLAG_SHUTDOWN))
        that->iwx_add_task(sc, sc->sc_nswq, &sc->mld_link_task);
}

int ItlIwx::
iwx_ttlm_apply(struct ieee80211com *ic, uint16_t ap_links)
{
    struct iwx_softc *sc = (struct iwx_softc *)ic->ic_softc;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    uint8_t allowed = 0;
    for (int i = 0; i < ic->ic_mld_link_count; i++)
        if (ic->ic_mld_links[i].assoc_accepted &&
            (ap_links & (1U << ic->ic_mld_links[i].ap_link_id)))
            allowed |= 1U << i;
    if (!allowed)
        return EINVAL;
    uint8_t links = sc->sc_mld_active_links & allowed;
    if (!links)
        links = allowed & -allowed;
    uint8_t primary = sc->sc_mld_primary_link;
    if (!(links & (1U << primary)))
        primary = __builtin_ctz((unsigned)links);
    int err = that->iwx_mld_update_active_links(sc, links, primary,
        sc->sc_mld_emlsr_active && __builtin_popcount((unsigned)links) == 2);
    return err;
}

#endif

void ItlIwx::
iwx_mld_active_link_task(void *arg)
{
    struct iwx_softc *sc = (struct iwx_softc *)arg;
    ItlIwx *that = container_of(sc, ItlIwx, com);
    uint8_t links, primary_link, emlsr_active, disconnect, pending, soft;
    int generation, err;

    if (!that->getMainWorkLoop()->inGate()) {
        that->getMainCommandGate()->runAction(
            [](OSObject *, void *arg0, void *, void *, void *) -> IOReturn {
                iwx_mld_active_link_task(arg0);
                return kIOReturnSuccess;
            }, arg);
        return;
    }
#ifdef AIRPORT_WCL
    const int ttlm_generation = sc->sc_generation;
    ieee80211_ttlm_task(&sc->sc_ic);
    if (ttlm_generation != sc->sc_generation)
        return;
#endif
    int s = splnet();
    pending = sc->sc_mld_link_update_pending;
    links = sc->sc_mld_pending_links;
    primary_link = sc->sc_mld_pending_primary_link;
    emlsr_active = sc->sc_mld_pending_emlsr;
    disconnect = sc->sc_mld_disconnect_pending;
    soft = sc->sc_mld_pending_soft;
    generation = sc->sc_mld_pending_generation;
    sc->sc_mld_link_update_pending = 0;
    sc->sc_mld_disconnect_pending = 0;
    sc->sc_mld_pending_soft = 0;
    splx(s);
    if (!pending || generation != sc->sc_generation ||
        (sc->sc_flags & IWX_FLAG_SHUTDOWN))
        return;
    if (sc->sc_ic.ic_state == IEEE80211_S_RUN &&
        !that->iwx_mld_associated_channels_valid(sc)) {
        that->iwx_newstate(&sc->sc_ic, IEEE80211_S_INIT, -1);
        return;
    }

#ifdef AIRPORT_WCL
    uint8_t allowed = ieee80211_ttlm_allowed_links(&sc->sc_ic);
    links &= allowed;
    if (!links && allowed)
        links = allowed & -allowed;
    if (links && !(links & (1U << primary_link)))
        primary_link = __builtin_ctz((unsigned)links);
    emlsr_active = emlsr_active && __builtin_popcount((unsigned)links) == 2;
#endif
    err = that->iwx_mld_update_active_links(sc, links, primary_link,
        emlsr_active);
    if (err && err != ENXIO) {
        iwx_mld_log_failure(sc, "mld-link-update", "apply-active-set",
            err, IWX_WIDE_ID(IWX_MAC_CONF_GROUP,
                IWX_MLD_LINK_CONFIG_CMD), links);
        if (soft || emlsr_active) {
            /* A choice of the policy that rolled back: stay on the links and wait before choosing again. */
            iwx_mld_note_emlsr_exit(sc, IWX_MLD_EMLSR_EXIT_FAIL_ENTRY);
        } else {
            disconnect = 1;
        }
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

    }
    if (ni->ni_chw != IEEE80211_CHAN_WIDTH_20_NOHT)
        cmd->qos_flags |= htole32(IWX_MAC_QOS_FLG_TGN);
    if (ic->ic_flags & IEEE80211_F_USEPROT)
        cmd->protection_flags |= htole32(IWX_MLD_LINK_PROT_FLG_TGG_PROTECT);

    if (ni->ni_mbssid_index) {
        IEEE80211_ADDR_COPY(cmd->ref_bssid_addr, ni->ni_mbssid_transmitted);
        cmd->bssid_index = ni->ni_mbssid_index;
    }
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
    cmd->flags_mask = htole32(flags);
    cmd->spec_link_id = ni->ni_mld_valid ? ni->ni_mld_link_id : 0;
    cmd->listen_lmac = 0;
    cmd->action = htole32(IWX_FW_CTXT_ACTION_MODIFY);
#undef IWX_EXP2
}


/* iwl_mld_get_htc_flags() */
static uint32_t
iwx_mld_get_htc_flags(const struct ieee80211_node *ni)
{
    const uint8_t *mac = ni->ni_he_cap_elem.mac_cap_info;
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
    return htc;
}

/* iwl_mld_fill_ampdu_size_and_dens() */
static void
iwx_mld_fill_ampdu_size_and_dens(const struct ieee80211_node *ni,
    uint32_t *aggsize_out, uint32_t *mpdu_dens_out)
{
    const uint32_t max_aggsize = IWX_STA_FLG_MAX_AGG_SIZE_4M >>
        IWX_STA_FLG_MAX_AGG_SIZE_SHIFT;
    uint32_t aggsize, mpdu_dens;

    if (IEEE80211_IS_CHAN_6GHZ(ni->ni_chan)) {
        mpdu_dens = ni->ni_he_6ghz_capa & IEEE80211_HE_6GHZ_CAP_MIN_MPDU_START;
        aggsize = (ni->ni_he_6ghz_capa &
            IEEE80211_HE_6GHZ_CAP_MAX_AMPDU_LEN_EXP) >> 3;
    } else {
        mpdu_dens = (ni->ni_ampdu_param & IEEE80211_AMPDU_PARAM_SS) >> 2;
        if (ni->ni_flags & IEEE80211_NODE_VHT)
            aggsize = (ni->ni_vhtcaps &
                IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK) >>
                IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT;
        else
            aggsize = ni->ni_ampdu_param & IEEE80211_AMPDU_PARAM_LE;
    }
    if (ni->ni_flags & IEEE80211_NODE_HE)
        aggsize += (ni->ni_he_cap_elem.mac_cap_info[3] &
            IEEE80211_HE_MAC_CAP3_MAX_AMPDU_LEN_EXP_MASK) >>
            IEEE80211_HE_MAC_CAP3_MAX_AMPDU_LEN_EXP_SHIFT;
    if (ni->ni_flags & IEEE80211_NODE_EHT)
        aggsize += ni->ni_eht_cap_elem.mac_cap_info[1] & 0x01;
    *aggsize_out = MIN(aggsize, max_aggsize);
    *mpdu_dens_out = mpdu_dens;
}

/* iwl_mld_fill_pkt_ext(): PPE thresholds, or the nominal padding without them. */
static void
iwx_mld_fill_pkt_ext(const struct ieee80211_node *ni,
    struct iwx_mld_he_pkt_ext_v2 *pkt_ext)
{
    memset(pkt_ext, 7, sizeof(*pkt_ext));
    if (ni->ni_he_cap_elem.phy_cap_info[6] &
        IEEE80211_HE_PHY_CAP6_PPE_THRESHOLD_PRESENT) {
        unsigned nss = (ni->ni_ppe_thres[0] & 7) + 1;
        unsigned mask = (ni->ni_ppe_thres[0] >> 3) & 15;
        unsigned bit = 7;

        for (unsigned ss = 0; ss < nss && ss < 2; ss++) {
            for (unsigned bw = 0; bw < 4; bw++) {
                if (!(mask & (1U << bw)))
                    continue;
                pkt_ext->pkt_ext_qam_th[ss][bw][1] =
                    iwx_mld_he_ppe_value(ni->ni_ppe_thres, bit);
                pkt_ext->pkt_ext_qam_th[ss][bw][0] =
                    iwx_mld_he_ppe_value(ni->ni_ppe_thres, bit + 3);
                bit += 6;
            }
        }
    } else {
        unsigned padding = (ni->ni_he_cap_elem.phy_cap_info[9] >> 6) & 3;

        if (padding == 3)
            return;
        for (unsigned ss = 0; ss < 2; ss++) {
            for (unsigned bw = 0; bw < 4; bw++) {
                pkt_ext->pkt_ext_qam_th[ss][bw][0] = padding == 1 ? 0 : 7;
                pkt_ext->pkt_ext_qam_th[ss][bw][1] = padding == 2 ? 0 : 7;
            }
        }
    }
}

/* iwl_mld_add_link(): the firmware link context of one link slot. */
int ItlIwx::
iwx_mld_add_link(struct iwx_softc *sc, struct iwx_node *in, int link_slot)

{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwx_mld_link_config_cmd link_cmd;
    int err;

    memset(&link_cmd, 0, sizeof(link_cmd));
    link_cmd.link_id = htole32(link_slot);
    link_cmd.mac_id = htole32(in->in_id);
    link_cmd.spec_link_id = in->in_ni.ni_mld_valid ?
        in->in_ni.ni_mld_link_id : 0;
    link_cmd.phy_id = htole32(in->in_phyctxt ? in->in_phyctxt->id :
        IWX_FW_CTXT_INVALID);
    IEEE80211_ADDR_COPY(link_cmd.local_link_addr,
        ic->ic_mld_link_count != 0 ?
            ic->ic_mld_links[link_slot].local_addr : ic->ic_myaddr);
    link_cmd.listen_lmac = 0;
    link_cmd.action = IWX_FW_CTXT_ACTION_ADD;

    err = iwx_send_cmd_pdu(sc,
        IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_LINK_CONFIG_CMD),
        0, sizeof(link_cmd), &link_cmd);
    if (!err)
        sc->sc_mld_link_active |= 1U << link_slot;
    return err;
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
    if (!update && !(sc->sc_mld_sta_mask & (1U << sta_id)))
        iwx_rs_reset_amsdu(in);

    if (!update && !(sc->sc_mld_link_active & (1U << link_slot))) {
        err = iwx_mld_add_link(sc, in, link_slot);
        if (err)
            return err;
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
        iwx_mld_fill_ampdu_size_and_dens(&in->in_ni, &aggsize, &mpdu_dens);
        sta_cmd.tx_ampdu_spacing = htole32(mpdu_dens);
        sta_cmd.tx_ampdu_max_size = htole32(aggsize);
    }

    if (in->in_ni.ni_flags & IEEE80211_NODE_HE) {
        sta_cmd.htc_flags = htole32(iwx_mld_get_htc_flags(&in->in_ni));
        sta_cmd.ack_enabled = htole32((in->in_ni.ni_he_cap_elem.mac_cap_info[2] &
            IEEE80211_HE_MAC_CAP2_ACK_EN) ? 1 : 0);
        iwx_mld_fill_pkt_ext(&in->in_ni, &sta_cmd.pkt_ext);
    }


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

    /*
     * As in iwlmld, the MAC is added before anything about the peer is
     * known: HE/EHT support follows in a MODIFY once the BSS is chosen, and
     * the EML client data (iwl_mld_fill_mac_cmd_sta()) only with the
     * association. An ADD carrying them for an AP MLD made the firmware
     * assert (UMAC ADVANCED_SYSASSERT 0x20103131).
     */
    cmd.mac_type = htole32(IWX_FW_MAC_TYPE_BSS_STA);
    IEEE80211_ADDR_COPY(cmd.local_mld_addr, ic->ic_myaddr);
    if (ic->ic_flags & IEEE80211_F_HEON) {
        cmd.nic_not_ack_enabled = htole32(
            (ic->ic_he_cap_elem.mac_cap_info[2] &
                IEEE80211_HE_MAC_CAP2_ACK_EN) ? 0 : 1);
        if (action != IWX_FW_CTXT_ACTION_ADD) {
            cmd.he_support = htole16(1);
            if (ic->ic_wcl_peer_is_mlo || (ni->ni_flags & IEEE80211_NODE_EHT))
                cmd.eht_support = htole32(1);
        }
    }
    cmd.client.assoc_id = htole16(IEEE80211_AID(ni->ni_associd));
    if (assoc && ni->ni_mld_valid) {
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
    uint32_t sta_mask = sc->sc_mld_sta_mask;
    if (k->k_flags & IEEE80211_KEY_MLO) {
        int slot = iwx_mld_link_slot(&sc->sc_ic, ni);
        if (slot < 0 || slot >= sc->sc_ic.ic_mld_link_count ||
            sc->sc_mld_sta_ids[slot] >= 32)
            return remove ? 0 : ENXIO;
        sta_mask &= 1U << sc->sc_mld_sta_ids[slot];
    }

    if (iwx_lookup_cmd_ver(sc, IWX_DATA_PATH_GROUP, IWX_MLD_SEC_KEY_CMD) != 1) {
        iwx_mld_log_key_reject(k, remove, "cmd-version");
        return ENOTSUP;
    }
    if (mgmt_key) {
        if ((is_igtk && is_bigtk) ||
            (is_igtk && (k->k_id < 4 || k->k_id > 5)) ||
            (is_bigtk && ((!remove && !sc->sc_ic.ic_beacon_prot) ||
                k->k_id < 6 || k->k_id > 7))) {
            iwx_mld_log_key_reject(k, remove, "mgmt-key-id");
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
            iwx_mld_log_key_reject(k, remove, "mgmt-cipher");
            return ENOTSUP;
        }
        if (!(flags & IWX_MLD_SEC_KEY_FLAG_CIPHER_MASK)) {
            iwx_mld_log_key_reject(k, remove, "mgmt-key-size");
            return ENOTSUP;
        }
    } else if (k->k_cipher == IEEE80211_CIPHER_CCMP && k->k_len == 16) {
        flags |= IWX_MLD_SEC_KEY_FLAG_CIPHER_CCMP;
    } else {
        iwx_mld_log_key_reject(k, remove, "cipher");
        return ENOTSUP;
    }
    if (!(sc->sc_flags & IWX_FLAG_STA_ACTIVE))
        return remove ? 0 : ENXIO;
    if (!sta_mask)
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
        cmd.u.remove.sta_mask = htole32(sta_mask);
        cmd.u.remove.key_id = htole32(k->k_id);
        cmd.u.remove.key_flags = htole32(flags);
    } else {
        cmd.u.add.sta_mask = htole32(sta_mask);
        cmd.u.add.key_id = htole32(k->k_id);
        cmd.u.add.key_flags = htole32(flags);
        cmd.u.add.rx_seq = htole64(mgmt_key ? k->k_mgmt_rsc : k->k_rsc[0]);
        cmd.u.add.tx_seq = htole64(k->k_tsc);
        memcpy(cmd.u.add.key, k->k_key, k->k_len);
    }

    // Complete the command before EAPOL code marks the port valid.
    err = iwx_send_cmd_pdu(sc,
        IWX_WIDE_ID(IWX_DATA_PATH_GROUP, IWX_MLD_SEC_KEY_CMD),
        0, sizeof(cmd), &cmd);
    if (err)
        return err;
    if (!remove && (k->k_flags & IEEE80211_KEY_GROUP))
        sc->sc_ic.ic_def_txkey = k->k_id;
    return 0;
}

/*
 * Linux iwlwifi waits IWL_FLUSH_WAIT_MS per queue in
 * iwl_trans_pcie_wait_txq_empty(); iwl_mvm_rm_sta() then aborts the removal
 * when that wait fails, before the queues are disabled and their rings freed.
 */
static constexpr int IWX_FLUSH_WAIT_MS = 2000;

void ItlIwx::
iwx_mld_rm_sta_local(struct iwx_softc *sc, struct iwx_node *in)
{
    struct ieee80211com *ic = &sc->sc_ic;
    iwx_rs_reset_amsdu(in);
    for (int i = 0; i < ic->ic_mld_link_count; i++)
        if (ic->ic_mld_links[i].ni)
            iwx_rs_reset_amsdu((struct iwx_node *)ic->ic_mld_links[i].ni);

    for (int tid = 0; tid < IWX_MAX_TID_COUNT; tid++) {
        const uint16_t qid = sc->sc_tid_data[tid].qid;
        if (qid == IWX_INVALID_QUEUE || qid >= nitems(sc->txq))
            continue;
        iwx_free_tx_ring(sc, &sc->txq[qid]);
        sc->sc_tid_data[tid].qid = IWX_INVALID_QUEUE;
    }
    for (int i = 0; i < IEEE80211_GROUP_NKID; i++) {
        struct ieee80211_key *key = &ic->ic_nw_keys[i];
        if (key->k_cipher != IEEE80211_CIPHER_CCMP &&
            !ieee80211_is_bip_cipher(key->k_cipher))
            continue;
        if (ieee80211_is_bip_cipher(key->k_cipher))
            ieee80211_delete_key(ic, &in->in_ni, key);
        explicit_bzero(key, sizeof(*key));
    }
    for (int i = 0; i < ic->ic_mld_link_count; i++) {
        for (int kid = 0; kid < IEEE80211_GROUP_NKID; kid++) {
            struct ieee80211_key *key = &ic->ic_mld_links[i].keys[kid];
            if (key->k_cipher != IEEE80211_CIPHER_NONE)
                ieee80211_delete_key(ic, ic->ic_mld_links[i].ni, key);
            explicit_bzero(key, sizeof(*key));
        }
    }
    explicit_bzero(&in->in_ni.ni_pairwise_key, sizeof(in->in_ni.ni_pairwise_key));

    sc->sc_flags &= ~IWX_FLAG_STA_ACTIVE;
    sc->sc_mld_sta_mask = 0;
    sc->sc_mld_active_sta_mask = 0;
    sc->sc_mld_link_active = 0;
    sc->sc_mld_active_links = 0;
    sc->sc_mld_primary_link = 0;
    sc->sc_mld_emlsr_active = 0;
    sc->sc_mld_txq_tidmask = 0;
}

/*
 * iwl_mvm_wait_sta_queues_empty(): wait for the station's TID queues, with one
 * deadline per queue as in iwl_trans_pcie_wait_txq_empty(). The rings are
 * freed afterwards, which must not happen while firmware may still read them.
 * The shared management queue (first_data_qid) is not released here, so it is
 * not waited on either.
 */
int ItlIwx::
iwx_mld_wait_sta_queues_empty(struct iwx_softc *sc, int generation)
{
    for (int tid = 0; tid < IWX_MAX_TID_COUNT; tid++) {
        uint16_t qid = sc->sc_tid_data[tid].qid;
        struct iwx_tx_ring *ring;
        AbsoluteTime deadline;

        if (qid == IWX_INVALID_QUEUE || qid >= nitems(sc->txq))
            continue;
        ring = &sc->txq[qid];
        clock_interval_to_deadline(IWX_FLUSH_WAIT_MS, kMillisecondScale,
            reinterpret_cast<uint64_t *>(&deadline));
        /* Logical write pointers map to the descriptor window, as in reclaim. */
        while (ring->tail != IWX_AGG_SSN_TO_TXQ_IDX(ring->cur, ring->ring_count)) {
            int result = getMainCommandGate()->commandSleep(
                &ring->queued, deadline, THREAD_UNINT);
            if (generation != sc->sc_generation)
                return ENXIO;
            if (result != THREAD_AWAKENED &&
                ring->tail != IWX_AGG_SSN_TO_TXQ_IDX(ring->cur, ring->ring_count))
                return result == THREAD_TIMED_OUT ? EWOULDBLOCK : EINTR;
        }
    }
    return 0;
}

/* Remove the station's firmware TX queues and release their rings. */
int ItlIwx::
iwx_mld_remove_sta_queues(struct iwx_softc *sc)
{
    for (int tid = 0; tid <= IWX_MGMT_TID; tid++) {
        int err;

        if (!(sc->sc_mld_txq_tidmask & (1U << tid)))
            continue;
        err = iwx_mld_queue_cmd(sc, sc->sc_mld_active_sta_mask, tid, 1, 0, 0, 0,
            NULL, NULL);
        if (err) {
            iwx_mld_log_failure(sc, "deauth", "station-queue-remove",
                err, IWX_WIDE_ID(IWX_DATA_PATH_GROUP,
                    IWX_MLD_SCD_QUEUE_CONFIG_CMD), tid);
            return err;
        }
        if (tid < IWX_MAX_TID_COUNT) {
            const uint16_t qid = sc->sc_tid_data[tid].qid;
            if (qid != IWX_INVALID_QUEUE && qid < nitems(sc->txq)) {
                iwx_free_tx_ring(sc, &sc->txq[qid]);
                sc->sc_tid_data[tid].qid = IWX_INVALID_QUEUE;
            }
        }
    }
    return 0;
}

/* Remove the group keys, every link's group keys and the pairwise key. */
int ItlIwx::
iwx_mld_remove_sta_keys(struct iwx_softc *sc, struct iwx_node *in)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_key *key;
    int err;

    for (int i = 0; i < IEEE80211_GROUP_NKID; i++) {
        key = &ic->ic_nw_keys[i];
        if (key->k_cipher != IEEE80211_CIPHER_CCMP &&
            !ieee80211_is_bip_cipher(key->k_cipher))
            continue;
        err = iwx_mld_set_key(sc, &in->in_ni, key, 1);
        if (err) {
            iwx_mld_log_failure(sc, "deauth", "group-key-remove",
                err, IWX_WIDE_ID(IWX_DATA_PATH_GROUP, IWX_MLD_SEC_KEY_CMD), i);
            return err;
        }
        if (ieee80211_is_bip_cipher(key->k_cipher))
            ieee80211_delete_key(ic, &in->in_ni, key);
        explicit_bzero(key, sizeof(*key));
    }
    for (int slot = 0; slot < ic->ic_mld_link_count; slot++) {
        struct ieee80211_mld_link_info *link = &ic->ic_mld_links[slot];

        for (int kid = 0; kid < IEEE80211_GROUP_NKID; kid++) {
            key = &link->keys[kid];
            if (key->k_cipher == IEEE80211_CIPHER_NONE)
                continue;
            err = iwx_mld_set_key(sc, link->ni, key, 1);
            if (err) {
                iwx_mld_log_failure(sc, "deauth", "link-key-remove",
                    err, IWX_WIDE_ID(IWX_DATA_PATH_GROUP, IWX_MLD_SEC_KEY_CMD), slot);
                return err;
            }
            ieee80211_delete_key(ic, link->ni, key);
            explicit_bzero(key, sizeof(*key));
        }
    }
    key = &in->in_ni.ni_pairwise_key;
    if (key->k_cipher == IEEE80211_CIPHER_CCMP) {
        err = iwx_mld_set_key(sc, &in->in_ni, key, 1);
        if (err) {
            iwx_mld_log_failure(sc, "deauth", "pairwise-key-remove",
                err, IWX_WIDE_ID(IWX_DATA_PATH_GROUP, IWX_MLD_SEC_KEY_CMD), -1);
            return err;
        }
        explicit_bzero(key, sizeof(*key));
    }
    return 0;
}

/* iwl_mld_remove_link(): deactivate, then remove one firmware link context. */
int ItlIwx::
iwx_mld_remove_link(struct iwx_softc *sc, struct iwx_node *in, int link_slot)
{
    struct iwx_mld_link_config_cmd link_cmd;
    int err;

    memset(&link_cmd, 0, sizeof(link_cmd));
    iwx_mld_modify_link_fill(sc, in, &link_cmd,
        IWX_MLD_LINK_CONTEXT_MODIFY_ACTIVE, 0);
    err = iwx_send_cmd_pdu(sc,
        IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_LINK_CONFIG_CMD),
        0, sizeof(link_cmd), &link_cmd);
    if (err)
        return err;
    memset(&link_cmd, 0, sizeof(link_cmd));
    link_cmd.action = htole32(IWX_FW_CTXT_ACTION_REMOVE);
    link_cmd.link_id = htole32(link_slot);
    link_cmd.spec_link_id = in->in_ni.ni_mld_valid ? in->in_ni.ni_mld_link_id : 0;
    link_cmd.phy_id = htole32(IWX_FW_CTXT_INVALID);
    err = iwx_send_cmd_pdu(sc,
        IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_LINK_CONFIG_CMD),
        0, sizeof(link_cmd), &link_cmd);
    if (!err)
        sc->sc_mld_link_active &= ~(1U << link_slot);
    return err;
}

int ItlIwx::
iwx_mld_rm_sta_cmd(struct iwx_softc *sc, struct iwx_node *in)
{
    struct iwx_mld_mvm_remove_sta_cmd sta_cmd;
    struct ieee80211com *ic = &sc->sc_ic;
    int err;
    int generation = sc->sc_generation;

    /*
     * A firmware that is not running cannot service the flushes, the MLD
     * queue removal or the key removal below, so each attempt would fail and
     * schedule another recovery on top of the one already coming. iwl_mvm
     * skips the queue wait outright in that state (CVE-2024-47672); with
     * nothing on the device left to remove, the removal is done locally.
     * A generation change means iwx_stop already owns the rings.
     */
    if ((sc->sc_flags & IWX_FLAG_SHUTDOWN) ||
        !(sc->sc_init_complete & IWX_INIT_COMPLETE)) {
        if (generation != sc->sc_generation) {
            return ENXIO;
        }
        iwx_mld_rm_sta_local(sc, in);
        return 0;
    }

    int version = iwx_lookup_cmd_ver(sc, IWX_MAC_CONF_GROUP, IWX_MLD_STA_REMOVE_CMD);
    if (version != 1 && version != IWX_FW_CMD_VER_UNKNOWN) {
        iwx_mld_log_failure(sc, "deauth", "station-remove-version",
            ENOTSUP, IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_STA_REMOVE_CMD), -1);
        return ENOTSUP;
    }

    if (sc->sc_flags & IWX_FLAG_STA_ACTIVE) {
        err = iwx_flush_sta(sc, in);
        if (err) {
            iwx_mld_log_failure(sc, "deauth", "station-tx-flush",
                err, IWX_TXPATH_FLUSH, -1);
            return err;
        }
        for (int i = 1; i < IWX_MLD_MAX_LINKS; i++) {
            uint8_t sta_id = sc->sc_mld_sta_ids[i];
            if (sta_id == 0xff || !(sc->sc_mld_sta_mask & (1U << sta_id)))
                continue;
            err = iwx_flush_sta_tids(sc, sta_id, 0xffff);
            if (err) {
                iwx_mld_log_failure(sc, "deauth", "link-tx-flush",
                    err, IWX_TXPATH_FLUSH, i);
                return err;
            }
        }
        err = iwx_mld_wait_sta_queues_empty(sc, generation);
        if (err) {
            iwx_mld_log_failure(sc, "deauth", "station-tx-drain",
                err, IWX_TXPATH_FLUSH, -1);
            return err;
        }
        err = iwx_mld_remove_sta_queues(sc);
        if (err)
            return err;
        err = iwx_mld_remove_sta_keys(sc, in);
        if (err)
            return err;
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
                iwx_mld_log_failure(sc, "deauth", "station-remove",
                    err, IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_STA_REMOVE_CMD), i);
                return err;
            }
            sc->sc_mld_sta_mask &= ~(1U << sta_id);
        }
        sc->sc_flags &= ~IWX_FLAG_STA_ACTIVE;
    }
    /* The primary firmware slot exists even when non-MLO discovery reports zero links. */
    for (int i = IWX_MLD_MAX_LINKS - 1; i >= 0; i--) {
        struct ieee80211_node *ni;

        if (!(sc->sc_mld_link_active & (1U << i)))
            continue;
        ni = i == 0 ? &in->in_ni :
            (i < ic->ic_mld_link_count ? ic->ic_mld_links[i].ni : NULL);
        if (ni == NULL)
            return EINVAL;
        err = iwx_mld_remove_link(sc, (struct iwx_node *)ni, i);
        if (err)
            return err;
    }

    iwx_rs_reset_amsdu(in);
    for (int i = 0; i < ic->ic_mld_link_count; i++)
        if (ic->ic_mld_links[i].ni)
            iwx_rs_reset_amsdu((struct iwx_node *)ic->ic_mld_links[i].ni);
    sc->sc_mld_sta_mask = 0;
    sc->sc_mld_active_sta_mask = 0;
    sc->sc_mld_active_links = 0;
    sc->sc_mld_primary_link = 0;
    sc->sc_mld_emlsr_active = 0;
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
    int link_version = iwx_lookup_cmd_ver(sc, IWX_MAC_CONF_GROUP, IWX_MLD_LINK_CONFIG_CMD);

    if (ic->ic_opmode != IEEE80211_M_STA ||
        (link_version != 1 && link_version != 2 &&
            link_version != IWX_FW_CMD_VER_UNKNOWN) ||
        !isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD))
        return ENOTSUP;
    if (sc->sc_mld_phy_active || (sc->sc_flags & IWX_FLAG_MAC_ACTIVE))
        return EBUSY;

#ifdef AIRPORT_WCL
    ieee80211_mld_discover_links(ic, &in->in_ni);
#endif
    iwx_mld_limit_link_resources(sc);
    /* Every context programmed below derives its centre from the BSS channel. */
    if (in->in_ni.ni_chan == NULL)
        return EINVAL;
    sc->sc_mld_link_active = 0;
    sc->sc_mld_phy_active = 0;
    sc->sc_mld_active_links = 1;
    sc->sc_mld_active_sta_mask = 0;
    sc->sc_mld_primary_link = 0;
    sc->sc_mld_emlsr_active = 0;
    sc->sc_mld_txq_tidmask = 0;
    for (int i = 0; i < IWX_NUM_PHY_CTX; i++) {
        sc->sc_phyctxt[i].id = i;
        sc->sc_phyctxt[i].mld_config_valid = 0;
    }

    in->in_ni.ni_chw = IEEE80211_CHAN_WIDTH_20_NOHT;
    in->in_ni.ni_flags &= ~(IEEE80211_NODE_HT |
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
    err = iwx_phy_ctxt_cmd(sc, in->in_phyctxt, 1, 1, IWX_FW_CTXT_ACTION_ADD, 0);
    if (err)
        return err;
    sc->sc_mld_phy_active |= 1U;
    err = iwx_mld_mac_ctxt_cmd(sc, in, IWX_FW_CTXT_ACTION_ADD, 0);
    if (err)
        goto fail;
    sc->sc_flags |= IWX_FLAG_MAC_ACTIVE;
    /* The BSS is known now, as when iwlmld handles BSS_CHANGED_BSSID. */
    err = iwx_mld_mac_ctxt_cmd(sc, in, IWX_FW_CTXT_ACTION_MODIFY, 0);
    if (err)
        goto fail;
    err = iwx_mld_add_sta_cmd(sc, in, 0);
    if (err)
        goto fail;
    err = iwx_enable_mgmt_queue(sc);

    if (err)
        goto fail;
    duration = in->in_ni.ni_intval ? in->in_ni.ni_intval * 9 : 900;
    err = iwx_schedule_protect_session(sc, in, duration);
    if (err)
        goto fail;
    sc->sc_flags |= IWX_FLAG_TE_ACTIVE;
    return 0;

fail:
    if (generation == sc->sc_generation) {
        cleanup_err = iwx_mld_deauth(sc);
        if (cleanup_err)
            XYLog("%s: MLD AUTH cleanup failed (%d), original error %d\n",
                sc->sc_dev.dv_xname, cleanup_err, err);
    }
    return err;
}

/*
 * What the association negotiated, one line per link, after the IWL_DEBUG_EHT
 * output of iwlmld: band, channel, the width in MHz the AP operates it at and
 * the PHY generation, and for an AP MLD what it accepted and whether it offers
 * EMLSR. Without it a report cannot tell a single-link association from one the
 * AP never offered EMLSR for, or say what width a link really runs at.
 */
static void
iwx_mld_log_links(struct iwx_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    const bool mlo = ic->ic_wcl_peer_is_mlo;

    if (mlo)
        XYLog("%s: %d link(s), AP EML capabilities 0x%04x (EMLSR %s), driver EMLSR %s, "
            "active links 0x%x\n", __FUNCTION__, ic->ic_mld_link_count,
            ic->ic_bss->ni_mld_eml_capa,
            ic->ic_mld_emlsr_peer_supported ? "offered" : "not offered",
            ic->ic_mld_emlsr_supported ? "available" : "unavailable",
            sc->sc_mld_active_links);
    for (int i = 0; i < (mlo ? ic->ic_mld_link_count : 1); i++) {
        const struct ieee80211_mld_link_info *link = &ic->ic_mld_links[i];
        const struct ieee80211_node *ni = mlo ? link->ni : ic->ic_bss;

        if (ni == NULL || ni->ni_chan == NULL)
            continue;
        XYLog("%s: slot %d link id %u %s ch %d width %d MHz %s rssi %d %s\n",
            __FUNCTION__, i, mlo ? link->ap_link_id : 0,
            IEEE80211_IS_CHAN_6GHZ(ni->ni_chan) ? "6GHz" :
            IEEE80211_IS_CHAN_5GHZ(ni->ni_chan) ? "5GHz" : "2.4GHz",
            ieee80211_chan2ieee(ic, ni->ni_chan), iwx_mld_width_mhz(ni),
            (ni->ni_flags & IEEE80211_NODE_EHT) ? "EHT" :
            (ni->ni_flags & IEEE80211_NODE_HE) ? "HE" : "legacy",
            (int)ni->ni_rssi + IWX_MIN_DBM,
            !mlo || i == 0 || link->assoc_accepted ? "accepted" : "rejected");
    }
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
    if (in->in_ni.ni_chan == NULL)
        return EINVAL;
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
    err = iwx_rs_init(sc, in, true);
    if (err)
        return err;
    /* Prepare data TIDs before RUN; TX must not wait for BA to get a queue. */
    const int tid_count = (in->in_ni.ni_flags & IEEE80211_NODE_QOS) ?
        IWX_MAX_TID_COUNT : 1;
    for (int tid = 0; tid < tid_count; tid++) {
        int qid = iwx_tvqm_alloc_txq(sc, tid, 0);
        if (qid < 0) {
            iwx_mld_log_failure(sc, "run", "data-tx-queue", -qid,
                IWX_WIDE_ID(IWX_DATA_PATH_GROUP, IWX_MLD_SCD_QUEUE_CONFIG_CMD), tid);
            return -qid;
        }
    }
#ifdef AIRPORT_WCL
    if (ic->ic_ttlm_schedule)
        ic->ic_ttlm_schedule(ic);
#endif
    iwx_mld_log_links(sc);
    iwx_mld_emlsr_start(sc);
    return 0;
}

int ItlIwx::
iwx_mld_run_stop(struct iwx_softc *sc)
{
    struct iwx_node *in = (struct iwx_node *)sc->sc_ic.ic_bss;

    iwx_mld_emlsr_stop(sc);
    int err = iwx_flush_sta(sc, in);
    if (err) {
        iwx_mld_log_failure(sc, "run-stop", "tx-flush", err,
            IWX_TXPATH_FLUSH, -1);
        return err;
    }
    for (int i = 0; i < nitems(sc->sc_rxba_data); i++) {
        struct iwx_rxba_data *rxba = &sc->sc_rxba_data[i];
        if (rxba->baid == IWX_RX_REORDER_DATA_INVALID_BAID)
            continue;
        err = iwx_sta_rx_agg(sc, &in->in_ni, rxba->tid, 0, 0, 0, 0);
        if (err) {
            iwx_mld_log_failure(sc, "run-stop", "rx-ba-stop", err,
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
            iwx_mld_log_failure(sc, "run-stop", "link-tx-flush", err,
                IWX_TXPATH_FLUSH, i);
            return err;
        }
    }
    err = iwx_mld_mac_ctxt_cmd(sc, in, IWX_FW_CTXT_ACTION_MODIFY, 0);
    if (err)
        iwx_mld_log_failure(sc, "run-stop", "mac-deactivate", err,
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
            iwx_mld_log_failure(sc, "deauth", "protection-cancel",
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
            iwx_mld_log_failure(sc, "deauth", "mac-remove", err,
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
            iwx_mld_log_failure(sc, "deauth", "phy-remove", err,
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


