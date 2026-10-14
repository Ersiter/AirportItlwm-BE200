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

void ItlIwx::
iwx_mld_modify_link_fill(struct iwx_softc *sc, struct iwx_node *in,
    struct iwx_mld_link_config_cmd *cmd, int changes, int active)
{
#define IWX_EXP2(x)    ((1 << (x)) - 1)    /* CWmin = 2^ECWmin - 1 */
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = &in->in_ni;
    int cck_ack_rates, ofdm_ack_rates;
    int i;

    cmd->link_id = htole32(0);
    cmd->mac_id = htole32(in->in_id);
    KASSERT(in->in_phyctxt, "MLD link requires a PHY context");
    cmd->phy_id = htole32(in->in_phyctxt->id);
    IEEE80211_ADDR_COPY(cmd->local_link_addr, ic->ic_myaddr);
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

    cmd->bi = htole32(ni->ni_intval);
    cmd->dtim_interval = htole32(ni->ni_intval * ni->ni_dtimperiod);

    cmd->modify_mask = htole32(changes);
    cmd->flags = 0;
    cmd->flags_mask = 0;
    cmd->spec_link_id = 0;
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
    int err, changes;

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
            DEVNAME(sc), cmd_ver);
        return ENOTSUP;
    }

    if (ic->ic_opmode != IEEE80211_M_STA ||
        (in->in_ni.ni_flags & (IEEE80211_NODE_MFP | IEEE80211_NODE_HE)))
        return ENOTSUP;

    if (!update && !sc->sc_mld_link_active) {
        memset(&link_cmd, 0, sizeof(link_cmd));
        link_cmd.link_id = htole32(0);
        link_cmd.mac_id = htole32(in->in_id);
        link_cmd.spec_link_id = 0;
        if (in->in_phyctxt)
            link_cmd.phy_id = htole32(in->in_phyctxt->id);
        else
            link_cmd.phy_id = htole32(IWX_FW_CTXT_INVALID);
        IEEE80211_ADDR_COPY(link_cmd.local_link_addr, ic->ic_myaddr);
        link_cmd.listen_lmac = 0;
        link_cmd.action = IWX_FW_CTXT_ACTION_ADD;

        err = iwx_send_cmd_pdu(sc,
            IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_LINK_CONFIG_CMD),
            0, sizeof(link_cmd), &link_cmd);
        if (err)
            return err;
        sc->sc_mld_link_active = 1;
    }

    changes = IWX_MLD_LINK_CONTEXT_MODIFY_ACTIVE;
    changes |= IWX_MLD_LINK_CONTEXT_MODIFY_RATES_INFO;
    if (update) {
        changes |= IWX_MLD_LINK_CONTEXT_MODIFY_PROTECT_FLAGS;
        changes |= IWX_MLD_LINK_CONTEXT_MODIFY_QOS_PARAMS;
        changes |= IWX_MLD_LINK_CONTEXT_MODIFY_BEACON_TIMING;
    }

    memset(&link_cmd, 0, sizeof(link_cmd));
    iwx_mld_modify_link_fill(sc, in, &link_cmd, changes, 1);
    err = iwx_send_cmd_pdu(sc,
        IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_LINK_CONFIG_CMD),
        0, sizeof(link_cmd), &link_cmd);
    if (err)
        return err;

    memset(&sta_cmd, 0, sizeof(sta_cmd));
    sta_cmd.sta_id = htole32(IWX_STATION_ID);
    sta_cmd.station_type = htole32(IWX_STA_LINK);
    sta_cmd.link_id = htole32(0);
    IEEE80211_ADDR_COPY(sta_cmd.peer_mld_address, in->in_macaddr);
    IEEE80211_ADDR_COPY(sta_cmd.peer_link_address, in->in_macaddr);
    sta_cmd.assoc_id = htole32(IEEE80211_AID(in->in_ni.ni_associd));

    if (in->in_ni.ni_flags & IEEE80211_NODE_HT) {
        if (iwx_mimo_enabled(sc) && in->in_ni.ni_rx_nss > 1)
            sta_cmd.mimo = htole32(1);

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
        if (aggsize > max_aggsize)
            aggsize = max_aggsize;

        sta_cmd.tx_ampdu_spacing = htole32(mpdu_dens);
        sta_cmd.tx_ampdu_max_size = htole32(aggsize);
    }

    err = iwx_send_cmd_pdu(sc,
        IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_STA_CONFIG_CMD),
        0, cmd_size, &sta_cmd);
    if (!err)
        sc->sc_flags |= IWX_FLAG_STA_ACTIVE;
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
    cmd.client.assoc_id = htole16(IEEE80211_AID(ni->ni_associd));
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
iwx_mld_queue_cmd(struct iwx_softc *sc, int sta_id, int tid, int remove,
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
        IWX_MLD_SCD_QUEUE_CONFIG_CMD) != 3)
        return ENOTSUP;
    if (sta_id != IWX_STATION_ID || tid < 0 || tid > IWX_MGMT_TID)
        return EINVAL;
    if (!remove && (!num_slots || (num_slots & (num_slots - 1))))
        return EINVAL;

    memset(&cmd, 0, sizeof(cmd));
    if (remove) {
        cmd.operation = htole32(IWX_MLD_SCD_QUEUE_REMOVE);
        cmd.u.remove.sta_mask = htole32(1U << sta_id);
        cmd.u.remove.tid = htole32(tid);
    } else {
        cmd.operation = htole32(IWX_MLD_SCD_QUEUE_ADD);
        cmd.u.add.sta_mask = htole32(1U << sta_id);
        cmd.u.add.tid = tid;
        cmd.u.add.cb_size = htole32(IWX_TFD_QUEUE_CB_SIZE(num_slots));
        cmd.u.add.tfdq_dram_addr = htole64(tfd_addr);
        cmd.u.add.bc_dram_addr = htole64(bc_addr);
    }
    hcmd.len[0] = sizeof(cmd);
    hcmd.data[0] = &cmd;
    err = iwx_send_cmd(sc, &hcmd);
    if (err)
        return err;

    struct iwx_rx_packet *pkt = hcmd.resp_pkt;
    if (!pkt || (pkt->hdr.group_id & IWX_CMD_FAILED_MSK) ||
        iwx_rx_packet_payload_len(pkt) != sizeof(struct iwx_tx_queue_cfg_rsp)) {
        err = EIO;
    } else {
        struct iwx_tx_queue_cfg_rsp *resp = (struct iwx_tx_queue_cfg_rsp *)pkt->data;
        if (le16toh(resp->flags)) {
            err = EIO;
        } else if (remove) {
            sc->sc_mld_txq_tidmask &= ~(1U << tid);
        } else {
            *qid = le16toh(resp->queue_number);
            *write_pointer = le16toh(resp->write_pointer);
            sc->sc_mld_txq_tidmask |= (1U << tid);
        }
    }
    iwx_free_resp(sc, &hcmd);
    return err;
}

int ItlIwx::
iwx_mld_set_key(struct iwx_softc *sc, struct ieee80211_node *ni,
    struct ieee80211_key *k, int remove)
{
    struct iwx_mld_sec_key_cmd cmd;
    uint32_t flags = IWX_MLD_SEC_KEY_FLAG_CIPHER_CCMP;
    int err;

    if (iwx_lookup_cmd_ver(sc, IWX_DATA_PATH_GROUP, IWX_MLD_SEC_KEY_CMD) != 1)
        return ENOTSUP;
    if (k->k_cipher != IEEE80211_CIPHER_CCMP || k->k_len != 16 ||
        (k->k_flags & IEEE80211_KEY_IGTK) || (ni->ni_flags & IEEE80211_NODE_MFP))
        return ENOTSUP;
    if (!(sc->sc_flags & IWX_FLAG_STA_ACTIVE))
        return remove ? 0 : ENXIO;
    if (k->k_flags & IEEE80211_KEY_GROUP)
        flags |= IWX_MLD_SEC_KEY_FLAG_MCAST_KEY;
    memset(&cmd, 0, sizeof(cmd));
    cmd.action = htole32(remove ? IWX_FW_CTXT_ACTION_REMOVE : IWX_FW_CTXT_ACTION_ADD);
    cmd.u.add.sta_mask = htole32(1U << IWX_STATION_ID);
    cmd.u.add.key_id = htole32(k->k_id);
    cmd.u.add.key_flags = htole32(flags);
    cmd.u.add.tx_seq = htole64(k->k_tsc);
    memcpy(cmd.u.add.key, k->k_key, k->k_len);

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

int ItlIwx::
iwx_mld_rm_sta_cmd(struct iwx_softc *sc, struct iwx_node *in)
{
    struct iwx_mld_mvm_remove_sta_cmd sta_cmd;
    struct iwx_mld_link_config_cmd link_cmd;
    int err;
    int version = iwx_lookup_cmd_ver(sc, IWX_MAC_CONF_GROUP, IWX_MLD_STA_REMOVE_CMD);
    if (version != 1 && version != IWX_FW_CMD_VER_UNKNOWN)
        return ENOTSUP;

    if (sc->sc_flags & IWX_FLAG_STA_ACTIVE) {
        err = iwx_flush_sta(sc, in);
        if (err)
            return err;
        for (int tid = 0; tid <= IWX_MGMT_TID; tid++) {
            if (!(sc->sc_mld_txq_tidmask & (1U << tid)))
                continue;
            err = iwx_mld_queue_cmd(sc, IWX_STATION_ID, tid, 1, 0, 0, 0, NULL, NULL);
            if (err)
                return err;
        }
        memset(&sta_cmd, 0, sizeof(sta_cmd));
        sta_cmd.sta_id = htole32(IWX_STATION_ID);
        err = iwx_send_cmd_pdu(sc,
            IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_STA_REMOVE_CMD),
            0, sizeof(sta_cmd), &sta_cmd);
        if (err)
            return err;
        sc->sc_flags &= ~IWX_FLAG_STA_ACTIVE;
    }
    if (!sc->sc_mld_link_active)
        return 0;
    memset(&link_cmd, 0, sizeof(link_cmd));
    iwx_mld_modify_link_fill(sc, in, &link_cmd, IWX_MLD_LINK_CONTEXT_MODIFY_ACTIVE, 0);
    err = iwx_send_cmd_pdu(sc,
        IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_LINK_CONFIG_CMD),
        0, sizeof(link_cmd), &link_cmd);
    if (err)
        return err;
    memset(&link_cmd, 0, sizeof(link_cmd));
    link_cmd.action = htole32(IWX_FW_CTXT_ACTION_REMOVE);
    err = iwx_send_cmd_pdu(sc,
        IWX_WIDE_ID(IWX_MAC_CONF_GROUP, IWX_MLD_LINK_CONFIG_CMD),
        0, sizeof(link_cmd), &link_cmd);
    if (!err)
        sc->sc_mld_link_active = 0;
    return err;
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
        (link_version != 1 && link_version != IWX_FW_CMD_VER_UNKNOWN) ||
        !isset(sc->sc_enabled_capa, IWX_UCODE_TLV_CAPA_SESSION_PROT_CMD))
        return ENOTSUP;
    if (sc->sc_mld_phy_active || (sc->sc_flags & IWX_FLAG_MAC_ACTIVE))
        return EBUSY;

    in->in_ni.ni_chw = IEEE80211_CHAN_WIDTH_20_NOHT;
    in->in_ni.ni_flags &= ~(IEEE80211_NODE_HT | IEEE80211_NODE_QOS |
        IEEE80211_NODE_HT_SGI20 | IEEE80211_NODE_HT_SGI40 |
        IEEE80211_NODE_VHT | IEEE80211_NODE_VHT_SGI80 |
        IEEE80211_NODE_VHT_SGI160 | IEEE80211_NODE_HE);
    in->in_phyctxt = &sc->sc_phyctxt[0];
    in->in_phyctxt->channel = in->in_ni.ni_chan;
    IEEE80211_ADDR_COPY(in->in_macaddr, in->in_ni.ni_macaddr);
    err = iwx_phy_ctxt_cmd(sc, in->in_phyctxt, 1, 1, IWX_FW_CTXT_ACTION_ADD, 0);
    if (err)
        return err;
    sc->sc_mld_phy_active = 1;
    err = iwx_mld_mac_ctxt_cmd(sc, in, IWX_FW_CTXT_ACTION_ADD, 0);
    if (err)
        goto fail;
    sc->sc_flags |= IWX_FLAG_MAC_ACTIVE;
    err = iwx_mld_add_sta_cmd(sc, in, 0);
    if (err)
        goto fail;
    err = iwx_enable_mgmt_queue(sc);
    if (err)
        goto fail;
    duration = in->in_ni.ni_intval ? in->in_ni.ni_intval * 2 : IEEE80211_DUR_TU;
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
                DEVNAME(sc), cleanup_err, err);
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
        (in->in_ni.ni_flags & (IEEE80211_NODE_MFP | IEEE80211_NODE_HE)) ||
        in->in_ni.ni_chw == IEEE80211_CHAN_WIDTH_80P80)
        return ENOTSUP;
    err = iwx_phy_ctxt_update(sc, in->in_phyctxt, in->in_ni.ni_chan, chains, chains, 0);
    if (err)
        return err;
    err = iwx_mld_mac_ctxt_cmd(sc, in, IWX_FW_CTXT_ACTION_MODIFY, 1);
    if (err)
        return err;
    err = iwx_mld_add_sta_cmd(sc, in, 1);
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
    in->in_ni.ni_txrate = 0;
    in->in_ni.ni_txmcs = 0;
    return iwx_rs_init(sc, in, true);
}

int ItlIwx::
iwx_mld_run_stop(struct iwx_softc *sc)
{
    struct iwx_node *in = (struct iwx_node *)sc->sc_ic.ic_bss;
    int err = iwx_flush_sta(sc, in);
    if (err)
        return err;
    for (int i = 0; i < nitems(sc->sc_rxba_data); i++) {
        struct iwx_rxba_data *rxba = &sc->sc_rxba_data[i];
        if (rxba->baid == IWX_RX_REORDER_DATA_INVALID_BAID)
            continue;
        err = iwx_sta_rx_agg(sc, &in->in_ni, rxba->tid, 0, 0, 0, 0);
        if (err)
            return err;
    }
    return iwx_mld_mac_ctxt_cmd(sc, in, IWX_FW_CTXT_ACTION_MODIFY, 0);
}

int ItlIwx::
iwx_mld_deauth(struct iwx_softc *sc)
{
    struct iwx_node *in = (struct iwx_node *)sc->sc_ic.ic_bss;
    int err;
    int generation = sc->sc_generation;
    if (sc->sc_flags & IWX_FLAG_TE_ACTIVE) {
        err = iwx_cancel_session_protection(sc, in);
        if (err)
            return err;
        sc->sc_flags &= ~IWX_FLAG_TE_ACTIVE;
    }
    err = iwx_mld_rm_sta_cmd(sc, in);
    if (err)
        return err;
    if (generation != sc->sc_generation)
        return ENXIO;
    if (sc->sc_flags & IWX_FLAG_MAC_ACTIVE) {
        err = iwx_mld_mac_ctxt_cmd(sc, in, IWX_FW_CTXT_ACTION_REMOVE, 0);
        if (err)
            return err;
        sc->sc_flags &= ~IWX_FLAG_MAC_ACTIVE;
    }
    if (sc->sc_mld_phy_active) {
        err = iwx_phy_ctxt_cmd(sc, in->in_phyctxt, 1, 1, IWX_FW_CTXT_ACTION_REMOVE, 0);
        if (err)
            return err;
        sc->sc_mld_phy_active = 0;
    }
    sc->sc_rx_ba_sessions = 0;
    sc->ba_rx.start_tidmask = 0;
    sc->ba_rx.stop_tidmask = 0;
    sc->ba_tx.start_tidmask = 0;
    sc->ba_tx.stop_tidmask = 0;
    return 0;
}


