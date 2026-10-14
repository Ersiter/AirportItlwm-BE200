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

// Command ABI from OpenBSD if_iwxreg.h revision 1.75 (2026-05-28).
#ifndef IF_IWX_MLD_H
#define IF_IWX_MLD_H

#define IWX_UCODE_TLV_CAPA_MLD_API_SUPPORT 110
#define IWX_MLD_RX_BAID_CONFIG_CMD 0x16
#define IWX_MLD_RLC_CONFIG_CMD 0x08

struct iwx_mld_rx_baid_cfg_cmd {
    uint32_t action;
    union {
        struct {
            uint32_t sta_id_mask;
            uint8_t tid;
            uint8_t reserved[3];
            uint16_t ssn;
            uint16_t win_size;
        } __packed alloc;
        struct {
            uint32_t sta_id_mask;
            uint32_t tid;
            uint32_t reserved;
        } __packed remove;
    };
} __packed;
static_assert(sizeof(iwx_mld_rx_baid_cfg_cmd) == 16, "MLD BAID v2 command ABI");

#define IWX_MLD_MAC_CONFIG_CMD 0x08
#define IWX_MLD_LINK_CONFIG_CMD 0x09
#define IWX_MLD_STA_CONFIG_CMD 0x0a
#define IWX_MLD_STA_REMOVE_CMD 0x0c
#define IWX_MLD_SCD_QUEUE_CONFIG_CMD 0x17
#define IWX_MLD_SEC_KEY_CMD 0x18
#define IWX_MLD_SCD_QUEUE_ADD 0
#define IWX_MLD_SCD_QUEUE_REMOVE 1
#define IWX_MLD_SCD_QUEUE_MODIFY 2

enum iwx_mld_mac_config_filter_flags {
	IWX_MLD_MAC_CFG_FILTER_PROMISC			= (1 << 0),
	IWX_MLD_MAC_CFG_FILTER_ACCEPT_CONTROL_AND_MGMT	= (1 << 1),
	IWX_MLD_MAC_CFG_FILTER_ACCEPT_GRP			= (1 << 2),
	IWX_MLD_MAC_CFG_FILTER_ACCEPT_BEACON		= (1 << 3),
	IWX_MLD_MAC_CFG_FILTER_ACCEPT_BCAST_PROBE_RESP	= (1 << 4),
	IWX_MLD_MAC_CFG_FILTER_ACCEPT_PROBE_REQ		= (1 << 5),
}; /* MAC_FILTER_FLAGS_MASK_E_VER_1 */

enum iwx_mld_link_ctx_modify_flags {
	IWX_MLD_LINK_CONTEXT_MODIFY_ACTIVE		= (1 << 0),
	IWX_MLD_LINK_CONTEXT_MODIFY_RATES_INFO	= (1 << 1),
	IWX_MLD_LINK_CONTEXT_MODIFY_PROTECT_FLAGS	= (1 << 2),
	IWX_MLD_LINK_CONTEXT_MODIFY_QOS_PARAMS	= (1 << 3),
	IWX_MLD_LINK_CONTEXT_MODIFY_BEACON_TIMING	= (1 << 4),
	IWX_MLD_LINK_CONTEXT_MODIFY_HE_PARAMS	= (1 << 5),
	IWX_MLD_LINK_CONTEXT_MODIFY_BSS_COLOR_DISABLE	= (1 << 6),
	IWX_MLD_LINK_CONTEXT_MODIFY_EHT_PARAMS	= (1 << 7),
	IWX_MLD_LINK_CONTEXT_MODIFY_ALL		= 0xff,
}; /* LINK_CONTEXT_MODIFY_MASK_E_VER_1 */

enum iwx_mld_link_ctx_protection_flags {
	IWX_MLD_LINK_PROT_FLG_TGG_PROTECT	= (1 << 0),
	IWX_MLD_LINK_PROT_FLG_HT_PROT	= (1 << 1),
	IWX_MLD_LINK_PROT_FLG_FAT_PROT	= (1 << 2),
	IWX_MLD_LINK_PROT_FLG_SELF_CTS_EN	= (1 << 3),
}; /* LINK_PROTECT_FLAGS_E_VER_1 */

enum iwx_mld_sec_key_flags {
	IWX_MLD_SEC_KEY_FLAG_CIPHER_MASK	= 0x07,
	IWX_MLD_SEC_KEY_FLAG_CIPHER_WEP	= 0x01,
	IWX_MLD_SEC_KEY_FLAG_CIPHER_CCMP	= 0x02,
	IWX_MLD_SEC_KEY_FLAG_CIPHER_TKIP	= 0x03,
	IWX_MLD_SEC_KEY_FLAG_CIPHER_GCMP	= 0x05,
	IWX_MLD_SEC_KEY_FLAG_NO_TX		= 0x08,
	IWX_MLD_SEC_KEY_FLAG_KEY_SIZE	= 0x10,
	IWX_MLD_SEC_KEY_FLAG_MFP		= 0x20,
	IWX_MLD_SEC_KEY_FLAG_MCAST_KEY	= 0x40,
	IWX_MLD_SEC_KEY_FLAG_SPP_AMSDU	= 0x80,
};

struct iwx_mld_mac_client_data {
	uint8_t is_assoc;
	uint8_t esr_transition_timeout;
	uint16_t medium_sync_delay;

	uint16_t assoc_id;
	uint16_t reserved1;
	uint16_t data_policy;
	uint16_t reserved2;
	uint32_t ctwin;
} __packed; /* MAC_CONTEXT_CONFIG_CLIENT_DATA_API_S_VER_2 */

struct iwx_mld_mac_p2p_dev_data {
	uint32_t is_disc_extended;
} __packed; /* MAC_CONTEXT_CONFIG_P2P_DEV_DATA_API_S_VER_1 */

struct iwx_mld_mac_config_cmd {
	/* COMMON_INDEX_HDR_API_S_VER_1 */
	uint32_t id_and_color;
	uint32_t action;
	/* MAC_CONTEXT_TYPE_API_E */
	uint32_t mac_type;
	uint8_t local_mld_addr[6];
	uint16_t reserved_for_local_mld_addr;
	uint32_t filter_flags;
	uint16_t he_support;
	uint16_t he_ap_support;
	uint32_t eht_support;
	uint32_t nic_not_ack_enabled;
	/* MAC_CONTEXT_CONFIG_SPECIFIC_DATA_API_U_VER_2 */
	union {
		struct iwx_mld_mac_client_data client;
		struct iwx_mld_mac_p2p_dev_data p2p_dev;
	};
} __packed; /* MAC_CONTEXT_CONFIG_CMD_API_S_VER_2 */

struct iwx_mld_he_backoff_conf {
	uint16_t cwmin;
	uint16_t cwmax;
	uint16_t aifsn;
	uint16_t mu_time;
} __packed; /* AC_QOS_DOT11AX_API_S */

struct iwx_mld_link_config_cmd {
	uint32_t action;
	uint32_t link_id;
	uint32_t mac_id;
	uint32_t phy_id;
	uint8_t local_link_addr[6];
	uint16_t reserved_for_local_link_addr;
	uint32_t modify_mask;
	uint32_t active;
	uint32_t listen_lmac;
	uint32_t cck_rates;
	uint32_t ofdm_rates;
	uint32_t cck_short_preamble;
	uint32_t short_slot;
	uint32_t protection_flags;
	/* MAC_QOS_PARAM_API_S_VER_1 */
	uint32_t qos_flags;
	struct iwx_ac_qos ac[IWX_AC_NUM + 1];
	uint8_t htc_trig_based_pkt_ext;
	uint8_t rand_alloc_ecwmin;
	uint8_t rand_alloc_ecwmax;
	uint8_t ndp_fdbk_buff_th_exp;
	struct iwx_mld_he_backoff_conf trig_based_txf[IWX_AC_NUM];
	uint32_t bi;
	uint32_t dtim_interval;
	uint16_t puncture_mask;
	uint16_t frame_time_rts_th;
	uint32_t flags;
	uint32_t flags_mask;
	/* The below fields are for multi-bssid */
	uint8_t ref_bssid_addr[6];
	uint16_t reserved_for_ref_bssid_addr;
	uint8_t bssid_index;
	uint8_t bss_color;
	uint8_t spec_link_id;
	uint8_t reserved;
	uint8_t ibss_bssid_addr[6];
	uint16_t reserved_for_ibss_bssid_addr;
	uint32_t reserved1[8];
} __packed; /* LINK_CONTEXT_CONFIG_CMD_API_S_VER_1 */

struct iwx_mld_he_pkt_ext_v2 {
	uint8_t pkt_ext_qam_th[2][5][2];
} __packed; /* PKT_EXT_DOT11AX_API_S_VER_2 */

struct iwx_mld_mvm_sta_cfg_cmd {
	uint32_t sta_id;
	uint32_t link_id;
	uint8_t peer_mld_address[6];
	uint16_t reserved_for_peer_mld_address;
	uint8_t peer_link_address[6];
	uint16_t reserved_for_peer_link_address;
	uint32_t station_type;
	uint32_t assoc_id;
	uint32_t beamform_flags;
	uint32_t mfp;
	uint32_t mimo;
	uint32_t mimo_protection;
	uint32_t ack_enabled;
	uint32_t trig_rnd_alloc;
	uint32_t tx_ampdu_spacing;
	uint32_t tx_ampdu_max_size;
	uint32_t sp_length;
	uint32_t uapsd_acs;
	struct iwx_mld_he_pkt_ext_v2 pkt_ext;
	uint32_t htc_flags;
} __packed; /* STA_CMD_API_S_VER_1 */

struct iwx_mld_sta_cfg_cmd_v2 {
	uint32_t sta_id;
	uint32_t link_id;
	uint8_t peer_mld_address[ETHER_ADDR_LEN];
	uint16_t reserved_for_peer_mld_address;
	uint8_t peer_link_address[ETHER_ADDR_LEN];
	uint16_t reserved_for_peer_link_address;
	uint32_t station_type;
	uint32_t assoc_id;
	uint32_t beamform_flags;
	uint32_t mfp;
	uint32_t mimo;
	uint32_t mimo_protection;
	uint32_t ack_enabled;
	uint32_t trig_rnd_alloc;
	uint32_t tx_ampdu_spacing;
	uint32_t tx_ampdu_max_size;
	uint32_t sp_length;
	uint32_t uapsd_acs;
	struct iwx_mld_he_pkt_ext_v2 pkt_ext;
	uint32_t htc_flags;
	uint8_t use_ldpc_x2_cw;
	uint8_t use_icf;
	uint8_t dps_pad_time;
	uint8_t dps_trans_delay;
	uint8_t mic_prep_pad_delay;
	uint8_t mic_compute_pad_delay;
	uint8_t reserved[2];
} __packed; /* STA_CMD_API_S_VER_2 */

struct iwx_mld_mvm_remove_sta_cmd {
	uint32_t sta_id;
} __packed; /* REMOVE_STA_API_S_VER_1 */

struct iwx_mld_scd_queue_cfg_cmd {
	uint32_t operation;
	union {
		struct {
			uint32_t sta_mask;
			uint8_t tid;
			uint8_t reserved[3];
			uint32_t flags;
			uint32_t cb_size;
			uint64_t bc_dram_addr;
			uint64_t tfdq_dram_addr;
		} __packed add; /* TX_QUEUE_CFG_CMD_ADD_API_S_VER_1 */
		struct {
			uint32_t sta_mask;
			uint32_t tid;
		} __packed remove; /* TX_QUEUE_CFG_CMD_REMOVE_API_S_VER_1 */
		struct {
			uint32_t old_sta_mask;
			uint32_t tid;
			uint32_t new_sta_mask;
		} __packed modify; /* TX_QUEUE_CFG_CMD_MODIFY_API_S_VER_1 */
	} __packed u; /* TX_QUEUE_CFG_CMD_OPERATION_API_U_VER_1 */
} __packed; /* TX_QUEUE_CFG_CMD_API_S_VER_3 */

struct iwx_mld_sec_key_cmd {
	uint32_t action;
	union {
		struct {
			uint32_t sta_mask;
			uint32_t key_id;
			uint32_t key_flags;
			uint8_t key[32];
			uint8_t tkip_mic_rx_key[8];
			uint8_t tkip_mic_tx_key[8];
			uint64_t rx_seq;
			uint64_t tx_seq;
		} __packed add; /* SEC_KEY_ADD_CMD_API_S_VER_1 */
		struct {
			uint32_t old_sta_mask;
			uint32_t new_sta_mask;
			uint32_t key_id;
			uint32_t key_flags;
		} __packed modify; /* SEC_KEY_MODIFY_CMD_API_S_VER_1 */
		struct {
			uint32_t sta_mask;
			uint32_t key_id;
			uint32_t key_flags;
		} __packed remove; /* SEC_KEY_REMOVE_CMD_API_S_VER_1 */
	} __packed u; /* SEC_KEY_OPERATION_API_U_VER_1 */
} __packed; /* SEC_KEY_CMD_API_S_VER_1 */

static_assert(sizeof(iwx_mld_mac_config_cmd) == 52, "MLD MAC command ABI");
static_assert(sizeof(iwx_mld_link_config_cmd) == 208, "MLD LINK command ABI");
static_assert(sizeof(iwx_mld_mvm_sta_cfg_cmd) == 96, "MLD STA v1 command ABI");
static_assert(sizeof(iwx_mld_sta_cfg_cmd_v2) == 104, "MLD STA v2 command ABI");
static_assert(sizeof(iwx_mld_scd_queue_cfg_cmd) == 36, "MLD SCD v3 command ABI");
static_assert(sizeof(iwx_mld_sec_key_cmd) == 80, "MLD SEC_KEY v1 command ABI");

#endif
