/*	$OpenBSD: if_iwxreg.h,v 1.75 2026/05/28 10:51:52 kirill Exp $	*/

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


#ifndef IF_IWXAPI86_H
#define IF_IWXAPI86_H

struct iwx_api86_scan_channel {
    uint32_t flags;
    uint8_t channel_num;
    uint8_t psd_20;
    uint8_t iter_count;
    uint8_t iter_interval;
} __packed;

struct iwx_api86_scan_general {
    uint16_t flags;
    uint8_t reserved;
    uint8_t scan_start_mac_or_link_id;
    uint8_t active_dwell[IWX_SCAN_TWO_LMACS];
    uint8_t adwell_default_2g;
    uint8_t adwell_default_5g;
    uint8_t adwell_default_social_chn;
    uint8_t flags2;
    uint16_t adwell_max_budget;
    uint32_t max_out_of_time[IWX_SCAN_TWO_LMACS];
    uint32_t suspend_time[IWX_SCAN_TWO_LMACS];
    uint32_t scan_priority;
    uint8_t passive_dwell[IWX_SCAN_TWO_LMACS];
    uint8_t num_of_fragments[IWX_SCAN_TWO_LMACS];
} __packed;

struct iwx_api86_scan_channels {
    uint8_t flags;
    uint8_t count;
    uint8_t n_aps_override[2];
    struct iwx_api86_scan_channel channel_config[67];
} __packed;

struct iwx_api86_scan_req {
    uint32_t uid;
    uint32_t ooc_priority;
    struct {
        struct iwx_api86_scan_general general_params;
        struct iwx_api86_scan_channels channel_params;
        struct iwx_scan_periodic_parms_v1 periodic_params;
        struct iwx_scan_probe_params_v4 probe_params;
    } __packed scan_params;
} __packed;

static_assert(sizeof(iwx_api86_scan_channel) == 8, "scan v17 channel wire size");
static_assert(sizeof(iwx_api86_scan_general) == 36, "scan v17 general wire size");
static_assert(sizeof(iwx_api86_scan_channels) == 540, "scan v17 channel array wire size");

#endif
