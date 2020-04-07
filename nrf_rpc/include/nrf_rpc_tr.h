/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef RP_TRANS_H_
#define RP_TRANS_H_

#if defined(CONFIG_NRF_RPC_TR_RPMSG)

#include <nrf_rpc_rpmsg.h>

#endif  /* CONFIG_RMPSG_TRANSPORT */

#if defined(CONFIG_NRF_RPC_TR_CUSTOM)

#include CONFIG_NRF_RPC_TR_CUSTOM

#endif  /* CONFIG_NRF_RPC_TR_CUSTOM */

#endif  /* RP_TRANS_H_ */
