/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NRF_RPC_TR_H_
#define NRF_RPC_TR_H_

#if defined(CONFIG_NRF_RPC_TR_RPMSG)

#include <nrf_rpc_rpmsg.h>

#elif defined(CONFIG_NRF_RPC_TR_CUSTOM)

#include CONFIG_NRF_RPC_TR_CUSTOM_INCLUDE

#else

#error No transport implementation selected for nRF RPC

#endif

#endif  /* NRF_RPC_TR_H_ */
