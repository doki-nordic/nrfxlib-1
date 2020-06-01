/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */


#ifndef _NRF_RPC_INTERNAL_H_
#define _NRF_RPC_INTERNAL_H_

#include <nrf_rpc_common.h>
#include <nrf_rpc_tr.h>


/**
 * @defgroup nrf_rpc_internal nRF RPC internal declarations.
 * @{
 * @ingroup nrf_rpc
 *
 * @brief Internals for nRF RPC.
 */


#ifdef __cplusplus
extern "C" {
#endif


/* Internal definition used in the macros. */
#define _NRF_RPC_HEADER_SIZE 2

/* Forward declarations. */
struct nrf_rpc_group;
struct nrf_rpc_tr_remote_ep;

/* Internal functions used by the macros only. */
struct nrf_rpc_tr_remote_ep *_nrf_rpc_cmd_prep(
	const struct nrf_rpc_group *group);
void _nrf_rpc_cmd_alloc_error(struct nrf_rpc_tr_remote_ep *tr_remote_ep);
void _nrf_rpc_cmd_unprep(void);
struct nrf_rpc_tr_remote_ep *_nrf_rpc_evt_prep(
	const struct nrf_rpc_group *group);
void _nrf_rpc_evt_alloc_error(struct nrf_rpc_tr_remote_ep *tr_remote_ep);
void _nrf_rpc_evt_unprep(struct nrf_rpc_tr_remote_ep *tr_remote_ep);
struct nrf_rpc_tr_remote_ep *_nrf_rpc_rsp_prep();


/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* _NRF_RPC_INTERNAL_H_ */
