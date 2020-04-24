/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NRF_RPC_ERRORS_H_
#define NRF_RPC_ERRORS_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup nrf_rpc_errors Error codes for nRF RPC
 * @{
 * @ingroup nrf_rpc
 *
 * @brief Error codes for nRF RPC.
 */

enum nrf_rpc_error_code {
	NRF_RPC_SUCCESS            = 0,
	NRF_RPC_ERR_NO_MEM         = -1,
	NRF_RPC_ERR_INVALID_PARAM  = -2,
	NRF_RPC_ERR_NULL           = -3,
	NRF_RPC_ERR_NOT_SUPPORTED  = -4,
	NRF_RPC_ERR_INTERNAL       = -5,
	NRF_RPC_ERR_OS_ERROR       = -6,
	NRF_RPC_ERR_INVALID_STATE  = -7,
	NRF_RPC_ERR_REMOTE         = -8,
};

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* NRF_RPC_ERRORS_H_ */
