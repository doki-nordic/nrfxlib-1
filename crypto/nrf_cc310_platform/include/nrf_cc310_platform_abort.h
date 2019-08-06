/**
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */
#ifndef NRF_CC310_PLATFORM_ABORT_H__
#define NRF_CC310_PLATFORM_ABORT_H__

#ifdef __cplusplus
extern "C"
{
#endif

/** @brief Type definition of handle used for abort
 *
 * This handle could point to the thread or task to abort or any other
 * static memory required for aborting
 */
typedef void* nrf_cc310_platform_abort_handle_t;


/** @brief Type definition of platform abort function
 *
 * @note This function pointer will be used when the nrf_cc310_platform
 *       or dependant libraries raises an error that can't be recovered.
 */
typedef void (*nrf_cc310_platform_abort_fn_t)(char const * const reason);


/** @brief Type definition of structure holding platform abort APIs
 */
typedef struct nrf_cc310_platform_abort_apis_t
{
	nrf_cc310_platform_abort_handle_t	abort_handle;
	nrf_cc310_platform_abort_fn_t		abort_fn;

} nrf_cc310_platform_abort_apis_t;


/** @brief External reference to the platform abort APIs
 */
extern nrf_cc310_platform_abort_apis_t  platform_abort_apis;


/** @brief Function to set platform abort APIs
 *
 * @param[in]   apis    Pointer to platform APIs.
 */
void nrf_cc310_platform_set_abort(
	nrf_cc310_platform_abort_apis_t const * const apis);


/** @brief Function to initialize platform abort APIs
 *
 * @note This function must be called before calling @c nrf_cc310_platform_init
 * to replace the platform abort functionality.
 */
void nrf_cc310_platform_abort_init(void);


#ifdef __cplusplus
}
#endif

#endif /* NRF_CC310_PLATFORM_ABORT_H__ */
