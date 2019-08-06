/**
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */
#ifndef NRF_CC310_PLATFORM_H__
#define NRF_CC310_PLATFORM_H__

#include <stdint.h>
#include <stddef.h>

#include "nrf_cc310_platform_defines.h"
#include "nrf_cc310_platform_abort.h"
#include "nrf_cc310_platform_mutex.h"

#ifdef __cplusplus
extern "C"
{
#endif


/** @brief Type definition of structure holding an RNG workbuffer.
 */
typedef struct nrf_cc310_platform_rng_workbuf_t
{
	uint32_t buffer[NRF_CC310_PLATFORM_WORKBUFF_SIZE_WORDS];
} nrf_cc310_platform_rng_workbuf_t;


/**@brief Function to initialize the Arm CC310 platform with rng support
 *
 * @param[in] rng_workbuf  Pointer to buffer used for RNG. Must not be NULL.
 *
 * @return Zero on success, otherwise a non-zero error code.
 */
int nrf_cc310_platform_init(nrf_cc310_platform_rng_workbuf_t * rng_workbuf);


/**@brief Function to initialize the Arm CC310 platform without rng support
 *
 * @return Zero on success, otherwise a non-zero error code.
 */
int nrf_cc310_platform_init_no_rng(void);


/** @brief Function to deintialize the Arm CC310 platform
 *
 * @return Zero on success, otherwise a non-zero error code.
 */
int nrf_cc310_platform_deinit(void);


#ifdef __cplusplus
}
#endif

#endif /* NRF_CC310_PLATFORM_H__ */
