/**
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */
#ifndef NRF_CC310_PLATFORM_ENTROPY_H__
#define NRF_CC310_PLATFORM_ENTROPY_H__

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

/** @brief Function that gives entropy from the platform
 *
 * @param[in]   data    Pointer to context structure for entropy get operation.
 * @param[in]   buffer  Pointer to buffer to hold entropy data.
 * @param[in]   length  Length of entropy to get.
 * @param[out]  olen    Length reported out.
 *
 * @return 0 on success, otherwise a non-zero failure.
 */
int nrf_cc310_platform_get_entropy(void *data,
				   uint8_t *buffer,
				   size_t length,
				   size_t* olen);

#ifdef __cplusplus
}
#endif

#endif /* NRF_CC310_PLATFORM_ENTROPY_H__ */
