/**
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */
#ifndef NRF_CC310_PLATFORM_DEFINES_H__
#define NRF_CC310_PLATFORM_DEFINES_H__

#ifdef __cplusplus
extern "C"
{
#endif

/** @brief Definition of work buffer used for rng initialization
 */
#define NRF_CC310_PLATFORM_WORKBUFF_SIZE_WORDS		(1528)

/** @brief max count of concurrent usage
 *
 *  @note The max value will never be reached.
 */
#define NRF_CC310_PLATFORM_USE_COUNT_MAX		(10)


#define NRF_CC310_PLATFORM_SUCCESS			(0)
#define NRF_CC310_PLATFORM_ERROR_PARAM_NULL		(-0x7001)
#define NRF_CC310_PLATFORM_ERROR_INTERNAL		(-0x7002)
#define NRF_CC310_PLATFORM_ERROR_RNG_INIT_FAILED	(-0x7003)
#define NRF_CC310_PLATFORM_ERROR_VERSION_FAILED		(-0x7004)
#define NRF_CC310_PLATFORM_ERROR_PARAM_WRITE_FAILED	(-0x7005)
#define NRF_CC310_PLATFORM_ERROR_MUTEX_FAILED		(-0x7016)

#ifdef __cplusplus
}
#endif

#endif /* NRF_CC310_PLATFORM_DEFINES_H__ */
