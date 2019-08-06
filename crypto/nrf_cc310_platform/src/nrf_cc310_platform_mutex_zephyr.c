/**
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */
#include <stdint.h>
#include <stddef.h>

#include "kernel.h"

#include "nrf_cc310_platform_defines.h"
#include "nrf_cc310_platform_mutex.h"


/** @brief Definition of mutex for symmetric cryptography
 */
K_MUTEX_DEFINE(sym_mutex);


/** @brief Definition of mutex for asymmetric cryptography
 */
K_MUTEX_DEFINE(asym_mutex);


/** @brief Definition of mutex for random number generation
*/
K_MUTEX_DEFINE(rng_mutex);


/** @brief Definition of mutex for threading operations
*/
K_MUTEX_DEFINE(thread_mutex);


/** @brief Definition of mutex for power mode changes
*/
K_MUTEX_DEFINE(power_mutex);


/**@brief static function to initialize a mutex
 */
static void mutex_init(void *mutex) {
	struct k_mutex * const p_mutex = (struct k_mutex *)mutex;
	k_mutex_init(p_mutex);
}


/** @brief Static function to free a mutex
 */
static void mutex_free(void *mutex) {
	(void)mutex;
}


/** @brief Static function to lock a mutex
 */
static int32_t mutex_lock(void *mutex) {
	int ret;
	struct k_mutex * const p_mutex = (struct k_mutex *)mutex;

	ret = k_mutex_lock(p_mutex, K_FOREVER);
	if (ret == 0) {
		return NRF_CC310_PLATFORM_SUCCESS;
	}
	else {
		return NRF_CC310_PLATFORM_ERROR_MUTEX_FAILED;
	}
}


/** @brief Static function to unlock a mutex
 */
static int32_t mutex_unlock(void *mutex) {
	struct k_mutex * const p_mutex = (struct k_mutex *)mutex;

	k_mutex_unlock(p_mutex);
	return NRF_CC310_PLATFORM_SUCCESS;
}

/**@brief Constant definition of mutex APIs to set in nrf_cc310_platform
 */
static const nrf_cc310_platform_mutex_apis_t mutex_apis =
{
	.mutex_init_fn = mutex_init,
	.mutex_free_fn = mutex_free,
	.mutex_lock_fn = mutex_lock,
	.mutex_unlock_fn = mutex_unlock
};


/** @brief Constant definition of mutexes to set in nrf_cc310_platform
 */
static const nrf_cc310_platform_mutexes_t mutexes =
{
	.sym_mutex = &sym_mutex,
	.asym_mutex = &asym_mutex,
	.rng_mutex = &rng_mutex,
	.reserved  = NULL,
	.thread_mutex = &thread_mutex,
	.power_mutex = &power_mutex,
};


int nrf_cc310_platform_mutex_init(void)
{
	nrf_cc310_platform_set_mutexes(&mutex_apis, &mutexes);
   	return NRF_CC310_PLATFORM_SUCCESS;
}
