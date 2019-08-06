/**
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */
#include <stdint.h>
#include <stddef.h>

#include "semphr.h"

#include "nrf_cc310_platform_defines.h"
#include "nrf_cc310_platform_mutex.h"


/** @brief Definition of mutex for symmetric cryptography
 */
static SemaphoreHandle_t sym_mutex;


/** @brief Definition of mutex for asymmetric cryptography
 */
static SemaphoreHandle_t asym_mutex;


/** @brief Definition of mutex for random number generation
 */
static SemaphoreHandle_t rng_mutex;


/** @brief Definition of mutex for threading operations
 */
static SemaphoreHandle_t thread_mutex;


/** @brief Definition of mutex for power management changes
 */
static SemaphoreHandle_t power_mutex;


/** @brief Static function to unlock a mutex
 */
static void mutex_init(void *mutex)
{
	*mutex = (void*)xSemaphoreCreateMutex();
	if (*mutex == NULL) {
		platform_abort_apis.abort_fn();
	}
}


/** @brief Static function to free a mutex
 */
static void mutex_free(void *mutex)
{
	int ret;
	SemaphoreHandle_t *p_mutex = (SemaphoreHandle_t*) mutex;

	ret = xSemaphoreDelete(*p_mutex);
	if (ret != 0) {
		platform_abort_apis.abort_fn();
	}
}


/** @brief Static function to lock a mutex
 */
static int32_t mutex_lock(void *mutex)
{
	int ret;
	SemaphoreHandle_t *p_mutex = (SemaphoreHandle_t*) mutex;
	ret = xSemaphoreTake(*p_mutex, MAX_DELAY)
	if (ret == pdTRUE) {
		return NRF_CC310_PLATFORM_SUCCESS;
	}
	else {
		return NRF_CC310_PLATFORM_ERROR_MUTEX_FAILED;
	}
}


/** @brief Static function to unlock a mutex
 */
static void mutex_unlock(void * mutex)
{
	int ret;
	SemaphoreHandle_t *p_mutex = (SemaphoreHandle_t*) mutex;
	ret = xSemaphoreGive(*p_mutex);
	if (ret != pdTRUE) {
		platform_abort_apis.abort_fn();
	}
}


/**@brief Constant definition of mutex APIs to set in nrf_cc310_platform
 */
const nrf_cc310_platform_mutex_apis_t mutex_apis =
{
	.mutex_init_fn = mutex_init,
	.mutex_free_fn = mutex_free,
	.mutex_lock_fn = mutex_lock,
	.mutex_unlock_fn = mutex_unlock
};


/** @brief Constant definition of mutexes to set in nrf_cc310_platform
 */
const nrf_cc310_platform_mutexes_t mutexes =
{
	.sym_mutex = &sym_mutex,
	.asym_mutex = &asym_mutex,
	.rng_mutex = &rng_mutex,
	.reserved = NULL,
	.thread_mutex = &thread_mutex,
	.power_mutex = &power_mutex
};


int nrf_cc310_platform_mutex_init(void)
{
	nrf_cc310_platform_set_mutexes(&mutex_apis, &mutexes);
	return NRF_CC310_PLATFORM_SUCCESS;
}