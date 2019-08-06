
/**
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */
#ifndef NRF_CC310_PLATFORM_MUTEX_H__
#define NRF_CC310_PLATFORM_MUTEX_H__

#include <stdint.h>
#include <stddef.h>

#include "nrf_cc310_platform_abort.h"

#ifdef __cplusplus
extern "C"
{
#endif


/** @brief Type definition of architecture neutral mutex type */
typedef void* nrf_cc310_platform_mutex_t;


/** @brief Type definition of function pointer to initialize a mutex
 *
 * Calling this function pointer should initialize a previously uninitialized
 * mutex or do nothing if the mutex is already initialized.
 *
 * @note Initialization may not imply memory allocation, as this can be done
 *       using static allocation through other APIs in the RTOS.
 *
 * @param[in]   mutex   Pointer to a mutex to initialize.
 */
typedef void (*nrf_cc310_platform_mutex_init_fn_t)(void *mutex);


/** @brief Type definition of function pointer to free a mutex
 *
 * Calling this function pointer should free a mutex.
 *
 * @note If the RTOS does not provide an API to free the mutex it is advised
 *       to reset the mutex to an initialized state with no owner.
 *
 * @param[in]   mutex   Pointer to a mutex to free.
 */
typedef void (*nrf_cc310_platform_mutex_free_fn_t)(void *mutex);


/** @brief Type definition of function pointer to lock a mutex
 *
 * Calling this function pointer should lock a mutex.
 *
 * @param[in]   mutex   Pointer to a mutex to lock.
 */
typedef int (*nrf_cc310_platform_mutex_lock_fn_t)(void *mutex);


/** @brief Type definition of function pointer to unlock a mutex
 *
 * Calling this function pointer should unlock a mutex.
 *
 * @param[in]   mutex   Pointer to a mutex to unlock.
 */
typedef int (*nrf_cc310_platform_mutex_unlock_fn_t)(void *mutex);


/**@brief Type definition of structure holding platform mutex APIs
 */
typedef struct nrf_cc310_platform_mutex_apis_t
{
	/* The platform mutex init function */
	nrf_cc310_platform_mutex_init_fn_t 	mutex_init_fn;

	/* The platform mutex free function */
	nrf_cc310_platform_mutex_free_fn_t	mutex_free_fn;

	/* The platform lock function */
	nrf_cc310_platform_mutex_lock_fn_t 	mutex_lock_fn;

	/* The platform unlock function */
	nrf_cc310_platform_mutex_unlock_fn_t 	mutex_unlock_fn;
} nrf_cc310_platform_mutex_apis_t;


/** @brief Type definition of structure to platform hw mutexes
 */
typedef struct nrf_cc310_platform_mutexes_t
{
	/* Mutex for symmetric operations. */
	void * sym_mutex;

	/* Mutex for asymetric operations. */
	void * asym_mutex;

	/* Mutex for rng operations. */
	void * rng_mutex;

	/* Mutex reserved for future use. */
	void * reserved;

	/* Mutex for threaded operations. */
	void * thread_mutex;

	/* Mutex for power mode changes */
	void * power_mutex;
} nrf_cc310_platform_mutexes_t;


/**@brief External reference to structure holding the currently set platform
 * mutexe APIs.
 */
extern nrf_cc310_platform_mutex_apis_t 	platform_mutex_apis;


/**@brief External reference to currently set platform hw mutexes */
extern nrf_cc310_platform_mutexes_t	platform_mutexes;


/** @brief Function to set platform mutex APIs and mutexes
 *
 * @param[in] apis              Structure holding the mutex APIs.
 * @param[in] mutexes           Structure holding the mutexes.
 */
void nrf_cc310_platform_set_mutexes(nrf_cc310_platform_mutex_apis_t const * const apis,
                                    nrf_cc310_platform_mutexes_t const * const mutexes);


/** @brief Function to initialize RTOS thread-safe mutexes
 *
 * This function must be implemented to set the platform mutex APIS,
 * platform mutexes and platform abort APIs.
 *
 * @return Zero on success, otherwise a non-zero error code.
 */
int nrf_cc310_platform_mutex_init(void);

#ifdef __cplusplus
}
#endif

#endif /* NRF_CC310_PLATFORM_MUTEX_H__ */
