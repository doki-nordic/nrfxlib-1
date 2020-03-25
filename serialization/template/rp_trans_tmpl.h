/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This is a template for rp_tran API. It can be user as a starting point to
 * implement a new transport. All transports must have API compatible to
 * this one. Small changes are allowed that does not break compatibility, e.g.
 * convert some function to function-like macros.
 *
 * It also contains documentation of the rp_trans API. Transports do not need
 * to duplicate this documentation.
 */

#ifndef RP_TRANS_TMPL_H_
#define RP_TRANS_TMPL_H_

#include <stdint.h>
#include <stddef.h>


/**
 * @file
 * @defgroup rp_transport Remote procedures transport
 * @{
 * @brief Remote procedures serialization transport API.
 */


#ifdef __cplusplus
extern "C" {
#endif


/** @brief Structure to hold and identify transport endpoint.
 *
 * Content is implementation specific.
 */
struct rp_trans_endpoint {
	void *_implementation_specific;
};


/** @brief Prepares data for transport endpoint
 *
 * @param _name       Name of the transport endpoint
 * @param _stack_size Stack size of the thread controling the endpoint (ignored
 *                    if implementation does not create a thread stack)
 * @param _prio       Priority of the thread controling the endpoint (ignored
 *                    if implementation does not set a thread priority)
 */
#define RP_TRANS_ENDPOINT_PREPARE(_name, _stack_size, _prio)

/** @brief Initializer for rp_trans_endpoint structure.
 *
 * Data for this initialized had to be prepared before with @a RP_TRANS_ENDPOINT
 * macro.
 * @param _name       Name of the transport endpoint
 */
#define RP_TRANS_ENDPOINT_INITIALIZER(_name)


/** @brief Callback called from endpoint's rx thread when a new packet arrived.
 * 
 * When the buffer is not needed callback must release it with
 * @a rp_trans_release_buffer.
 *
 * @param endpoint endpoint at which a new packet arrived
 * @param buf      data buffer with the packet or NULL if at least one packet
 *                 was filtered out
 * @param length   size of the packet or 0 if at least one packet was filtered
 *                 out
 */
typedef void (*rp_trans_receive_handler)(struct rp_trans_endpoint *endpoint,
	const uint8_t *buf, size_t length);


/** @brief Callback called before it goes into endpoint's rx thread.
 *
 * This callback will be called in context of transport received thread
 * before packet goes into endpoint's rx thread. This allows to handle
 * packets as soon as possible. If some packet was filtered out
 * (return false) user thread or endpoint's rx thread will be waken up.
 * In this case buffer will be NULL and there is no need to release it.
 * If multiple packets were filtered out in short period of time then
 * user or endpoint's thread can be waken up once. Additionally if
 * one unfiltered buffer was received just aftere filtered one then
 * again thread can be waken up only once with non NULL buffer.
 *
 * @param endpoint endpoint at which a new packet arrived
 * @param buf      data buffer with the packet
 * @param length   size of the packet on input
 * @return         false if filter processed the packet and it should be
 *                 discarted,
 *                 true if the packet should be passed to the
 *                 @a rp_trans_receive_handler or @a rp_trans_read_start
 */
typedef bool (*rp_trans_filter)(struct rp_trans_endpoint *endpoint,
	const uint8_t *buf, size_t length);


/** @brief Initializes RP transport layer
 *
 * @param callback A callback called from endpoint's rx thread with newly
 *                 received packet.
 */
int rp_trans_init(rp_trans_receive_handler callback, rp_trans_filter filter);


/** @brief Uninitializes RP transport layer
 */
void rp_trans_uninit(void);


/** @brief Initialize an endpoint
 *
 * @param endpoint        endpoint structure to initialize
 * @param endpoint_number endpoint number the same endpoint on both sides
 */
int rp_trans_endpoint_init(struct rp_trans_endpoint *endpoint,
	int endpoint_number);


/** @brief Uninitialize the endpoint
 *
 * @param endpoint        endpoint structure to uninitialize
 */
void rp_trans_endpoint_uninit(struct rp_trans_endpoint *endpoint);


/** @brief Allocates a buffer to transmit packet.
 *
 * Allocated memory must be release by exactly one of two functions:
 * rp_trans_send or rp_trans_free_tx_buf.
 *
 * Transport implementation may decide to allocate data on the stack, so
 * buffer may be lost after return from the caller.
 *
 * @param         endpoint Endpoint where packet will be send
 * @param[out]    buf      Pointer to start of the buffer
 * @param[in,out] length   Requested buffer length on input, actual allocated
 *                         length on output which can be greaten than
 *                         requested.
 */
void rp_trans_alloc_tx_buf(struct rp_trans_endpoint *endpoint, uint8_t **buf,
	size_t *length);


/**  @brief Free allocated transmit buffer in case it was not send.
 *
 * @param buf      Pointer to start of the buffer
 */
void rp_trans_free_tx_buf(struct rp_trans_endpoint *endpoint, uint8_t *buf);


/**  @brief Sends a packet via specified endpoint.
 *
 * @param endpoint Endpoint where packet will be send
 * @param buf      Pointer to start of the buffer
 * @param buf_len  Length of @a buf, may be less than allocated
 */
int rp_trans_send(struct rp_trans_endpoint *endpoint, const uint8_t *buf,
	size_t buf_len);


/** @brief Own endpoint's responsibility for incoming packets.
 *
 * Calling thread tells the transport that it owns responsibility for fetching
 * and handling incoming packets. After call all incoming packets
 * will not go into the endpoint's receive thread (or an IRQ), but they will
 * wait until this thread reads it with @a rp_trans_read_start or give
 * responsibility back with @a rp_trans_give. This function also works as a
 * mutex i.e. if some other thread will try to own the endpoint it will wait.
 * 
 * Owning is recursice, so calling thread may call this function multiple
 * times. Responsibility is actually given back when @a rp_trans_give was
 * called the same number of times.
 * 
 * @param endpoint Endpoint
 */
void rp_trans_own(struct rp_trans_endpoint *endpoint);


/** @brief Give back endpoint's responsibility for incoming packets.
 *
 * @see rp_trans_own()
 *
 * @param endpoint Endpoint
 */
void rp_trans_give(struct rp_trans_endpoint *endpoint);


/** @brief Read packet from endpoint synchronously.
 *
 * Endpoint must be owned by the caller with @a rp_trans_own() function.
 * When the buffer is no longer needed caller must call
 * @a rp_trans_release_buffer() to inform tranport that buffer can be discarted.
 *
 * @param      endpoint Endpoint to read from
 * @param[out] buf      Buffer containing a packet or NULL if at least one
 *                      packet was filered.
 * @return              Size of the packet or 0 if at least one packet was
 *                      filered.
 */
int rp_trans_read(struct rp_trans_endpoint *endpoint, const uint8_t **buf);


/** @brief Release buffers returned by @a rp_trans_read_start().
 *
 * @param      endpoint Endpoint
 */
void rp_trans_release_buffer(struct rp_trans_endpoint *endpoint);


#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* TRANS_RPMSG_H_ */
