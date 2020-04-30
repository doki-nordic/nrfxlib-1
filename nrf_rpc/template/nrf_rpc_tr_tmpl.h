/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef NRF_RPC_TR_TMPL_H_
#define NRF_RPC_TR_TMPL_H_


/*
 * THIS IS A TEMPLATE FILE.
 * This is a template for nrf_rpc_tr API. It can be user as a starting point to
 * implement a new transport. All transports must have API compatible to
 * this one. Small changes are allowed that does not break compatibility, e.g.
 * convert some function to function-like macros.
 *
 * It also contains documentation of the nrf_rpc_tr API. Transports do not need
 * to duplicate this documentation.
 */


#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


/**
 * @defgroup nrf_rpc_tr nRF RPC transport layer
 * @{
 * @brief nRF RPC transport layer API.
 */


#ifdef __cplusplus
extern "C" {
#endif


/** @brief Defines maximum size of a header that transport layer can add to
 * a packet.
 */
#define NRF_RPC_TR_MAX_HEADER_SIZE 2


/** @brief Instance of a remote endpoint.
 * 
 * Remote endpoint is an endpoint that nRF RPC sends to. Each remote endpoint
 * has a thread on the remote side that is reading from it. The thread can be
 * from a thread pool or a different thread (e.g. one that waits for
 * a response).
 * 
 * There is also one special endpoint: null endpoint. It is used to send packets
 * that have no specific sender or receiver, e.g. ACK packets. To indicate
 * null endpoint API uses NULL pointer to this structure.
 * 
 * Transport should not directly creates this structure, but should create
 * @a nrf_rpc_remote_ep structure that contains this structure.
 */
struct nrf_rpc_tr_remote_ep {
	/** @brief Address of the endpoint. nRF PRC requires only this field to
	 * be present.
	 */
	uint8_t addr;

	/** @brief Other fields are implementation specific.
	 */
	int implementation_specific;
};


/** @brief Instance of a local endpoint.
 * 
 * Local endpoint is an endpoint that nRF RPC receives from. Each thread that
 * wants to read anything from nRF PRC (e.g. command or response) has
 * assigned local endpoint. Remote side can send packets to this endpoint.
 * 
 * There is also one special endpoint: null endpoint. It is used to send packets
 * that have no specific sender or receiver, e.g. ACK packets. To indicate
 * null endpoint API uses NULL pointer to this structure.
 * 
 * Transport should not directly creates this structure, but should create
 * @a nrf_rpc_local_ep structure that contains this structure.
 */
struct nrf_rpc_tr_local_ep {
	/** @brief Address of the endpoint. nRF PRC requires only this field to
	 * be present.
	 */
	uint8_t addr;

	/** @brief Other fields are implementation specific.
	 */
	int implementation_specific;
};


/** @brief Callback called from thread poll when a new packet arrived.
 * 
 * When the buffer is not needed callback must release it with
 * @a nrf_rpc_tr_release_buffer.
 *
 * @param dst_ep Local destination endpoint.
 * @param src_ep Remote source endpoint. Can be NULL to indicate null endpoint.
 * @param buf    Data buffer with the packet or NULL if packet was filtered out.
 * @param len    Size of the packet or a value returned from
 *               @a nrf_rpc_tr_filter if a packet was filtered out.
 */
typedef void (*nrf_rpc_tr_receive_handler)(struct nrf_rpc_tr_local_ep *dst_ep,
					   struct nrf_rpc_tr_remote_ep *src_ep,
					   const uint8_t *buf, int len);


/** @brief Callback called before it goes into destination thread.
 *
 * This callback can be called before it goes into destination thread (e.g. in
 * context of transport received thread or IRQ). This allows to handle packets
 * as soon as possible and also makes it possible to handle packet that
 * are directed to null endpoint. If some packet was filtered out (returned
 * non-zero value) and the destination endpoint is not null then the next read
 * from endpoint will return NULL buffer and length equal to return value of
 * this callback.
 *
 * @param dst_ep Local destination endpoint. Can be NULL for null endpoint.
 * @param src_ep Remote source endpoint. Can be NULL for null endpoint.
 * @param buf    Data buffer with the packet.
 * @param len    Size of the packet.
 * 
 * @return 0 if packet should be passed to read function. Non-zero to filter out
 *         this packet. In this case data buffer will be released immediately.
 *         Return value must be less than 0x80000000.
 */
typedef uint32_t (*nrf_rpc_tr_filter)(struct nrf_rpc_tr_local_ep *dst_ep,
				      struct nrf_rpc_tr_remote_ep *src_ep,
				      const uint8_t *buf, int len);


/** @brief Initializes nRF RPC transport layer
 *
 * @param callback A callback called from thread pool with received packet.
 * @param filter   A callback called to filter the packets as soos as possible
 *                 before they goes to destination.
 * 
 * @return NRF_RPC_SUCCESS or negative error code.
 */
int nrf_rpc_tr_init(nrf_rpc_tr_receive_handler callback,
		    nrf_rpc_tr_filter filter);


/** @brief Allocates a new packet to send.
 * 
 * Allocation failure is not indicated by NULL pointer, but
 * @a nrf_rpc_tr_alloc_failed function must be used to check it.
 * 
 * Allocated packet must be send using @a nrf_rpc_tr_send. If fore some reason
 * allocated packet will not be send then @a nrf_rpc_tr_free_tx_buf must be
 * called.
 * 
 * Transport implementation may replace this function (and also related
 * alloc/free) by a function-like macros, e.g. when a buffer is allocated on
 * stack.
 *
 * @param      dst_ep Destination endpoint. Can be NULL for a null endpoint.
 * @param[out] buf    Pointer to allocated buffer.
 * @param      len    Requested size of the packet.
 */
void nrf_rpc_tr_alloc_tx_buf(struct nrf_rpc_tr_local_ep *dst_ep, uint8_t **buf,
			     size_t len);


/** @brief Deallocates packet if it will not be send.
 * 
 * This function cannot be called if buffer was already send using
 * @a nrf_rpc_tr_send function.
 * 
 * @param dst_ep Destination endpoint. Can be NULL for a null endpoint.
  */
void nrf_rpc_tr_free_tx_buf(struct nrf_rpc_tr_local_ep *dst_ep, uint8_t *buf);


/** @brief Checks if packet allocation was successfull.
 * 
 * @param buf Output from @a nrf_rpc_tr_alloc_tx_buf.
 * 
 * @return true is allocation was successfull, false otherwise.
  */
bool nrf_rpc_tr_alloc_failed(uint8_t *buf);


/** @brief Sends a packet.
 *
 * @param local_ep Source endpoint. Can be NULL for null endpoint.
 * @param dst_ep   Destination endpoint. Can be NULL for null endpoint.
 * @param buf      Packet allocated previously with @a nrf_rpc_tr_alloc_tx_buf.
 *                 After call this buffer cannout be used again
 * @param len      Length of @a buf, may be less than allocated.
 * 
 * @return NRF_RPC_SUCCESS or negative error code.
 */
int nrf_rpc_tr_send(struct nrf_rpc_tr_local_ep *local_ep,
		    struct nrf_rpc_tr_remote_ep *dst_ep, u8_t *buf, size_t len);


/** @brief Receives a packet.
 *
 * @param      local_ep Destination endpoint.
 * @param[out] src_ep   Source endpoint. Can be NULL for null endpoint.
 * @param[out] buf      Buffer containing the packet or NULL if packet was
 *                      filtered out. If it is no longer needed caller have to
 *                      call @a nrf_rpc_tr_release_buffer to release it.
 *
 * @return Size of the returned buffer if packet was received.
 *         Value returned by filter callback if packet was filtered out.
 *         Negative error code if error occurred.
 */
int nrf_rpc_tr_read(struct nrf_rpc_tr_local_ep *local_ep,
		    struct nrf_rpc_tr_remote_ep **src_ep, const uint8_t **buf);


/** @brief Release incoming buffer.
 * 
 * Buffer returned from @a nrf_rpc_tr_read or provided to
 * @a nrf_rpc_tr_receive_handler must be released as soon as it is not needed
 * any more. Calling this function multiple times is allowed, so calling it
 * when buffer is already released has no effect.
 * 
 * @param local_ep Endpoint from which buffer was received.
 */
void nrf_rpc_tr_release_buffer(struct nrf_rpc_tr_local_ep *local_ep);


/** @brief Reserve one thread from remote thread pool.
 * 
 * If thread is no longer need it must be released by
 * @a nrf_rpc_tr_remote_release.
 *
 * @return Endpoint associated with reserved thread.
 */
struct nrf_rpc_tr_remote_ep *nrf_rpc_tr_remote_reserve(void);


/** @brief Release thread from remote thread pool.
 * 
 * @param ep Endpoint associated with the reserved thread.
 */
void nrf_rpc_tr_remote_release(struct nrf_rpc_tr_remote_ep *ep);


/** @brief Get local endpoint associated with current thread.
 * 
 * If thread has no local endpoint associated then new endpoint is associated
 * with current thread.
 *
 * @return Endpoint associated with current thread.
 */
struct nrf_rpc_tr_local_ep *nrf_rpc_tr_current_get();


#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* TRANS_RPMSG_H_ */
