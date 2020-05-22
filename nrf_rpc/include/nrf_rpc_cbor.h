/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#ifndef _NRF_RPC_CBOR_H_
#define _NRF_RPC_CBOR_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <cbor.h>

#include <nrf_rpc.h>
#include <nrf_rpc_errors.h>
#include <nrf_rpc_common.h>
#include <nrf_rpc_tr.h>


#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup nrf_rpc_cbor TinyCBOR serialization layer for nRF RPC.
 * @{
 * @ingroup nrf_rpc
 *
 * @brief Module simplifying usage of TinyCBOR as a serialization for nRF RPC
 * module.
 */


/** @brief Callback that handles decoding of commands, events and responses.
 *
 * @param value        TinyCBOR value to decode.
 * @param handler_data Custom handler data.
 */
typedef int (*nrf_rpc_cbor_handler_t)(CborValue *value, void *handler_data);


/** @brief Structure type of the context variable for allocated resources.
 *
 * Variable of this type should be used as a context for
 * @ref NRF_RPC_CBOR_CMD_ALLOC, @ref NRF_RPC_CBOR_EVT_ALLOC and
 * @ref NRF_RPC_CBOR_RPS_ALLOC. After that should be passed to any of the send
 * functions.
 */
struct nrf_rpc_cbor_alloc_ctx
{
	nrf_rpc_alloc_ctx base_ctx;
	CborEncoder encoder;
	uint8_t *packet;
};


/* Internal structure used to store decoder data. */
struct _nrf_rpc_cbor_decoder {
	nrf_rpc_cbor_handler_t handler;
	void *handler_data;
};


/** @brief Register a command decoder.
 *
 * @param _group   Group that the decoder will belong to.
 * @param _name    Name of the decoder.
 * @param _cmd     Command id. Can be from 0 to 254.
 * @param _handler Handler function of type @ref nrf_rpc_cbor_handler_t.
 * @param _data    Opaque data for the handler.
 */
#define NRF_RPC_CBOR_CMD_DECODER(_group, _name, _cmd, _handler, _data)	       \
	static const struct _nrf_rpc_cbor_decoder NRF_RPC_CONCAT(_name, _cbor_data) = {    \
		.handler = _handler, \
		.handler_data = _data, \
	}; \
	NRF_RPC_CMD_DECODER(_group, _name, _cmd, _nrf_rpc_cbor_proxy_handler, \
			    (void *)&NRF_RPC_CONCAT(_name, _cbor_data))


/** @brief Register an event decoder.
 *
 * @param _group   Group that the decoder will belong to.
 * @param _name    Name of the decoder.
 * @param _evt     Event id. Can be from 0 to 254.
 * @param _handler Handler function of type @ref nrf_rpc_cbor_handler_t.
 * @param _data    Opaque data for the handler.
 */
#define NRF_RPC_CBOR_EVT_DECODER(_group, _name, _evt, _handler, _data)	       \
	static const struct _nrf_rpc_cbor_decoder NRF_RPC_CONCAT(_name, _cbor_data) = {    \
		.handler = _handler, \
		.handler_data = _data, \
	}; \
	NRF_RPC_EVT_DECODER(_group, _name, _evt, _nrf_rpc_cbor_proxy_handler, \
			    (void *)&NRF_RPC_CONCAT(_name, _cbor_data))


/** @brief Allocates resources for a new command.
 *
 * Macro may allocate some variables on stack, so it should be used at top level
 * of a function.
 *
 * @param[out] _ctx    Variable of type @ref nrf_rpc_cbor_alloc_ctx that will
 *                     hold allocated resources.
 * @param      _group  Group that command belongs to.
 * @param[out] _packet Variable of type @ref CborEncoder* that will hold pointer
 *                     to newly allocated packet encoder.
 * @param      _len    Requested length of the packet.
 * @param __VA_ARGS__  Code that will be executed in case of allocation failure.
 *                     This can be e.g. return or goto statement.
 */
#define NRF_RPC_CBOR_CMD_ALLOC(_ctx, _group, _packet, _len, ...)	       \
	NRF_RPC_CMD_ALLOC(_ctx.base_ctx, _group, _ctx.packet, _len, __VA_ARGS__);\
	_packet = &_ctx.encoder; \
	cbor_encoder_init(_packet, _ctx.packet, _len, 0)


/** @brief Discards resources allocated for a new command.
 *
 * This macro should be used if a command was allocated, but it will not be
 * send.
 *
 * @param _ctx    Context that was previously allocated.
 */
#define NRF_RPC_CBOR_CMD_DISCARD(_ctx)					       \
	NRF_RPC_CMD_DISCARD(_ctx.base_ctx, _ctx.packet)


/** @brief Allocates resources for a new event.
 *
 * Macro may allocate some variables on stack, so it should be used at top level
 * of a function.
 *
 * @param[out] _ctx    Variable of type @ref nrf_rpc_cbor_alloc_ctx that will
 *                     hold allocated resources.
 * @param      _group  Group that event belongs to.
 * @param[out] _packet Variable of type @ref CborEncoder* that will hold pointer
 *                     to newly allocated packet encoder.
 * @param      _len    Requested length of the packet.
 * @param __VA_ARGS__  Code that will be executed in case of allocation failure.
 *                     This can be e.g. return or goto statement.
 */
#define NRF_RPC_CBOR_EVT_ALLOC(_ctx, _group, _packet, _len, ...)	       \
	NRF_RPC_EVT_ALLOC(_ctx.base_ctx, _group, _ctx.packet, _len, __VA_ARGS__);\
	_packet = &_ctx.encoder; \
	cbor_encoder_init(_packet, _ctx.packet, _len, 0)


/** @brief Discards resources allocated for a new event.
 *
 * This macro should be used if an event was allocated, but it will not be send.
 *
 * @param _ctx    Context that was previously allocated.
 */
#define NRF_RPC_CBOR_EVT_DISCARD(_ctx)					       \
	NRF_RPC_EVT_DISCARD(_ctx.base_ctx, _ctx.packet)


/** @brief Allocates resources for a response.
 *
 * Macro may allocate some variables on stack, so it should be used at top level
 * of a function.
 *
 * @param[out] _ctx    Variable of type @ref nrf_rpc_cbor_alloc_ctx that will
 *                     hold allocated resources.
 * @param[out] _packet Variable of type @ref CborEncoder* that will hold pointer
 *                     to newly allocated packet encoder.
 * @param      _len    Requested length of the packet.
 * @param __VA_ARGS__  Code that will be executed in case of allocation failure.
 *                     This can be e.g. return or goto statement.
 */
#define NRF_RPC_CBOR_RSP_ALLOC(_ctx, _packet, _len, ...)	       \
	NRF_RPC_RSP_ALLOC(_ctx.base_ctx, _ctx.packet, _len, __VA_ARGS__);\
	_packet = &_ctx.encoder; \
	cbor_encoder_init(_packet, _ctx.packet, _len, 0)


/** @brief Discards resources allocated for a response.
 *
 * This macro should be used if an response was allocated, but it will not be
 * send.
 *
 * @param _ctx    Context that was previously allocated.
 */
#define NRF_RPC_CBOR_RSP_DISCARD(_ctx, _packet)				       \
	NRF_RPC_RSP_DISCARD(_ctx.base_ctx, _ctx.packet)


/* Internal function that translates callbacks from `nrf_rpc` to
 * `nrf_rpc_cbor`.
 */
int _nrf_rpc_cbor_proxy_handler(const uint8_t *packet, size_t len,
				void *handler_data);


/** @brief Send a command.
 *
 * @param ctx          Context that was previously allocated by the
 *                     @ref NRF_RPC_CBOR_CMD_ALLOC.
 * @param cmd          Command id.
 * @param handler      Callback that handles the response. In case of error
 *                     it is undefined if the handler will be called.
 * @param handler_data Opaque pointer that will be passed to a handler.
 * @returns            @ref NRF_RPC_SUCCESS or error code from
 *                     enum @ref nrf_rpc_error_code.
 */
int nrf_rpc_cbor_cmd_send(struct nrf_rpc_cbor_alloc_ctx *ctx, uint8_t cmd,
			  nrf_rpc_cbor_handler_t handler, void *handler_data);


/** @brief Send a command and get response directly.
 *
 * See @ref nrf_rpc_cmd_rsp_send for more details about this version of send
 * command.
 *
 * @param ctx             Context that was previously allocated by the
 *                        @ref NRF_RPC_CBOR_CMD_ALLOC.
 * @param cmd             Command id.
 * @param parser          TinyCBOR parser instance used to parse the response.
 * @param rsp_packet      TinyCBOR value that will contain response packet.
 * @returns               @ref NRF_RPC_SUCCESS or error code from
 *                        enum @ref nrf_rpc_error_code.
 */
int nrf_rpc_cbor_cmd_rsp_send(struct nrf_rpc_cbor_alloc_ctx *ctx, uint8_t cmd,
			      CborParser *parser, CborValue *rsp_packet);


/** @brief Send a command passing any errors to an error handler.
 *
 * See @ref nrf_rpc_cmd_send_noerr for more details how the errors are handled.
 * 
 * See @ref nrf_rpc_cbor_cmd_send for more details about parameters.
 */
void nrf_rpc_cbor_cmd_send_noerr(struct  nrf_rpc_cbor_alloc_ctx *ctx,
				 uint8_t cmd, nrf_rpc_cbor_handler_t handler,
				 void *handler_data);


/** @brief Send an event.
 *
 * See @ref nrf_rpc_evt_send for more details how events are send.
 *
 * @param ctx       Context that was previously allocated by the
 *                  @ref NRF_RPC_CBOR_EVT_ALLOC.
 * @param evt       Event id.
 * @returns         @ref NRF_RPC_SUCCESS or error code from
 *                  enum @ref nrf_rpc_error_code.
 */
int nrf_rpc_cbor_evt_send(struct nrf_rpc_cbor_alloc_ctx *ctx, uint8_t evt);


/** @brief Send an event passing any errors to an error handler.
 *
 * See @ref nrf_rpc_evt_send_noerr for more details how the errors are handled.
 * 
 * See @ref nrf_rpc_cbor_evt_send for more details about parameters.
 */
void nrf_rpc_cbor_evt_send_noerr(struct nrf_rpc_cbor_alloc_ctx *ctx, uint8_t evt);


/** @brief Send a response.
 *
 * See @ref nrf_rpc_rsp_send for more details how responses are send.
 *
 * @param ctx       Context that was previously allocated by the
 *                  @ref NRF_RPC_CBOR_RSP_ALLOC.
 * @returns         @ref NRF_RPC_SUCCESS or error code from
 *                  enum @ref nrf_rpc_error_code.
 */
int nrf_rpc_cbor_rsp_send(struct nrf_rpc_cbor_alloc_ctx *ctx);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* _NRF_RPC_CBOR_H_ */
