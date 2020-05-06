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


/**
 * @defgroup nrf_rpc nRF RPC (Remote Procedure Calls) module.
 * @{
 * @brief Module to call procedures on a remote processor.
 */


#ifdef __cplusplus
extern "C" {
#endif


/** @brief Callback that handles decoding of commands, events and responses.
 *
 * @param packet       Packet data.
 * @param len          Length of the packet.
 * @param handler_data Custom handler data. In case of commands, events it is a
 *                     pointer to @a nrf_rpc_decoder structure associated with
 *                     this command or event. In case of response handler it is
 *                     an opaque pointer provided to @a NRF_RPC_CMD_SEND.
 */
typedef int (*nrf_rpc_cbor_handler_t)(CborValue *value, void *handler_data);

struct nrf_rpc_cbor_cmd_ctx
{
	nrf_rpc_cmd_ctx_t base_ctx;
	CborEncoder encoder;
	uint8_t *packet;
};

struct nrf_rpc_cbor_evt_ctx
{
	nrf_rpc_evt_ctx_t base_ctx;
	CborEncoder encoder;
	uint8_t *packet;
};

struct nrf_rpc_cbor_rsp_ctx
{
	nrf_rpc_rsp_ctx_t base_ctx;
	CborEncoder encoder;
	uint8_t *packet;
};

struct nrf_rpc_cbor_decoder {
	nrf_rpc_cbor_handler_t handler;
	void *handler_data;
};

/** @brief Register a command decoder.
 *
 * @param _group   Group that the decoder will belong to.
 * @param _name    Name of the decoder.
 * @param _cmd     Command id. Can be from 0 to 255.
 * @param _handler Handler function of type @a nrf_rpc_handler_t.
 */
#define NRF_RPC_CBOR_CMD_DECODER(_group, _name, _cmd, _handler, _data)	       \
	static const struct nrf_rpc_cbor_decoder NRF_RPC_CONCAT(_name, _cbor_data) = {    \
		.handler = _handler, \
		.handler_data = _data, \
	}; \
	NRF_RPC_CMD_DECODER(_group, _name, _cmd, _nrf_rpc_cbor_proxy_handler, \
			    (void *)&NRF_RPC_CONCAT(_name, _cbor_data))


/** @brief Register an event decoder.
 *
 * @param _group   Group that the decoder will belong to.
 * @param _name    Name of the decoder.
 * @param _evt     Event id. Can be from 0 to 255.
 * @param _handler Handler function of type @a nrf_rpc_handler_t.
 */
#define NRF_RPC_CBOR_EVT_DECODER(_group, _name, _evt, _handler, _data)	       \
	static const struct nrf_rpc_cbor_decoder NRF_RPC_CONCAT(_name, _cbor_data) = {    \
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
 * @param      _group  Group that command belongs to.
 * @param[out] _ctx    Variable of type `nrf_rpc_cmd_ctx_t` that will hold
 *                     allocated resources.
 * @param[out] _packet Variable of type `CborEncoder *` that will hold pointer to
 *                     newly allocated packet buffer.
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
 * This macro should be used if a command was allocated, but it will not be send
 * with @a NRF_RPC_CMD_SEND.
 *
 * @param _ctx    Context that was previously allocated to send the command.
 * @param _packet Packet that was previously allocated to send the command.
 */
#define NRF_RPC_CBOR_CMD_DISCARD(_ctx, _packet)				       \
	NRF_RPC_CMD_DISCARD(_ctx.base_ctx, _packet)


/** @brief Allocates resources for a new event.
 *
 * Macro may allocate some variables on stack, so it should be used at top level
 * of a function.
 *
 * @param      _group  Group that event belongs to.
 * @param[out] _ctx    Variable of type `nrf_rpc_evt_ctx_t` that will hold
 *                     allocated resources.
 * @param[out] _packet Variable of type `uint8_t *` that will hold pointer to
 *                     newly allocated packet buffer.
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
 * This macro should be used if an event was allocated, but it will not be send
 * with @a NRF_RPC_EVT_SEND.
 *
 * @param _ctx    Context that was previously allocated to send the event.
 * @param _packet Packet that was previously allocated to send the event.
 */
#define NRF_RPC_CBOR_EVT_DISCARD(_ctx, _packet)				       \
	NRF_RPC_EVT_DISCARD(_ctx.base_ctx, _packet)


/** @brief Allocates resources for a response.
 *
 * Macro may allocate some variables on stack, so it should be used at top level
 * of a function.
 *
 * @param[out] _ctx    Variable of type `nrf_rpc_rsp_ctx_t` that will hold
 *                     allocated resources.
 * @param[out] _packet Variable of type `uint8_t *` that will hold pointer to
 *                     newly allocated packet buffer.
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
 * send with @a NRF_RPC_RSP_SEND.
 *
 * @param _ctx    Context that was previously allocated to send the response.
 * @param _packet Packet that was previously allocated to send the response.
 */
#define NRF_RPC_CBOR_RSP_DISCARD(_ctx, _packet)				       \
	NRF_RPC_RSP_DISCARD(_ctx.base_ctx, _packet)

int _nrf_rpc_cbor_proxy_handler(const uint8_t *packet, size_t len, void *handler_data);

/** @brief Send a command.
 *
 * @param remote_ep    Destination endpoint allocated by @a NRF_RPC_CMD_ALLOC.
 * @param cmd          Command id.
 * @param packet       Packet allocated by @a NRF_RPC_CMD_ALLOC and filled with
 *                     encoded data.
 * @param len          Length of the packet. Can be smaller than allocated.
 * @param handler      Callback that handles the response. In case of error
 *                     it is undefined if the handler will be called.
 * @param handler_data Opaque pointer that will be passed to @a handler.
 * @returns            NRF_RPC_SUCCESS or error code from
 *                     enum nrf_rpc_error_code.
 */
int nrf_rpc_cbor_cmd_send(struct nrf_rpc_cbor_cmd_ctx *ctx, uint8_t cmd, nrf_rpc_cbor_handler_t handler, void *handler_data);


/** @brief Send a command and get response directly.
 *
 * After successful return caller is resposible for decoding content of the
 * response packet an call @a nrf_rpc_decoding_done just after that. After
 * calling @a nrf_rpc_decoding_done @a rsp_packet is no longer valid.
 *
 * Depending on transport layer implementation this function may be slightly
 * slower than @a nrf_rpc_cmd_send, because additional thread context switching
 * may happen.
 *
 * @param remote_ep       Destination endpoint allocated @a NRF_RPC_CMD_ALLOC.
 * @param cmd             Command id.
 * @param packet          Packet allocated by @a NRF_RPC_CMD_ALLOC and filled
 *                        with encoded data.
 * @param len             Length of the packet. Can be smaller than allocated.
 * @param[out] rsp_packet Response packet.
 * @param[out] rsp_len    Response packet length.
 * @returns               NRF_RPC_SUCCESS or error code from
 *                        enum nrf_rpc_error_code.
 */
int nrf_rpc_cbor_cmd_rsp_send(struct nrf_rpc_cbor_cmd_ctx *ctx, uint8_t cmd, CborParser *parser, CborValue *rsp_packet);


/** @brief Send a command passing any errors to an error handler.
 *
 * If error occurred during sending this command it will be passed to
 * @a nrf_rpc_error_handler instead of returning it. This form of error handling
 * can be useful for serializing API function that has no ability to report
 * an error in any other way, e.g. it returns void.
 *
 * See @a nrf_rpc_cmd_send for more details.
 */
void nrf_rpc_cbor_cmd_send_noerr(struct  nrf_rpc_cbor_cmd_ctx *ctx, uint8_t cmd, nrf_rpc_cbor_handler_t handler,
			    void *handler_data);


/** @brief Send an event.
 *
 * Sending an event always allocates a new thread from thread pool to handler
 * it, so it should be done carefully. Seding to many events at once may
 * consume all remote thread and as the result block other remote calls.
 *
 * @param remote_ep Destination endpoint allocated by @a NRF_RPC_ENT_ALLOC.
 * @param evt       Event id.
 * @param packet    Packet allocated by @a NRF_RPC_ENT_ALLOC and filled with
 *                  encoded data.
 * @param len       Length of the packet. Can be smaller than allocated.
 * @returns         NRF_RPC_SUCCESS or error code from enum nrf_rpc_error_code.
 */
int nrf_rpc_cbor_evt_send(struct nrf_rpc_cbor_evt_ctx *ctx, uint8_t evt);


/** @brief Send an event passing any errors to an error handler.
 *
 * If error occurred during sending this event it will be passed to
 * @a nrf_rpc_error_handler instead of returning it. This form of error handling
 * can be useful for serializing API function that has no ability to report
 * an error in any other way, e.g. it returns void.
 *
 * See @a nrf_rpc_evt_send for more details.
 */
void nrf_rpc_cbor_evt_send_noerr(struct nrf_rpc_cbor_evt_ctx *ctx, uint8_t evt);


/** @brief Send a response to a command.
 *
 * There is no _noerr form of this function, because it is always called from
 * command decoder, so the error code returned by @a nrf_rpc_rsp_send can
 * be passed further and returned from command decoder. Error returned from
 * commands decoders always go to @a nrf_rpc_error_handler.
 *
 * @param remote_ep Destination endpoint allocated by @a NRF_RPC_RSP_ALLOC.
 * @param packet    Packet allocated by @a NRF_RPC_RSP_ALLOC and filled with
 *                  encoded data.
 * @param len       Length of the packet. Can be smaller than allocated.
 * @returns         NRF_RPC_SUCCESS or error code from enum nrf_rpc_error_code.
 */
int nrf_rpc_cbor_rsp_send(struct nrf_rpc_cbor_rsp_ctx *ctx);


/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* _NRF_RPC_CBOR_H_ */
