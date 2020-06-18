/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */


#ifndef _NRF_RPC_CBOR_H_
#define _NRF_RPC_CBOR_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <tinycbor/cbor.h>
#include <tinycbor/cbor_buf_writer.h>
#include <tinycbor/cbor_buf_reader.h>

#include <nrf_rpc_common.h>
#include <nrf_rpc_tr.h>
#include <nrf_rpc_internal.h>


/**
 * @defgroup nrf_rpc_cbor TinyCBOR serialization layer for nRF RPC.
 * @{
 * @ingroup nrf_rpc
 *
 * @brief Module simplifying usage of TinyCBOR as a serialization for nRF RPC
 * module.
 */


#ifdef __cplusplus
extern "C" {
#endif


/** @brief Callback that handles decoding of commands, events and responses.
 *
 * @param value        TinyCBOR value to decode.
 * @param handler_data Custom handler data.
 */
typedef void (*nrf_rpc_cbor_handler_t)(CborValue *value, void *handler_data);


/** @brief Helper structure for command and event decoders.
 */
struct nrf_rpc_cbor_decoder {
	nrf_rpc_cbor_handler_t handler;
	void *handler_data;
	bool decoding_done_required;
};


/** @brief Context where .
 */
struct nrf_rpc_cbor_ctx {
	CborEncoder encoder;
	struct cbor_buf_writer writer;
	uint8_t *out_packet;
};

struct nrf_rpc_cbor_rsp_ctx {
	union
	{
		struct {
			CborEncoder encoder;
			struct cbor_buf_writer writer;
			uint8_t *out_packet;
		};
		struct {
			CborValue value;
			CborParser parser;
			struct cbor_buf_reader reader;
			const uint8_t *in_packet;
		};
	};
};

/** @brief Register a command decoder.
 *
 * @param _group   Group that the decoder will belong to, created with a
 *                 @ref NRF_RPC_GROUP_DEFINE().
 * @param _name    Name of the decoder.
 * @param _cmd     Command id. Can be from 0 to 254.
 * @param _handler Handler function of type @ref nrf_rpc_cbor_handler_t.
 * @param _data    Opaque pointer for the @a _handler.
 */
#define NRF_RPC_CBOR_CMD_DECODER(_group, _name, _cmd, _handler, _data)	       \
	static const							       \
	struct _nrf_rpc_cbor_decoder NRF_RPC_CONCAT(_name, _cbor_data) = {     \
		.handler = _handler,					       \
		.handler_data = _data,					       \
		.decode_done_required = true,				       \
	};								       \
	NRF_RPC_CMD_DECODER(_group, _name, _cmd, _nrf_rpc_cbor_proxy_handler,  \
			    (void *)&NRF_RPC_CONCAT(_name, _cbor_data))


/** @brief Register an event decoder.
 *
 * @param _group   Group that the decoder will belong to, created with a
 *                 @ref NRF_RPC_GROUP_DEFINE().
 * @param _name    Name of the decoder.
 * @param _evt     Event id. Can be from 0 to 254.
 * @param _handler Handler function of type @ref nrf_rpc_cbor_handler_t.
 * @param _data    Opaque pointer for the @a _handler.
 */
#define NRF_RPC_CBOR_EVT_DECODER(_group, _name, _evt, _handler, _data)	       \
	static const							       \
	struct _nrf_rpc_cbor_decoder NRF_RPC_CONCAT(_name, _cbor_data) = {     \
		.handler = _handler,					       \
		.handler_data = _data,					       \
		.decode_done_required = true,				       \
	};								       \
	NRF_RPC_EVT_DECODER(_group, _name, _evt, _nrf_rpc_cbor_proxy_handler,  \
			    (void *)&NRF_RPC_CONCAT(_name, _cbor_data))


/** @brief Allocates memory for a packet.
 *
 * Macro may allocate some variables on stack, so it should be used at top level
 * of a function.
 * 
 * Memory is automatically deallocated when it is passed to any of the send
 * functions. If not @ref NRF_RPC_DISCARD() can be used.
 *
 * @param[out] _ctx  Variable of type @ref nrf_rpc_cbor_ctx or
 *                   @ref nrf_rpc_cbor_rsp_ctx that will hold newly allocated
 *                   resources to encode and send a packet.
 * @param[in]  _len  Requested length of the packet.
 */
#define NRF_RPC_CBOR_ALLOC(_ctx, _len)					       \
	NRF_RPC_ALLOC(&(_ctx).out_packet, (_len));			       \
	_nrf_rpc_cbor_prepare((struct nrf_rpc_cbor_ctx *)(&(_ctx)), (_len))


/** @brief Deallocate memory for a packet.
 *
 * This macro should be used if memory was allocated, but it will not be send
 * with any of the send functions.
 *
 * @param _ctx Packet that was previously allocated.
 */
#define NRF_RPC_CBOR_DISCARD(_ctx) NRF_RPC_DISCARD((_ctx).out_packet);


/** @brief Send a command and provide callback to handle response.
 *
 * @param group        Group that command belongs to.
 * @param cmd          Command id.
 * @param packet       Packet allocated by @ref NRF_RPC_ALLOC and filled with
 *                     an encoded data.
 * @param len          Length of the packet. Can be smaller than allocated.
 * @param handler      Callback that handles the response. In case of error
 *                     (e.g. malformed response packet was received) it is
 *                     undefined if the handler will be called.
 * @param handler_data Opaque pointer that will be passed to @a handler.
 *
 * @return             0 on success or negative error code if a transport layer
 *                     reported a sendig error.
 */
int nrf_rpc_cbor_cmd(const struct nrf_rpc_group *group,
				   uint8_t cmd, struct nrf_rpc_cbor_ctx *ctx,
				   nrf_rpc_cbor_handler_t handler,
				   void *handler_data);


/** @brief Send a command and get response as an output parameter.
 * 
 * This variant of command send function outputs response as an output
 * parameter. Caller is responsible to call @ref nrf_rpc_decoding_done with
 * a response packet just after response packet was decoded and can be
 * deallocated.
 *
 * @param[in]  group      Group that command belongs to.
 * @param[in]  cmd        Command id.
 * @param[in]  packet     Packet allocated by @ref NRF_RPC_ALLOC and filled
 *                        with an encoded data.
 * @param[in]  len        Length of the packet. Can be smaller than allocated.
 * @param[out] rsp_packet Packet containing the response or NULL on error.
 * @param[out] rsp_len    Length of @a rsp_packet.
 *
 * @return                0 on success or negative error code if a transport
 *                        layer reported a sendig error.
 */
int nrf_rpc_cbor_cmd_rsp(const struct nrf_rpc_group *group,
				  uint8_t cmd,
				  struct nrf_rpc_cbor_rsp_ctx *ctx);


/** @brief Send a command, provide callback to handle response and pass any
 * error to an error handler.
 * 
 * This variant of command send function returns `void`, so sending error
 * returned from the transport layer is passed to the error handler.
 * Source of error is @ref NRF_RPC_ERR_SRC_SEND.
 *
 * @param group        Group that command belongs to.
 * @param cmd          Command id.
 * @param packet       Packet allocated by @ref NRF_RPC_ALLOC and filled with
 *                     an encoded data.
 * @param len          Length of the packet. Can be smaller than allocated.
 * @param handler      Callback that handles the response. In case of error
 *                     (e.g. malformed response packet was received) it is
 *                     undefined if the handler will be called.
 * @param handler_data Opaque pointer that will be passed to @a handler.
 */
void nrf_rpc_cbor_cmd_no_err(const struct nrf_rpc_group *group,
				      uint8_t cmd, struct nrf_rpc_cbor_ctx *ctx,
				      nrf_rpc_handler_t handler,
				      void *handler_data);


/** @brief Send a command, get response as an output parameter and pass any
 * error to an error handler.
 * 
 * See both @ref nrf_rpc_cmd_rsp and @ref nrf_rpc_cmd_no_err for more
 * details on this variant of command send function.
 *
 * @param[in]  group      Group that command belongs to.
 * @param[in]  cmd        Command id.
 * @param[in]  packet     Packet allocated by @ref NRF_RPC_ALLOC and filled
 *                        with an encoded data.
 * @param[in]  len        Length of the packet. Can be smaller than allocated.
 * @param[out] rsp_packet Packet containing the response or NULL on error.
 * @param[out] rsp_len    Length of @a rsp_packet.
 */
void nrf_rpc_cbor_cmd_rsp_no_err(
					      const struct nrf_rpc_group *group,
					      uint8_t cmd,
					      struct nrf_rpc_cbor_rsp_ctx *ctx);

/** @brief Send an event.
 *
 * @param group  Group that event belongs to.
 * @param evt    Event id.
 * @param packet Packet allocated by @ref NRF_RPC_ALLOC and filled with
 *               an encoded data.
 * @param len    Length of the packet. Can be smaller than allocated.
 *
 * @return       0 on success or negative error code if a transport layer
 *               reported a sendig error.
 */
int nrf_rpc_cbor_evt(const struct nrf_rpc_group *group, uint8_t evt,
		     struct nrf_rpc_cbor_ctx *ctx);


/** @brief Send an event and pass any error to an error handler.
 * 
 * This variant of event send function returns `void`, so sending error
 * returned from the transport layer is passed to the error handler.
 * Source of error is @ref NRF_RPC_ERR_SRC_SEND.
 *
 * @param group  Group that event belongs to.
 * @param evt    Event id.
 * @param packet Packet allocated by @ref NRF_RPC_ALLOC and filled with
 *               an encoded data.
 * @param len    Length of the packet. Can be smaller than allocated.
 */
void nrf_rpc_cbor_evt_noerr(const struct nrf_rpc_group *group, uint8_t evt,
			    struct nrf_rpc_cbor_ctx *ctx);


/** @brief Send a response.
 *
 * @param packet Packet allocated by @ref NRF_RPC_ALLOC and filled with
 *               encoded data.
 * @param len    Length of the packet. Can be smaller than allocated.
 *
 * @return       0 on success or negative error code if a transport layer
 *               reported a sendig error.
 */
int nrf_rpc_cbor_rsp(struct nrf_rpc_cbor_ctx *ctx);


/** @brief Send a response and pass any error to an error handler.
 * 
 * This variant of response send function returns `void`, so sending error
 * returned from the transport layer is passed to the error handler.
 * Source of error is @ref NRF_RPC_ERR_SRC_SEND.
 *
 * @param packet Packet allocated by @ref NRF_RPC_ALLOC and filled with
 *               encoded data.
 * @param len    Length of the packet. Can be smaller than allocated.
 */
void nrf_rpc_cbor_rsp_noerr(struct nrf_rpc_cbor_ctx *ctx);


/** @brief Indicate that decoding of the input packet is done.
 *
 * This function must be called as soon as the input packet was parsed and can
 * be deallocated. It must be called in command decoder, event decoder and after
 * @ref nrf_rpc_cmd_rsp or @ref nrf_rpc_cmd_rsp_no_err. Packet is
 * automatically deallocated after completetion of the response handler
 * function, so this `nrf_rpc_decoding_done` is not needed in response handler.
 */
void nrf_rpc_cbor_decoding_done(CborValue *value);


/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* _NRF_RPC_CBOR_H_ */
