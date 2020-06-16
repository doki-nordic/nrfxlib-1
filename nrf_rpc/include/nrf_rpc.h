/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */


#ifndef _NRF_RPC_H_
#define _NRF_RPC_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <nrf_rpc_common.h>
#include <nrf_rpc_tr.h>
#include <nrf_rpc_internal.h>


/**
 * @defgroup nrf_rpc nRF RPC (Remote Procedure Calls) module.
 * @{
 * @brief Module to call procedures on a remote processor.
 */


#ifdef __cplusplus
extern "C" {
#endif

/** @brief Value passed to the @ref nrf_rpc_error_handler() to indicate that id
 * of the command or event that caused the error is unkown.
 */
#define NRF_RPC_UNKNOWN_ID 0xFF


/** @brief Callback that handles decoding of commands, events and responses.
 *
 * @param packet       Packet data.
 * @param len          Length of the packet.
 * @param handler_data Opaque pointer provided by the user.
 */
typedef void (*nrf_rpc_handler_t)(const uint8_t *packet, size_t len,
	void *handler_data);

typedef void (*nrf_rpc_ack_handler_t)(uint8_t id, int return_value,
	void *handler_data);


/** @brief Command and event decoder structure.
 *
 * Created by @a NRF_RPC_CMD_DECODER or @a NRF_RPC_EVT_DECODER.
 */
struct nrf_rpc_decoder {

	/** @brief Command or event id. */
	uint8_t id;

	/** @brief Command or event decoder. */
	nrf_rpc_handler_t handler;

	/** @brief Command or event data for decoder. */
	void *handler_data;
};


/** @brief Defines a group of commands and events.
 *
 * One group is mostly assigned to a single API that needs to be serialized.
 * Created by @a NRF_RPC_GROUP_DEFINE.
 */
struct nrf_rpc_group {
	uint8_t *group_id;
	const void *cmd_array;
	const void *evt_array;
	nrf_rpc_ack_handler_t ack_handler;
	void *ack_handler_data;
	const char *strid;
};

/** @brief Define a group of commands and events.
 *
 * @param _name  Symbol name for the group.
 * @param _strid String containing unique identifier of the group. Naming
 *               conventions the same as C symbol name. Groups on local and
 *               remote must have the same unique identifier.
 * @param _ack_handler Handler called when ACK was received after event
 *                     completion. Can be NULL if group does not want to receive
 *                     ACK notifications. Packet parameter of the handler
 *                     is a single @a int value containing event handler return
 *                     value.
 * @param _data    Opaque pointer for the @a _ack_handler.
 */
#define NRF_RPC_GROUP_DEFINE(_name, _strid, _ack_handler, _data)	       \
	NRF_RPC_AUTO_ARR(NRF_RPC_CONCAT(_name, _cmd_array),		       \
			      "cmd_" NRF_RPC_STRINGIFY(_name));		       \
	NRF_RPC_AUTO_ARR(NRF_RPC_CONCAT(_name, _evt_array),		       \
			      "evt_" NRF_RPC_STRINGIFY(_name));		       \
	static uint8_t NRF_RPC_CONCAT(_name, _group_id);		       \
	NRF_RPC_AUTO_ARR_ITEM(const struct nrf_rpc_group, _name, "grp",	       \
			      _strid) = {				       \
		.group_id = &NRF_RPC_CONCAT(_name, _group_id),		       \
		.cmd_array = &NRF_RPC_CONCAT(_name, _cmd_array),	       \
		.evt_array = &NRF_RPC_CONCAT(_name, _evt_array),	       \
		.ack_handler = _ack_handler,				       \
		.ack_handler_data = _data,				       \
		.strid = _strid,					       \
	}


/** @brief Extern declaration of a group.
 *
 * Can be used in a header files.
 *
 * @param _name  Symbol name for the group.
 */
#define NRF_RPC_GROUP_DECLARE(_name)					       \
	extern const struct nrf_rpc_group _name;

/** @brief Register a command decoder.
 *
 * @param _group   Group that the decoder will belong to created with
 *                 @ref NRF_RPC_GROUP_DEFINE().
 * @param _name    Name of the decoder.
 * @param _cmd     Command id. Can be from 0 to 254.
 * @param _handler Handler function of type @ref nrf_rpc_handler_t.
 * @param _data    Opaque pointer for the @a _handler.
 */
#define NRF_RPC_CMD_DECODER(_group, _name, _cmd, _handler, _data)	       \
	NRF_RPC_STATIC_ASSERT(_cmd <= 0xFE, "Command out of range");	       \
	NRF_RPC_AUTO_ARR_ITEM(const struct nrf_rpc_decoder,		       \
			       NRF_RPC_CONCAT(_name, _cmd_dec),		       \
			       "cmd_" NRF_RPC_STRINGIFY(_group),	       \
			       NRF_RPC_STRINGIFY(_name)) = {		       \
		.id = _cmd,						       \
		.handler = _handler,					       \
		.handler_data = _data,					       \
	}


/** @brief Register an event decoder.
 *
 * @param _group   Group that the decoder will belong to created with
 *                 @ref NRF_RPC_GROUP_DEFINE().
 * @param _name    Name of the decoder.
 * @param _evt     Event id. Can be from 0 to 254.
 * @param _handler Handler function of type @a nrf_rpc_handler_t.
 * @param _data    Opaque pointer for the @a _handler.
 */
#define NRF_RPC_EVT_DECODER(_group, _name, _evt, _handler, _data)	       \
	NRF_RPC_STATIC_ASSERT(_evt <= 0xFE, "Event out of range");	       \
	NRF_RPC_AUTO_ARR_ITEM(const struct nrf_rpc_decoder,		       \
			       NRF_RPC_CONCAT(_name, _evt_dec),		       \
			       "evt_" NRF_RPC_STRINGIFY(_group),	       \
			       NRF_RPC_STRINGIFY(_name)) = {		       \
		.id = _evt,						       \
		.handler = _handler,					       \
		.handler_data = _data,					       \
	}


/** @brief Allocates resources for a new command.
 *
 * Macro may allocate some variables on stack, so it should be used at top level
 * of a function.
 *
 * @param[out] _ctx    Variable of type `nrf_rpc_cmd_ctx_t` that will hold
 *                     allocated resources.
 * @param _group       Group that the decoder will belong to created with
 *                     @ref NRF_RPC_GROUP_DEFINE().
 * @param[out] _packet Variable of type `uint8_t *` that will hold pointer to
 *                     newly allocated packet buffer.
 * @param      _len    Requested length of the packet.
 * @param __VA_ARGS__  Code that will be executed in case of allocation failure.
 *                     This can be e.g. return or goto statement.
 */
#define NRF_RPC_ALLOC(_packet, _len)					       \
	nrf_rpc_tr_alloc_tx_buf(&(_packet), _NRF_RPC_HEADER_SIZE + (_len));    \
	*(uint8_t **)&(_packet) += _NRF_RPC_HEADER_SIZE

/** @brief Discards resources allocated for a new command.
 *
 * This macro should be used if a command was allocated, but it will not be send
 * with @a NRF_RPC_CMD_SEND.
 *
 * @param _ctx    Context that was previously allocated to send the command.
 * @param _packet Packet that was previously allocated to send the command.
 */
#define NRF_RPC_CMD_DISCARD(_packet) nrf_rpc_tr_free_tx_buf((_packet))


/** @brief Initialize the nRF RPC
 *
 * @returns         0 or negative error code.
 */
int nrf_rpc_init(void);


/** @brief Send a command.
 *
 * @param ctx          Context allocated by the @ref NRF_RPC_CMD_ALLOC.
 * @param cmd          Command id.
 * @param packet       Packet allocated by @a NRF_RPC_CMD_ALLOC and filled with
 *                     encoded data.
 * @param len          Length of the packet. Can be smaller than allocated.
 * @param handler      Callback that handles the response. In case of error
 *                     it is undefined if the handler will be called.
 * @param handler_data Opaque pointer that will be passed to @a handler.
 * @returns            0 or negative error code.
 */
int nrf_rpc_cmd_send(const struct nrf_rpc_group *group, uint8_t cmd, uint8_t *packet,
		     size_t len, nrf_rpc_handler_t handler, void *handler_data);


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
 * @param ctx             Context allocated by the @ref NRF_RPC_CMD_ALLOC.
 * @param cmd             Command id.
 * @param packet          Packet allocated by @a NRF_RPC_CMD_ALLOC and filled
 *                        with encoded data.
 * @param len             Length of the packet. Can be smaller than allocated.
 * @param[out] rsp_packet Response packet.
 * @param[out] rsp_len    Response packet length.
 * @returns               0 or negative error code.
 */
int nrf_rpc_cmd_rsp_send(const struct nrf_rpc_group *group, uint8_t cmd, uint8_t *packet,
			 size_t len, const uint8_t **rsp_packet,
			 size_t *rsp_len);


/** @brief Send a command passing any errors to an error handler.
 *
 * If error occurred during sending this command it will be passed to
 * @a nrf_rpc_error_handler instead of returning it. This form of error handling
 * can be useful for serializing API function that has no ability to report
 * an error in any other way, e.g. it returns void.
 *
 * See @a nrf_rpc_cmd_send for more details.
 */
void nrf_rpc_cmd_send_noerr(const struct nrf_rpc_group *group, uint8_t cmd, uint8_t *packet,
			    size_t len, nrf_rpc_handler_t handler,
			    void *handler_data);


/** @brief Send an event.
 *
 * Sending an event always allocates a new thread from thread pool to handler
 * it, so it should be done carefully. Seding to many events at once may
 * consume all remote thread and as the result block other remote calls.
 *
 * @param ctx       Context allocated by the @ref NRF_RPC_EVT_ALLOC.
 * @param evt       Event id.
 * @param packet    Packet allocated by @a NRF_RPC_ENT_ALLOC and filled with
 *                  encoded data.
 * @param len       Length of the packet. Can be smaller than allocated.
 * @returns         0 or negative error code.
 */
int nrf_rpc_evt_send(const struct nrf_rpc_group *group, uint8_t evt, uint8_t *packet, size_t len);


/** @brief Send an event passing any errors to an error handler.
 *
 * If error occurred during sending this event it will be passed to
 * @a nrf_rpc_error_handler instead of returning it. This form of error handling
 * can be useful for serializing API function that has no ability to report
 * an error in any other way, e.g. it returns void.
 *
 * See @a nrf_rpc_evt_send for more details.
 */
void nrf_rpc_evt_send_noerr(const struct nrf_rpc_group *group, uint8_t evt, uint8_t *packet, size_t len);


/** @brief Send a response to a command.
 *
 * There is no _noerr form of this function, because it is always called from
 * command decoder, so the error code returned by @a nrf_rpc_rsp_send can
 * be passed further and returned from command decoder. Error returned from
 * commands decoders always go to @a nrf_rpc_error_handler.
 *
 * @param ctx       Destination endpoint allocated by @a NRF_RPC_RSP_ALLOC.
 * @param packet    Packet allocated by @a NRF_RPC_RSP_ALLOC and filled with
 *                  encoded data.
 * @param len       Length of the packet. Can be smaller than allocated.
 * @returns         0 or negative error code.
 */
int nrf_rpc_rsp_send(uint8_t *packet, size_t len);


/** @brief Indicate that decoding of the input data is done.
 *
 * This function must be called from a command decoder and an event decoder
 * as soon as the input was parsed. If a response is decoded inside a command
 * encoder (i.e. using @a nrf_rpc_cmd_rsp_send) then this function also must
 * be called. If a response is decoded in separete handler (i.e. using
 * @a nrf_rpc_cmd_send or @a nrf_rpc_cmd_send_noerr) then this function cannot
 * be called. Content of the input data is no longer valid after this function
 * call.
 */
void nrf_rpc_decoding_done(const uint8_t *packet);


/** @brief Function for handling errors that cannot be exposed as an API return
 * value.
 *
 * Some errors (e.g. corrupted packet received) cannot be easily returned by a
 * function, because there was no actual function call from user.
 * `nrf_rpc_error_handler` function will be called in case of such error. It is
 * weakly defined as empty function, so user can provide a different
 * implementation.
 *
 * @param tr_local_ep  Local endpoint associated with an error or NULL if it is
 *                     unknown.
 * @param tr_remote_ep Remote encpoint associated with an error or NULL if it is
 *                     unknown.
 * @param cmd_evt_id   Id of command or event that cause the error or
 *                     @ref NRF_RPC_UNKNOWN_ID.
 * @param code         Error code
 * @param from_remote  If error occurred on the remote side.
 */
void nrf_rpc_error_handler(int code, bool from_remote);


/** @brief Function to pass errors from encoder function to
 * @ref nrf_rpc_error_handler.
 *
 * @param ctx        Context allocated by the @ref NRF_RPC_CMD_ALLOC or
 *                   the @ref NRF_RPC_EVT_ALLOC.
 * @param cmd_evt_id Id of command or event that cause the error or
 *                   @ref NRF_RPC_UNKNOWN_ID.
 * @param code       Error code
 */
void nrf_rpc_report_error(int code);


/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* _NRF_RPC_H_ */
