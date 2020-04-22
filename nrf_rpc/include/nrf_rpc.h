/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <nrf_rpc_errors.h>
#include <nrf_rpc_common.h>
#include <nrf_rpc_tr.h>

/** @brief First id of the nRF RPC group that can be used by the user */
#define NRF_RPC_USER_GROUP_ID_FIRST 64

/** @brief Biggest possible id of the nRF RPC group */
#define NRF_RPC_GROUP_ID_LAST 127


#define _NRF_RPC_HEADER_SIZE 2


/** @brief Callback that handles decoding of commands, events and responses.
 * 
 * @param packet       Packet data.
 * @param len          Length of the packet.
 * @param handler_data Custom handler data. In case of commands, events it is a
 *                     pointer to @a nrf_rpc_decoder structure associated with
 *                     this command or event. In case of response handler it is
 *                     an opaque pointer provided to @a NRF_RPC_CMD_SEND.
 */
typedef int (*nrf_rpc_handler)(const uint8_t *packet, size_t len,
	void *handler_data);


/** @brief Command and event decoder structure.
 * 
 * Created by @a NRF_RPC_CMD_DECODER or @a NRF_RPC_EVT_DECODER.
 */
struct nrf_rpc_decoder {

	/** @brief Command or event code. */
	uint8_t code;

	/** @brief Command or event decoder. */
	nrf_rpc_handler handler;
};


/** @brief Defines a group of commands and events.
 * 
 * One group is mostly assigned to a single API that needs to be serialized.
 * Created by @a NRF_RPC_GROUP_DEFINE.
 */
struct nrf_rpc_group {
	uint8_t group_id;
	const void *cmd_array;
	const void *evt_array;
};


/** @brief Contains information about remote endpoint.
 */
struct nrf_rpc_remote_ep {
	struct nrf_rpc_tr_remote_ep tr_ep;
	uint8_t current_group_id;
};


/** @brief Contains information about local endpoint.
 */
struct nrf_rpc_local_ep {
	struct nrf_rpc_tr_local_ep tr_ep;
	struct nrf_rpc_remote_ep *default_dst;
	uint32_t cmd_nesting_counter;
	nrf_rpc_handler handler;
	void *handler_data;
};


/** @brief Define a group of commands and events
 * 
 * @param _name  Symbol name for the group
 * @param _id    Unique identified of the group
 */
#define NRF_RPC_GROUP_DEFINE(_name, _id) \
	NRF_RPC_ORD_VAR_ARRAY(RP_CONCAT(_name, _cmd_array), "cmd_" RP_STRINGIFY(_name));      \
	NRF_RPC_ORD_VAR_ARRAY(RP_CONCAT(_name, _evt_array), "evt_" RP_STRINGIFY(_name));      \
	NRF_RPC_ORD_VAR_CREATE(const struct nrf_rpc_group, _name, "grp", RP_STRINGIFY(_name)) \
	 = {		  \
		.group_id = (_id), \
		.cmd_array = &RP_CONCAT(_name, _cmd_array),			\
		.evt_array = &RP_CONCAT(_name, _evt_array),			\
	};


#define NRF_RPC_CMD_DECODER(_group, _name, _cmd, _handler) \
	RP_STATIC_ASSERT(_cmd <= 0xFE, "Command out of range");     \
	NRF_RPC_ORD_VAR_CREATE(const struct nrf_rpc_decoder, RP_CONCAT(_name, _cmd_dec), "cmd_" RP_STRINGIFY(_group), RP_STRINGIFY(_name)) \
	 = {   \
		.code = _cmd,					    \
		.handler = _handler,				    \
	}

#define NRF_RPC_EVT_DECODER(_group, _name, _evt, _handler) \
	RP_STATIC_ASSERT(_evt <= 0xFE, "Event out of range");     \
	NRF_RPC_ORD_VAR_CREATE(const struct nrf_rpc_decoder, RP_CONCAT(_name, _evt_dec), "evt_" RP_STRINGIFY(_group), RP_STRINGIFY(_name)) \
	 = {   \
		.code = _evt,					    \
		.handler = _handler,				    \
	}

/** @brief Allocates resources for a new command.
 * 
 * Macro may allocate some variables on stack, so it should be used at top level
 * of a function.
 * 
 * @param      group  Group that command belongs to.
 * @param[out] ep     Variable of type `nrf_rpc_local_ep *` that will hold the
 *                    source endpoint for this command.
 * @param[out] packet Variable of type `uint8_t *` that will hold pointer to
 *                    newly allocated packet buffer.
 * @param      len    Requested length of the packet.
 * @param __VA_ARGS__ Code that will be executed in case of allocation failure.
 *                    This can be e.g. return or goto statement.
 */
#define NRF_RPC_CMD_ALLOC(ep, group, packet, len, ...)			       \
	(ep) = _nrf_rpc_cmd_prepare((group));				       \
	nrf_rpc_tr_alloc_tx_buf(&(ep)->tr_ep, &(packet),		       \
				_NRF_RPC_HEADER_SIZE + (len));		       \
	if (nrf_rpc_tr_alloc_failed((packet))) {			       \
		_nrf_rpc_cmd_alloc_error(ep);				       \
		__VA_ARGS__;						       \
	}								       \
	(packet) += _NRF_RPC_HEADER_SIZE


/** @brief Discards resources allocated for a new command.
 * 
 * This macro should be used if a command was allocated, but it will not be send
 * with @a NRF_RPC_CMD_SEND.
 * 
 * @param ep     Endpoint that was previously assigned to send the command.
 * @param packet Packet that was previously allocated to send the command.
 */
#define NRF_RPC_CMD_DISCARD(ep, packet)					       \
	_nrf_rpc_cmd_unprepare();					       \
	nrf_rpc_tr_free_tx_buf(&(ep)->tr_ep, (packet))

/** @brief Allocates resources for a new event.
 * 
 * Macro may allocate some variables on stack, so it should be used at top level
 * of a function.
 * 
 * @param      group  Group that event belongs to.
 * @param[out] ep     Variable of type `nrf_rpc_remote_ep *` that will hold the
 *                    destination endpoint for this event.
 * @param[out] packet Variable of type `uint8_t *` that will hold pointer to
 *                    newly allocated packet buffer.
 * @param      len    Requested length of the packet.
 * @param __VA_ARGS__ Code that will be executed in case of allocation failure.
 *                    This can be e.g. return or goto statement.
 */
#define NRF_RPC_EVT_ALLOC(ep, group, packet, len, ...)			       \
	(ep) = _nrf_rpc_evt_prepare((group));				       \
	nrf_rpc_tr_alloc_tx_buf(&(ep)->tr_ep, &(packet),		       \
				_NRF_RPC_HEADER_SIZE + (len));		       \
	if (nrf_rpc_tr_alloc_failed((packet))) {			       \
		_nrf_rpc_evt_alloc_error((ep));				       \
		__VA_ARGS__;						       \
	}								       \
	(packet) += _NRF_RPC_HEADER_SIZE


/** @brief Discards resources allocated for a new event.
 * 
 * This macro should be used if an event was allocated, but it will not be send
 * with @a NRF_RPC_EVT_SEND.
 * 
 * @param ep     Endpoint that was previously assigned to send the event.
 * @param packet Packet that was previously allocated to send the event.
 */
#define NRF_RPC_EVT_DISCARD(ep, packet)					       \
	_nrf_rpc_evt_unprepare((ep));					       \
	nrf_rpc_tr_free_tx_buf(&(ep)->tr_ep, (packet))


/** @brief Allocates resources for a response.
 * 
 * Macro may allocate some variables on stack, so it should be used at top level
 * of a function.
 * 
 * @param[out] ep     Variable of type `nrf_rpc_remote_ep *` that will hold the
 *                    destination endpoint for this response.
 * @param[out] packet Variable of type `uint8_t *` that will hold pointer to
 *                    newly allocated packet buffer.
 * @param      len    Requested length of the packet.
 * @param __VA_ARGS__ Code that will be executed in case of allocation failure.
 *                    This can be e.g. return or goto statement.
 */
#define NRF_RPC_RSP_ALLOC(ep, packet, len, ...)				       \
	(ep) = _nrf_rpc_rsp_prepare();					       \
	nrf_rpc_tr_alloc_tx_buf(&(ep)->tr_ep, &(packet),		       \
				_NRF_RPC_HEADER_SIZE + (len));		       \
	if (nrf_rpc_tr_alloc_failed((packet))) {			       \
		__VA_ARGS__;						       \
	}								       \
	(packet) += _NRF_RPC_HEADER_SIZE


/** @brief Discards resources allocated for a response.
 * 
 * This macro should be used if an event was allocated, but it will not be send
 * with @a NRF_RPC_RSP_SEND.
 * 
 * @param ep     Endpoint that was previously assigned to send the response.
 * @param packet Packet that was previously allocated to send the response.
 */
#define NRF_RPC_RSP_DISCARD(ep, packet)					       \
	nrf_rpc_tr_free_tx_buf(&(ep)->tr_ep, (packet))


/* Internal functions used by the macros only. */
struct nrf_rpc_remote_ep *_nrf_rpc_cmd_prepare(const struct nrf_rpc_group *group);
void _nrf_rpc_cmd_alloc_error(struct nrf_rpc_remote_ep *remote_ep);
void _nrf_rpc_cmd_unprepare(void);
struct nrf_rpc_remote_ep *_nrf_rpc_evt_prepare(const struct nrf_rpc_group *group);
void _nrf_rpc_evt_alloc_error(struct nrf_rpc_remote_ep *remote_ep);
void _nrf_rpc_evt_unprepare(struct nrf_rpc_remote_ep *remote_ep);
struct nrf_rpc_remote_ep *_nrf_rpc_rsp_prepare();


/** @brief Send a new command.
 * 
 * @param      group  Group that command belongs to.
 * @param      cmd    Command code.
 * @param[out] ep     Variable of type `nrf_rpc_remote_ep *` that will hold the
 *                    destination endpoint for this command.
 * @param[out] packet Variable of type `uint8_t *` that will hold pointer to
 *                    newly allocated packet buffer.
 * @param      len    Requested length of the packet.
 * @param __VA_ARGS__ Code that will be executed in case of allocation failure.
 *                    This can be e.g. return or goto statement.
 * @returns           
 */
int nrf_rpc_cmd_send(struct nrf_rpc_remote_ep *remote_ep, uint8_t cmd,
			  uint8_t *packet, size_t len, nrf_rpc_handler handler,
			  void *handler_data);

int nrf_rpc_evt_send(struct nrf_rpc_remote_ep *remote_ep, uint8_t evt,
			  uint8_t *packet, size_t len);

int nrf_rpc_rsp_send(struct nrf_rpc_remote_ep *remote_ep, uint8_t *packet,
			  size_t len);

void nrf_rpc_decoding_done();

int nrf_rpc_init(void);

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
 * @param code         Error code
 * @param from_remote  If error occurred on the remote side.
 */
void nrf_rpc_error_handler(struct nrf_rpc_tr_local_ep *tr_local_ep,
			   struct nrf_rpc_tr_remote_ep *tr_remote_ep, int code,
			   bool from_remote);

