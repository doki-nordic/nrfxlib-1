/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define NRF_RPC_LOG_MODULE NRF_RPC
#include <nrf_rpc_log.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "nrf_rpc.h"
#include "nrf_rpc_tr.h"

#define ERROR_FLAG_REMOTE 1
#define ERROR_FLAG_SEND 2

#define CMD_FLAG_WITH_RSP 0x10000

enum {
	/* Packet types with header variant 1:
	 *      byte 0: bit 7: packet type, bits 6-0: group id,
	 *      byte 1: command/event id
	 */
	PACKET_TYPE_CMD = 0x00,
	PACKET_TYPE_EVT = 0x80,

	/* Packet types with header variant 2:
	 *      byte 0: packet type
	 *      byte 1: 0xFF,
	 */
	PACKET_TYPE_RSP = 0x01,
	PACKET_TYPE_ACK = 0x02,
	PACKET_TYPE_ERR = 0x03,
};


/* Array with all defiend groups */
NRF_RPC_AUTO_ARR(nrf_rpc_groups_array, "grp");


/* ======================== Common utilities ======================== */


/** Put header variant 1 into packet based on specified parameters */
static inline void header_variant_1(uint8_t* packet, uint8_t type,
				    uint8_t group_id, uint8_t id)
{
	packet[0] = type | group_id;
	packet[1] = id;
}


/** Put header variant 2 into packet based on specified parameters */
static inline void header_variant_2(uint8_t* packet, uint8_t type)
{
	packet[0] = type;
	packet[1] = 0xFF;
}


/** Function simplifying sending a short packets */
static int send_simple(struct nrf_rpc_tr_local_ep *tr_local_ep,
		       struct nrf_rpc_tr_remote_ep *tr_remote_ep, uint8_t type,
		       const uint8_t *packet, size_t len)
{
	uint8_t *tx_buf;

	nrf_rpc_tr_alloc_tx_buf(tr_remote_ep, &tx_buf,
				_NRF_RPC_HEADER_SIZE + len);

	if (nrf_rpc_tr_alloc_failed(tx_buf)) {
		return NRF_RPC_ERR_NO_MEM;
	}

	header_variant_2(tx_buf, type);

	if (packet != NULL && len > 0) {
		memcpy(&tx_buf[_NRF_RPC_HEADER_SIZE], packet, len);
	}

	return nrf_rpc_tr_send(tr_local_ep, tr_remote_ep, tx_buf,
			       _NRF_RPC_HEADER_SIZE + len);
}


/** Report an error that cannot be reported as a function return value */
static void report_error(struct nrf_rpc_tr_local_ep *tr_local_ep,
			 struct nrf_rpc_tr_remote_ep *tr_remote_ep, int code,
			 uint32_t flags)
{
	NRF_RPC_ERR("%sERROR: code=%d local=%d remote=%d",
		   flags & ERROR_FLAG_REMOTE ? "REMOTE " : "", code,
		   tr_local_ep ? tr_local_ep->addr : -1,
		   tr_remote_ep ? tr_remote_ep->addr : -1);

	nrf_rpc_error_handler(tr_local_ep, tr_remote_ep, code,
			      flags & ERROR_FLAG_REMOTE);

	if (flags & ERROR_FLAG_SEND) {
		int8_t data = (int8_t)code;

		send_simple(tr_local_ep, tr_remote_ep, PACKET_TYPE_ERR, &data,
			    sizeof(data));
	}
}


static inline bool valid_packet(const uint8_t *packet)
{
	uintptr_t addr = (uintptr_t)packet;
	/* Checking NULL may be sometimes not enough, because pointer can be
	 * shifted by size of headers. */
	return (addr > NRF_RPC_TR_MAX_HEADER_SIZE + _NRF_RPC_HEADER_SIZE) &&
	       (addr < (uintptr_t)0 - (uintptr_t)NRF_RPC_TR_MAX_HEADER_SIZE -
		       (uintptr_t)_NRF_RPC_HEADER_SIZE);
}


/* ======================== Receiving Packets ======================== */


/** Find in array and execute command or event handler */
static int handler_execute(uint8_t id, const uint8_t *packet, size_t len,
			   const void *array)
{
	int err;
	void *iter;
	const struct nrf_rpc_decoder *decoder;

	NRF_RPC_ASSERT(valid_packet(packet));
	NRF_RPC_ASSERT(array != NULL);

	for (NRF_RPC_AUTO_ARR_FOR(iter, decoder, array,
				 const struct nrf_rpc_decoder)) {

		if (id == decoder->id) {
			err = decoder->handler(packet, len,
					       decoder->handler_data);
			if (err < 0) {
				NRF_RPC_ERR("Command or event handler "
					   "returned an error %d", err);
			}
			return err;
		}
	}

	NRF_RPC_ERR("Unsupported command or event received");
	return NRF_RPC_ERR_NOT_SUPPORTED;
}


/** Search for a group based on group_id */
static const struct nrf_rpc_group *group_from_id(uint8_t group_id)
{
	void *iter;
	const struct nrf_rpc_group *group;

	for (NRF_RPC_AUTO_ARR_FOR(iter, group, &nrf_rpc_groups_array,
				 const struct nrf_rpc_group)) {

		if (group->group_id == group_id) {
			return group;
		}
	}

	NRF_RPC_ERR("Unknown group 0x%02X", group_id);
	return NULL;
}


/** Parse incoming packet and execute if needed.
 *
 * @param local_ep          Local receiving endpoint.
 * @param tr_remote_ep      Remote sending endpoint. Can be NULL if packet was
 *                          send without providing a source endpoint.
 * @param packet            Packer to parse.
 * @param len               Length of the packet.
 * @param response_expected If packet contains response and this parameter is
 *                          false then error code will be returned.
 * @return NRF_RPC_SUCCESS if packet was correctly parsed and executed.
 *         PACKET_TYPE_RSP if packet contains a response and response_expected
 *         was true. Negative error code on failure.
 */
static int parse_incoming_packet(struct nrf_rpc_local_ep *local_ep,
				 struct nrf_rpc_tr_remote_ep *tr_remote_ep,
				 const uint8_t *packet, size_t len,
				 bool response_expected)
{
	int result;
	int send_result;
	uint8_t id;
	uint8_t type;
	const struct nrf_rpc_group *group = NULL;
	struct nrf_rpc_remote_ep *old_default_dst;
	struct nrf_rpc_remote_ep *remote_ep = NRF_RPC_CONTAINER_OF(tr_remote_ep,
		struct nrf_rpc_remote_ep, tr_ep);

	/* Validate required parameters */
	NRF_RPC_ASSERT(local_ep != NULL);
	NRF_RPC_ASSERT(valid_packet(packet));

	if (len < _NRF_RPC_HEADER_SIZE) {
		result = NRF_RPC_ERR_INTERNAL;
		goto exit_function;
	}

	/* Parse header */
	type = packet[0];
	id = packet[1];
	if (id != 0xFF) {
		group = group_from_id(type & 0x7F);
		type &= 0x80;
	}

	switch (type)
	{
	case PACKET_TYPE_CMD:
		/* Group and remote endpoint must be known for the commands */
		if (group == NULL || tr_remote_ep == NULL) {
			result = NRF_RPC_ERR_INTERNAL;
			goto exit_function;
		}
		/* Default destination is set to sender and restored later */
		old_default_dst = local_ep->default_dst;
		local_ep->default_dst = remote_ep;
		/* Executing associated handler from command array */
		NRF_RPC_DBG("Executing command 0x%02X from group 0x%02X", id,
			   group->group_id);
		result = handler_execute(id, &packet[_NRF_RPC_HEADER_SIZE],
					 len - _NRF_RPC_HEADER_SIZE,
					 group->cmd_array);
		local_ep->default_dst = old_default_dst;
		break;

	case PACKET_TYPE_EVT:
		/* Group must be known for the events */
		if (group == NULL) {
			result = NRF_RPC_ERR_INTERNAL;
			goto exit_function;
		}
		/* Executing associated handler from event array */
		NRF_RPC_DBG("Executing event 0x%02X from group 0x%02X", id,
			   group->group_id);
		result = handler_execute(id, &packet[_NRF_RPC_HEADER_SIZE],
					 len - _NRF_RPC_HEADER_SIZE,
					 group->evt_array);
		/* Always send back ACK even in case of handler failure */
		send_result = send_simple(&local_ep->tr_ep, NULL,
					  PACKET_TYPE_ACK, NULL, 0);
		if (send_result < 0) {
			NRF_RPC_ERR("ACK sending error %d", send_result);
		}
		/* Select correct error code if any */
		result = (result < 0) ? result : send_result;
		break;

	case PACKET_TYPE_RSP:
		if (response_expected) {
			/* Return packet type and skip buffer releasing */
			NRF_RPC_DBG("Response received");
			return type;
		} else {
			NRF_RPC_ERR("Response not expected at this point");
			result = NRF_RPC_ERR_INVALID_STATE;
		}
		break;

	case PACKET_TYPE_ERR:
	case PACKET_TYPE_ACK:
	default:
		/* ERR and ACK packets should be handled before in filter */
		NRF_RPC_ERR("Packet type 0x%02X not expected", type);
		result = NRF_RPC_ERR_INVALID_STATE;
		break;
	}

exit_function:
	/* Make sure that input buffer is released. Can be called twice. */
	nrf_rpc_tr_release_buffer(&local_ep->tr_ep);

	return result;
}


/** Callback from transport layer that handles incoming packet directed to
 * thread from the thread pool.
 *
 * @param tr_local_ep  Local destination endpoint of the packet.
 * @param tr_remote_ep Remote source endpoint of the packet. Can be NULL if
 *                     source was not specified by sending side.
 * @param packet       Incoming packet or NULL if packet was filtered by
 *                     @a filter_handler.
 * @param len          Length of the packet, packet type returned from
 *                     @a filter_handler if packet was filtered or negative
 *                     error code to indicate some error during receiving
 *                     packet.
 */
static void receive_handler(struct nrf_rpc_tr_local_ep *tr_local_ep,
			    struct nrf_rpc_tr_remote_ep *tr_remote_ep,
			    const uint8_t *packet, int len)
{
	int err = NRF_RPC_SUCCESS;
	struct nrf_rpc_local_ep *local_ep = NRF_RPC_CONTAINER_OF(tr_local_ep,
		struct nrf_rpc_local_ep, tr_ep);

	NRF_RPC_ASSERT(tr_local_ep != NULL);

	if (len < 0) {
		err = len;
		NRF_RPC_ERR("Packet receive error %d", err);
	} else if (packet != NULL) {
		err = parse_incoming_packet(local_ep, tr_remote_ep, packet, len,
					    false);
	}

	if (err < 0) {
		report_error(tr_local_ep, tr_remote_ep, err, ERROR_FLAG_SEND);
	}
}


/** Callback from transport layer to filter incoming packets before they go
 * to destination thread.
 *
 * @param tr_local_ep  Local destination endpoint of the packet. Can be NULL
 *                     if packet was not send to any specific endpoint.
 * @param tr_remote_ep Remote source endpoint of the packet. Can be NULL if
 *                     source was not specified by sending side.
 * @param packet       Incoming packet.
 * @param len          Length of the packet or negative error code to indicate
 *                     some error during receiving packet.
 * @return 0 to pass packet to destination thread. Positive value with packet
 *         type to indicate that packet was filered out.
 */
static uint32_t filter_handler(struct nrf_rpc_tr_local_ep *tr_local_ep,
			       struct nrf_rpc_tr_remote_ep *tr_remote_ep,
			       const uint8_t *packet, int len)
{
	uint8_t type;
	int err = NRF_RPC_SUCCESS;
	struct nrf_rpc_local_ep *local_ep = NRF_RPC_CONTAINER_OF(tr_local_ep,
		struct nrf_rpc_local_ep, tr_ep);

	NRF_RPC_ASSERT(valid_packet(packet));

	if (len < 0) {
		err = len;
	} else if (len < _NRF_RPC_HEADER_SIZE) {
		err = NRF_RPC_ERR_INTERNAL;
	}

	if (err < 0) {
		NRF_RPC_ERR("Packet receive error %d", err);
		report_error(tr_local_ep, tr_remote_ep, err, 0);
		return PACKET_TYPE_ERR;
	}

	type = packet[0];

	switch (type) {
	case PACKET_TYPE_ACK:
		NRF_RPC_DBG("ACK received from EP[%d]",
			   tr_remote_ep != NULL ? tr_remote_ep->addr : -1);
		nrf_rpc_tr_remote_release(tr_remote_ep);
		return type;

	case PACKET_TYPE_ERR:
		if (len >= _NRF_RPC_HEADER_SIZE + 1) {
			report_error(tr_local_ep, tr_remote_ep,
				     (int8_t)packet[_NRF_RPC_HEADER_SIZE],
				     ERROR_FLAG_REMOTE);
		}
		return type;

	case PACKET_TYPE_RSP:
		if (tr_local_ep == NULL) {
			NRF_RPC_ERR("Response arrived to unexpected endpoint");
			report_error(tr_local_ep, tr_remote_ep,
				     NRF_RPC_ERR_INVALID_STATE, 0);
			return PACKET_TYPE_ERR;
		} else if (local_ep->handler != NULL) {
			NRF_RPC_DBG("Executing response handler");
			err = local_ep->handler(&packet[_NRF_RPC_HEADER_SIZE],
						len - _NRF_RPC_HEADER_SIZE,
						local_ep->handler_data);
			local_ep->handler = NULL;
			if (err < 0) {
				NRF_RPC_ERR("Response handler returned an "
					   "error %d", err);
				report_error(tr_local_ep, tr_remote_ep, err, 0);
			}
			return type;
		}
		break;

	default:
		break;
	}

	return 0;
}


void nrf_rpc_decoding_done(void)
{
	struct nrf_rpc_tr_local_ep *tr_local_ep = nrf_rpc_tr_current_get();

	NRF_RPC_DBG("Done of decoding process reported");
	nrf_rpc_tr_release_buffer(tr_local_ep);
}


/* ======================== Command sending ======================== */


struct nrf_rpc_tr_remote_ep *_nrf_rpc_cmd_prep(
	const struct nrf_rpc_group *group)
{
	struct nrf_rpc_tr_remote_ep *tr_remote_ep;
	struct nrf_rpc_remote_ep *remote_ep;
	struct nrf_rpc_tr_local_ep *tr_local_ep = nrf_rpc_tr_current_get();
	struct nrf_rpc_local_ep *local_ep = NRF_RPC_CONTAINER_OF(tr_local_ep,
		struct nrf_rpc_local_ep, tr_ep);

	NRF_RPC_ASSERT(group != NULL);

	if (tr_local_ep == NULL) {
		NRF_RPC_ERR("Not enough local endpoints");
		return NULL;
	}

	if (local_ep->default_dst == NULL) {
		tr_remote_ep = nrf_rpc_tr_remote_reserve();
		remote_ep = NRF_RPC_CONTAINER_OF(tr_remote_ep,
			struct nrf_rpc_remote_ep, tr_ep);
		local_ep->default_dst = remote_ep;
		local_ep->cmd_nesting_counter = 1;
		NRF_RPC_DBG("Default destination EP[%d] assigned to EP[%d]",
			   tr_remote_ep->addr, tr_local_ep->addr);
	} else {
		local_ep->cmd_nesting_counter++;
	}

	local_ep->default_dst->current_group_id = group->group_id;

	return &local_ep->default_dst->tr_ep;
}


void _nrf_rpc_cmd_alloc_error(struct nrf_rpc_tr_remote_ep *tr_remote_ep)
{
	struct nrf_rpc_tr_local_ep *tr_local_ep = nrf_rpc_tr_current_get();

	NRF_RPC_ERR("Command allocation failed");
	report_error(tr_local_ep, tr_remote_ep, NRF_RPC_ERR_NO_MEM, 0);

	_nrf_rpc_cmd_unprep();
}


void _nrf_rpc_cmd_unprep(void)
{
	struct nrf_rpc_tr_local_ep *tr_local_ep = nrf_rpc_tr_current_get();
	struct nrf_rpc_local_ep *local_ep = NRF_RPC_CONTAINER_OF(tr_local_ep,
		struct nrf_rpc_local_ep, tr_ep);

	if (tr_local_ep == NULL) {
		return;
	}

	local_ep->cmd_nesting_counter--;
	if (local_ep->cmd_nesting_counter == 0) {
		NRF_RPC_DBG("Default destination EP[%d] unassigned from EP[%d]",
			   local_ep->default_dst->tr_ep.addr,
			   tr_local_ep->addr);
		nrf_rpc_tr_remote_release(&local_ep->default_dst->tr_ep);
		local_ep->default_dst = NULL;
	}
}

/** Wait for response after sending a command.
 *
 * Setting @a rsp_packet and @a rsp_len to NULL informs that the response packet
 * should be handled from filter function before it gets here.
 *
 * @param      local_ep   Endpoint that will receive the response.
 * @param[out] rsp_packet If not NULL contains response packet data.
 * @param[out] rsp_len    If not NULL contains response packet length.
 * @return NRF_RPC_SUCCESS on success or negative error code.
 */
static int wait_for_response(struct nrf_rpc_local_ep *local_ep,
			     const uint8_t **rsp_packet, size_t *rsp_len)
{
	uint8_t type;
	int len;
	struct nrf_rpc_tr_remote_ep *tr_remote_ep;
	const uint8_t *packet;

	NRF_RPC_ASSERT(local_ep != NULL);

	NRF_RPC_DBG("Waiting for response");

	do {
		len = nrf_rpc_tr_read(&local_ep->tr_ep, &tr_remote_ep, &packet);

		if (len < 0) {
			return  len;
		}

		if (packet == NULL) {
			NRF_RPC_DBG("Filtered packet of type 0x%02X received",
				   len);
			if (len == PACKET_TYPE_ERR) {
				return NRF_RPC_ERR_REMOTE;
			} if (len == PACKET_TYPE_RSP) {
				return NRF_RPC_SUCCESS;
			} else {
				continue;
			}
		}

		type = parse_incoming_packet(local_ep, tr_remote_ep, packet,
					     len, (rsp_packet != NULL));

		if (type < 0) {
			return type;
		}

	} while (type != PACKET_TYPE_RSP);

	if (rsp_packet != NULL && rsp_len != NULL) {
		*rsp_packet = &packet[_NRF_RPC_HEADER_SIZE];
		*rsp_len = len - _NRF_RPC_HEADER_SIZE;
	}

	return NRF_RPC_SUCCESS;
}


static int cmd_send_common(struct nrf_rpc_tr_remote_ep *tr_remote_ep,
			   uint32_t cmd, uint8_t *packet, size_t len,
			   void *ptr1, void *ptr2)
{
	int err;
	nrf_rpc_handler_t old_handler;
	void *old_handler_data;
	struct nrf_rpc_tr_local_ep *tr_local_ep = nrf_rpc_tr_current_get();
	struct nrf_rpc_local_ep *local_ep = NRF_RPC_CONTAINER_OF(tr_local_ep,
		struct nrf_rpc_local_ep, tr_ep);
	struct nrf_rpc_remote_ep *remote_ep = NRF_RPC_CONTAINER_OF(tr_remote_ep,
		struct nrf_rpc_remote_ep, tr_ep);
	uint8_t *full_packet = &packet[-_NRF_RPC_HEADER_SIZE];
	nrf_rpc_handler_t handler = NULL;
	void *handler_data = NULL;
	const uint8_t **rsp_packet = NULL;
	size_t *rsp_len = NULL;

	NRF_RPC_ASSERT(valid_packet(packet));
	NRF_RPC_ASSERT(ptr1 != NULL);

	if (tr_local_ep == NULL || tr_remote_ep == NULL) {
		NRF_RPC_ERR("Invalid endpoint");
		return NRF_RPC_ERR_NO_MEM;
	}

	if (cmd & CMD_FLAG_WITH_RSP) {
		NRF_RPC_ASSERT(ptr2 != NULL);
		rsp_packet = ptr1;
		rsp_len = ptr2;
	} else {
		handler = ptr1;
		handler_data = ptr2;
	}

	header_variant_1(full_packet, PACKET_TYPE_CMD,
			 remote_ep->current_group_id, cmd);

	old_handler = local_ep->handler;
	old_handler_data = local_ep->handler_data;
	local_ep->handler = handler;
	local_ep->handler_data = handler_data;

	NRF_RPC_DBG("Sending command 0x%02X from group 0x%02X", cmd,
		   remote_ep->current_group_id);

	err = nrf_rpc_tr_send(tr_local_ep, tr_remote_ep, full_packet,
			      len + _NRF_RPC_HEADER_SIZE);
	if (err < 0) {
		goto error_exit;
	}

	err = wait_for_response(local_ep, rsp_packet, rsp_len);

error_exit:

	_nrf_rpc_cmd_unprep();

	if (err < 0) {
		nrf_rpc_tr_release_buffer(tr_local_ep);
	}

	local_ep->handler = old_handler;
	local_ep->handler_data = old_handler_data;

	return err;
}


int nrf_rpc_cmd_send(nrf_rpc_alloc_ctx ctx, uint8_t cmd, uint8_t *packet,
		     size_t len, nrf_rpc_handler_t handler, void *handler_data)
{
	struct nrf_rpc_tr_remote_ep *tr_remote_ep = ctx;

	return cmd_send_common(tr_remote_ep, cmd, packet, len, handler,
			       handler_data);
}


int nrf_rpc_cmd_rsp_send(nrf_rpc_alloc_ctx ctx, uint8_t cmd, uint8_t *packet,
			 size_t len, const uint8_t **rsp_packet,
			 size_t *rsp_len)
{
	struct nrf_rpc_tr_remote_ep *tr_remote_ep = ctx;

	return cmd_send_common(tr_remote_ep, cmd | CMD_FLAG_WITH_RSP, packet,
			       len, rsp_packet, rsp_len);
}


void nrf_rpc_cmd_send_noerr(nrf_rpc_alloc_ctx ctx, uint8_t cmd, uint8_t *packet,
			    size_t len, nrf_rpc_handler_t handler,
			    void *handler_data)
{
	int err;
	struct nrf_rpc_tr_local_ep *tr_local_ep;
	struct nrf_rpc_tr_remote_ep *tr_remote_ep = ctx;

	err = cmd_send_common(tr_remote_ep, cmd, packet, len, handler,
			      handler_data);
	if (err < 0) {
		NRF_RPC_ERR("Unhandled command send error %d", err);
		tr_local_ep = nrf_rpc_tr_current_get();
		report_error(tr_local_ep, tr_remote_ep, err, 0);
	}
}


/* ======================== Event sending ======================== */


struct nrf_rpc_tr_remote_ep *_nrf_rpc_evt_prep(
	const struct nrf_rpc_group *group)
{
	struct nrf_rpc_tr_remote_ep *tr_remote_ep = nrf_rpc_tr_remote_reserve();
	struct nrf_rpc_remote_ep *remote_ep = NRF_RPC_CONTAINER_OF(tr_remote_ep,
		struct nrf_rpc_remote_ep, tr_ep);

	remote_ep->current_group_id = group->group_id;

	return &remote_ep->tr_ep;
}


void _nrf_rpc_evt_alloc_error(struct nrf_rpc_tr_remote_ep *tr_remote_ep)
{
	NRF_RPC_ERR("Event allocation failed");
	report_error(NULL, tr_remote_ep, NRF_RPC_ERR_NO_MEM, 0);
	_nrf_rpc_evt_unprep(tr_remote_ep);
}


void _nrf_rpc_evt_unprep(struct nrf_rpc_tr_remote_ep *tr_remote_ep)
{
	NRF_RPC_ASSERT(tr_remote_ep != NULL);
	nrf_rpc_tr_remote_release(tr_remote_ep);
}


int nrf_rpc_evt_send(nrf_rpc_alloc_ctx ctx, uint8_t evt, uint8_t *packet,
		     size_t len)
{
	int err;
	struct nrf_rpc_tr_remote_ep *tr_remote_ep = ctx;
	struct nrf_rpc_remote_ep *remote_ep = NRF_RPC_CONTAINER_OF(tr_remote_ep,
		struct nrf_rpc_remote_ep, tr_ep);
	uint8_t *full_packet = &packet[-_NRF_RPC_HEADER_SIZE];

	NRF_RPC_ASSERT(valid_packet(packet));
	NRF_RPC_ASSERT(tr_remote_ep != NULL);

	header_variant_1(full_packet, PACKET_TYPE_EVT,
			 remote_ep->current_group_id, evt);

	NRF_RPC_DBG("Sending event 0x%02X from group 0x%02X", evt,
		   remote_ep->current_group_id);

	err = nrf_rpc_tr_send(NULL, tr_remote_ep, full_packet,
			      len + _NRF_RPC_HEADER_SIZE);

	return err;
}


void nrf_rpc_evt_send_noerr(nrf_rpc_alloc_ctx ctx, uint8_t evt, uint8_t *packet,
			    size_t len)
{
	int err;
	struct nrf_rpc_tr_remote_ep *tr_remote_ep = ctx;

	err = nrf_rpc_evt_send(tr_remote_ep, evt, packet, len);
	if (err < 0) {
		NRF_RPC_ERR("Unhandled event send error %d", err);
		report_error(NULL, tr_remote_ep, err, 0);
	}
}


/* ======================== Response sending ======================== */


struct nrf_rpc_tr_remote_ep *_nrf_rpc_rsp_prep()
{
	struct nrf_rpc_tr_local_ep *tr_local_ep = nrf_rpc_tr_current_get();
	struct nrf_rpc_local_ep *local_ep = NRF_RPC_CONTAINER_OF(tr_local_ep,
		struct nrf_rpc_local_ep, tr_ep);

	NRF_RPC_ASSERT(local_ep != NULL);
	NRF_RPC_ASSERT(local_ep->default_dst != NULL);

	return &local_ep->default_dst->tr_ep;
}


int nrf_rpc_rsp_send(nrf_rpc_alloc_ctx ctx, uint8_t *packet, size_t len)
{
	int err;
	struct nrf_rpc_tr_remote_ep *tr_remote_ep = ctx;
	struct nrf_rpc_tr_local_ep *tr_local_ep = nrf_rpc_tr_current_get();
	uint8_t *full_packet = &packet[-_NRF_RPC_HEADER_SIZE];

	NRF_RPC_ASSERT(valid_packet(packet));
	NRF_RPC_ASSERT(tr_remote_ep != NULL);
	NRF_RPC_ASSERT(tr_local_ep != NULL);

	header_variant_2(full_packet, PACKET_TYPE_RSP);

	NRF_RPC_DBG("Sending response");

	err = nrf_rpc_tr_send(tr_local_ep, tr_remote_ep, full_packet,
			      len + _NRF_RPC_HEADER_SIZE);

	return err;
}


/* ======================== Common API functions ======================== */


int nrf_rpc_init(void)
{
	NRF_RPC_DBG("Initializing nRF RPC Module");
	return nrf_rpc_tr_init(receive_handler, filter_handler);
}


__attribute__((weak))
void nrf_rpc_error_handler(struct nrf_rpc_tr_local_ep *tr_local_ep,
			   struct nrf_rpc_tr_remote_ep *tr_remote_ep, int code,
			   bool from_remote)
{
	NRF_RPC_DBG("Empty nrf_rpc_error_handler called");
}


void nrf_rpc_report_error(nrf_rpc_alloc_ctx ctx, int err)
{
	struct nrf_rpc_tr_local_ep *tr_local_ep;
	struct nrf_rpc_tr_remote_ep *tr_remote_ep = ctx;

	if (err < 0) {
		tr_local_ep = nrf_rpc_tr_current_get();
		report_error(tr_local_ep, tr_remote_ep, err, 0);
	}
}
