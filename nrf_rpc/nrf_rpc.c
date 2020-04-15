

#include "nrf_rpc.h"
#include "nrf_rpc_tr.h"

#define RP_LOG_MODULE SER_CORE
#include <rp_log.h>

/////////////////////////////////////////
//#define CONFIG_NRF_RPC_LIMIT_EVENTS 1
/////////////////////////////////////////

enum {
	/* Header variant 1: 
	 *      byte 0: bit 7: packet type, bits 6-0: group id,
	 *      byte 1: command/event code
	 */
	PACKET_TYPE_CMD = 0x00,
	PACKET_TYPE_EVT = 0x80,
	/* Header variant 2: 
	 *      byte 0: packet type
	 *      byte 1: 0xFF,
	 */
	PACKET_TYPE_RSP = 0x01,
	PACKET_TYPE_ACK = 0x02,
	PACKET_TYPE_RDY = 0x03,
	PACKET_TYPE_ERR = 0x04,
};

const uintptr_t __attribute__((__section__(".nrf_rpc.grp."))) groups_before = 0;
const uintptr_t __attribute__((__section__(".nrf_rpc.grp.}"))) groups_after = 0;

static const struct nrf_rpc_group *groups_begin = (const struct nrf_rpc_group *)(&groups_before + 1);
static const struct nrf_rpc_group *groups_end = (const struct nrf_rpc_group *)(&groups_after);

static rp_err_t send_simple(struct nrf_rpc_tr_local_ep *local_tr_ep, struct nrf_rpc_tr_remote_ep *tr_dst, uint8_t type,
			    uint8_t code, const uint8_t *data, size_t len)
{
	uint8_t *buf;
	nrf_rpc_tr_alloc_tx_buf(tr_dst, &buf, _NRF_RPC_HEADER_SIZE + len);
	if (nrf_rpc_tr_alloc_failed(buf)) {
		return NRF_RPC_ERR_NO_MEM;
	}
	buf[0] = type;
	buf[1] = 0xFF;
	if (data != NULL && len > 0) {
		memcpy(&buf[2], data, len);
	}
	return nrf_rpc_tr_send(local_tr_ep, tr_dst, buf, _NRF_RPC_HEADER_SIZE + len);
}

static void handler_execute(uint8_t code,
				const uint8_t *packet,
				size_t len,
				const struct nrf_rpc_decoder *begin,
				const struct nrf_rpc_decoder *end)
{
	rp_err_t err;
	const struct nrf_rpc_decoder *iter;

	for (iter = begin; iter < end; iter++) {
		if (code == iter->code) {
			err = iter->handler(packet, len, (void *)iter);
			if (err) {
				RP_LOG_ERR("Command/event handler returned an error %d", err);
				//TODO: rp_ser_error(rp, RP_SER_ERROR_ON_RECEIVE, code, true, err); // DKTODO: not fatal, but other side should know
			}
			return;
		}
	}

	RP_LOG_ERR("Unsupported command or event received");
	// TODO: rp_ser_error(rp, RP_SER_ERROR_ON_RECEIVE, code, true, RP_ERROR_NOT_SUPPORTED);
}

static const struct nrf_rpc_group *group_from_id(uint8_t group_id)
{
	const struct nrf_rpc_group *iter;

	for (iter = groups_begin; iter < groups_end; iter++) {
		if (iter->group_id == group_id) {
			return iter;
		}
	}
	
	return NULL;
}

static void cmd_execute(uint8_t cmd, const uint8_t *packet, size_t len, const struct nrf_rpc_group *group)
{
	handler_execute(cmd, packet, len, group->cmd_begin, group->cmd_end);
}

#if 0
static void event_execute(uint8_t evt, const uint8_t *packet, size_t len, const struct nrf_rpc_group *group)
{
	handler_execute(evt, packet, len, group->evt_begin, group->evt_end);
}
#endif

static rp_err_t wait_for_ack(struct nrf_rpc_local_ep *src)
{
	if (src->waiting_for_ack_from == NULL) {
		return NRF_RPC_SUCCESS;
	}
	send_simple(&src->tr_ep, &src->waiting_for_ack_from->tr_ep, PACKET_TYPE_RDY, 0, NULL, 0);
	/* error code from send_simple may be ignored, because this
	 * packet is an optimization that is not mandatory. */
	while (src->waiting_for_ack_mask && src->waiting_for_ack_from->tr_ep.addr_mask) {
		// TODO: read and parse incoming packets
	}
}

struct nrf_rpc_tr_remote_ep *_nrf_rpc_cmd_prepare()
{
	rp_err_t err;
	struct nrf_rpc_tr_local_ep *tr_local_ep = nrf_rpc_tr_current_get();
	struct nrf_rpc_local_ep *local_ep = CONTAINER_OF(tr_local_ep, struct nrf_rpc_local_ep, tr_ep);

	if (IS_ENABLED(CONFIG_NRF_RPC_LIMIT_EVENTS)) {
		err = wait_for_ack(local_ep);
		if (err != NRF_RPC_SUCCESS) {
			// TODO: handle error
			return NULL;
		}
	}

	if (local_ep->default_dst == NULL) {
		struct nrf_rpc_tr_remote_ep *tr_remote_ep = nrf_rpc_tr_remote_reserve();
		struct nrf_rpc_remote_ep *remote_ep = CONTAINER_OF(tr_remote_ep, struct nrf_rpc_remote_ep, tr_ep);
		local_ep->default_dst = remote_ep;
		local_ep->cmd_nesting_counter = 1;
	} else {
		local_ep->cmd_nesting_counter++;
	}

	return &local_ep->default_dst->tr_ep;
}

struct nrf_rpc_tr_remote_ep *_nrf_rpc_rsp_prepare()
{
	struct nrf_rpc_tr_local_ep *tr_local_ep = nrf_rpc_tr_current_get();
	struct nrf_rpc_local_ep *local_ep = CONTAINER_OF(tr_local_ep, struct nrf_rpc_local_ep, tr_ep);

	if (local_ep->default_dst == NULL) {
		return NULL;
	}

	return &local_ep->default_dst->tr_ep;
}

void _nrf_rpc_cmd_unprepare()
{
	struct nrf_rpc_tr_local_ep *tr_local_ep = nrf_rpc_tr_current_get();
	struct nrf_rpc_local_ep *local_ep = CONTAINER_OF(tr_local_ep, struct nrf_rpc_local_ep, tr_ep);
	local_ep->cmd_nesting_counter--;
	if (local_ep->cmd_nesting_counter == 0) {
		nrf_rpc_tr_remote_release(&local_ep->default_dst->tr_ep);
		local_ep->default_dst = NULL;
	}
}

void _nrf_rpc_cmd_alloc_error()
{
	_nrf_rpc_cmd_unprepare();
}

static int parse_incoming_packet(struct nrf_rpc_local_ep *local_ep, struct nrf_rpc_tr_remote_ep *src_tr_ep, const uint8_t *buf, size_t len, bool response_expected)
{
	int result;
	uint8_t type;
	const struct nrf_rpc_group *group = groups_begin;
	uint8_t code = 0;
	struct nrf_rpc_remote_ep *old_default_dst;
	struct nrf_rpc_remote_ep *old_waiting_for_ack_from;
	struct nrf_rpc_remote_ep *src = CONTAINER_OF(local_ep, struct nrf_rpc_remote_ep, tr_ep);

	if (len < _NRF_RPC_HEADER_SIZE) {
		result = NRF_RPC_ERR_INTERNAL;
		goto exit_function;
	}

	type = buf[0];
	code = buf[1];
	if (code != 0xFF) {
		group = group_from_id(type & 0x7F);
		type &= 0x80;
		if (!group) {
			result = NRF_RPC_ERR_INTERNAL;
			goto exit_function;
		}
	}

	result = type;

	switch (type)
	{
	case PACKET_TYPE_CMD:
		if (IS_ENABLED(CONFIG_NRF_RPC_LIMIT_EVENTS)) {
			old_waiting_for_ack_from = local_ep->waiting_for_ack_from;
			local_ep->waiting_for_ack_from = NULL;
		}
		old_default_dst = local_ep->default_dst;
		local_ep->default_dst = src;
		cmd_execute(code, &buf[_NRF_RPC_HEADER_SIZE], len - _NRF_RPC_HEADER_SIZE, group);
		local_ep->default_dst = old_default_dst;
		if (IS_ENABLED(CONFIG_NRF_RPC_LIMIT_EVENTS)) {
			local_ep->waiting_for_ack_from = old_waiting_for_ack_from;
		}
		break;

	case PACKET_TYPE_EVT:
		// TODO: events
		break;

	case PACKET_TYPE_RSP:
		if (response_expected) {
			return type;
		} else {
			result = NRF_RPC_ERR_INVALID_STATE;
		}
		break;

	case PACKET_TYPE_ERR:
		// TODO: error reporting
		break;
	
	case PACKET_TYPE_ACK:
	case PACKET_TYPE_RDY:
	default:
		result = NRF_RPC_ERR_INVALID_STATE;
		break;
	}

exit_function:
	nrf_rpc_tr_release_buffer(&local_ep->tr_ep);
	if (result < 0) {
		// TODO: rp_ser_error(rp, RP_SER_ERROR_ON_RECEIVE, RP_SER_CMD_EVT_CODE_UNKNOWN, true, result);
	}
	return result;
}

void nrf_rpc_decoding_done()
{
	nrf_rpc_tr_release_buffer(NULL);
}


static rp_err_t wait_for_response(struct nrf_rpc_local_ep *local)
{
	uint8_t type;
	int len;
	struct nrf_rpc_tr_remote_ep *src_tr_ep;
	const uint8_t *buf;

	do {
		len = nrf_rpc_tr_read(&local->tr_ep, &src_tr_ep, &buf);

		if (len < 0) {
			// TODO: error reporting
			return  len;
		}

		if (buf == NULL) {
			if (len == PACKET_TYPE_RSP) {
				break;
			} else {
				continue;
			}
		}

		type = parse_incoming_packet(local, src_tr_ep, buf, len, false); // TODO: response_expected==true on inline decoder

		if (type < 0) {
			return type;
		}

	} while (type != PACKET_TYPE_RSP);

	// TODO: inline decoder

	return NRF_RPC_SUCCESS;
}

rp_err_t _nrf_rpc_cmd_send(const struct nrf_rpc_group *group, uint8_t cmd, uint8_t *packet, size_t len,
			   nrf_rpc_handler handler, void *handler_data)
{
	rp_err_t err;
	nrf_rpc_handler old_handler;
	void *old_handler_data;
	struct nrf_rpc_tr_local_ep *tr_src = nrf_rpc_tr_current_get();
	struct nrf_rpc_local_ep *src = CONTAINER_OF(tr_src, struct nrf_rpc_local_ep, tr_ep);
	uint8_t *full_packet = &packet[-_NRF_RPC_HEADER_SIZE];

	full_packet[0] = PACKET_TYPE_CMD | group->tr_group.id;
	full_packet[1] = cmd;

	old_handler = src->handler;
	old_handler_data = src->handler_data;
	src->handler = handler;
	src->handler_data = handler_data;

	err = nrf_rpc_tr_send(tr_src, &src->default_dst->tr_ep, full_packet, len + _NRF_RPC_HEADER_SIZE);
	if (err != NRF_RPC_SUCCESS) {
		goto error_exit;
	}

	err = wait_for_response(src);

error_exit:

	_nrf_rpc_cmd_unprepare();

	src->handler = old_handler;
	src->handler_data = old_handler_data;

	return err;

}

rp_err_t _nrf_rpc_rsp_send(uint8_t *packet, size_t len)
{
	rp_err_t err;
	struct nrf_rpc_tr_local_ep *tr_src = nrf_rpc_tr_current_get();
	struct nrf_rpc_local_ep *src = CONTAINER_OF(tr_src, struct nrf_rpc_local_ep, tr_ep);
	uint8_t *full_packet = &packet[-_NRF_RPC_HEADER_SIZE];

	full_packet[0] = PACKET_TYPE_RSP;
	full_packet[1] = 0xFF;

	err = nrf_rpc_tr_send(tr_src, &src->default_dst->tr_ep, full_packet, len + _NRF_RPC_HEADER_SIZE);

	return err;
}

static void receive_handler(struct nrf_rpc_tr_local_ep *dst_ep,
					   struct nrf_rpc_tr_remote_ep *src_ep,
					   const uint8_t *buf, size_t len)
{
	struct nrf_rpc_local_ep *local_ep = CONTAINER_OF(dst_ep, struct nrf_rpc_local_ep, tr_ep);

	if (buf != NULL) {
		parse_incoming_packet(local_ep, src_ep, buf, len, false);
	} else {
	 	printk("filtered %d\n", len);
	}
}

static uint32_t filter_handler(struct nrf_rpc_tr_local_ep *dst_ep,
				      struct nrf_rpc_tr_remote_ep *src_ep,
				      const uint8_t *buf, size_t len)
{
	rp_err_t err;
	struct nrf_rpc_local_ep *local_ep = CONTAINER_OF(dst_ep, struct nrf_rpc_local_ep, tr_ep);
	uint8_t type;

	type = buf[0];

	switch (type) {
	case PACKET_TYPE_ACK:
		nrf_rpc_tr_remote_release(src_ep);
		return type;
	
	case PACKET_TYPE_ERR:
		// TODO: report error
		return type;
	
	case PACKET_TYPE_RDY:
		// TODO: implement for limiting events
		return type;

	case PACKET_TYPE_RSP:
		if (local_ep->handler) {
			err = local_ep->handler(&buf[_NRF_RPC_HEADER_SIZE], len - _NRF_RPC_HEADER_SIZE, local_ep->handler_data);
			local_ep->handler = NULL;
			local_ep->handler_data = NULL;
			if (err) {
				RP_LOG_ERR("Response handler returned an error %d", err);
				// TODO: report error
				//rp_ser_error(rp, RP_SER_ERROR_ON_RECEIVING_RSP, RP_SER_CMD_EVT_CODE_UNKNOWN, false, err);
			}
			return type;
		}
		break;
	
	default:
		break;
	}

	return 0;
}

rp_err_t nrf_rpc_init(void)
{
	return nrf_rpc_tr_init(receive_handler, filter_handler);
}


#pragma region xxxxxx
#if 0
/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <rp_ser.h>
#include <rp_trans.h>
#include <rp_errors.h>

#define RP_LOG_MODULE SER_CORE
#include <rp_log.h>

#ifndef __ASSERT
#include <assert.h>
#define __ASSERT(test, message) assert(message && (test))
#endif

#if defined(CONFIG_RP_SER_FORCE_EVENT_ACK) || RP_TRANS_REQUIRE_EVENT_ACK
#define USE_EVENT_ACK 1
#else
#define USE_EVENT_ACK 0
#endif

#define FILTERED_RESPONSE 1
#define FILTERED_ACK 2

#define HEADER_TYPE_INDEX 0
#define HEADER_CODE_INDEX 1

#define ERROR_FLAG_FATAL 1
#define ERROR_FLAG_NOTIFY_REMOTE 2


enum rp_ser_packet_type {
	/** Serialization command packet. */
	RP_SER_PACKET_TYPE_CMD          = 0x01,

	/** Serialization event packet. */
	RP_SER_PACKET_TYPE_EVT,

	/** Serialization command response packet. */
	RP_SER_PACKET_TYPE_RSP,

	/** Serialization event acknowledge packet. */
	RP_SER_PACKET_TYPE_ACK,

	/** Serialization fatal error notification packet. */
	RP_SER_PACKET_TYPE_ERR,
};

struct error_packet
{
	struct {
		uint8_t type;
	} header;
	struct {
		uint8_t code;
		uint8_t location;
		uint8_t fatal;
		int err;
	} data;	
};

#define SIZE 20
#define TYPE struct k_poll_event
_Static_assert(sizeof(TYPE) <= SIZE, "MORE");
_Static_assert(sizeof(TYPE) >= SIZE, "LESS");
_Static_assert(sizeof(TYPE) != SIZE, "OK");

static uint8_t endpoint_cnt;

void __attribute__((weak)) rp_ser_error_handler(struct rp_ser *rp, rp_ser_error_location_t location, uint8_t code, rp_err_t err, bool fatal)
{
	RP_LOG_ERR("Unhandled serialization error: %d, cmd/evt: %d, loc: %d", err, code, location);
	if (fatal) {
		__ASSERT(0, "Unhandled fatal serialization error");
		while (1);
	}
}

static void send_simple(struct rp_ser *rp, const uint8_t *packet, size_t len) {
	uint8_t *buf;
	rp_trans_alloc_tx_buf(&rp->endpoint, &buf, len);
	if (!rp_trans_alloc_failed(buf)) {
		memcpy(buf, packet, len);
		rp_trans_send(&rp->endpoint, buf, len);
	}
}

static void rp_ser_error(struct rp_ser *rp, rp_ser_error_location_t location, uint8_t code, rp_err_t err, int flags)
{
	if (flags & ERROR_FLAG_NOTIFY_REMOTE) {
		struct error_packet packet;
		packet.header.type = RP_SER_PACKET_TYPE_ERR;
		packet.data.code = code;
		packet.data.location = (uint8_t)location;
		packet.data.fatal = (flags & ERROR_FLAG_FATAL) ? 1 : 0;
		packet.data.err = err;
		send_simple(rp, (const uint8_t *)&packet, sizeof(struct error_packet));
	}
	rp_ser_error_handler(rp, location, code, err, (flags & ERROR_FLAG_FATAL));
}

static void parse_error(struct rp_ser *rp, const uint8_t* buf, size_t len)
{
	struct error_packet packet;

	if (len < sizeof(struct error_packet)) {
		rp_ser_handler_decoding_done(rp);
		RP_LOG_ERR("Invalid error packet received");
		rp_ser_error_handler(rp, RP_SER_ERROR_ON_RECEIVE, RP_SER_CMD_EVT_CODE_UNKNOWN, RP_ERROR_INTERNAL, true);
		return;
	}

	memcpy(&packet, buf, sizeof(struct error_packet));

	rp_ser_handler_decoding_done(rp);

	rp_ser_error_handler(rp, packet.data.location, packet.data.code, packet.data.fatal, packet.data.err | RP_SER_ERROR_ON_REMOTE);
}

static void handler_execute(struct rp_ser *rp,
				uint8_t code,
				const uint8_t *packet,
				size_t len,
				const struct nrf_rpc_decoder *begin,
				const struct nrf_rpc_decoder *end)
{
	rp_err_t err;
	const struct nrf_rpc_decoder *iter;
	nrf_rpc_handler handler = NULL;

	for (iter = begin; iter < end; iter++) {
		if (code == iter->code) {
			handler = iter->func;
			break;
		}
	}

	if (!handler) {
		RP_LOG_ERR("Unsupported command or event received");
		rp_ser_error(rp, RP_SER_ERROR_ON_RECEIVE, code, true, RP_ERROR_NOT_SUPPORTED);
		return;
	}

	err = handler(code, packet, len);
	if (err) {
		RP_LOG_ERR("Command/event handler returned an error %d", err);
		rp_ser_error(rp, RP_SER_ERROR_ON_RECEIVE, code, true, err); // DKTODO: not fatal, but other side should know
	}
}

static void cmd_execute(struct rp_ser *rp, uint8_t cmd, const uint8_t *packet, size_t len)
{
	handler_execute(rp, cmd, packet, len, rp->conf->cmd_begin, rp->conf->cmd_end);
}

static void event_execute(struct rp_ser *rp, uint8_t evt, const uint8_t *packet, size_t len)
{
	handler_execute(rp, evt, packet, len, rp->conf->evt_begin, rp->conf->evt_end);
}

static int received_data_parse(struct rp_ser *rp, const uint8_t *data, size_t len)
{
	int result;
	uint8_t packet_type;
	bool prev_wait_for_ack;


	rp->decoding_done_required = true;

	if (len < RP_SER_CMD_EVT_HADER_SIZE) {
		RP_LOG_ERR("Packet too small");
		result = RP_ERROR_INTERNAL;
		goto exit_function;
	}

	packet_type = data[HEADER_TYPE_INDEX];
	result = packet_type;

	switch (packet_type) {
	case RP_SER_PACKET_TYPE_CMD:
		RP_LOG_DBG("Command received");
		if (USE_EVENT_ACK) {
			// If we are executing command then the other end is waiting for
			// response, so sending notifications and commands is available again now.
			prev_wait_for_ack = rp->waiting_for_ack;
			rp->waiting_for_ack = false;
		}
		cmd_execute(rp, data[HEADER_CODE_INDEX], &data[RP_SER_CMD_EVT_HADER_SIZE], len - RP_SER_CMD_EVT_HADER_SIZE);
		if (USE_EVENT_ACK) {
			// Resore previous state of waiting for ack
			rp->waiting_for_ack = prev_wait_for_ack;
		}
		break;

	case RP_SER_PACKET_TYPE_EVT:
		RP_LOG_DBG("Event received");
		event_execute(rp, data[HEADER_CODE_INDEX], &data[RP_SER_CMD_EVT_HADER_SIZE], len - RP_SER_CMD_EVT_HADER_SIZE);
		if (USE_EVENT_ACK) {
			packet_type = RP_SER_PACKET_TYPE_ACK;
			send_simple(rp, &packet_type, 1);
		}
		break;

	case RP_SER_PACKET_TYPE_ERR:
		RP_LOG_DBG("Error received");
		parse_error(rp, data, len);
		return RP_ERROR_REMOTE;

	default:
		RP_LOG_ERR("Unknown packet received");
		result = RP_ERROR_INVALID_STATE;
		break;
	}

exit_function:
	rp_ser_handler_decoding_done(rp);
	if (result < 0) {
		rp_ser_error(rp, RP_SER_ERROR_ON_RECEIVE, RP_SER_CMD_EVT_CODE_UNKNOWN, true, result);
	}
	return result;
}

static void transport_handler(struct rp_trans_endpoint *endpoint,
			      const uint8_t *buf, size_t length)
{
	struct rp_ser *rp = RP_CONTAINER_OF(endpoint, struct rp_ser, endpoint);

	printbuf("transport_handler", buf, length);

	if (buf != NULL) {
		received_data_parse(rp, buf, length);
	} else {
	 	printk("filtered %d\n", length);
		if (length != FILTERED_ACK || !USE_EVENT_ACK) {
			RP_LOG_ERR("Invalid packet");
			rp_ser_error(rp, RP_SER_ERROR_ON_RECEIVE, RP_SER_CMD_EVT_CODE_UNKNOWN, true, RP_ERROR_INVALID_STATE);
		} else {
			rp->waiting_for_ack = false;
		}
	}
}

static uint32_t transport_filter(struct rp_trans_endpoint *endpoint,
			  const uint8_t *buf, size_t length)
{
	rp_err_t err;
	struct rp_ser *rp = RP_CONTAINER_OF(endpoint, struct rp_ser, endpoint);

	printbuf("filter", buf, length);
	printk("rsp_handler %d\n", (int)rp->rsp_handler);

	if (length < RP_SER_RSP_ACK_HEADER_SIZE)
	{
		return 0;
	}

	switch (buf[HEADER_TYPE_INDEX])
	{
	case RP_SER_PACKET_TYPE_RSP:
		if (rp->rsp_handler) {
			err = rp->rsp_handler(&buf[RP_SER_RSP_ACK_HEADER_SIZE], length - RP_SER_RSP_ACK_HEADER_SIZE);
			rp->rsp_handler = NULL;
			if (err) {
				RP_LOG_ERR("Response handler returned an error %d", err);
				rp_ser_error(rp, RP_SER_ERROR_ON_RECEIVING_RSP, RP_SER_CMD_EVT_CODE_UNKNOWN, false, err);
			}
			return FILTERED_RESPONSE;
		}
		break;

	case RP_SER_PACKET_TYPE_ACK:
		if (USE_EVENT_ACK) {
			return FILTERED_ACK;
		}
		break;
	
	default:
		break;
	}
	return 0;
}

// Call after send of command to wait for response
static int wait_for_response(struct rp_ser *rp) // NEXT: Add buffer output parameter for inline decoder
{
	int type;
	const uint8_t *packet;
	int packet_length;

	do {
		// Wait for something from rx callback
		packet_length = rp_trans_read(&rp->endpoint, &packet);

		if (packet == NULL) {
			if (packet_length == FILTERED_RESPONSE) {
				return RP_SUCCESS;
			} else {
				RP_LOG_ERR("Expecting response");
				return RP_ERROR_INVALID_STATE;
			}
		}

		printbuf("wait_for_response", packet, packet_length);

		type = received_data_parse(rp, packet, packet_length);

		/* NEXT: Allow inline decoder
		case RP_SER_PACKET_TYPE_RSP:
			if (out_packet) {
				*out_packet = packet;
			}
			return packet_length;*/

		if (type == RP_SER_PACKET_TYPE_CMD || type == RP_SER_PACKET_TYPE_EVT) {
			// nothing to do
		} else if (type < 0) {
			return type;
		} else {
			return RP_ERROR_INVALID_STATE;
		}
	} while (true);
}

// Called before sending command or notify to make sure that last notification was finished and the other end
// can handle this packet imidetally.
static rp_err_t wait_for_last_ack(struct rp_ser *rp)
{
	int type;
	const uint8_t *packet;
	int packet_length;

	if (!rp->waiting_for_ack) {
		return RP_SUCCESS;
	}

	do {
		// Wait for something from rx callback
		packet_length = rp_trans_read(&rp->endpoint, &packet);

		if (packet == NULL) {
			if (packet_length == FILTERED_ACK) {
				return RP_SUCCESS;
			} else {
				RP_LOG_ERR("Expecting acknowledge");
				return RP_ERROR_INVALID_STATE;
			}
		}

		printbuf("wait_for_last_ack", packet, packet_length);

		type = received_data_parse(rp, packet, packet_length);

		if (type == RP_SER_PACKET_TYPE_CMD || type == RP_SER_PACKET_TYPE_EVT) {
			// nothing to do
		} else if (type < 0) {
			return type;
		} else {
			return RP_ERROR_INVALID_STATE;
		}
	} while (true);
}

void printbuf(const char* text, const uint8_t *packet, size_t len)
{
	printk("%s ", text);
	for (size_t i = 0; i < len; i++)
	{
		printk("  %02X", packet[i]);
	}
	printk("\n");
}

rp_err_t rp_ser_cmd_send(struct rp_ser *rp,
			 uint8_t cmd,
			 uint8_t *packet,
			 size_t len,
			 rp_ser_response_handler_t rsp) // NEXT: add result pointer
{
	rp_ser_response_handler_t old_rsp;
	rp_err_t err;
	uint8_t *full_packet = &packet[-RP_SER_CMD_EVT_HADER_SIZE];

	__ASSERT(rp, "Instance cannot be NULL");
	__ASSERT(packet, "Packet cannot be NULL");

	/* Fill header fields */
	full_packet[HEADER_TYPE_INDEX] = RP_SER_PACKET_TYPE_CMD;
	full_packet[HEADER_CODE_INDEX] = cmd;

	/* Instance is not accessible by any other thread from this point */
	rp_trans_own(&rp->endpoint);
	if (USE_EVENT_ACK) {
		/* Make sure that someone can handle packet immediately */
		err = wait_for_last_ack(rp);
		if (err) {
			goto exit_with_give;
		}
	}
	/* Save previous decoder on stack and set it for current command */
	old_rsp = rp->rsp_handler; // NEXT: add pointer to result
	rp->rsp_handler = rsp;
	printk("rsp_handler %d\n", (int)rp->rsp_handler);

	printbuf("rp_ser_cmd_send", full_packet, len + RP_SER_CMD_EVT_HADER_SIZE);

	/* Send buffer to transport layer */
	err = rp_trans_send(&rp->endpoint, full_packet, len + RP_SER_CMD_EVT_HADER_SIZE);
	if (err) {
		goto exit_with_restore;
	}
	/* Wait for response. During waiting nested commands and notifications are possible */
	err = wait_for_response(rp);

exit_with_restore:
	// restore decoder for previously waiting response
	rp->rsp_handler = old_rsp;
exit_with_give:
	rp_trans_give(&rp->endpoint);
	return err;
}

void rp_ser_cmd_send_no_err(struct rp_ser *rp,
			    uint8_t cmd,
			    uint8_t *packet,
			    size_t len,
			    rp_ser_response_handler_t rsp)
{
	rp_err_t err;

	err = rp_ser_cmd_send(rp, cmd, packet, len, rsp);
	
	if (err) {
		RP_LOG_ERR("Unhandled send cmd error %d", err);
		rp_ser_error(rp, RP_SER_ERROR_ON_SENDING_CMD, cmd, false, err);
	}
}

rp_err_t rp_ser_evt_send(struct rp_ser *rp,
			 uint8_t evt,
			 uint8_t *packet,
			 size_t len)
{
	rp_err_t err;
	uint8_t *full_packet = &packet[-RP_SER_CMD_EVT_HADER_SIZE];

	__ASSERT(rp, "Instance cannot be NULL");
	__ASSERT(packet, "Packet cannot be NULL");

	full_packet[HEADER_TYPE_INDEX] = RP_SER_PACKET_TYPE_EVT;
	full_packet[HEADER_CODE_INDEX] = evt;

	/* Endpoint is not accessible by other thread from this point */
	rp_trans_own(&rp->endpoint);
	if (USE_EVENT_ACK) {
		/* Make sure that someone can handle packet immidietallty */
		err = wait_for_last_ack(rp);
		if (err) {
			goto exit_with_give;
		}
		/* we are expecting ack later */
		rp->waiting_for_ack = true;
	}
	/* Send buffer to transport layer */
	err = rp_trans_send(&rp->endpoint, full_packet, len + RP_SER_CMD_EVT_HADER_SIZE);
	/* We can unlock now, nothing more to do */
exit_with_give:
	rp_trans_give(&rp->endpoint);
	return err;
}

void rp_ser_evt_send_no_err(struct rp_ser *rp,
				uint8_t evt,
				uint8_t *packet,
				size_t len)
{
	rp_err_t err;

	err = rp_ser_evt_send(rp, evt, packet, len);
	
	if (err) {
		RP_LOG_ERR("Unhandled send evt error %d", err);
		rp_ser_error(rp, RP_SER_ERROR_ON_SENDING_EVT, evt, false, err);
	}
}

rp_err_t rp_ser_rsp_send(struct rp_ser *rp,
			 uint8_t *packet,
			 size_t len)
{
	rp_err_t err;
	uint8_t *full_packet = &packet[-RP_SER_RSP_ACK_HEADER_SIZE];

	__ASSERT(rp, "Instance cannot be NULL");
	__ASSERT(packet, "Packet cannot be NULL");

	full_packet[HEADER_TYPE_INDEX] = RP_SER_PACKET_TYPE_RSP;

	for (int i = 0; i < len + 1; i++)
	{
		printk("  %02X", full_packet[i]);
	}
	printk("\n");

	/* Send buffer to transport layer */
	err = rp_trans_send(&rp->endpoint, full_packet, len + RP_SER_RSP_ACK_HEADER_SIZE);

	return err;
}

void rp_ser_rsp_send_no_err(struct rp_ser *rp,
				uint8_t *packet,
				size_t len)
{
	rp_err_t err;

	err = rp_ser_rsp_send(rp, packet, len);
	
	if (err) {
		RP_LOG_ERR("Unhandled send response error %d", err);
		rp_ser_error(rp, RP_SER_ERROR_ON_SENDING_RSP, RP_SER_CMD_EVT_CODE_UNKNOWN, false, err);
	}
}

void rp_ser_handler_decoding_done(struct rp_ser *rp)
{
	if (rp->decoding_done_required) {
		rp->decoding_done_required = false;
		rp_trans_release_buffer(&rp->endpoint);
	}
}

rp_err_t rp_ser_init(struct rp_ser *rp)
{
	rp_err_t err;

	__ASSERT(rp, "Instance cannot be NULL");

	if (!endpoint_cnt) {
		err = rp_trans_init(transport_handler, transport_filter);
		if (err) {
			return err;
		}

		endpoint_cnt++;
	}

	return rp_trans_endpoint_init(&rp->endpoint, rp->conf->ep_number);
}
#endif
#pragma endregion
