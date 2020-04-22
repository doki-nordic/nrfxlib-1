/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "nrf_rpc.h"
#include "nrf_rpc_tr.h"

#define RP_LOG_MODULE SER_CORE
#include <rp_log.h>


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
	PACKET_TYPE_ERR = 0x03,
};

enum {
	ERROR_FLAG_REMOTE = 1,
	ERROR_FLAG_SEND = 2,
};


NRF_RPC_ORD_VAR_ARRAY(nrf_rpc_groups_array, "grp");


static int send_simple(struct nrf_rpc_tr_local_ep *local_tr_ep,
			    struct nrf_rpc_tr_remote_ep *tr_dst, uint8_t type,
			    uint8_t code, const uint8_t *data, size_t len)
{
	uint8_t *buf;

	nrf_rpc_tr_alloc_tx_buf(tr_dst, &buf, _NRF_RPC_HEADER_SIZE + len);
	if (nrf_rpc_tr_alloc_failed(buf)) {
		return NRF_RPC_ERR_NO_MEM;
	}

	buf[0] = type;
	buf[1] = code;

	if (data != NULL && len > 0) {
		memcpy(&buf[2], data, len);
	}

	return nrf_rpc_tr_send(local_tr_ep, tr_dst, buf, _NRF_RPC_HEADER_SIZE + len);
}

__attribute__((weak))
void nrf_rpc_error_handler(struct nrf_rpc_tr_local_ep *tr_local_ep,
			   struct nrf_rpc_tr_remote_ep *tr_remote_ep, int code,
			   bool from_remote)
{
}

static void report_error(struct nrf_rpc_tr_local_ep *tr_src,
			 struct nrf_rpc_tr_remote_ep *tr_dst, int code,
			 uint32_t flags)
{
	RP_LOG_ERR("NRF_RPC %sERROR: code=%d local=%d remote=%d",
		   flags & ERROR_FLAG_REMOTE ? "REMOTE " : "", code,
		   tr_src ? tr_src->addr : -1,
		   tr_dst ? tr_dst->addr : -1);

	nrf_rpc_error_handler(tr_src, tr_dst, code, flags & ERROR_FLAG_REMOTE);

	if (flags & ERROR_FLAG_SEND) {
		int8_t data = (int8_t)code;

		send_simple(tr_src, tr_dst, PACKET_TYPE_ERR, 0xFF, &data,
			    sizeof(data));
	}
}


static int handler_execute(uint8_t code,
				const uint8_t *packet,
				size_t len,
				const void *array)
{
	int err;
	void *iter;
	const struct nrf_rpc_decoder *decoder;

	NRF_RPC_ORD_VAR_FOR_EACH(iter, decoder, array,
				 const struct nrf_rpc_decoder) {

		if (code == decoder->code) {
			err = decoder->handler(packet, len, (void *)decoder);
			if (err < 0) {
				RP_LOG_ERR("Command or event handler returned an error %d", err);
			}
			return err;
		}
	}

	RP_LOG_ERR("Unsupported command or event received 0x%02X", code);
	return NRF_RPC_ERR_NOT_SUPPORTED;
}

static int cmd_execute(uint8_t cmd, const uint8_t *packet, size_t len,
			    const struct nrf_rpc_group *group)
{
	return handler_execute(cmd, packet, len, group->cmd_array);
}

static int evt_execute(uint8_t evt, const uint8_t *packet, size_t len,
			    const struct nrf_rpc_group *group)
{
	return handler_execute(evt, packet, len, group->evt_array);
}

static const struct nrf_rpc_group *group_from_id(uint8_t group_id)
{
	void *iter;
	const struct nrf_rpc_group *group;
	
	NRF_RPC_ORD_VAR_FOR_EACH(iter, group, &nrf_rpc_groups_array,
				 const struct nrf_rpc_group) {

		if (group->group_id == group_id) {
			return group;
		}
	}
	
	return NULL;
}

static int parse_incoming_packet(struct nrf_rpc_local_ep *local_ep,
				 struct nrf_rpc_tr_remote_ep *src_tr_ep,
				 const uint8_t *buf, size_t len,
				 bool response_expected)
{
	int result;
	uint8_t type;
	const struct nrf_rpc_group *group = NULL;
	uint8_t code = 0;
	struct nrf_rpc_remote_ep *old_default_dst;
	struct nrf_rpc_remote_ep *src = RP_CONTAINER_OF(src_tr_ep, struct nrf_rpc_remote_ep, tr_ep);

	if (len < _NRF_RPC_HEADER_SIZE) {
		result = NRF_RPC_ERR_INTERNAL;
		goto exit_function;
	}

	type = buf[0];
	code = buf[1];
	if (code != 0xFF) {
		group = group_from_id(type & 0x7F);
		type &= 0x80;
	}

	result = type;

	switch (type)
	{
	case PACKET_TYPE_CMD:
		if (!group || src_tr_ep == NULL) {
			result = NRF_RPC_ERR_INTERNAL;
			goto exit_function;
		}
		old_default_dst = local_ep->default_dst;
		local_ep->default_dst = src;
		result = cmd_execute(code, &buf[_NRF_RPC_HEADER_SIZE], len - _NRF_RPC_HEADER_SIZE, group);
		local_ep->default_dst = old_default_dst;
		break;

	case PACKET_TYPE_EVT:
		if (!group) {
			result = NRF_RPC_ERR_INTERNAL;
			goto exit_function;
		}
		evt_execute(code, &buf[_NRF_RPC_HEADER_SIZE], len - _NRF_RPC_HEADER_SIZE, group);
		result = send_simple(&local_ep->tr_ep, NULL, PACKET_TYPE_ACK, 0xFF, NULL, 0);
		break;

	case PACKET_TYPE_RSP:
		if (response_expected) {
			return type;
		} else {
			result = NRF_RPC_ERR_INVALID_STATE;
		}
		break;

	case PACKET_TYPE_ERR:
	case PACKET_TYPE_ACK:
	default:
		result = NRF_RPC_ERR_INVALID_STATE;
		break;
	}

exit_function:
	nrf_rpc_tr_release_buffer(&local_ep->tr_ep);
	return result;
}

void nrf_rpc_decoding_done(void)
{
	struct nrf_rpc_tr_local_ep *tr_local_ep = nrf_rpc_tr_current_get();
	nrf_rpc_tr_release_buffer(tr_local_ep);
}


static int wait_for_response(struct nrf_rpc_local_ep *local)
{
	uint8_t type;
	int len;
	struct nrf_rpc_tr_remote_ep *src_tr_ep;
	const uint8_t *buf;

	do {
		len = nrf_rpc_tr_read(&local->tr_ep, &src_tr_ep, &buf);

		if (len < 0) {
			return  len;
		}

		if (buf == NULL) {
			if (len == PACKET_TYPE_ERR) {
				return NRF_RPC_ERR_REMOTE;
			} if (len == PACKET_TYPE_RSP) {
				return NRF_RPC_SUCCESS;
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

struct nrf_rpc_remote_ep *_nrf_rpc_cmd_prepare(const struct nrf_rpc_group *group)
{
	struct nrf_rpc_tr_local_ep *tr_local_ep = nrf_rpc_tr_current_get();
	struct nrf_rpc_local_ep *local_ep = RP_CONTAINER_OF(tr_local_ep, struct nrf_rpc_local_ep, tr_ep);

	printk("_nrf_rpc_cmd_prepare\n");

	if (local_ep->default_dst == NULL) {
		struct nrf_rpc_tr_remote_ep *tr_remote_ep = nrf_rpc_tr_remote_reserve();
		struct nrf_rpc_remote_ep *remote_ep = RP_CONTAINER_OF(tr_remote_ep, struct nrf_rpc_remote_ep, tr_ep);

		local_ep->default_dst = remote_ep;
		local_ep->cmd_nesting_counter = 1;
	} else {
		local_ep->cmd_nesting_counter++;
	}

	local_ep->default_dst->current_group_id = group->group_id;

	return local_ep->default_dst;
}

void _nrf_rpc_cmd_alloc_error(struct nrf_rpc_remote_ep *remote_ep)
{
	struct nrf_rpc_tr_local_ep *tr_local_ep = nrf_rpc_tr_current_get();

	RP_LOG_ERR("Command allocation failed");
	report_error(tr_local_ep, &remote_ep->tr_ep, NRF_RPC_ERR_NO_MEM, 0);

	_nrf_rpc_cmd_unprepare();
}

void _nrf_rpc_cmd_unprepare(void)
{
	struct nrf_rpc_tr_local_ep *tr_local_ep = nrf_rpc_tr_current_get();
	struct nrf_rpc_local_ep *local_ep = RP_CONTAINER_OF(tr_local_ep, struct nrf_rpc_local_ep, tr_ep);

	local_ep->cmd_nesting_counter--;
	if (local_ep->cmd_nesting_counter == 0) {
		nrf_rpc_tr_remote_release(&local_ep->default_dst->tr_ep);
		local_ep->default_dst = NULL;
	}
}

int nrf_rpc_cmd_send(struct nrf_rpc_remote_ep *remote_ep, uint8_t cmd,
			  uint8_t *packet, size_t len, nrf_rpc_handler handler,
			  void *handler_data)
{
	int err;
	nrf_rpc_handler old_handler;
	void *old_handler_data;
	struct nrf_rpc_tr_local_ep *tr_src = nrf_rpc_tr_current_get();
	struct nrf_rpc_local_ep *src = RP_CONTAINER_OF(tr_src, struct nrf_rpc_local_ep, tr_ep);
	uint8_t *full_packet = &packet[-_NRF_RPC_HEADER_SIZE];

	full_packet[0] = PACKET_TYPE_CMD | remote_ep->current_group_id;
	full_packet[1] = cmd;

	old_handler = src->handler;
	old_handler_data = src->handler_data;
	src->handler = handler;
	src->handler_data = handler_data;

	printbuf("_nrf_rpc_cmd_send", full_packet, len + _NRF_RPC_HEADER_SIZE);

	err = nrf_rpc_tr_send(tr_src, &remote_ep->tr_ep, full_packet, len + _NRF_RPC_HEADER_SIZE);
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

void nrf_rpc_cmd_send_noerr(struct nrf_rpc_remote_ep *remote_ep, uint8_t cmd,
			  uint8_t *packet, size_t len, nrf_rpc_handler handler,
			  void *handler_data)
{
	int err;
	
	err = nrf_rpc_cmd_send(remote_ep, cmd, packet, len, handler,
			       handler_data);
	if (err < 0) {
		struct nrf_rpc_tr_local_ep *tr_src = nrf_rpc_tr_current_get();

		RP_LOG_ERR("Unhandled command send error %d", err);
		report_error(tr_src, &remote_ep->tr_ep, err, 0);
	}
}

struct nrf_rpc_remote_ep *_nrf_rpc_evt_prepare(const struct nrf_rpc_group *group)
{
	struct nrf_rpc_tr_remote_ep *tr_remote_ep = nrf_rpc_tr_remote_reserve();
	struct nrf_rpc_remote_ep *remote_ep = RP_CONTAINER_OF(tr_remote_ep, struct nrf_rpc_remote_ep, tr_ep);

	remote_ep->current_group_id = group->group_id;

	printk("_nrf_rpc_evt_prepare\n");
	return remote_ep;
}

void _nrf_rpc_evt_alloc_error(struct nrf_rpc_remote_ep *remote_ep)
{
	RP_LOG_ERR("Event allocation failed");
	report_error(NULL, &remote_ep->tr_ep, NRF_RPC_ERR_NO_MEM, 0);

	_nrf_rpc_evt_unprepare(remote_ep);
}

void _nrf_rpc_evt_unprepare(struct nrf_rpc_remote_ep *remote_ep)
{
	nrf_rpc_tr_remote_release(&remote_ep->tr_ep);
}

int nrf_rpc_evt_send(struct nrf_rpc_remote_ep *remote_ep, uint8_t evt,
			  uint8_t *packet, size_t len)
{
	int err;
	uint8_t *full_packet = &packet[-_NRF_RPC_HEADER_SIZE];

	full_packet[0] = PACKET_TYPE_EVT | remote_ep->current_group_id;
	full_packet[1] = evt;

	printbuf("_nrf_rpc_evt_send", full_packet, len + _NRF_RPC_HEADER_SIZE);

	err = nrf_rpc_tr_send(NULL, &remote_ep->tr_ep, full_packet, len + _NRF_RPC_HEADER_SIZE);
	
	return err;
}

void nrf_rpc_evt_send_noerr(struct nrf_rpc_remote_ep *remote_ep, uint8_t evt,
			  uint8_t *packet, size_t len)
{
	int err;
	
	err = nrf_rpc_evt_send(remote_ep, evt, packet, len);
	if (err < 0) {
		RP_LOG_ERR("Unhandled event send error %d", err);
		report_error(NULL, &remote_ep->tr_ep, err, 0);
	}
}

struct nrf_rpc_remote_ep *_nrf_rpc_rsp_prepare(void)
{
	struct nrf_rpc_tr_local_ep *tr_local_ep = nrf_rpc_tr_current_get();
	struct nrf_rpc_local_ep *local_ep = RP_CONTAINER_OF(tr_local_ep, struct nrf_rpc_local_ep, tr_ep);

	__ASSERT(local_ep->default_dst != NULL, "Response must be send from a command handler");

	return local_ep->default_dst;
}


int nrf_rpc_rsp_send(struct nrf_rpc_remote_ep *remote_ep, uint8_t *packet,
			  size_t len)
{
	int err;
	struct nrf_rpc_tr_local_ep *tr_src = nrf_rpc_tr_current_get();
	uint8_t *full_packet = &packet[-_NRF_RPC_HEADER_SIZE];

	full_packet[0] = PACKET_TYPE_RSP;
	full_packet[1] = 0xFF;

	printbuf("_nrf_rpc_rsp_send", full_packet, len + _NRF_RPC_HEADER_SIZE);

	err = nrf_rpc_tr_send(tr_src, &remote_ep->tr_ep, full_packet, len + _NRF_RPC_HEADER_SIZE);

	return err;
}

static void receive_handler(struct nrf_rpc_tr_local_ep *dst_ep,
					   struct nrf_rpc_tr_remote_ep *src_ep,
					   const uint8_t *buf, int len)
{
	int err;
	struct nrf_rpc_local_ep *local_ep = RP_CONTAINER_OF(dst_ep, struct nrf_rpc_local_ep, tr_ep);

	if (buf != NULL) {
		printbuf("receive_handler1", buf, len);
		err = parse_incoming_packet(local_ep, src_ep, buf, len, false);
		if (err < 0) {
			RP_LOG_ERR("Error parsing incoming packet %d", err);
			report_error(dst_ep, src_ep, err, ERROR_FLAG_SEND);
		}
	} else {
	 	printk("receive_handler filtered %d\n", len);
	}
}

static uint32_t filter_handler(struct nrf_rpc_tr_local_ep *dst_ep,
				      struct nrf_rpc_tr_remote_ep *src_ep,
				      const uint8_t *buf, int len)
{
	int err;
	struct nrf_rpc_local_ep *local_ep = RP_CONTAINER_OF(dst_ep, struct nrf_rpc_local_ep, tr_ep);
	uint8_t type;

	if (len < _NRF_RPC_HEADER_SIZE) {
		len = NRF_RPC_ERR_INVALID_PARAM;
	}

	if (len < 0) {
		RP_LOG_ERR("Packet too small");
		report_error(dst_ep, src_ep, NRF_RPC_ERR_INTERNAL, 0);
		return PACKET_TYPE_ERR;
	}

	type = buf[0];

	switch (type) {
	case PACKET_TYPE_ACK:
		if (src_ep != NULL) {
			nrf_rpc_tr_remote_release(src_ep);
		}
		return type;
	
	case PACKET_TYPE_ERR:
		if (len >= 1 + _NRF_RPC_HEADER_SIZE) {
			report_error(dst_ep, src_ep, (int8_t)buf[_NRF_RPC_HEADER_SIZE], ERROR_FLAG_REMOTE);
		}
		return type;
	
	case PACKET_TYPE_RSP:
		if (dst_ep != NULL && local_ep->handler) {
			err = local_ep->handler(&buf[_NRF_RPC_HEADER_SIZE], len - _NRF_RPC_HEADER_SIZE, local_ep->handler_data);
			local_ep->handler = NULL;
			local_ep->handler_data = NULL;
			if (err) {
				RP_LOG_ERR("Response handler returned an error %d", err);
				report_error(dst_ep, src_ep, err, 0);
			}
			return type;
		}
		break;
	
	default:
		break;
	}

	return 0;
}

int nrf_rpc_init(void)
{
	return nrf_rpc_tr_init(receive_handler, filter_handler);
}

