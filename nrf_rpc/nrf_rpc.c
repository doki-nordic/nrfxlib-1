/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
 */
#define NRF_RPC_LOG_MODULE NRF_RPC
#include <nrf_rpc_log.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "nrf_rpc.h"
#include "nrf_rpc_tr.h"
#include "nrf_rpc_os.h"

/**
 */
struct nrf_rpc_cmd_ctx {
	uint8_t id;
	uint8_t remote_id;
	uint8_t use_count;
	bool response_sent;
	nrf_rpc_handler_t handler;
	void* handler_data;
	struct nrf_rpc_os_msg recv_msg;
};

static struct nrf_rpc_cmd_ctx transaction_pool[CONFIG_NRF_RPC_TRANSACTION_POLL_SIZE];
static uint32_t groups_check_sum;

#define ID_UNKNOWN 0xFF

#define RSP_ID_VALID 0
#define RSP_ID_MISSING 1

#define ERROR_FLAG_REMOTE 1
#define ERROR_FLAG_SEND 2

#define CMD_FLAG_WITH_RSP 0x10000

enum {
	PACKET_TYPE_EVT  = 0x00, // U -> U
	PACKET_TYPE_RSP  = 0x01, // U -> 1
	PACKET_TYPE_ACK  = 0x02, // U -> U
	PACKET_TYPE_ERR  = 0x03, // U -> 1
	PACKET_TYPE_INIT = 0x04, // U -> 1
	PACKET_TYPE_CMD  = 0x80, // 1 -> 4, 1 -> U
};

struct nrf_rpc_os_event decode_done_event;


static int alloc_cmd_ctx(struct nrf_rpc_cmd_ctx **ctx)
{
	int index;

	index = nrf_rpc_os_ctx_pool_reserve();
	if (index < 0) {
		return index;
	}

	NRF_RPC_ASSERT(index < CONFIG_NRF_RPC_TRANSACTION_POLL_SIZE);

	*ctx = &transaction_pool[index];
	(*ctx)->handler = NULL;
	NRF_RPC_WRN("------- %d = %d", (*ctx)->remote_id, ID_UNKNOWN);
	(*ctx)->remote_id = ID_UNKNOWN;
	(*ctx)->use_count = 1;

	nrf_rpc_os_tls_set(*ctx);

	return 0;
}

static struct nrf_rpc_cmd_ctx *get_cmd_ctx_by_id(uint8_t id)
{
	if (id >= CONFIG_NRF_RPC_TRANSACTION_POLL_SIZE) {
		return NULL;
	}
	return &transaction_pool[id];
}

static int get_cmd_ctx(struct nrf_rpc_cmd_ctx **ctx, bool alloc_if_needed)
{
	*ctx = nrf_rpc_os_tls_get();
	if (alloc_if_needed) {
		if (*ctx == NULL) {
			return alloc_cmd_ctx(ctx);
		} else {
			(*ctx)->use_count++;
		}
	}
	return 0;
}

static void release_cmd_ctx(struct nrf_rpc_cmd_ctx *ctx)
{
	ctx->use_count--;
	if (ctx->use_count == 0) {
		nrf_rpc_os_tls_set(NULL);
		nrf_rpc_os_ctx_pool_release(ctx->id);
	}
}



static inline int decode_header(const uint8_t *packet, size_t len, uint8_t *dst, uint8_t *src, uint8_t *type, uint8_t *id, uint8_t *group_id)
{
	// DKTODO: check if this function will be compiled to the same form if parameters packed into a structure.

	if (len < _NRF_RPC_HEADER_SIZE) {
		return -EIO;
	}

	if (packet[0] & 0x80) {
		*src = packet[0] & 0x7F;
		*type = packet[0] & 0x80;
	} else {
		*src = ID_UNKNOWN;
		*type = packet[0];
	}

	*id = packet[1];
	*dst = packet[2];
	*group_id = packet[3];

	return 0;
}


static inline void encode_header(uint8_t *packet, uint8_t dst, uint8_t type, uint8_t id, uint8_t group_id)
{
	packet[0] = type;
	packet[1] = id;
	packet[2] = dst;
	packet[3] = group_id;
}


static inline void encode_cmd_header(uint8_t *packet, uint8_t dst, uint8_t src, uint8_t id, uint8_t group_id)
{
	packet[0] = PACKET_TYPE_CMD | src;
	packet[1] = id;
	packet[2] = dst;
	packet[3] = group_id;
}


/* Array with all defiend groups */
NRF_RPC_AUTO_ARR(nrf_rpc_groups_array, "grp");


/* Number of groups */
static uint8_t group_id_count; 


/* ======================== Common utilities ======================== */


/** Function simplifying sending a short packets */
static int send_simple(uint8_t dst, uint8_t type, uint8_t id, uint8_t group_id,
		       const uint8_t *packet, size_t len)
{
	uint8_t *tx_buf;

	nrf_rpc_tr_alloc_tx_buf(&tx_buf, _NRF_RPC_HEADER_SIZE + len);

	if (nrf_rpc_tr_alloc_failed(tx_buf)) {
		return -ENOMEM;
	}

	encode_header(tx_buf, dst, type, id, group_id);

	if (packet != NULL && len > 0) {
		memcpy(&tx_buf[_NRF_RPC_HEADER_SIZE], packet, len);
	}

	return nrf_rpc_tr_send(tx_buf, _NRF_RPC_HEADER_SIZE + len);
}


/** Report an error that cannot be reported as a function return value */
static void report_error(int code)
{
	/*NRF_RPC_ERR("%sERROR: code=%d local=%d remote=%d",
		   flags & ERROR_FLAG_REMOTE ? "REMOTE " : "", code,
		   tr_local_ep ? tr_local_ep->addr : -1,
		   tr_remote_ep ? tr_remote_ep->addr : -1);

	nrf_rpc_error_handler(tr_local_ep, tr_remote_ep, cmd_evt_id, code,
			      flags & ERROR_FLAG_REMOTE);

	if (flags & ERROR_FLAG_SEND) {
		uint8_t data = (uint8_t)(-code);

		send_simple(tr_local_ep, tr_remote_ep, PACKET_TYPE_ERR, &data,
			    sizeof(data));
	}*/
}


static inline bool valid_packet(const uint8_t *packet)
{
	uintptr_t addr = (uintptr_t)packet;
	/* Checking NULL may be sometimes not enough, because pointer can be
	 * shifted by size of headers.
	 */
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
			NRF_RPC_WRN("------ EXECUTED");
			return err;
		}
	}

	nrf_rpc_decoding_done();

	NRF_RPC_ERR("Unsupported command or event received");
	return -ENOSYS;
}


/** Search for a group based on group_id */
static const struct nrf_rpc_group *group_from_id(uint8_t group_id)
{
	if (group_id >= group_id_count) {
		return NULL;
	}

	return &NRF_RPC_AUTO_ARR_GET(&nrf_rpc_groups_array, group_id,
				    const struct nrf_rpc_group);
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
 * @return 0 if packet was correctly parsed and executed.
 *         PACKET_TYPE_RSP if packet contains a response and response_expected
 *         was true. Negative error code on failure.
 */
static int parse_incoming_packet(struct nrf_rpc_cmd_ctx *cmd_ctx,
				 const uint8_t *packet, size_t len,
				 bool response_expected)
{
	int err;
	int send_result;
	uint8_t dst;
	uint8_t src;
	uint8_t type = ID_UNKNOWN;
	uint8_t id;
	uint8_t group_id;
	const struct nrf_rpc_group *group = NULL;
	struct nrf_rpc_cmd_ctx *allocated_ctx = NULL;

	/* Validate required parameters */
	NRF_RPC_ASSERT(valid_packet(packet));

	err = decode_header(packet, len, &dst, &src, &type, &id, &group_id);
	if (err < 0) {
		goto decode_done_and_exit;
	}

	if (type == PACKET_TYPE_RSP) {
		if (response_expected) {
			NRF_RPC_DBG("Response received");
			return type;
		} else {
			NRF_RPC_ERR("Response not expected at this point");
			err = -EIO;
			goto decode_done_and_exit;
		}
	}

	group = group_from_id(group_id);
	if (group == NULL) {
		err = -EIO;
		goto decode_done_and_exit;
	}

	if (type == PACKET_TYPE_CMD) {

		if (cmd_ctx == NULL) {
			err = alloc_cmd_ctx(&allocated_ctx);
			if (err < 0) {
				goto decode_done_and_exit;
			}
			cmd_ctx = allocated_ctx;
		}
		NRF_RPC_WRN("------- %d = %d", cmd_ctx->remote_id, src);
		cmd_ctx->remote_id = src;
		cmd_ctx->response_sent = false;
		NRF_RPC_DBG("Executing command 0x%02X from group 0x%02X", id,
			    *group->group_id);
		err = handler_execute(id, &packet[_NRF_RPC_HEADER_SIZE],
					 len - _NRF_RPC_HEADER_SIZE,
					 group->cmd_array);
		if (!cmd_ctx->response_sent) {
			/* Report missing response to the caller to avoid
			 * infinite wait for a response.
			 */
			NRF_RPC_WRN("------- %d", cmd_ctx->remote_id);
			send_result = send_simple(cmd_ctx->remote_id,
						  PACKET_TYPE_RSP,
						  RSP_ID_MISSING, // DKTODO: receive part
						  ID_UNKNOWN, NULL, 0);
		}
		NRF_RPC_WRN("------- DONE HANDLER");
		cmd_ctx->response_sent = false;
		if (allocated_ctx != NULL) {
			release_cmd_ctx(allocated_ctx);
		}
		NRF_RPC_WRN("------- RELEASED");

	} else if (type == PACKET_TYPE_EVT) {

		NRF_RPC_DBG("Executing event 0x%02X from group 0x%02X", id,
			    *group->group_id);
		err = handler_execute(id, &packet[_NRF_RPC_HEADER_SIZE],
					 len - _NRF_RPC_HEADER_SIZE,
					 group->evt_array);
		/* Always send back ACK even in case of handler failure */
		send_result = send_simple(ID_UNKNOWN, PACKET_TYPE_ACK, id,
					  *group->group_id, (uint8_t *)&err,
					  sizeof(err));
		if (send_result < 0) {
			NRF_RPC_ERR("ACK sending error %d", send_result);
		}
		/* Select correct error code if any */
		err = (err < 0) ? err : send_result;

	} else {

		NRF_RPC_ERR("Unexpected packet received");
		err = -EIO;
		goto decode_done_and_exit;

	}

	if (err < 0) {
		return err;
	}

	return type;

decode_done_and_exit:

	nrf_rpc_decoding_done();
	return err;
}

void execute_packet(void* data, size_t len)
{
	int err;
	const uint8_t *packet = (const uint8_t *)data;

	err = parse_incoming_packet(NULL, packet, len, false);
	if (err < 0) {
		return; // DKTODO: report error
	}
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
static void receive_handler(const uint8_t *packet, int len)
{
	uint8_t dst;
	uint8_t src;
	uint8_t type;
	uint8_t id;
	uint8_t group_id;
	const struct nrf_rpc_group *group;
	int err;
	struct nrf_rpc_cmd_ctx *cmd_ctx;


	err = decode_header(packet, len, &dst, &src, &type, &id, &group_id);
	if (err < 0) {
		NRF_RPC_ERR("Invalid header in received packet.");
		goto error_exit;
	}

	NRF_RPC_DBG("Received %d bytes packet from %d to %d, type 0x%02X, "
		    "cmd/evt/cnt 0x%02X, grp %d", len, src, dst, type, id,
		    group_id);

	if (type == PACKET_TYPE_CMD && dst == ID_UNKNOWN) {
		/* In this place command behaves almost the same as an event if
		 * destination in unknown or as a response if destination is
		 * known. Local change of type avoids code duplication.
		 */
		type = PACKET_TYPE_EVT;
	}

	switch (type)
	{
	case PACKET_TYPE_EVT: /* or PACKET_TYPE_CMD with unknown destination */
		err = nrf_rpc_os_thread_pool_send(execute_packet, (void *)packet, len);
		if (err < 0) {
			goto error_exit;
		}
		err = nrf_rpc_os_event_wait(&decode_done_event);
		if (err < 0) {
			goto error_exit;
		}
		break;

	case PACKET_TYPE_CMD: /* with known destination */
	case PACKET_TYPE_RSP:
		cmd_ctx = get_cmd_ctx_by_id(dst);
		if (cmd_ctx == NULL) {
			goto error_exit;
		}
		if (cmd_ctx->handler != NULL && type == PACKET_TYPE_RSP) {
			err = cmd_ctx->handler(&packet[_NRF_RPC_HEADER_SIZE], len - _NRF_RPC_HEADER_SIZE, cmd_ctx->handler_data);
			err = nrf_rpc_os_msg_set(&cmd_ctx->recv_msg, NULL, err);
			if (err < 0) {
				goto error_exit;
			}
		} else {
			err = nrf_rpc_os_msg_set(&cmd_ctx->recv_msg, (void *)packet, len);
			if (err < 0) {
				goto error_exit;
			}
			err = nrf_rpc_os_event_wait(&decode_done_event);
			if (err < 0) {
				goto error_exit;
			}
		}
		break;

	case PACKET_TYPE_ACK:
		nrf_rpc_os_remote_release();

		group = group_from_id(group_id);

		if (group != NULL && group->ack_handler != NULL &&
		    len >= _NRF_RPC_HEADER_SIZE + sizeof(int)) {

			int return_value = *(int*)&packet[_NRF_RPC_HEADER_SIZE];

			group->ack_handler(id, return_value, group->ack_handler_data);
		}
		break;

	case PACKET_TYPE_ERR:
		// DKTODO: err
		break;

	case PACKET_TYPE_INIT:
		err = nrf_rpc_os_remote_count(id);
		if (len >= _NRF_RPC_HEADER_SIZE + sizeof(uint32_t) &&
		    *(uint32_t*)(&packet[_NRF_RPC_HEADER_SIZE]) !=
		    groups_check_sum) {
			NRF_RPC_ERR("Remote groups does not match local");
			NRF_RPC_ASSERT(0);
			nrf_rpc_os_fault();
		} else {
			NRF_RPC_DBG("Groups checksum matching");
		}
		break;

	default:
		goto error_exit;
	}

	if (err >= 0) {
		return;
	}

error_exit:
	if (err >= 0) {
		err = -EIO;
	}

	NRF_RPC_ERR("Error on packet receive %d", err);
	report_error(err);
}



void nrf_rpc_decoding_done(void)
{
	nrf_rpc_os_event_set(&decode_done_event);
}


/* ======================== Command sending ======================== */


/** Wait for response after sending a command.
 *
 * Setting @a rsp_packet and @a rsp_len to NULL informs that the response packet
 * should be handled from filter function before it gets here.
 *
 * @param      local_ep   Endpoint that will receive the response.
 * @param[out] rsp_packet If not NULL contains response packet data.
 * @param[out] rsp_len    If not NULL contains response packet length.
 * @return 0 on success or negative error code.
 */
static int wait_for_response(struct nrf_rpc_cmd_ctx *cmd_ctx,
			     const uint8_t **rsp_packet, size_t *rsp_len)
{
	int err;
	uint8_t type;
	int len;
	const uint8_t *packet;
	void *msg_data;
	size_t msg_len;

	NRF_RPC_ASSERT(cmd_ctx != NULL);

	NRF_RPC_DBG("Waiting for response");

	do {
		err = nrf_rpc_os_msg_get(&cmd_ctx->recv_msg, &msg_data, &msg_len);
		if (err < 0) {
			return err;
		}

		packet = msg_data;
		len = msg_len;

		if (packet == NULL) {
			return len;
		}

		type = parse_incoming_packet(cmd_ctx, packet, len, (rsp_packet != NULL));

		if (type < 0) {
			return type;
		}

	} while (type != PACKET_TYPE_RSP);

	if (rsp_packet != NULL && rsp_len != NULL) {
		*rsp_packet = &packet[_NRF_RPC_HEADER_SIZE];
		*rsp_len = len - _NRF_RPC_HEADER_SIZE;
	}

	return 0;
}


static int cmd_send_common(const struct nrf_rpc_group *group,
			   uint32_t cmd, uint8_t *packet, size_t len,
			   void *ptr1, void *ptr2)
{
	int err;
	nrf_rpc_handler_t old_handler;
	void *old_handler_data;
	uint8_t *full_packet = &packet[-_NRF_RPC_HEADER_SIZE];
	nrf_rpc_handler_t handler = NULL;
	void *handler_data = NULL;
	const uint8_t **rsp_packet = NULL;
	size_t *rsp_len = NULL;
	struct nrf_rpc_cmd_ctx *cmd_ctx;

	NRF_RPC_ASSERT(valid_packet(packet));
	NRF_RPC_ASSERT(ptr1 != NULL);

	if (cmd & CMD_FLAG_WITH_RSP) {
		NRF_RPC_ASSERT(ptr2 != NULL);
		rsp_packet = ptr1;
		rsp_len = ptr2;
	} else {
		handler = ptr1;
		handler_data = ptr2;
	}

	err = get_cmd_ctx(&cmd_ctx, true);
	if (err < 0) {
		nrf_rpc_tr_free_tx_buf(full_packet);
		return err;
	}

	NRF_RPC_WRN("------- %d", cmd_ctx->remote_id);
	encode_cmd_header(full_packet, cmd_ctx->remote_id, cmd_ctx->id, cmd & 0xFF, *group->group_id);

	old_handler = cmd_ctx->handler;
	old_handler_data = cmd_ctx->handler_data;
	cmd_ctx->handler = handler;
	cmd_ctx->handler_data = handler_data;

	NRF_RPC_DBG("Sending command 0x%02X from group 0x%02X", cmd,
		   *group->group_id);

	err = nrf_rpc_tr_send(full_packet, len + _NRF_RPC_HEADER_SIZE);

	if (err >= 0) {
		err = wait_for_response(cmd_ctx, rsp_packet, rsp_len);
	}

	cmd_ctx->handler = old_handler;
	cmd_ctx->handler_data = old_handler_data;

	release_cmd_ctx(cmd_ctx);

	if ((cmd & CMD_FLAG_WITH_RSP) && (err < 0)) {
		nrf_rpc_decoding_done();
	}

	return err;
}


int nrf_rpc_cmd_send(const struct nrf_rpc_group *group, uint8_t cmd, uint8_t *packet,
		     size_t len, nrf_rpc_handler_t handler, void *handler_data)
{
	return cmd_send_common(group, cmd, packet, len, handler, handler_data);
}


int nrf_rpc_cmd_rsp_send(const struct nrf_rpc_group *group, uint8_t cmd, uint8_t *packet,
			 size_t len, const uint8_t **rsp_packet,
			 size_t *rsp_len)
{
	return cmd_send_common(group, cmd | CMD_FLAG_WITH_RSP, packet, len, rsp_packet, rsp_len);
}


void nrf_rpc_cmd_send_noerr(const struct nrf_rpc_group *group, uint8_t cmd, uint8_t *packet,
			    size_t len, nrf_rpc_handler_t handler,
			    void *handler_data)
{
	int err;

	err = cmd_send_common(group, cmd, packet, len, handler, handler_data);
	if (err < 0) {
		NRF_RPC_ERR("Unhandled command send error %d", err);
		report_error(err);
	}
}


/* ======================== Event sending ======================== */



int nrf_rpc_evt_send(const struct nrf_rpc_group *group, uint8_t evt, uint8_t *packet, size_t len)
{
	int err;
	uint8_t *full_packet = &packet[-_NRF_RPC_HEADER_SIZE];

	NRF_RPC_ASSERT(group != NULL);
	NRF_RPC_ASSERT(valid_packet(packet));

	encode_header(full_packet, ID_UNKNOWN, PACKET_TYPE_EVT, evt, *group->group_id);

	NRF_RPC_DBG("Sending event 0x%02X from group 0x%02X", evt,
		    *group->group_id);

	nrf_rpc_os_remote_reserve();

	err = nrf_rpc_tr_send(full_packet, len + _NRF_RPC_HEADER_SIZE);

	if (err < 0) {
		nrf_rpc_os_remote_release();
	}

	return err;
}


void nrf_rpc_evt_send_noerr(const struct nrf_rpc_group *group, uint8_t evt, uint8_t *packet, size_t len)
{
	int err;

	err = nrf_rpc_evt_send(group, evt, packet, len);
	if (err < 0) {
		NRF_RPC_ERR("Unhandled event send error %d", err);
		report_error(err);
	}
}


/* ======================== Response sending ======================== */


int nrf_rpc_rsp_send(uint8_t *packet, size_t len)
{
	int err;
	struct nrf_rpc_cmd_ctx *cmd_ctx;
	uint8_t *full_packet = &packet[-_NRF_RPC_HEADER_SIZE];

	NRF_RPC_ASSERT(valid_packet(packet));

	err = get_cmd_ctx(&cmd_ctx, false);
	if (err < 0) {
		return err;
	}
	NRF_RPC_WRN("------- %d", cmd_ctx->remote_id);
	encode_header(full_packet, cmd_ctx->remote_id, PACKET_TYPE_RSP, RSP_ID_VALID, ID_UNKNOWN);

	NRF_RPC_DBG("Sending response");

	err = nrf_rpc_tr_send(full_packet, len + _NRF_RPC_HEADER_SIZE);

	if (err >= 0) {
		cmd_ctx->response_sent = true;
	}
	NRF_RPC_WRN("------ SEND DONE");
	return err;
}


/* ======================== Common API functions ======================== */


int nrf_rpc_init(void)
{
	int err;
	int i;
	void *iter;
	const struct nrf_rpc_group *group;
	uint8_t group_id = 0;
	const char *strid_ptr;

	NRF_RPC_DBG("Initializing nRF RPC module");

	groups_check_sum = 0;

	for (NRF_RPC_AUTO_ARR_FOR(iter, group, &nrf_rpc_groups_array,
				 const struct nrf_rpc_group)) {
		
		if (group_id >= 0xFF) {
			return -ENOMEM;
		}
		for (strid_ptr = group->strid; *strid_ptr != 0; strid_ptr++)
		{
			groups_check_sum += (uint8_t)(*strid_ptr);
		}
		*group->group_id = group_id;
		group_id++;
	}

	group_id_count = group_id;
	groups_check_sum |= (uint32_t)group_id_count << 24;

	memset(&transaction_pool, 0, sizeof(transaction_pool));

	err = nrf_rpc_os_init();
	if (err < 0) {
		return err;
	}

	nrf_rpc_os_event_init(&decode_done_event);

	for (i = 0; i < CONFIG_NRF_RPC_TRANSACTION_POLL_SIZE; i++) {
		transaction_pool[i].id = i;
		nrf_rpc_os_msg_init(&transaction_pool[i].recv_msg);
	}

	err = nrf_rpc_tr_init(receive_handler);
	if (err < 0) {
		return err;
	}

	err = send_simple(ID_UNKNOWN, PACKET_TYPE_INIT,
			  CONFIG_NRF_RPC_THREAD_POOL_SIZE, ID_UNKNOWN,
			  (uint8_t *)(&groups_check_sum),
			  sizeof(groups_check_sum));

	NRF_RPC_DBG("Done initializing nRF RPC module");

	return err;
}


__attribute__((weak))
void nrf_rpc_error_handler(int code, bool from_remote)
{
	NRF_RPC_DBG("Empty Error Handler called");
}


void nrf_rpc_report_error(int code)
{
	struct nrf_rpc_cmd_ctx *cmd_ctx;

	if (code < 0) {
		get_cmd_ctx(&cmd_ctx, false);
		report_error(code);
	}
}
