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


/** @brief Special value to indicate that ID is unknown or irrelevant. */
#define ID_UNKNOWN 0xFF


/** @brief Flag used only to call @ref cmd_send_common to indicate how the
 * response will be interpreted.
 */
#define CMD_FLAG_WITH_RSP 0x10000

#define RESPONSE_HANDLED_PTR ((uint8_t *)1)



/** @brief Context holding state of the command execution.
 * 
 * Context contains data required to receive response to the command and
 * receive recursice commands. When a thread is waiting for a response
 * this context is associated with that thread to make sure that consecutive
 * commands from that thread will reuse this context.
 */
struct nrf_rpc_cmd_ctx {
	
	uint8_t id;		   /**< Context id (index in cmd_ctx_pool
				    * array).
				    */
	uint8_t remote_id;	   /**< Context id on the remote side which is
				    * associated with this context or ID_UNKNOWN
				    * if it was not associated yet.
				    */
	uint8_t use_count;	   /**< Context usage counter. It increases
				    * each time context is reused.
				    */
	nrf_rpc_handler_t handler; /**< Response handler provided be the user.
				    */
	void* handler_data;	   /**< Pointer for the response handler.
				    */
	struct nrf_rpc_os_msg recv_msg;
				   /**< Message passing between transport
				    * receive callback and a thread that waits
				    * for a response or a recursive commands.
				    */
};


struct header {
	uint8_t dst;
	uint8_t src;
	uint8_t type;
	uint8_t id;
	uint8_t group_id;
};


/** @brief Pool of statically allocated command contexts. */
static struct nrf_rpc_cmd_ctx cmd_ctx_pool[CONFIG_NRF_RPC_CMD_CTX_POLL_SIZE];

/** @brief Checksum of all registered groups. */
static uint32_t groups_check_sum;

/** @brief Event to indicate that packet decoding is completed. */
static struct nrf_rpc_os_event decode_done_event;

/* Array with all defiend groups */
NRF_RPC_AUTO_ARR(nrf_rpc_groups_array, "grp");

/* Number of groups */
static uint8_t group_count; 

static nrf_rpc_err_handler_t global_err_handler;

static struct nrf_rpc_cmd_ctx *cmd_ctx_alloc()
{
	struct nrf_rpc_cmd_ctx *ctx;
	uint32_t index;

	index = nrf_rpc_os_ctx_pool_reserve();

	NRF_RPC_ASSERT(index < CONFIG_NRF_RPC_CMD_CTX_POLL_SIZE);

	ctx = &cmd_ctx_pool[index];
	ctx->handler = NULL;
	ctx->remote_id = ID_UNKNOWN;
	ctx->use_count = 1;

	nrf_rpc_os_tls_set(ctx);

	NRF_RPC_DBG("Command context %d allocated", ctx->id);

	return ctx;
}


static void cmd_ctx_free(struct nrf_rpc_cmd_ctx *ctx)
{
	nrf_rpc_os_tls_set(NULL);
	nrf_rpc_os_ctx_pool_release(ctx->id);
}


static struct nrf_rpc_cmd_ctx *cmd_ctx_reserve()
{
	struct nrf_rpc_cmd_ctx *ctx = nrf_rpc_os_tls_get();

	if (ctx == NULL) {
		nrf_rpc_os_remote_reserve();
		return cmd_ctx_alloc(ctx);
	} else {
		ctx->use_count++;
	}

	return ctx;
}


static void cmd_ctx_release(struct nrf_rpc_cmd_ctx *ctx)
{
	ctx->use_count--;
	if (ctx->use_count == 0) {
		cmd_ctx_free(ctx);
		nrf_rpc_os_remote_release();
	}
}


static struct nrf_rpc_cmd_ctx *cmd_ctx_get_by_id(uint8_t id)
{
	if (id >= CONFIG_NRF_RPC_CMD_CTX_POLL_SIZE) {
		return NULL;
	}
	return &cmd_ctx_pool[id];
}


static struct nrf_rpc_cmd_ctx *cmd_ctx_get_current()
{
	struct nrf_rpc_cmd_ctx *ctx = nrf_rpc_os_tls_get();

	NRF_RPC_ASSERT(ctx != NULL);

	return ctx;
}


static inline int header_decode(const uint8_t *packet, size_t len, struct header *hdr)
{
	if (len < _NRF_RPC_HEADER_SIZE) {
		hdr->src = ID_UNKNOWN;
		hdr->type = ID_UNKNOWN;
		hdr->id = ID_UNKNOWN;
		hdr->dst = ID_UNKNOWN;
		hdr->group_id = ID_UNKNOWN;
		NRF_RPC_ERR("Packet too small");
		return -EBADMSG; // ERR: 1 [EBADMSG] Packet smaller than header
	}

	if (packet[0] & 0x80) {
		hdr->src = packet[0] & 0x7F;
		hdr->type = packet[0] & 0x80;
	} else {
		hdr->src = ID_UNKNOWN;
		hdr->type = packet[0];
	}

	hdr->id = packet[1];
	hdr->dst = packet[2];
	hdr->group_id = packet[3];

	return 0;
}


static inline void header_encode(uint8_t *packet, struct header *hdr)
{
	packet[0] = hdr->type;
	packet[1] = hdr->id;
	packet[2] = hdr->dst;
	packet[3] = hdr->group_id;
}


static inline void header_cmd_encode(uint8_t *packet, struct header *hdr)
{
	packet[0] = NRF_RPC_PACKET_TYPE_CMD | hdr->src;
	packet[1] = hdr->id;
	packet[2] = hdr->dst;
	packet[3] = hdr->group_id;
}


/* ======================== Common utilities ======================== */


/** Function simplifying sending a short packets */
static int simple_send(uint8_t dst, uint8_t type, uint8_t id, uint8_t group_id,
			const uint8_t *packet, size_t len)
{
	struct header hdr;
	uint8_t *tx_buf;

	hdr.dst = dst;
	hdr.type = type;
	hdr.id = id;
	hdr.group_id = group_id;

	nrf_rpc_tr_alloc_tx_buf(&tx_buf, _NRF_RPC_HEADER_SIZE + len);

	header_encode(tx_buf, &hdr);

	if (packet != NULL && len > 0) {
		memcpy(&tx_buf[_NRF_RPC_HEADER_SIZE], packet, len);
	}

	return nrf_rpc_tr_send(tx_buf, _NRF_RPC_HEADER_SIZE + len);
}

/** Report an error that cannot be reported as a function return value */
static void error_report(int code, enum nrf_rpc_err_src src,
			 const struct nrf_rpc_group *group, uint8_t id,
			 uint8_t packet_type)
{
	struct nrf_rpc_err_report report;
	uint8_t group_id = (group != NULL) ? *group->group_id : ID_UNKNOWN;

	NRF_RPC_ERR("Error %s reported %d, group %s, id 0x%02X, type 0x%02X",
		    (src == NRF_RPC_ERR_SRC_RECV) ? "on receive" :
		    (src == NRF_RPC_ERR_SRC_SEND) ? "on send" : "from remote",
		    code, (group != NULL) ? group->strid : "unknown", id,
		    packet_type);

	if (src == NRF_RPC_ERR_SRC_RECV) {
		simple_send(packet_type, NRF_RPC_PACKET_TYPE_ERR, id, group_id, 
			    (const uint8_t *)&code, sizeof(code));
	}

	report.src = src;
	report.group = group;
	report.id = id;
	report.packet_type = packet_type;

	if (group != NULL && group->err_handler != NULL) {
		group->err_handler(&report);
	}

	if (global_err_handler != NULL) {
		global_err_handler(&report);
	}
}


static inline bool packet_validate(const uint8_t *packet)
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
static void handler_execute(uint8_t id, const uint8_t *packet, size_t len,
			    const void *array,
			    const struct nrf_rpc_group *group)
{
	void *iter;
	const struct nrf_rpc_decoder *decoder;

	NRF_RPC_ASSERT(packet_validate(packet));
	NRF_RPC_ASSERT(array != NULL);

	for (NRF_RPC_AUTO_ARR_FOR(iter, decoder, array,
				 const struct nrf_rpc_decoder)) {

		if (id == decoder->id) {
			decoder->handler(packet, len, decoder->handler_data);
			return;
		}
	}

	nrf_rpc_decoding_done(packet);

	NRF_RPC_ERR("Unknown command or event received"); // ERR: 3 Unknown cmd/evt handler

	error_report(-ENOENT, NRF_RPC_ERR_SRC_RECV, group, id,
		     (group->evt_array == array ? NRF_RPC_PACKET_TYPE_EVT :
		      NRF_RPC_PACKET_TYPE_CMD));
}


/** Search for a group based on group_id */
static const struct nrf_rpc_group *group_from_id(uint8_t group_id)
{
	if (group_id >= group_count) {
		return NULL; // ERR: 4 [EBADMSG] Invalid group id
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
 *         NRF_RPC_PACKET_TYPE_RSP if packet contains a response and response_expected
 *         was true. Negative error code on failure.
 */
static uint8_t parse_incoming_packet(struct nrf_rpc_cmd_ctx *cmd_ctx,
				     const uint8_t *packet, size_t len)
{
	int err;
	struct header hdr;
	const struct nrf_rpc_group *group = NULL;
	struct nrf_rpc_cmd_ctx *allocated_ctx = NULL;

	/* Validate required parameters */
	NRF_RPC_ASSERT(packet_validate(packet));

	err = header_decode(packet, len, &hdr);

	/* It was already validated in receive handler, so ASSERT is enough. */
	NRF_RPC_ASSERT(err >= 0);

	if (hdr.type == NRF_RPC_PACKET_TYPE_RSP) {
		/* Receive handler will not pass a response if cmd context is
		 * unknown, so ASSERT is enough.
		 */
		NRF_RPC_ASSERT(cmd_ctx != NULL)
		NRF_RPC_DBG("Response received");
		return hdr.type;
	}

	group = group_from_id(hdr.group_id);

	/* It was already validated in receive handler, so ASSERT is enough. */
	NRF_RPC_ASSERT(group != NULL); 

	if (hdr.type == NRF_RPC_PACKET_TYPE_CMD) {

		if (cmd_ctx == NULL) {
			allocated_ctx = cmd_ctx_alloc();
			cmd_ctx = allocated_ctx;
		}
		cmd_ctx->remote_id = hdr.src;
		NRF_RPC_DBG("Executing command 0x%02X from group 0x%02X", hdr.id,
			    *group->group_id);
		handler_execute(hdr.id, &packet[_NRF_RPC_HEADER_SIZE],
				len - _NRF_RPC_HEADER_SIZE, group->cmd_array, group);
		if (allocated_ctx != NULL) {
			cmd_ctx_free(allocated_ctx);
		}

	} else if (hdr.type == NRF_RPC_PACKET_TYPE_EVT) {

		NRF_RPC_ASSERT(cmd_ctx == NULL); 
		NRF_RPC_DBG("Executing event 0x%02X from group 0x%02X", hdr.id,
			    *group->group_id);
		handler_execute(hdr.id, &packet[_NRF_RPC_HEADER_SIZE],
				len - _NRF_RPC_HEADER_SIZE, group->evt_array, group);
		err = simple_send(ID_UNKNOWN, NRF_RPC_PACKET_TYPE_ACK, hdr.id,
				  *group->group_id, NULL, 0);
		if (err < 0) {
			NRF_RPC_ERR("ACK send error");
			error_report(err, NRF_RPC_ERR_SRC_SEND, group, hdr.id,
				     hdr.type);
		}

	} else {

		/* It was already validated in receive handler. */
		NRF_RPC_ASSERT(0);

	}

	return hdr.type;
}

void execute_packet(const uint8_t *packet, size_t len)
{
	parse_incoming_packet(NULL, packet, len);
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
static void receive_handler(const uint8_t *packet, size_t len)
{
	int err;
	int remote_err;
	struct header hdr;
	struct nrf_rpc_cmd_ctx *cmd_ctx;
	const struct nrf_rpc_group *group = NULL;

	err = header_decode(packet, len, &hdr); // ERR: -> 1
	if (err < 0) {
		goto cleanup_and_exit;
	}

	if (hdr.type == NRF_RPC_PACKET_TYPE_CMD || hdr.type == NRF_RPC_PACKET_TYPE_EVT || hdr.type == NRF_RPC_PACKET_TYPE_ACK || hdr.type == NRF_RPC_PACKET_TYPE_ERR) {
		group = group_from_id(hdr.group_id); // ERR: -> 4
		if (group == NULL && hdr.type != NRF_RPC_PACKET_TYPE_ERR) {
			NRF_RPC_ERR("Invalid group id");
			err = -EBADMSG; // ERR: 4 [EBADMSG] Invalid group id
			goto cleanup_and_exit;
		}
	}

	NRF_RPC_DBG("Received %d bytes packet from %d to %d, type 0x%02X, "
		    "cmd/evt/cnt 0x%02X, grp %d", len, hdr.src, hdr.dst, hdr.type, hdr.id,
		    hdr.group_id);

	if (hdr.type == NRF_RPC_PACKET_TYPE_CMD && hdr.dst == ID_UNKNOWN) {
		/* In this place command behaves almost the same as an event if
		 * destination in unknown or as a response if destination is
		 * known. Local change of type avoids code duplication.
		 */
		hdr.type = NRF_RPC_PACKET_TYPE_EVT;
	}

	switch (hdr.type)
	{
	case NRF_RPC_PACKET_TYPE_CMD: /* with known destination */
	case NRF_RPC_PACKET_TYPE_RSP:
		cmd_ctx = cmd_ctx_get_by_id(hdr.dst);
		if (cmd_ctx == NULL) {
			NRF_RPC_ERR("Invalid ctx id in received packet");
			err = -EBADMSG; // ERR: 7 [EBADMSG] Invalid dst ctx id
			goto cleanup_and_exit;
		}
		if (cmd_ctx->handler != NULL && hdr.type == NRF_RPC_PACKET_TYPE_RSP && NRF_RPC_TR_AUTO_FREE_RX_BUF) {
			cmd_ctx->handler(&packet[_NRF_RPC_HEADER_SIZE], len - _NRF_RPC_HEADER_SIZE, cmd_ctx->handler_data);
			nrf_rpc_os_msg_set(&cmd_ctx->recv_msg, RESPONSE_HANDLED_PTR, 0);
			goto cleanup_and_exit;
		} else {
			nrf_rpc_os_msg_set(&cmd_ctx->recv_msg, (void *)packet, len);
			if (NRF_RPC_TR_AUTO_FREE_RX_BUF) {
				nrf_rpc_os_event_wait(&decode_done_event);
			}
		}
		return;

	case NRF_RPC_PACKET_TYPE_EVT: /* or NRF_RPC_PACKET_TYPE_CMD with unknown destination */
		nrf_rpc_os_thread_pool_send(packet, len);
		if (NRF_RPC_TR_AUTO_FREE_RX_BUF) {
			nrf_rpc_os_event_wait(&decode_done_event);
		}
		return;

	case NRF_RPC_PACKET_TYPE_ACK:
		nrf_rpc_os_remote_release();
		if (group->ack_handler != NULL) {
			group->ack_handler(hdr.id, group->ack_handler_data);
		}
		break;

	case NRF_RPC_PACKET_TYPE_ERR:
		remote_err = -EBADMSG;
		if (len >= _NRF_RPC_HEADER_SIZE + sizeof(int)) {
			remote_err = *(int*)(&packet[_NRF_RPC_HEADER_SIZE]);
		}
		error_report(remote_err, NRF_RPC_ERR_SRC_REMOTE, group, hdr.id,
			     hdr.src);
		break;

	case NRF_RPC_PACKET_TYPE_INIT:
		nrf_rpc_os_remote_count(hdr.id);
		if (len >= _NRF_RPC_HEADER_SIZE + sizeof(uint32_t) &&
		    *(uint32_t*)(&packet[_NRF_RPC_HEADER_SIZE]) !=
		    groups_check_sum) {
			NRF_RPC_ERR("Remote groups does not match local");
			NRF_RPC_ASSERT(0);
			err = -EFAULT; // ERR: 8 FAULT Invalid group checksum
		} else {
			NRF_RPC_DBG("Groups checksum matching");
		}
		break;

	default:
		NRF_RPC_ERR("Invalid type of packet received");
		err = -EBADMSG; // ERR: 6 [EBADMSG] Invalid type of packet received
		break;
	}

cleanup_and_exit:
	if (!NRF_RPC_TR_AUTO_FREE_RX_BUF) {
		nrf_rpc_tr_free_rx_buf(packet);
	}

	if (err < 0) {
		error_report(err, NRF_RPC_ERR_SRC_RECV, group, hdr.id,
			     hdr.type); // ERR: -> 1 6 7 8
	}
}


void nrf_rpc_decoding_done(const uint8_t *packet)
{
	const uint8_t *full_packet = &packet[-_NRF_RPC_HEADER_SIZE];

	if (NRF_RPC_TR_AUTO_FREE_RX_BUF) {
		nrf_rpc_os_event_set(&decode_done_event);
	} else {
		nrf_rpc_tr_free_rx_buf(full_packet);
	}
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
static void wait_for_response(struct nrf_rpc_cmd_ctx *cmd_ctx,
			      const uint8_t **rsp_packet, size_t *rsp_len)
{
	size_t len;
	const uint8_t *packet;
	uint8_t type;

	NRF_RPC_ASSERT(cmd_ctx != NULL);

	NRF_RPC_DBG("Waiting for a response");

	do {
		nrf_rpc_os_msg_get(&cmd_ctx->recv_msg, &packet, &len);

		NRF_RPC_ASSERT(packet != NULL);

		if (packet == RESPONSE_HANDLED_PTR) {
			return;
		}

		type = parse_incoming_packet(cmd_ctx, packet, len);

	} while (type != NRF_RPC_PACKET_TYPE_RSP);

	if (rsp_packet != NULL) {

		NRF_RPC_ASSERT(rsp_len != NULL);
		*rsp_packet = &packet[_NRF_RPC_HEADER_SIZE];
		*rsp_len = len - _NRF_RPC_HEADER_SIZE;

	} else if (!NRF_RPC_TR_AUTO_FREE_RX_BUF && cmd_ctx->handler != NULL) {

		cmd_ctx->handler(&packet[_NRF_RPC_HEADER_SIZE], len - _NRF_RPC_HEADER_SIZE, cmd_ctx->handler_data);
		nrf_rpc_decoding_done(&packet[_NRF_RPC_HEADER_SIZE]);

	}
}


static int cmd_send_common(const struct nrf_rpc_group *group,
			   uint32_t cmd, uint8_t *packet, size_t len,
			   void *ptr1, void *ptr2)
{
	int err;
	struct header hdr;
	nrf_rpc_handler_t old_handler;
	void *old_handler_data;
	uint8_t *full_packet = &packet[-_NRF_RPC_HEADER_SIZE];
	nrf_rpc_handler_t handler = NULL;
	void *handler_data = NULL;
	const uint8_t **rsp_packet = NULL;
	size_t *rsp_len = NULL;
	struct nrf_rpc_cmd_ctx *cmd_ctx;

	NRF_RPC_ASSERT(group != NULL);
	NRF_RPC_ASSERT(packet_validate(packet));
	NRF_RPC_ASSERT(ptr1 != NULL);

	if (cmd & CMD_FLAG_WITH_RSP) {
		NRF_RPC_ASSERT(ptr2 != NULL);
		rsp_packet = ptr1;
		rsp_len = ptr2;
	} else {
		handler = ptr1;
		handler_data = ptr2;
	}

	cmd_ctx = cmd_ctx_reserve();

	hdr.dst = cmd_ctx->remote_id;
	hdr.src = cmd_ctx->id;
	hdr.id = cmd & 0xFF;
	hdr.group_id = *group->group_id;
	header_cmd_encode(full_packet, &hdr);

	old_handler = cmd_ctx->handler;
	old_handler_data = cmd_ctx->handler_data;
	cmd_ctx->handler = handler;
	cmd_ctx->handler_data = handler_data;

	NRF_RPC_DBG("Sending command 0x%02X from group 0x%02X", cmd,
		    *group->group_id);

	err = nrf_rpc_tr_send(full_packet, len + _NRF_RPC_HEADER_SIZE); // ERR: 9 Send transport error

	if (err >= 0) {
		wait_for_response(cmd_ctx, rsp_packet, rsp_len);
	}

	cmd_ctx->handler = old_handler;
	cmd_ctx->handler_data = old_handler_data;

	cmd_ctx_release(cmd_ctx);

	return err; // ERR: -> 9
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
		error_report(err, NRF_RPC_ERR_SRC_SEND, group, cmd,
			     NRF_RPC_PACKET_TYPE_CMD); // ERR: -> 9
	}
}


/* ======================== Event sending ======================== */



int nrf_rpc_evt_send(const struct nrf_rpc_group *group, uint8_t evt, uint8_t *packet, size_t len)
{
	int err;
	struct header hdr;
	uint8_t *full_packet = &packet[-_NRF_RPC_HEADER_SIZE];

	NRF_RPC_ASSERT(group != NULL);
	NRF_RPC_ASSERT(packet_validate(packet));

	hdr.dst = ID_UNKNOWN;
	hdr.type = NRF_RPC_PACKET_TYPE_EVT;
	hdr.id = evt;
	hdr.group_id = *group->group_id;
	header_encode(full_packet, &hdr);

	NRF_RPC_DBG("Sending event 0x%02X from group 0x%02X", evt,
		    *group->group_id);

	nrf_rpc_os_remote_reserve();

	err = nrf_rpc_tr_send(full_packet, len + _NRF_RPC_HEADER_SIZE);

	if (err < 0) {
		nrf_rpc_os_remote_release();
	}

	return err; // ERR: -> 9
}


void nrf_rpc_evt_send_noerr(const struct nrf_rpc_group *group, uint8_t evt, uint8_t *packet, size_t len)
{
	int err;

	err = nrf_rpc_evt_send(group, evt, packet, len);
	if (err < 0) {
		NRF_RPC_ERR("Unhandled event send error %d", err);
		error_report(err, NRF_RPC_ERR_SRC_SEND, group, evt,
			     NRF_RPC_PACKET_TYPE_EVT); // ERR: -> 9
	}
}


/* ======================== Response sending ======================== */


int nrf_rpc_rsp_send(uint8_t *packet, size_t len)
{
	int err;
	struct header hdr;
	struct nrf_rpc_cmd_ctx *cmd_ctx;
	uint8_t *full_packet = &packet[-_NRF_RPC_HEADER_SIZE];

	NRF_RPC_ASSERT(packet_validate(packet));

	cmd_ctx = cmd_ctx_get_current();
	
	hdr.dst = cmd_ctx->remote_id;
	hdr.type = NRF_RPC_PACKET_TYPE_RSP;
	hdr.id = ID_UNKNOWN;
	hdr.group_id = ID_UNKNOWN;
	header_encode(full_packet, &hdr);

	NRF_RPC_DBG("Sending response");

	err = nrf_rpc_tr_send(full_packet, len + _NRF_RPC_HEADER_SIZE);

	return err; // ERR: -> 9
}


void nrf_rpc_rsp_send_noerr(uint8_t *packet, size_t len)
{
	int err;

	err = nrf_rpc_rsp_send(packet, len);
	if (err < 0) {
		NRF_RPC_ERR("Unhandled response send error %d", err);
		error_report(err, NRF_RPC_ERR_SRC_SEND, NULL, ID_UNKNOWN,
			     NRF_RPC_PACKET_TYPE_RSP); // ERR: -> 9
	}
}


/* ======================== Common API functions ======================== */


int nrf_rpc_init(nrf_rpc_err_handler_t err_handler)
{
	int err;
	int i;
	void *iter;
	const struct nrf_rpc_group *group;
	uint8_t group_id = 0;
	const char *strid_ptr;

	NRF_RPC_DBG("Initializing nRF RPC module");

	groups_check_sum = 0;

	global_err_handler = err_handler;

	for (NRF_RPC_AUTO_ARR_FOR(iter, group, &nrf_rpc_groups_array,
				 const struct nrf_rpc_group)) {
		
		if (group_id >= 0xFF) {
			return -ENOMEM;
		}
		for (strid_ptr = group->strid; *strid_ptr != 0; strid_ptr++)
		{
			groups_check_sum += (uint8_t)(*strid_ptr);
		}
		NRF_RPC_DBG("Group '%s' has id %d", group->strid, group_id);
		*group->group_id = group_id;
		group_id++;
	}

	group_count = group_id;
	groups_check_sum |= (uint32_t)group_count << 24;

	memset(&cmd_ctx_pool, 0, sizeof(cmd_ctx_pool));

	err = nrf_rpc_os_init(execute_packet);
	if (err < 0) {
		return err;
	}

	if (NRF_RPC_TR_AUTO_FREE_RX_BUF) {
		err = nrf_rpc_os_event_init(&decode_done_event);
		if (err < 0) {
			return err;
		}
	}

	for (i = 0; i < CONFIG_NRF_RPC_CMD_CTX_POLL_SIZE; i++) {
		cmd_ctx_pool[i].id = i;
		err = nrf_rpc_os_msg_init(&cmd_ctx_pool[i].recv_msg);
		if (err < 0) {
			return err;
		}
	}

	err = nrf_rpc_tr_init(receive_handler);
	if (err < 0) {
		return err;
	}

	err = simple_send(ID_UNKNOWN, NRF_RPC_PACKET_TYPE_INIT,
			  CONFIG_NRF_RPC_THREAD_POOL_SIZE, ID_UNKNOWN,
			  (uint8_t *)(&groups_check_sum),
			  sizeof(groups_check_sum));

	NRF_RPC_DBG("Done initializing nRF RPC module");

	return err; // ERR: 10 Init error
}


__attribute__((weak))
void nrf_rpc_err_handler(int code, bool from_remote)
{
	NRF_RPC_DBG("Empty Error Handler called");
}

