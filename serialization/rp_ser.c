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

#define RP_SER_ERROR_HADER_SIZE 1

#define FILTERED_RESPONSE 1
#define FILTERED_ACK 2

#define HEADER_TYPE_INDEX 0
#define HEADER_CODE_INDEX 1


enum rp_ser_packet_type {
	/** Serialization command packet. */
	RP_SER_PACKET_TYPE_CMD          = 0x01,

	/** Serialization event packet. */
	RP_SER_PACKET_TYPE_EVENT,

	/** Serialization command response packet. */
	RP_SER_PACKET_TYPE_RSP,

	/** Serialization event acknowledge packet. */
	RP_SER_PACKET_TYPE_ACK,

	/** Serialization fatal error notification packet. */
	RP_SER_PACKET_TYPE_ERROR = 0xFF,
};

static uint8_t endpoint_cnt;

void rp_ser_error_handler(struct rp_ser *rp, rp_ser_error_location_t location, uint8_t code, bool fatal, rp_err_t err)
{
	// TODO: weak
	RP_LOG_ERR("Unhandled serialization error: %d, cmd/evt: %d, loc: %d", err, code, location);
	if (fatal) {
		__ASSERT(0, "Unhandled fatal serialization error");
		while (1);
	}
}

static void rp_ser_error(struct rp_ser *rp, rp_ser_error_location_t location, uint8_t code, bool fatal, rp_err_t err)
{
	if (fatal) {
		uint8_t *buf;
		rp_trans_alloc_tx_buf(&rp->endpoint, &buf, 1, 3 * sizeof(uint8_t)  + sizeof(int));
		if (!rp_trans_alloc_failed(buf)) {
			buf[HEADER_TYPE_INDEX] = RP_SER_PACKET_TYPE_ERROR;
			buf[1] = (uint8_t)code;
			buf[2] = (uint8_t)location;
			buf[3] = (uint8_t)fatal;
			*(int *)&buf[4] = (int)err;
			rp_trans_send(&rp->endpoint, buf, 1 + 3 * sizeof(uint8_t) + sizeof(int));
		}
	}
	rp_ser_error_handler(rp, location, code, fatal, err);
}

static void parse_error(struct rp_ser *rp, const uint8_t* buf, size_t len)
{
	rp_ser_error_location_t location;
	uint8_t code;
	bool fatal;
	rp_err_t err;

	if (len < 3 * sizeof(uint8_t) + sizeof(int)) {
		return;
	}

	code = buf[0];
	fatal = (bool)buf[1];
	location = (rp_ser_error_location_t)buf[2] | RP_SER_ERROR_ON_REMOTE;
	err = (rp_err_t)(*(int *)&buf[3]);
	rp_ser_error_handler(rp, location, code, fatal, err);
}

static void handler_execute(struct rp_ser *rp,
				uint8_t code,
				const uint8_t *packet,
				size_t len,
				const struct rp_ser_decoder *begin,
				const struct rp_ser_decoder *end)
{
	rp_err_t err;
	const struct rp_ser_decoder *iter;
	rp_ser_decoder_handler_t handler = NULL;

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

static void received_data_parse(struct rp_ser *rp, const uint8_t *data, size_t len)
{
	uint8_t packet_type;
	bool prev_wait_for_ack;

	if (data == NULL) {
	 	printk("filtered %d\n", len);
		rp->waiting_for_ack = false;
		if (len != FILTERED_ACK || !USE_EVENT_ACK) {
			RP_LOG_ERR("Invalid packet");
			goto exit_with_error;
		}
	}

 	printbuf("received_data_parse", data, len);

	if (len < RP_SER_CMD_EVT_HADER_SIZE) {
		RP_LOG_ERR("Packet too small");
		goto exit_with_error;
	}

	packet_type = data[HEADER_TYPE_INDEX];

	switch (packet_type) {
	case RP_SER_PACKET_TYPE_CMD:
		if (USE_EVENT_ACK) {
			// If we are executing command then the other end is waiting for
			// response, so sending notifications and commands is available again now.
			prev_wait_for_ack = rp->waiting_for_ack;
			rp->waiting_for_ack = false;
		}
		RP_LOG_DBG("Command received");
		cmd_execute(rp, data[HEADER_CODE_INDEX], &data[RP_SER_CMD_EVT_HADER_SIZE], len - RP_SER_CMD_EVT_HADER_SIZE);
		if (USE_EVENT_ACK) {
			// Resore previous state of waiting for ack
			rp->waiting_for_ack = prev_wait_for_ack;
		}
		break;

	case RP_SER_PACKET_TYPE_EVENT:
		RP_LOG_DBG("Event received");
		event_execute(rp, data[HEADER_CODE_INDEX], &data[RP_SER_CMD_EVT_HADER_SIZE], len - RP_SER_CMD_EVT_HADER_SIZE);
		if (USE_EVENT_ACK) {
			packet_type = RP_SER_PACKET_TYPE_ACK;
			rp_trans_send(&rp->endpoint, &packet_type, RP_SER_RSP_ACK_HEADER_SIZE); // DKTODO: rp trans Alloc required!!! e.g. send_simple_packet
		}
		break;

	case RP_SER_PACKET_TYPE_ERROR:
		parse_error(rp, &data[RP_SER_ERROR_HADER_SIZE], len - RP_SER_ERROR_HADER_SIZE);
		break;

	default:
		RP_LOG_ERR("Unknown packet received");
		goto exit_with_error;
	}

	return;

exit_with_error:
	rp_ser_error(rp, RP_SER_ERROR_ON_RECEIVE, RP_SER_CMD_EVT_CODE_UNKNOWN, true, RP_ERROR_INTERNAL);
}

static void transport_handler(struct rp_trans_endpoint *endpoint,
			      const uint8_t *buf, size_t length)
{
	struct rp_ser *rp = RP_CONTAINER_OF(endpoint, struct rp_ser, endpoint);

	printbuf("transport_handler", buf, length);

	received_data_parse(rp, buf, length);
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

		switch (packet[HEADER_TYPE_INDEX])
		{
		/* NEXT: Allow inline decoder
		case RP_SER_PACKET_TYPE_RSP:
			if (out_packet) {
				*out_packet = packet;
			}
			return packet_length;*/
		case RP_SER_PACKET_TYPE_CMD:
		case RP_SER_PACKET_TYPE_EVENT:
			// rp_trans_read_end will be called indirectly from command/event decoder
			received_data_parse(rp, packet, packet_length);
			break;
		case RP_SER_PACKET_TYPE_ERROR:
			// rp_trans_read_end will be called indirectly from command/event decoder
			received_data_parse(rp, packet, packet_length);
			return RP_ERROR_REMOTE;
		default:
			RP_LOG_ERR("Invalid response");
			return RP_ERROR_INVALID_STATE;
		}
	} while (true);
}

// Called before sending command or notify to make sure that last notification was finished and the other end
// can handle this packet imidetally.
static rp_err_t wait_for_last_ack(struct rp_ser *rp)
{
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

		switch (packet[HEADER_TYPE_INDEX])
		{
		case RP_SER_PACKET_TYPE_CMD:
		case RP_SER_PACKET_TYPE_EVENT:
			// rp_trans_read_end will be called indirectly from command/event decoder
			received_data_parse(rp, packet, packet_length);
			break;
		case RP_SER_PACKET_TYPE_ERROR:
			// rp_trans_read_end will be called indirectly from command/event decoder
			received_data_parse(rp, packet, packet_length);
			return RP_ERROR_REMOTE;
		default:
			RP_LOG_ERR("Invalid response");
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

	full_packet[HEADER_TYPE_INDEX] = RP_SER_PACKET_TYPE_EVENT;
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
	rp_trans_release_buffer(&rp->endpoint);
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
