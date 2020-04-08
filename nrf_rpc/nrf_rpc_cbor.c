/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 * /
#include <rp_ser.h>
#include <rp_trans.h>
#include <rp_errors.h>

#define RP_LOG_MODULE SER_CORE
#include <rp_log.h>


#if defined(CONFIG_RP_SER_FORCE_EVENT_ACK) || RP_TRANS_REQUIRE_EVENT_ACK
#define USE_EVENT_ACK 1
#else
#define USE_EVENT_ACK 0
#endif


#define FILTERED_RESPONSE 1
#define FILTERED_ACK 2

#define RP_SER_RSP_INITIAL_ARRAY_SIZE 2
#define RP_SER_CMD_EVT_INITIAL_ARRAY_SIZE 3

static uint8_t endpoint_cnt;

static uint8_t *buf_tail_get(struct rp_ser_buf *rp_buf)
{
	return rp_buf->buf + rp_buf->packet_size;
}

static size_t buf_free_space_get(struct rp_ser_buf *rp_buf)
{
	return rp_buf->size - rp_buf->packet_size;
}

static cmd_handler_t cmd_handler_get(struct rp_ser *rp, uint8_t cmd)
{
	cmd_handler_t cmd_handler = NULL;

	for (const struct rp_ser_cmd *iter = rp->conf->cmd_begin;
	     iter <  rp->conf->cmd_end; iter++) {
		if (cmd == iter->cmd) {
			cmd_handler = iter->func;
			break;
		}
	}

	return cmd_handler;
}

static rp_err_t cmd_execute(struct rp_ser *rp, uint8_t cmd, CborValue *it)
{
	rp_err_t err;
	cmd_handler_t cmd_handler;

	cmd_handler = cmd_handler_get(rp, cmd);

	if (cmd_handler) {
		err = cmd_handler(it);
	} else {
		RP_LOG_ERR("Unsupported command received");
		err = RP_ERROR_NOT_SUPPORTED;
	}

	return err;
}

static rp_err_t event_parse(struct rp_ser *rp, uint8_t evt, CborValue *it) // DKTODO: Why cmd is splited and event not?
{
	rp_err_t err;
	evt_handler_t evt_handler = NULL;

	for (const struct rp_ser_evt *iter = rp->conf->evt_begin;
	     iter <  rp->conf->evt_end; iter++) {
		if (evt == iter->evt) {
			evt_handler = iter->func;
			break;
		}
	}

	if (evt_handler) {
		err = evt_handler(evt, it);
	} else {
		RP_LOG_ERR("Unsupported event received");
		err = RP_ERROR_NOT_SUPPORTED;
	}

	return err;
}

static rp_err_t response_parse(struct rp_ser *rp, const uint8_t *data,
			       size_t len)
{
	rp_err_t err = RP_SUCCESS;
	CborParser parser;
	CborValue value;

	if (len > 0) {
		if (cbor_parser_init(data, len, 0, &parser, &value) !=
		    CborNoError) {
			return RP_ERROR_INTERNAL;
		    }

		/ * Extend paraser to handle more than one item. * /
		value.remaining = UINT32_MAX;
	}

	if (rp->rsp_handler) {
		err = rp->rsp_handler(&value);
	}

	return err;
}

static rp_err_t event_dispatch(struct rp_ser *rp, const uint8_t *data,
			       size_t len)
{
	uint8_t evt;
	CborParser parser;
	CborValue value;
	uint32_t index = 0;

	if (len < 1) {
		return RP_ERROR_INVALID_PARAM;
	}

	evt = data[index];
	index++;
	len -= index;

	if (len > 0) {
		if (cbor_parser_init(&data[index], len, 0, &parser, &value) !=
		    CborNoError) {
			return RP_ERROR_INTERNAL;
		    }

		value.remaining = UINT32_MAX;
	}

	return event_parse(rp, evt, &value);
}

static rp_err_t cmd_dispatch(struct rp_ser *rp, const uint8_t *data,
			     size_t len)
{
	rp_err_t err;
	uint8_t cmd;
	CborParser parser;
	CborValue value;
	uint32_t index = 0;

	if (len < 1) {
		return RP_ERROR_INVALID_PARAM;
	}

	cmd = data[index];
	index++;
	len -= index;

	if (len > 0) {
		if (cbor_parser_init(&data[index], len, 0, &parser, &value) !=
		    CborNoError) {
			return RP_ERROR_INTERNAL;
		    }

		value.remaining = UINT32_MAX;
	}

	err = cmd_execute(rp, cmd, &value);
	if (err) {
		return err;
	}

	RP_LOG_DBG("Received command 0x%02x", cmd);

	return RP_SUCCESS;
}

static rp_err_t received_data_parse(struct rp_ser *rp,
				    const uint8_t *data, size_t len)
{
	rp_err_t err;
	uint8_t packet_type;
	uint32_t index = 0;
	bool prev_wait_for_ack;

	if (data == NULL) {
		if (USE_EVENT_ACK) {
			__ASSERT(length == FILTERED_ACK, "Invalid response");
			rp->waiting_for_ack = false;
		} else {
			__ASSERT(0, "Invalid response"); // DKTODO: Check if __ASSERT is available outside zephyr
		}
		return RP_SUCCESS;
	}
 
	if (len  < 1) {
		return RP_ERROR_INVALID_PARAM;
	}

	packet_type = data[index];
	index++;
	len -= index;

	// We get response - this kind of packet should be handled before
	__ASSERT(type != RP_SER_PACKET_TYPE_RSP, "Response packet without any call");

	switch (packet_type) {
	case RP_SER_PACKET_TYPE_CMD:
		if (USE_EVENT_ACK) {
			// If we are executing command then the other end is waiting for
			// response, so sending notifications and commands is available again now.
			prev_wait_for_ack = rp->waiting_for_ack;
			rp->waiting_for_ack = false;
		}
		RP_LOG_DBG("Command received");
		err = cmd_dispatch(rp, &data[index], len);
		if (USE_EVENT_ACK) {
			// Resore previous state of waiting for ack
			rp->waiting_for_ack = prev_wait_for_ack;
		}
		break;

	case RP_SER_PACKET_TYPE_EVENT:
		RP_LOG_DBG("Event received");
		err = event_dispatch(rp, &data[index], len);
		if (USE_EVENT_ACK) {
			packet_type = RP_SER_PACKET_TYPE_ACK;
			rp_trans_send(&rp->endpoint, &packet_type, 1);
		}
		break;

	default:
		RP_LOG_ERR("Unknown packet received");
		return RP_ERROR_NOT_SUPPORTED;
	}

	return err;
}

static void transport_handler(struct rp_trans_endpoint *endpoint,
			      const uint8_t *buf, size_t length)
{
	struct rp_ser *rp = RP_CONTAINER_OF(endpoint, struct rp_ser, endpoint);

	received_data_parse(rp, buf, length);
}

static uint32_t transport_filter(struct rp_trans_endpoint *endpoint,
			  const uint8_t *buf, size_t length)
{
	struct rp_ser *rp = RP_CONTAINER_OF(endpoint, struct rp_ser, endpoint);

	switch (buf[0])
	{
	case RP_SER_PACKET_TYPE_RSP:
		if (rp->rsp_handler) {
			response_parse(rp, &buf[1], length - 1); // NEXT: Unify len and length
			rp->rsp_handler = NULL;
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

		if (packet == NULL)
		{
			__ASSERT(packet_length == FILTERED_RESPONSE, "Invalid response");
			return 0;
		}

		switch (packet[0])
		{
		/ * NEXT: Allow inline decoder
		case RP_SER_PACKET_TYPE_RSP:
			if (out_packet) {
				*out_packet = packet;
			}
			return packet_length;* /
		case RP_SER_PACKET_TYPE_CMD:
		case RP_SER_PACKET_TYPE_EVENT:
			// rp_trans_read_end will be called indirectly from command/event decoder
			received_data_parse(rp, packet, packet_length);
			break;
		default:
			__ASSERT(0, "Invalid response");
			break;
		}
	} while (true);
}

// Called before sending command or notify to make sure that last notification was finished and the other end
// can handle this packet imidetally.
static void wait_for_last_ack(struct rp_ser *rp)
{
	const uint8_t *packet;
	int packet_length;

	if (!rp->waiting_for_ack) {
		return;
	}

	do {
		// Wait for something from rx callback
		packet_length = rp_trans_read(&rp->endpoint, &packet);

		if (packet == NULL)
		{
			__ASSERT(packet_length == FILTERED_ACK, "Invalid response");
			rp->waiting_for_ack = false;
			return;
		}

		switch (packet[0])
		{
		case RP_SER_PACKET_TYPE_CMD:
		case RP_SER_PACKET_TYPE_EVENT:
			// rp_trans_read_end will be called indirectly from command/event decoder
			received_data_parse(rp, packet, packet_length);
			break;
		default:
			__ASSERT(0, "Invalid response");
			break;
		}
	} while (true);
}

rp_err_t rp_ser_cmd_send(struct rp_ser *rp, struct rp_ser_buf *rp_buf, // NEXT: Replace rp_buf and encoder by buffer and length
			 CborEncoder *encoder, cmd_handler_t rsp) // NEXT: add result pointer
{
	cmd_handler_t old_rsp;
	rp_err_t err;

	if (!rp || !rp_buf) {
		return RP_ERROR_NULL;
	}

	/ * Encode NULL value to indicate packet end. * /
	if (cbor_encode_null(encoder) != CborNoError) { // NEXT: Move to cbor layer
		return RP_ERROR_INTERNAL;
	}

	/ * Calculate TinyCbor packet size * /
	rp_buf->packet_size += cbor_encoder_get_buffer_size(encoder,
							    buf_tail_get(rp_buf)); // NEXT: Move to cbor layer

	if (rp_buf->packet_size < 1) {
		return RP_ERROR_INVALID_PARAM; // NEXT: Not needed
	}

	// Endpoint is not accessible by other thread from this point
	rp_trans_own(&rp->endpoint);
	// Make sure that someone can handle packet immidietallty
	if (USE_EVENT_ACK) {
		wait_for_last_ack(rp);
	}
	// Set decoder for current command and save on stack decoder for previously waiting response
	old_rsp = rp->rsp_handler; // NEXT: add pointer to result
	rp->rsp_handler = rsp;
	// Send buffer to transport layer
	err = rp_trans_send(&rp->endpoint, rp_buf->buf, rp_buf->packet_size);
	if (err) {
		goto error;
	}
	// Wait for response. During waiting nested commands and notifications are possible
	err = wait_for_response(rp);

error:
	// restore decoder for previously waiting response
	rp->rsp_handler = old_rsp;
	rp_trans_give(&rp->endpoint);
	return err;
}

rp_err_t rp_ser_evt_send(struct rp_ser *rp, struct rp_ser_buf *rp_buf,
			 CborEncoder *encoder)
{
	rp_err_t err;

	if (!rp || !rp_buf) {
		return RP_ERROR_NULL;
	}

	/ * Encode NULL value to indicate packet end. * /
	if (cbor_encode_null(encoder) != CborNoError) {
		return RP_ERROR_INTERNAL;
	}

	/ * Calculate TinyCbor packet size * /
	rp_buf->packet_size += cbor_encoder_get_buffer_size(encoder,
							    buf_tail_get(rp_buf));
	if (rp_buf->packet_size < 1) {
		return RP_ERROR_INVALID_PARAM;
	}

	// Endpoint is not accessible by other thread from this point
	rp_trans_own(&rp->endpoint);
	if (USE_EVENT_ACK) {
		// Make sure that someone can handle packet immidietallty
		wait_for_last_ack(rp);
		// we are expecting ack later
		rp->waiting_for_ack = true;
	}
        // Send buffer to transport layer
	err = rp_trans_send(&rp->endpoint, rp_buf->buf, rp_buf->packet_size);
        // We can unlock now, nothing more to do
	rp_trans_give(&rp->endpoint);
	return err;
}

rp_err_t rp_ser_rsp_send(struct rp_ser *rp, struct rp_ser_buf *rp_buf,
			 CborEncoder *encoder)
{
	rp_err_t err;

	if (!rp || !rp_buf) {
		return RP_ERROR_NULL;
	}

	/ * Encode NULL value to indicate packet end. * /
	if (cbor_encode_null(encoder) != CborNoError) {
		return RP_ERROR_INTERNAL;
	}

	/ * Calculate TinyCbor packet size * /
	rp_buf->packet_size += cbor_encoder_get_buffer_size(encoder,
							    buf_tail_get(rp_buf));
	if (rp_buf->packet_size < 1) {
		return RP_ERROR_INVALID_PARAM;
	}

        // Send buffer to transport layer
	err = rp_trans_send(&rp->endpoint, rp_buf->buf, rp_buf->packet_size);
	return err;
}

void rp_ser_decode_done(struct rp_ser *rp)
{
	rp_trans_release_buffer(&rp->endpoint);
}

rp_err_t rp_ser_init(struct rp_ser *rp)
{
	rp_err_t err;

	if (!rp) {
		return RP_ERROR_NULL;
	}

	if (!endpoint_cnt) {
		err = rp_trans_init(transport_handler, transport_filter);
		if (err) {
			return err;
		}

		endpoint_cnt++;
	}

	return rp_trans_endpoint_init(&rp->endpoint, rp->conf->ep_number);
}

rp_err_t rp_ser_cmd_init(struct rp_ser_buf *rp_buf, CborEncoder *encoder,
			 uint8_t cmd)
{
	uint8_t *data = rp_buf->buf;

	if (!rp_buf) {
		return RP_ERROR_NULL;
	}

	if (rp_buf->size < RP_SER_CMD_EVT_INITIAL_ARRAY_SIZE) {
		return RP_ERROR_NO_MEM;
	}

	*data = RP_SER_PACKET_TYPE_CMD;
	rp_buf->packet_size++;
	data++;

	*data = cmd;
	rp_buf->packet_size++;

	cbor_encoder_init(encoder, buf_tail_get(rp_buf),
			  buf_free_space_get(rp_buf), 0);

	return RP_SUCCESS;
}

rp_err_t rp_ser_evt_init(struct rp_ser_buf *rp_buf, CborEncoder *encoder,
			 uint8_t evt)
{
	uint8_t *data = rp_buf->buf;

	if (!rp_buf) {
		return RP_ERROR_NULL;
	}

	if (rp_buf->size < RP_SER_CMD_EVT_INITIAL_ARRAY_SIZE) {
		return RP_ERROR_NO_MEM;
	}

	*data = RP_SER_PACKET_TYPE_EVENT;
	rp_buf->packet_size++;
	data++;

	*data = evt;
	rp_buf->packet_size++;

	cbor_encoder_init(encoder, buf_tail_get(rp_buf),
			  buf_free_space_get(rp_buf), 0);

	return RP_SUCCESS;
}

rp_err_t rp_ser_rsp_init(struct rp_ser_buf *rp_buf, CborEncoder *encoder)
{
	uint8_t *data = rp_buf->buf;

	if (!rp_buf) {
		return RP_ERROR_NULL;
	}

	if (rp_buf->size < RP_SER_RSP_INITIAL_ARRAY_SIZE) {
		return RP_ERROR_NO_MEM;
	}

	*data = RP_SER_PACKET_TYPE_RSP;
	rp_buf->packet_size++;

	cbor_encoder_init(encoder, buf_tail_get(rp_buf),
			  buf_free_space_get(rp_buf), 0);

	return RP_SUCCESS;
}

*/