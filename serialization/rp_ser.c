/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <rp_ser.h>
#include <rp_trans.h>
#include <rp_os.h>
#include <rp_errors.h>

#define RP_LOG_MODULE SER_CORE
#include <rp_log.h>

#define RP_SER_RSP_INITIAL_ARRAY_SIZE 1
#define RP_SER_CMD_EVT_INITIAL_ARRAY_SIZE 2

static uint8_t endpoint_cnt;

static cmd_handler_t cmd_handler_get(struct rp_ser *rp, uint8_t cmd)
{
	cmd_handler_t cmd_handler = NULL;

	for (const struct rp_ser_cmd *iter = rp->decoders->cmd_begin;
	     iter <  rp->decoders->cmd_end; iter++) {
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

static rp_err_t event_parse(struct rp_ser *rp, uint8_t evt, CborValue *it)
{
	rp_err_t err;
	evt_handler_t evt_handler = NULL;

	for (const struct rp_ser_evt *iter = rp->decoders->evt_begin;
	     iter <  rp->decoders->evt_end; iter++) {
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

static rp_err_t rp_ser_response_parse(struct rp_ser *rp, CborValue *it)
{
	rp_err_t err;

	if (rp->rsp_handler) {
		err = rp->rsp_handler(it);
		if (err) {
			return err;
		}

		rp->rsp_handler = NULL;
	}

	return rp_os_response_signal(rp);
}

static rp_err_t rp_ser_event_parse(struct rp_ser *rp, CborValue *it)
{
	uint8_t event;

	if (!cbor_value_is_simple_type(it) ||
	    cbor_value_get_simple_type(it, &event) != CborNoError) {
		return RP_ERROR_INTERNAL;
	}

	if (cbor_value_advance_fixed(it) != CborNoError) {
		return RP_ERROR_INTERNAL;
	}

	return event_parse(rp, event, it);
}

static rp_err_t rp_ser_cmd_parse(struct rp_ser *rp, CborValue *it)
{
	rp_err_t err;
	uint8_t cmd;

	if (!cbor_value_is_simple_type(it) ||
	    cbor_value_get_simple_type(it, &cmd) != CborNoError) {
		return RP_ERROR_INTERNAL;
	}

	if (cbor_value_advance_fixed(it) != CborNoError) {
		return RP_ERROR_INTERNAL;
	}

	err = cmd_execute(rp, cmd, it);
	if (err) {
		return err;
	}

	RP_LOG_DBG("Received command 0x%02x", cmd);

	return RP_SUCCESS;
}

static rp_err_t rp_ser_received_data_parse(struct rp_ser *rp,
					   const uint8_t *data, size_t len)
{
	rp_err_t err;
	CborParser parser;
	CborValue value;
	CborValue recursed;
	uint8_t packet_type;

	if (cbor_parser_init(data, len, 0, &parser, &value) != CborNoError) {
		return RP_ERROR_INTERNAL;
	}

	if (!cbor_value_is_array(&value)) {
		return RP_ERROR_INTERNAL;
	}

	if (cbor_value_enter_container(&value, &recursed) != CborNoError) {
		return RP_ERROR_INTERNAL;
	}

	/* Get BLE packet type. */
	if (!cbor_value_is_simple_type(&recursed) ||
	    cbor_value_get_simple_type(&recursed,
				       &packet_type) != CborNoError) {
		return RP_ERROR_INTERNAL;
	}

	cbor_value_advance_fixed(&recursed);

	switch (packet_type) {
	case RP_SER_PACKET_TYPE_CMD:
		RP_LOG_DBG("Command received");
		err = rp_ser_cmd_parse(rp, &recursed);

		break;

	case RP_SER_PACKET_TYPE_EVENT:
		RP_LOG_DBG("Event received");
		err = rp_ser_event_parse(rp, &recursed);

		break;

	case RP_SER_PACKET_TYPE_RSP:
		RP_LOG_DBG("Response received");
		err = rp_ser_response_parse(rp, &recursed);

		break;

	default:
		RP_LOG_ERR("Unknown packet received");
		return RP_ERROR_NOT_SUPPORTED;
	}

	if (err) {
		return err;
	}

	/* Be sure that we unpacked all data from the array */
	if (!cbor_value_at_end(&recursed)) {
		RP_LOG_ERR("Received more data than expected");
		return RP_ERROR_INTERNAL;
	}

	if (cbor_value_leave_container(&value, &recursed) != CborNoError) {
		return RP_ERROR_INTERNAL;
	}

	return RP_SUCCESS;
}

static void transport_handler(struct rp_trans_endpoint *endpoint,
			      const uint8_t *buf, size_t length)
{
	struct rp_ser *rp = RP_CONTAINER_OF(endpoint, struct rp_ser, endpoint);

	rp_ser_received_data_parse(rp, buf, length);
}

rp_err_t rp_ser_cmd_send(struct rp_ser *rp, struct rp_ser_encoder *encoder,
			 cmd_rsp_handler_t rsp)
{
	rp_err_t err;

	if (!rp || !encoder) {
		return RP_ERROR_NULL;
	}

	if (encoder->packet_size < 1) {
		return RP_ERROR_INVALID_PARAM;
	}

	if (rp->rsp_handler) {
		return RP_ERROR_BUSY;
	}

	err = rp_trans_send(&rp->endpoint, encoder->buf, encoder->packet_size);
	if (err) {
		return err;
	}

	RP_LOG_DBG("Command sent");

	if (rsp) {
		rp->rsp_handler = rsp;

		RP_LOG_DBG("Waiting for response");

		return rp_os_response_wait(rp);
	}

	return RP_SUCCESS;
}

rp_err_t rp_ser_evt_send(struct rp_ser *rp, struct rp_ser_encoder *encoder)
{
	if (!rp || !encoder) {
		return RP_ERROR_NULL;
	}

	if (encoder->packet_size < 1) {
		return RP_ERROR_INVALID_PARAM;
	}

	return rp_trans_send(&rp->endpoint, encoder->buf, encoder->packet_size);
}

rp_err_t rp_ser_rsp_send(struct rp_ser *rp, struct rp_ser_encoder *encoder)
{
	return rp_ser_evt_send(rp, encoder);
}

rp_err_t rp_ser_init(struct rp_ser *rp)
{
	rp_err_t err;

	if (!rp) {
		return RP_ERROR_NULL;
	}

	err = rp_os_signal_init(rp);
	if (err) {
		return err;
	}

	RP_LOG_DBG("Os signal initialized");

	if (!endpoint_cnt) {
		err = rp_trans_init(transport_handler);
		if (err) {
			return err;
		}

		endpoint_cnt++;
	}

	return rp_trans_endpoint_init(&rp->endpoint, rp->ep_conf->number);
}

void rp_ser_uninit(struct rp_ser *rp)
{
	rp_trans_endpoint_uninit(&rp->endpoint);

	if (endpoint_cnt > 0) {
		endpoint_cnt--;
	} else {
		RP_LOG_DBG("Uninitializing RP transport");
		rp_trans_uninit();
	}
}

rp_err_t rp_ser_procedure_initialize(struct rp_ser_encoder *encoder,
				     CborEncoder *container,
				     size_t argc, enum rp_ser_packet_type type,
				     uint8_t value)
{
	CborError err;
	size_t container_size;

	if (!encoder || !container) {
		return RP_ERROR_NULL;
	}

	encoder->container = container;

	cbor_encoder_init(&encoder->encoder, encoder->buf,
			  encoder->buf_size, 0);

	container_size = argc + (type == RP_SER_PACKET_TYPE_RSP ?
				 RP_SER_RSP_INITIAL_ARRAY_SIZE : RP_SER_CMD_EVT_INITIAL_ARRAY_SIZE);

	err = cbor_encoder_create_array(&encoder->encoder, encoder->container,
					container_size);
	if (err) {
		return RP_ERROR_INTERNAL;
	}

	err = cbor_encode_simple_value(encoder->container, type);
	if (err) {
		return RP_ERROR_INTERNAL;
	}

	if (type == RP_SER_PACKET_TYPE_RSP) {
		return RP_SUCCESS;
	}

	err = cbor_encode_simple_value(encoder->container, value);
	if (err) {
		return RP_ERROR_INTERNAL;
	}

	return RP_SUCCESS;
}

rp_err_t rp_ser_procedure_end(struct rp_ser_encoder *encoder)
{
	CborError err;

	if (!encoder) {
		return RP_ERROR_NULL;
	}

	err = cbor_encoder_close_container(&encoder->encoder, encoder->container);
	if (err) {
		return RP_ERROR_INTERNAL;
	}

	encoder->packet_size = cbor_encoder_get_buffer_size(&encoder->encoder, encoder->buf);

	if (encoder->packet_size < 1) {
		return RP_ERROR_INVALID_PARAM;
	}

	return RP_SUCCESS;
}
