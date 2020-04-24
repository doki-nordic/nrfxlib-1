/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define NRF_RPC_LOG_MODULE NRF_RPC_CBOR
#include <nrf_rpc_log.h>

#include <stdint.h>

#include <nrf_rpc.h>
#include <nrf_rpc_cbor.h>


CborEncoder* _nrf_rpc_cbor_encoder_init(struct nrf_rpc_cbor_alloc_ctx *ctx,
					size_t len)
{
	cbor_buf_writer_init(&ctx->writer, ctx->packet, len);
	cbor_encoder_init(&ctx->encoder, &ctx->writer.enc, 0);
	return &ctx->encoder;
}


int _nrf_rpc_cbor_proxy_handler(const uint8_t *packet, size_t len,
				void *handler_data)
{
	CborParser parser;
	CborValue value;
	struct cbor_buf_reader reader;
	struct _nrf_rpc_cbor_decoder *cbor_handler =
		(struct _nrf_rpc_cbor_decoder *)handler_data;

	cbor_buf_reader_init(&reader, packet, len);

	if (cbor_parser_init(&reader.r, 0, &parser, &value) != CborNoError) {
		return NRF_RPC_ERR_INVALID_PARAM;
	}
	value.remaining = UINT32_MAX;

	return cbor_handler->handler(&value, cbor_handler->handler_data);
}


int nrf_rpc_cbor_cmd_send(struct nrf_rpc_cbor_alloc_ctx *ctx, uint8_t cmd,
			  nrf_rpc_cbor_handler_t handler, void *handler_data)
{
	size_t len;
	const struct _nrf_rpc_cbor_decoder cbor_handler = {
		.handler = handler,
		.handler_data = handler_data,
	};

	if (cbor_encode_null(&ctx->encoder) != CborNoError) {
		goto cbor_error_exit;
	}

	len = cbor_buf_writer_buffer_size(&ctx->writer, ctx->packet);

	return nrf_rpc_cmd_send(ctx->base_ctx, cmd, ctx->packet, len,
				&_nrf_rpc_cbor_proxy_handler,
				(void *)&cbor_handler);

cbor_error_exit:
	NRF_RPC_CMD_DISCARD(ctx->base_ctx, ctx->packet);
	return NRF_RPC_ERR_NO_MEM;
}


int nrf_rpc_cbor_cmd_rsp_send(struct nrf_rpc_cbor_alloc_ctx *ctx, uint8_t cmd,
			      struct nrf_rpc_cbor_cmd_rsp_ctx *rsp_ctx,
			      CborValue *rsp_packet)
{
	int err;
	size_t len;
	const uint8_t *rsp_packet_buf;
	size_t rsp_len;

	if (cbor_encode_null(&ctx->encoder) != CborNoError) {
		goto encoder_error_exit;
	}

	len = cbor_buf_writer_buffer_size(&ctx->writer, ctx->packet);

	err = nrf_rpc_cmd_rsp_send(ctx->base_ctx, cmd, ctx->packet, len,
				   &rsp_packet_buf, &rsp_len);
	if (err != 0) {
		return err;
	}

	cbor_buf_reader_init(&rsp_ctx->reader, rsp_packet_buf, rsp_len);

	if (cbor_parser_init(&rsp_ctx->reader.r, 0, &rsp_ctx->parser, rsp_packet)
				!= CborNoError)
	{
		nrf_rpc_decoding_done();
		return NRF_RPC_ERR_INTERNAL;
	}
	rsp_packet->remaining = UINT32_MAX;

	return NRF_RPC_SUCCESS;

encoder_error_exit:
	NRF_RPC_CMD_DISCARD(ctx->base_ctx, ctx->packet);
	return NRF_RPC_ERR_NO_MEM;
}

void nrf_rpc_cbor_cmd_send_noerr(struct  nrf_rpc_cbor_alloc_ctx *ctx,
				 uint8_t cmd, nrf_rpc_cbor_handler_t handler,
				 void *handler_data)
{
	int err;

	err = nrf_rpc_cbor_cmd_send(ctx, cmd, handler, handler_data);

	if (err < 0) {
		NRF_RPC_ERR("Unhandled command send error %d", err);
		nrf_rpc_report_error(ctx->base_ctx, err);
	}
}

int nrf_rpc_cbor_evt_send(struct nrf_rpc_cbor_alloc_ctx *ctx, uint8_t evt)
{
	size_t len;

	if (cbor_encode_null(&ctx->encoder) != CborNoError) {
		goto cbor_error_exit;
	}

	len = cbor_buf_writer_buffer_size(&ctx->writer, ctx->packet);

	return nrf_rpc_evt_send(ctx->base_ctx, evt, ctx->packet, len);

cbor_error_exit:
	NRF_RPC_EVT_DISCARD(ctx->base_ctx, ctx->packet);
	return NRF_RPC_ERR_NO_MEM;
}

void nrf_rpc_cbor_evt_send_noerr(struct nrf_rpc_cbor_alloc_ctx *ctx,
				 uint8_t evt)
{
	int err;

	err = nrf_rpc_cbor_evt_send(ctx, evt);

	if (err < 0) {
		NRF_RPC_ERR("Unhandled event send error %d", err);
		nrf_rpc_report_error(ctx->base_ctx, err);
	}
}

int nrf_rpc_cbor_rsp_send(struct nrf_rpc_cbor_alloc_ctx *ctx)
{
	size_t len;

	if (cbor_encode_null(&ctx->encoder) != CborNoError) {
		goto cbor_error_exit;
	}

	len = cbor_buf_writer_buffer_size(&ctx->writer, ctx->packet);

	return nrf_rpc_rsp_send(ctx->base_ctx,ctx->packet, len);

cbor_error_exit:
	NRF_RPC_RSP_DISCARD(ctx->base_ctx, ctx->packet);
	return NRF_RPC_ERR_NO_MEM;

}
