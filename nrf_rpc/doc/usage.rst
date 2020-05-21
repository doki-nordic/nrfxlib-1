.. _usage:

Implementing Remote Procedure Calls
###################################

Specific API can be used remotely if encoders/decoders are provided for it.
One one side there are encoders that encodes parameters and sends a commands or events.
On the other side there are decoders that decodes and executes specific procedure.

Main goal of the nRF_RPC API is to allow creation of encoders/decoders.

Encoders and decoders are grouped.
Each group contains functions related to a single API, e.g. Bluetooth, entropy, e.t.c.
Group is created with the :c:macro:`NRF_RPC_GROUP_DEFINE`.
Grouping allows locally divide the API, but also increase performance of nRF_PRC.

Encoders
========

Encoders encodes commands and events into serialized packets.
Creating an encoder is similar for all packet type.
The first step is allocation of the buffer using e.g. :c:macro:`NRF_RPC_CMD_ALLOC`, :c:macro:`NRF_RPC_CBOR_EVT_ALLOC` or similar depending what kind of packet will be send.
After that you can encode parameters directly into buffer or using `TinyCBOR <https://intel.github.io/tinycbor/current/>`_ library.
In the last step packet is send using one of the sending function, e.g. :cpp:func:`nrf_rpc_cmd_send`, :cpp:func:`nrf_rpc_cbor_evt_send` or similar.

As the result of sending command response is received, so it have to be parsed.
There are two ways to prase the response.

First is to provide response handler in parameters of :cpp:func:`nrf_rpc_cmd_send`.
It will be called before :cpp:func:`nrf_rpc_cmd_send` returns.
It may be called from a different thread.

Second is to call :cpp:func:`nrf_rpc_cmd_rsp_send` or :cpp:func:`nrf_rpc_cbor_cmd_rsp_send` which have output parameters that will contain the response.
After parsing it :cpp:func:`nrf_rpc_decoding_done` function must be called to indicate that parsing is done and the buffers holding the response can be released.

Events have no response, so nothing more have to be done after sending it.

Sample command encoder using TinyCBOR API:

.. code-block:: c

	/* Function will remotely increment `input` by one and put the
	 * result into `output`. Function returns 0 on success or
	 * non-zero error code.
	 */
	int remote_inc(int input, int *output)
	{
		int err;
		CborEncoder *encoder;
		int result[2];
		struct nrf_rpc_cbor_alloc_ctx ctx;

		NRF_RPC_CBOR_CMD_ALLOC(ctx, &math_group, encoder, 16,
				       return NRF_RPC_NO_MEM);

		cbor_encode_int(encoder, input);

		err = nrf_rpc_cbor_cmd_send(&ctx, MATH_COMMAND_INC,
					    remote_inc_rsp, result);

		if (err == NRF_RPC_SUCCESS) {
			*output = result[0];
			err = result[1];
		}

		return err;
	}

Above code uses `remote_inc_rsp` function to parse the response.
Following code shows how this function may look like.

.. code-block:: c

	static int remote_inc_rsp(CborValue *parser, void *hander_data)
	{
		CborError cbor_err;
		int *result = (int *)hander_data;

	 	if (!cbor_value_is_integer(parser)) {
			goto cbor_error_exit;
		}

		cbor_err = cbor_value_get_int(parser, &result[0]);
		if (cbor_err != CborNoError) {
			goto cbor_error_exit;
		}

		result[1] = NRF_RPC_SUCCESS;
		return NRF_RPC_SUCCESS;

	cbor_error_exit:
		result[1] = NRF_RPC_ERR_INVALID_PARAM;
		return NRF_RPC_SUCCESS;
	}

Decoders
========

Decoders are registered with a :c:macro:`NRF_RPC_CMD_DECODER`, :c:macro:`NRF_RPC_CBOR_EVT_DECODER` or similar depending on what kind of decoder it will be.
Decoders are called automatically when command or event is received with a matching id.
Commands decoders must also send a response.

Decoder associated with the examples above may be following:

.. code-block:: c

	static int remote_inc_handler(CborValue *packet, void* handler_data)
	{
		int input;
		int output;
		struct nrf_rpc_cbor_alloc_ctx ctx;
		CborEncoder *encoder;
		CborError cbor_err;

		/* Parsing the input */

	 	if (cbor_value_is_integer(parser)) {
			cbor_err = cbor_value_get_int(packet, &input);
		} else {
			cbor_err = CborErrorIO;
		}
		
		nrf_rpc_decoding_done();

		if (cbor_err != CborNoError) {
			return NRF_RPC_ERR_INTERNAL;
		}

		/* Actual hard work is done in below line */

		output = input + 1;

		/* Encoding and sending the response */

		NRF_RPC_CBOR_RSP_ALLOC(ctx, encoder, 16,
				       return -NRF_RPC_ERR_NO_MEM);

		cbor_encode_int(encoder, output);

		return nrf_rpc_cbor_rsp_send(&ctx);
	}

	NRF_RPC_CBOR_CMD_DECODER(math_group, remote_inc, MATH_COMMAND_INC,
				 remote_inc_handler, NULL);
