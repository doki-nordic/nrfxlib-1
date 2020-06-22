.. _usage:


Implementing Remote Procedure Calls
###################################

Specific API can be used remotely if encoders/decoders are provided for it.
One one side there are encoders that encode parameters and send a commands or events.
On the other side there are decoders that decode and execute specific procedure.

Main goal of the nRF RPC API is to allow creation of encoders/decoders.

Encoders and decoders are grouped.
Each group contains functions related to a single API, e.g. Bluetooth, entropy, e.t.c.
Group is created with the :c:macro:`NRF_RPC_GROUP_DEFINE`.
Grouping allows logically divide the remote API, but also increases performance of nRF RPC.


Encoders
========

Encoders encodes commands and events into serialized packets.
Creating an encoder is similar for all packet type.
The first step is allocation of the buffer using :c:macro:`NRF_RPC_ALLOC`.
After that you can encode parameters directly into buffer or using `TinyCBOR <https://github.com/zephyrproject-rtos/tinycbor>`_ library.
In the last step packet is send using one of the sending function, e.g. :cpp:func:`nrf_rpc_cmd`, :cpp:func:`nrf_rpc_cbor_evt` or similar.

As the result of sending command response is received, so it have to be parsed.
There are two ways to prase the response.

First is to provide response handler in parameters of :cpp:func:`nrf_rpc_cmd` or :cpp:func:`nrf_rpc_cbor_cmd`.
It will be called before :cpp:func:`nrf_rpc_cmd` returns.
It may be called from a different thread.

Second is to call :cpp:func:`nrf_rpc_cmd_rsp` or :cpp:func:`nrf_rpc_cbor_cmd_rsp`.
Output of those functions contains the response.
After parsing it :cpp:func:`nrf_rpc_decoding_done` or :cpp:func:`nrf_rpc_cbor_decoding_done` function must be called to indicate that parsing is completed and the buffers holding the response can be released.

Events have no response, so nothing more have to be done after sending it.

Below is a sample command encoder using nRF RPC TinyCBOR API.
Function remotely adds ``1`` to the ``input`` parameter and put the result to the ``output`` parameter.
It returns 0 on success or negative error code if communication with remote failed.

.. code-block:: c

	/* Helper define holding maximum CBOR encoded packet length
	 * for this sample.
	 */
	#define MAX_ENCODED_LEN 16

	/* Defines a group that contains functions implemented in this
	 * sample.
	 */
	NRF_RPC_GROUP_DEFINE(math_group, "sample_math", NULL, NULL, NULL);

	/* Defines a helper structure to pass the results.
	 */
	struct remote_inc_result {
		int err;
		int output;
	};

	int remote_inc(int input, int *output)
	{
		int err;
		struct remote_inc_result result;
		struct nrf_rpc_cbor_ctx ctx;

		NRF_RPC_CBOR_ALLOC(ctx, MAX_ENCODED_LEN);

		cbor_encode_int(&ctx.encoder, input);

		err = nrf_rpc_cbor_cmd(&math_group, MATH_COMMAND_INC, &ctx,
				       remote_inc_rsp, &result);

		if (err == 0) {
			*output = result.output;
			err = result.err;
		}

		return err;
	}

Above code uses `remote_inc_rsp` function to parse the response.
Following code shows how this function may look like.

.. code-block:: c

	static void remote_inc_rsp(CborValue *value, void *handler_data)
	{
		CborError cbor_err;
		struct remote_inc_result *result =
			(struct remote_inc_result *)handler_data;

	 	if (!cbor_value_is_integer(value)) {
			result->err = -EINVAL;
			return;
		}

		cbor_err = cbor_value_get_int(value, &result->output);
		if (cbor_err != CborNoError) {
			result->err = -EINVAL;
			return;
		}

		result->err = 0;
	}


Decoders
========

Decoders are registered with a :c:macro:`NRF_RPC_CMD_DECODER`, :c:macro:`NRF_RPC_CBOR_EVT_DECODER` or similar depending on what kind of decoder it will be.
Decoders are called automatically when command or event is received with a matching id.
Command decoders must send a response.

Decoder associated with the example above may be implemented in a following way:

.. code-block:: c

	/* Defines a group that contains functions implemented in this
	 * sample. Second parameter have to be the same in both remote
	 * and local side.
	 */
	NRF_RPC_GROUP_DEFINE(math_group, "sample_math", NULL, NULL, NULL);


	static void remote_inc_handler(CborValue *value, void* handler_data)
	{
		int err;
		int input = 0;
		int output;
		struct nrf_rpc_cbor_ctx ctx;

		/* Parsing the input */

	 	if (cbor_value_is_integer(value)) {
			cbor_value_get_int(value, &input);
		}

		nrf_rpc_cbor_decoding_done(value);

		/* Actual hard work is done in below line */

		output = input + 1;

		/* Encoding and sending the response */

		NRF_RPC_CBOR_ALLOC(ctx, MAX_ENCODED_LEN);

		cbor_encode_int(&ctx.encoder, output);

		err = nrf_rpc_cbor_rsp(&ctx);

		if (err < 0) {
			fatal_error(err);
		}
	}

	NRF_RPC_CBOR_CMD_DECODER(math_group, remote_inc_handler,
				 MATH_COMMAND_INC, remote_inc_handler, NULL);
