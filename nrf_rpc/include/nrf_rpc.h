/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef RP_SER_H_
#define RP_SER_H_

#include <stdint.h>

#include <cbor.h>

#include <nrf_rpc_errors.h>
#include <nrf_rpc_common.h>
#include <nrf_rpc_tr.h>

/**
 * @file
 * @defgroup rp_ser Remote Procedures Serialization core
 * @{
 * @brief Remote Procedures Serialization core API.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define RP_SER_CMD_EVT_HADER_SIZE 2
#define RP_SER_RSP_ACK_HEADER_SIZE 1

/**@brief Command and event decoder handler type. */
typedef rp_err_t (*rp_ser_decoder_handler_t)(uint8_t code, const uint8_t *packet, size_t len);

/**@brief Command and event decoder handler type. */
typedef rp_err_t (*rp_ser_response_handler_t)(const uint8_t *packet, size_t len);

/**@brief Command/event decoder structure. */
struct rp_ser_decoder {
	/** Command/event code. */
	uint8_t code;

	/** Command/event decoder. */
	rp_ser_decoder_handler_t func;
};

/**@brief Configuration for Remote Procedure Serialization instance. */
struct rp_ser_conf {
	/** Command section start address. */
	const struct rp_ser_decoder *cmd_begin;

	/** Command section end address. */
	const struct rp_ser_decoder *cmd_end;

	/** Event section start address. */
	const struct rp_ser_decoder *evt_begin;

	/** Event section end address. */
	const struct rp_ser_decoder *evt_end;

	/** Endpoint number. */
	int ep_number;
};

typedef enum {
	RP_SER_ERROR_ON_SENDING_CMD = 1,
	RP_SER_ERROR_ON_SENDING_EVT,
	RP_SER_ERROR_ON_SENDING_RSP,
	RP_SER_ERROR_ON_RECEIVING_RSP,
	RP_SER_ERROR_ON_RECEIVE,
	RP_SER_ERROR_ON_REMOTE = 0x80,
} rp_ser_error_location_t;

#define RP_SER_CMD_EVT_CODE_MAX 0xFE
#define RP_SER_CMD_EVT_CODE_UNKNOWN 0xFF

/**@brief Helper macro for creating command decoder. All comands decoders have to be assigned
 *        to proper Remote Procedure Serialization instance. After receiving a command, the
 *        command decoder function is searching in command data memory section based on command
 *        number and calls the actual decoder.
 *
 * @param[in] _rp_inst Remote Procedure Serialization instance.
 * @param[in] _name Command decoder name.
 * @param[in] _cmd Command number.
 * @param[in] _handler Command decoder function @ref cmd_handler_t.
 */
#define RP_SER_CMD_DECODER(_rp_inst, _name, _cmd, _handler)         \
	RP_STATIC_ASSERT(_cmd <= 0xFF, "Command out of range");     \
	const struct rp_ser_decoder RP_CONCAT(_name, _cmd_dec) __used   \
	__attribute__((__section__("." RP_STRINGIFY(rp_ser_decoder) \
				   "." "cmd"                        \
				   "." RP_STRINGIFY(_rp_inst)       \
				   "." RP_STRINGIFY(_name)))) = {   \
		.code = _cmd,					    \
		.func = _handler				    \
	}

/**@brief Helper macro for creating event decoder. All events decoders have to be assigned
 *        to proper Remote Procedure Serialization instance. After receiving a event the
 *        event decoder function is searching in command data memory section based on command
 *        number and called.
 *
 * @param[in] _rp_inst Remote Procedure Serialization instance.
 * @param[in] _name Event decoder name.
 * @param[in] _cmd Event number.
 * @param[in] _handler Event decoder function @ref cmd_handler_t.
 */
#define RP_SER_EVT_DECODER(_rp_inst, _name, _evt, _handler)         \
	RP_STATIC_ASSERT(_evt <= 0xFF, "Event out of range");       \
	const struct rp_ser_decoder RP_CONCAT(_name, _evt_dec) __used   \
	__attribute__((__section__("." RP_STRINGIFY(rp_ser_decoder) \
				   "." "evt"                        \
				   "." RP_STRINGIFY(_rp_inst)       \
				   "." RP_STRINGIFY(_name)))) = {   \
		.code = _evt,                                         \
		.func = _handler			            \
	}

/**@brief Remote Procedure Serialization instance. */
struct rp_ser {
	/** Transport endpoint instance. */
	struct rp_trans_endpoint endpoint;

	/** Configuration of this instance including decoders addresses. */
	const struct rp_ser_conf *conf;

	/** Current processing command response decoder. */
	rp_ser_response_handler_t rsp_handler;

	/** Is this instance waiting for the event acknowledge */
	bool waiting_for_ack; // DKTODO: bit flags to save a memory

	/** Does this instance have to report decoding done  */
	bool decoding_done_required;
};

/**@brief Macro for defining the Remote Procedure Serialization instance.
 *
 * @param[in] _name Instance name.
 * @param[in] _endpoint_num Endpoint number, used for transport endpoint identification.
 * @param[in] _endpoint_stack_size Endpoint thread stack size.
 * @param[in] _endpoint_thread_prio Endpoint thread priority.
 */
#define RP_SER_DEFINE(_name, _endpoint_num, _endpoint_stack_size,                 \
                      _endpoint_thread_prio)                                      \
	/* Helper variables used to specify start and end addresses of specific   \
	 * subsection instance event and command decoders data. The section must  \
	 * be sorted in alphabetical order to ensure the valid value.             \
	 */                                                                       \
	const struct rp_ser_decoder RP_CONCAT(_name, _cmd_begin) __used               \
	__attribute__((__section__("." RP_STRINGIFY(rp_ser_decoder)               \
				   "." "cmd" "." RP_STRINGIFY(_name) ".")));      \
	const struct rp_ser_decoder RP_CONCAT(_name, _cmd_end) __used         \
	__attribute__((__section__("." RP_STRINGIFY(rp_ser_decoder)               \
				   "." "cmd" "." RP_STRINGIFY(_name) "." "}")));  \
	const struct rp_ser_decoder RP_CONCAT(_name, _evt_begin) __used       \
	__attribute__((__section__("." RP_STRINGIFY(rp_ser_decoder)               \
				   "." "evt" "." RP_STRINGIFY(_name) ".")));      \
	const struct rp_ser_decoder RP_CONCAT(_name, _evt_end) __used         \
	__attribute__((__section__("." RP_STRINGIFY(rp_ser_decoder)               \
				   "." "evt" "." RP_STRINGIFY(_name) "." "}")));  \
										  \
	RP_TRANS_ENDPOINT_PREPARE(RP_CONCAT(_name, _ep),                          \
					    _endpoint_stack_size,                 \
					    _endpoint_thread_prio);               \
										  \
	static const struct rp_ser_conf RP_CONCAT(_name, _conf) = {		  \
		.cmd_begin = (&RP_CONCAT(_name, _cmd_begin) + 1),		  \
		.cmd_end = &RP_CONCAT(_name, _cmd_end),			          \
		.evt_begin = (&RP_CONCAT(_name, _evt_begin) + 1),		  \
		.evt_end = &RP_CONCAT(_name, _evt_end),				  \
		.ep_number = _endpoint_num,					  \
	};									  \
										  \
	struct rp_ser _name = {							  \
		.endpoint = RP_TRANS_ENDPOINT_INITIALIZER(RP_CONCAT(_name, _ep)), \
		.conf = &RP_CONCAT(_name, _conf),				  \
	}

/**@brief Macro for declaring a serialization instance (not creating it)
 *
 * Serialization which are split up over multiple files must have exactly
 * one file use @ref RP_SER_DEFINE to create module-specific state
 * and register the decoders data section.
 *
 * The other serialization files which could share the same instance should
 * use this macro instead to creating the new one.
 *
 * @param[in] _name Exiting instance name.
 */
#define RP_SER_DECLARE(_name) \
	extern struct rp_ser _name

/**@brief Function for initializing the Remote Procedure Serialization instance.
 *
 * This function initializes Remote Procedure Serialization instance, and creates a new
 * tranport endpoint for it. Multiple instances can be initialized during runtime. This ensures
 * parallel remote function calls.
 *
 * @param[in] rp Remote procedure instance.
 *
 * @retval RP_SUCCESS Initialization was successful.
 * @retval RP_ERROR_NULL A parameter was NULL.
 */
rp_err_t rp_ser_init(struct rp_ser *rp);

/**@brief Function for sending command(function call) to the Remote processor.
 *
 * This function sends a procedure call to the remote processor and waits for response
 * * a specified amount of time if rsp is not NULL. After receiving command response
 * the response decoder is called and received data can be returned.
 *
 * @param[in] rp Remote Procedure Serialization instance.
 * @param[in] encoder Remote Procedure instance encoder.
 * @param[in] rsp Command response decoder. If not NULL, function waits for response and
 *                decodes it using this handler.
 *
 * @retval RP_SUCCESS Command send was successful.
 * @retval RP_ERROR_NULL A parameter was NULL.
 * @retval RP_ERROR_INVALID_PARAM A serialization packet length was 0.
 */
rp_err_t rp_ser_cmd_send(struct rp_ser *rp,
			 uint8_t cmd,
			 uint8_t *packet,
			 size_t len,
			 rp_ser_response_handler_t rsp);

void rp_ser_cmd_send_no_err(struct rp_ser *rp,
			    uint8_t cmd,
			    uint8_t *packet,
			    size_t len,
			    rp_ser_response_handler_t rsp);

int rp_ser_cmd_send_and_rsp_get(struct rp_ser *rp,
				uint8_t cmd,
				uint8_t *in_packet,
				size_t in_len,
				const uint8_t **out_packet);

int rp_ser_cmd_send_and_rsp_get_no_err(struct rp_ser *rp,
				       uint8_t cmd,
				       uint8_t *in_packet,
				       size_t in_len,
				       const uint8_t **out_packet);

void rp_ser_rsp_release(struct rp_ser *rp);


/**@brief Function for sending event to the Remote processor.
 *
 * This function sends an event to the remote processor. Event is asynchronous and
 * receiving it is not confirmed by the Remote processor. Event can be used in case
 * when remote function call doesn't return any data or the remote processor gets an
 * event which should be transported to the local processor it is needed to pass it
 * to other processor.
 *
 * @param[in] rp Remote Procedure Serialization instance.
 * @param[in] encoder Event encoder.
 *
 * @retval RP_SUCCESS Command send was successful.
 * @retval RP_ERROR_NULL A parameter was NULL.
 * @retval RP_ERROR_INVALID_PARAM A serialization packet length was 0.
 */
rp_err_t rp_ser_evt_send(struct rp_ser *rp,
			 uint8_t evt,
			 uint8_t *packet,
			 size_t len);

void rp_ser_evt_send_no_err(struct rp_ser *rp,
				uint8_t evt,
				uint8_t *packet,
				size_t len);

/**@brief Function for sending command response to the Remote processor.
 *
 * This function sends response after the received command was processed.
 *
 * @param[in] rp Remote Procedure Serialization instance.
 * @param[in] encoder Response encoder.
 *
 * @retval RP_SUCCESS Command send was successfull.
 * @retval RP_ERROR_NULL A parameter was NULL.
 * @retval RP_ERROR_INVALID_PARAM A serialization packet length was 0.
 */
rp_err_t rp_ser_rsp_send(struct rp_ser *rp,
			 uint8_t *packet,
			 size_t len);

void rp_ser_rsp_send_no_err(struct rp_ser *rp,
				uint8_t *packet,
				size_t len);


void rp_ser_handler_decoding_done(struct rp_ser *rp);

/**@brief Define the rp_ser_buf stack variable and allocate Remote Procedure
 *        buffer. Every remote procedure needs to alloc the buffer for
 *        encoded data.
 *
 * @param[in] rp The Remote Procedure serialization instance.
 * @param[in, out] encoder Remote Procedure encoder data.
 * @param[in, out] size Requested buffer size as input, allocated buffer size as output.
 *
 */
#define RP_SER_CMD_ALLOC(_rp_buf_name, _rp, _size)			              \
	uint8_t *RP_CONCAT(_rp_buf_name, _buf);                                       \
	rp_trans_alloc_tx_buf(&(_rp)->endpoint, &RP_CONCAT(_rp_buf_name, _buf), RP_SER_CMD_EVT_HADER_SIZE + (_size)); \
	uint8_t *_rp_buf_name = &RP_CONCAT(_rp_buf_name, _buf)[RP_SER_CMD_EVT_HADER_SIZE];                                       \

#define RP_SER_EVT_ALLOC(_rp_buf_name, _rp, _size) RP_SER_CMD_ALLOC(_rp_buf_name, _rp, _size)

#define RP_SER_RSP_ALLOC(_rp_buf_name, _rp, _size)			              \
	uint8_t *RP_CONCAT(_rp_buf_name, _buf);                                       \
	rp_trans_alloc_tx_buf(&(_rp)->endpoint, &RP_CONCAT(_rp_buf_name, _buf), RP_SER_RSP_ACK_HEADER_SIZE + (_size)); \
	uint8_t *_rp_buf_name = &RP_CONCAT(_rp_buf_name, _buf)[RP_SER_RSP_ACK_HEADER_SIZE];                                       \

#define RP_SER_ALLOC_FAILED(_rp_buf_name) \
	rp_trans_alloc_failed(RP_CONCAT(_rp_buf_name, _buf))


/**@brief Macro for releasing the allocated buffer.
 *        It can be used in case of error in the Remote Procedure Serialization.
 *
 * @param[in] rp The Remote Procedure Serialization instance.
 * @param[in] buf Pointer to currently used buffer.
 */
#define RP_SER_BUF_DISCARD(_rp_buf_name, _rp) \
	rp_trans_free_tx_buf(&(_rp)->endpoint, RP_CONCAT(_rp_buf_name, _buf))

#ifdef __cplusplus
}
#endif

/**
 *@}
 */

#endif /* RP
 * @brief Remote procedures OS specific API_SER_H_ */
