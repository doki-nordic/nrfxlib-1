/*
 * Copyright (c) 2020 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef RP_SER_H_
#define RP_SER_H_

#include <stdint.h>

#include <cbor.h>

#include <rp_errors.h>
#include <rp_common.h>
#include <rp_trans.h>

/**
 * @file
 * @defgroup rp_ser Remote procedures serialization core
 * @{
 * @brief Remote procedures serialization core API.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**@brief Serialization packet type.*/
enum rp_ser_packet_type {
	/** Serialization command packet. */
	RP_SER_PACKET_TYPE_CMD          = 0x01,

	/** Serialization event packet. */
	RP_SER_PACKET_TYPE_EVENT,

	/** Serialization command response packet. */
	RP_SER_PACKET_TYPE_RSP,

	/** Serialization transport reserved packet. */
	RP_SER_PACKET_TRANSPORT_RESERVED = 128,

	/** Serialization upper bound. */
	RP_SER_PACKER_TYPE_MAX           = 255
};

/**@brief Command response handler type. */
typedef rp_err_t (*cmd_rsp_handler_t)(CborValue *it);

/**@brief Command decoder type. */
typedef rp_err_t (*cmd_handler_t)(CborValue *it);

/**@brief Event decoder type. */
typedef rp_err_t (*evt_handler_t)(uint8_t evt, CborValue *it);

/**@brief Encoder data structure. */
struct rp_ser_encoder {
	/** Main encoder. */
	CborEncoder encoder;

	/** Encoder container like array or map */
	CborEncoder *container;

	/** Encoder buffer. */
	uint8_t *buf;

	/** Encoder buffer size. */
	size_t buf_size;

	/** Packet size after encoding. */
	size_t packet_size;
};

/**@brief Command decoder structure. */
struct rp_ser_cmd {
	/** Command code. */
	uint8_t cmd;

	/** Command decoder. */
	cmd_handler_t func;
};

/**@brief Event decoder structure. */
struct rp_ser_evt {
	/** Event code. */
	uint8_t evt;

	/** Event decoder. */
	evt_handler_t func;
};

/**@brief Commands and events decoder structure. */
struct rp_ser_decoders {
	/** Command section start address. */
	const struct rp_ser_cmd *cmd_begin;

	/** Command section end address. */
	const struct rp_ser_cmd *cmd_end;

	/** Event section start address. */
	const struct rp_ser_evt *evt_begin;

	/** Event section end address. */
	const struct rp_ser_evt *evt_end;
};

/**@brief Helper macro for creating command decoder. All comands decoders have to be assigned
 *        to proper Remote Procedure Serialization instance. After receiving a command the
 *        command decoder function is searching in command data memory section based on command
 *        number and called.
 *
 * @param[in] _rp_inst Remote Procedure Serialization instance.
 * @param[in] _name Command decoder name.
 * @param[in] _cmd Command number.
 * @param[in] _handler Command decoder function @ref cmd_handler_t.
 */
#define RP_SER_CMD_DECODER(_rp_inst, _name, _cmd, _handler)					 \
	RP_STATIC_ASSERT(&_rp_inst != NULL, "Invalid instance");                                 \
	RP_STATIC_ASSERT(_cmd <= 0xFF, "Command out of range");                                  \
	const struct rp_ser_cmd RP_CONCAT(_name, _cmd_dec) __used				 \
	__attribute__((__section__(RP_STRINGIFY(RP_CONCAT(rp_ser_cmd_decoder_, _rp_inst))))) = { \
		.cmd = _cmd,									 \
		.func = _handler								 \
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
#define RP_SER_EVT_DECODER(_rp_inst, _name, _evt, _handler)					 \
	RP_STATIC_ASSERT(&_rp_inst != NULL, "Invalid instance");                                 \
	RP_STATIC_ASSERT(_cmd <= 0xFF, "Event out of range");                                    \
	const struct rp_ser_evt RP_CONCAT(_name, _evt_dec) __used				 \
	__attribute__((__section__(RP_STRINGIFY(RP_CONCAT(rp_ser_evt_decoder_, _rp_inst))))) = { \
		.evt = _evt,									 \
		.func = _handler								 \
	}

/**@brief Endpoint configuration structure. */
struct rp_ser_endpoint {
	/** Endpoint number. */
	int number;

	/** Endoint thread stack size. */
	size_t stack_size;

	/** Endpoint thread priority. */
	int prio;
};

/**@brief Remote Procedure Serialization instance. */
struct rp_ser {
	/** Transport endpoint instance. */
	struct rp_trans_endpoint endpoint;

	/** Decoders section addresses. */
	const struct rp_ser_decoders *decoders;

	/** Transport endpoint initial configuration. */
	const struct rp_ser_endpoint *ep_conf;

	/** Pointer to Os signal mechanism. */
	void *rp_sem;

	/** Current processing command response decoder. */
	cmd_rsp_handler_t rsp_handler;
};

/**@brief Macro for defining the Remote Procedure Serialization instance.
 *
 * @param[in] _name Instance name.
 * @param[in] _lock_type Os lock data type. For example in Zephyr struct k_sem can be used.
 * @param[in] _endpoint_num Endpoint number, used for transport endpoint identify.
 * @param[in] _endpoint_stack_size Endpoint thread stack size.
 * @param[in] _endpoint_thread_prio Endpoint thread priority.
 */
#define RP_SER_DEFINE(_name, _lock_type, _endpoint_num, _endpoint_stack_size, _endpoint_thread_prio) \
	__weak extern const struct rp_ser_cmd RP_CONCAT(__start_rp_ser_cmd_decoder_, _name)[];	     \
	__weak extern const struct rp_ser_cmd RP_CONCAT(__stop_rp_ser_cmd_decoder_, _name)[];	     \
	__weak extern const struct rp_ser_evt RP_CONCAT(__start_rp_ser_evt_decoder_, _name)[];	     \
	__weak extern const struct rp_ser_evt RP_CONCAT(__stop_rp_ser_evt_decoder_, _name)[];	     \
												     \
	static _lock_type RP_CONCAT(_name, _sem);						     \
	static const struct rp_ser_endpoint RP_CONCAT(_name, _ep) = {				     \
		.number = _endpoint_num,							     \
		.stack_size = _endpoint_stack_size,						     \
		.prio = _endpoint_thread_prio							     \
	};											     \
												     \
												     \
	const struct rp_ser_decoders RP_CONCAT(_name, _decoders) = {				     \
		.cmd_begin = RP_CONCAT(__start_rp_ser_cmd_decoder_, _name),			     \
		.cmd_end = RP_CONCAT(__stop_rp_ser_cmd_decoder_, _name),			     \
		.evt_begin = RP_CONCAT(__start_rp_ser_evt_decoder_, _name),			     \
		.evt_end = RP_CONCAT(__stop_rp_ser_evt_decoder_, _name)				     \
	};											     \
												     \
	static struct rp_ser _name = {			                        	             \
		.decoders = &RP_CONCAT(_name, _decoders),					     \
		.ep_conf = &RP_CONCAT(_name, _ep),						     \
		.rp_sem = (void *)&RP_CONCAT(_name, _sem),					     \
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
 * This function initialize Remote Procedure Serialization instance, and create a new
 * tranport endpoint for it. Multiple instance can be initialized during runtime. This ensure
 * paraller remote function call.
 *
 * @param[in] rp Remote procedure instance.
 *
 * @retval RP_SUCCESS Initialization was successful.
 * @retval RP_ERROR_NULL A parameter was NULL.
 */
rp_err_t rp_ser_init(struct rp_ser *rp);

/**@brief Function for uninitializing the Remote Procedure Serialization
 *        instance.
 *
 * This function uninitialize the Remote Procedure instance and abort
 * the endpoint thread.
 *
 * @param[in] rp Remote Procedure instance.
 */
void rp_ser_uninit(struct rp_ser *rp);

/**@brief Function for sending command(function call) to the Remote processor.
 *
 * This function send procedure call to the Remote processor and waiting for response
 * the specific amount of time if rsp is not NULL. After receiving command response
 * the response decoder is called and received data can be returned.
 *
 * @param[in] rp Remote Procedure Serialization instance.
 * @param[in] encoder Remote Procedure instance encoder.
 * @param[in] rsp Command response decoder. If not NULL, function waiting for response and
 *                decode it using this handler.
 *
 * @retval RP_SUCCESS Command send was successful.
 * @retval RP_ERROR_NULL A parameter was NULL.
 * @retval RP_ERROR_INVALID_PARAM A serialization packet length was 0.
 */
rp_err_t rp_ser_cmd_send(struct rp_ser *rp,
			 struct rp_ser_encoder *encoder,
			 cmd_rsp_handler_t rsp);

/**@brief Function for sending event to the Remote processor.
 *
 * This function send event to the Remote processor. Event is asynchronous and
 * receiving it is not confirmed by the Remote processor. Event can be used in case
 * when remote function call is asynchronous or the Remote Processor has it own event and
 * it is needed to pass it to other processor.
 *
 * @param[in] rp Remote Procedure Serialization instance.
 * @param[in] encoder Event encoder.
 *
 * @retval RP_SUCCESS Command send was successful.
 * @retval RP_ERROR_NULL A parameter was NULL.
 * @retval RP_ERROR_INVALID_PARAM A serialization packet length was 0.
 */
rp_err_t rp_ser_evt_send(struct rp_ser *rp, struct rp_ser_encoder *encoder);

/**@brief Function for sending command response to the Remote processor.
 *
 * This function send command response after receiving command was processed.
 *
 * @param[in] rp Remote Procedure Serialization instance.
 * @param[in] encoder Response encoder.
 *
 * @retval RP_SUCCESS Command send was successfull.
 * @retval RP_ERROR_NULL A parameter was NULL.
 * @retval RP_ERROR_INVALID_PARAM A serialization packet length was 0.
 */
rp_err_t rp_ser_rsp_send(struct rp_ser *rp, struct rp_ser_encoder *encoder);

/**@brief Function for initializing the remote procedure.
 *
 * This function initializes the Remote Procedure. Should be used
 * after allocation of the buffer for encoding the Remote procedure.
 *
 * @param[in, out] encoder Remote Procedure encoder data.
 * @param[in, out] container Serialized data container.
 * @param[in] argc Serialized data count.
 * @param[in] type Type of the Remote Procedure.
 * @param[in] value Command/event number. In case of command response this
 *                  parameter is not used.
 *
 * @retval RP_SUCCESS The Remote Procedure initialization was successful.
 * @retval RP_ERROR_NULL A parameter was NULL.
 * @retval RP_ERROR_INTERNAL Serializator encoding error.
 */
rp_err_t rp_ser_procedure_initialize(struct rp_ser_encoder *encoder,
				     CborEncoder *container,
				     size_t argc, enum rp_ser_packet_type type,
				     uint8_t value);

/**@brief Function for ending the Remote Procedure.
 *
 * This function ends the Remote Procedure encoding. Should be
 * used i conjuction with the @ref rp_ser_procedure_initialize when
 * all procedure parameters are encoded.
 *
 * @param[in, out] encoder Remote procedure encoder data.
 *
 * @retval RP_SUCCESS Operation success.
 * @retval RP_ERROR_NULL A parameter was NULL.
 * @retval RP_ERROR_INTERNAL Serializator error.
 * @retval RP_ERROR_INVALID_PARAM A serialization packet length was 0.
 */
rp_err_t rp_ser_procedure_end(struct rp_ser_encoder *encoder);

/**@brief Macro for the Remote Procedure buffer allocation.
 *        Every remote procedure needs to alloc the buffer for
 *        encoded data.
 *
 * @param[in] rp The Remote Procedure serialization instance.
 * @param[in, out] encoder Remote Procedure encoder data.
 * @param[in, out] len Requested buffer size as input, allocated buffer size as output.
 *
 */
#define rp_ser_buf_alloc(rp, encoder, len)			 \
	rp_trans_alloc_tx_buf(&rp.endpoint, &encoder.buf, &len); \
	encoder.buf_size = len

/**@brief Macro for releasing the allocated buffer.
 *        It can be used in case of error in the Remote Procedure Serialization.
 *
 * @param[in] rp The Remote Procedure Serialization instance.
 * @param[in] buf Pointer to currently used buffer.
 */
#define rp_ser_buf_free(rp, buf) \
	rp_trans_free_tx_buf(rp.endpoint, buf)

#ifdef __cplusplus
}
#endif

/**
 *@}
 */

#endif /* BT_SER_H_ */
