
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <nrf_rpc_errors.h>
#include <nrf_rpc_common.h>
#include <nrf_rpc_tr.h>

//#define CONFIG_NRF_RPC_ORD_VAR_CONSTRUCTORS 1 // TODO: detelte
#define CONFIG_NRF_RPC_ORD_VAR_SECTIONS 1 // TODO: detelte

#define _NRF_RPC_HEADER_SIZE 2

typedef rp_err_t (*nrf_rpc_handler)(const uint8_t *packet, size_t len, void *handler_data);

/**@brief Command/event decoder structure. */
struct nrf_rpc_decoder {

	/** Command/event code. */
	uint8_t code;

	/** Command/event decoder. */
	nrf_rpc_handler handler;
};

struct nrf_rpc_group {
	uint8_t group_id;
	const void *cmd_array;
	const void *evt_array;
};

struct nrf_rpc_remote_ep {
	struct nrf_rpc_tr_remote_ep tr_ep;
};

struct nrf_rpc_local_ep {
	struct nrf_rpc_tr_local_ep tr_ep;
	struct nrf_rpc_remote_ep *default_dst;
	uint32_t cmd_nesting_counter;
	nrf_rpc_handler handler;
	void *handler_data;
};


#if defined(nrf_rpc_tr_alloc_tx_buf)
/* nrf_rpc_tr_alloc_tx_buf is a macro, so we cannot wrap it with a function. */

#define NRF_RPC_CMD_ALLOC(group, packet, len, ...)			       \
	struct nrf_rpc_tr_remote_ep *_nrf_rpc_alloc_ep = _nrf_rpc_cmd_prepare();	       \
	nrf_rpc_tr_alloc_tx_buf(_nrf_rpc_alloc_ep, (packet),				       \
				_NRF_RPC_HEADER_SIZE + (len));		       \
	if (nrf_rpc_tr_alloc_failed(*(packet))) {			       \
		_nrf_rpc_cmd_alloc_error();		       \
		__VA_ARGS__;						       \
	}								       \
	*(uint8_t **)(packet) += _NRF_RPC_HEADER_SIZE

#define NRF_RPC_CMD_ALLOC_FAILED(packet)				       \
	nrf_rpc_tr_alloc_failed(((uint8_t *)(packet) -			       \
				_NRF_RPC_HEADER_SIZE))

#define NRF_RPC_CMD_FREE(packet)					       \
	_nrf_rpc_cmd_unprepare();				       \
	nrf_rpc_tr_free_tx_buf(_nrf_rpc_alloc_ep, packet)


#define NRF_RPC_RSP_ALLOC(packet, len, ...)			       \
	struct nrf_rpc_tr_remote_ep *_nrf_rpc_alloc_ep = _nrf_rpc_rsp_prepare();	       \
	nrf_rpc_tr_alloc_tx_buf(_nrf_rpc_alloc_ep, (packet),				       \
				_NRF_RPC_HEADER_SIZE + (len));		       \
	if (nrf_rpc_tr_alloc_failed(*(packet))) {			       \
		__VA_ARGS__;						       \
	}								       \
	*(uint8_t **)(packet) += _NRF_RPC_HEADER_SIZE

#define NRF_RPC_RSP_FREE(packet)					       \
	nrf_rpc_tr_free_tx_buf(_nrf_rpc_alloc_ep, packet)

#define NRF_RPC_EVT_ALLOC(group, packet, len, ...)			       \
	struct nrf_rpc_tr_remote_ep *_nrf_rpc_alloc_ep = _nrf_rpc_evt_prepare();	       \
	nrf_rpc_tr_alloc_tx_buf(_nrf_rpc_alloc_ep, (packet),				       \
				_NRF_RPC_HEADER_SIZE + (len));		       \
	if (nrf_rpc_tr_alloc_failed(*(packet))) {			       \
		_nrf_rpc_evt_alloc_error(_nrf_rpc_alloc_ep);		       \
		__VA_ARGS__;						       \
	}								       \
	*(uint8_t **)(packet) += _NRF_RPC_HEADER_SIZE

#define NRF_RPC_EVT_FREE(packet)					       \
	_nrf_rpc_evt_unprepare(_nrf_rpc_alloc_ep);				       \
	nrf_rpc_tr_free_tx_buf(_nrf_rpc_alloc_ep, packet)


struct nrf_rpc_tr_remote_ep *_nrf_rpc_cmd_prepare(void);
void _nrf_rpc_cmd_alloc_error();
void _nrf_rpc_cmd_unprepare();
struct nrf_rpc_tr_remote_ep *_nrf_rpc_evt_prepare(void);
void _nrf_rpc_evt_alloc_error(struct nrf_rpc_tr_remote_ep *remote_ep);
void _nrf_rpc_evt_unprepare(struct nrf_rpc_tr_remote_ep *remote_ep);
struct nrf_rpc_tr_remote_ep *_nrf_rpc_rsp_prepare();

#else

//TODO: this option

#endif

#define NRF_RPC_CMD_SEND(group, cmd, packet, len, handler, handler_data)	       \
	_nrf_rpc_cmd_send((group), (cmd), (packet), (len), (handler), (handler_data))

#define NRF_RPC_CMD_SEND_NOERR(group, cmd, packet, len, handler, handler_data)	       \
	_nrf_rpc_cmd_send((group), (cmd), (packet), (len), (handler), (handler_data)) // TODO: send_noerr

rp_err_t _nrf_rpc_cmd_send(const struct nrf_rpc_group *group, uint8_t cmd, uint8_t *packet, size_t len,
			   nrf_rpc_handler handler, void *handler_data);

#define NRF_RPC_RSP_SEND(packet, len)	       \
	_nrf_rpc_rsp_send((packet), (len))

#define NRF_RPC_RSP_SEND_NOERR(packet, len)	       \
	_nrf_rpc_rsp_send((packet), (len)) // TODO: noerr

rp_err_t _nrf_rpc_rsp_send(uint8_t *packet, size_t len);

#define NRF_RPC_EVT_SEND(group, evt, packet, len)	       \
	_nrf_rpc_evt_send(_nrf_rpc_alloc_ep, (group), (evt), (packet), (len))

rp_err_t _nrf_rpc_evt_send(struct nrf_rpc_tr_remote_ep *remote_ep, const struct nrf_rpc_group *group, uint8_t evt, uint8_t *packet, size_t len);

void nrf_rpc_decoding_done();

#if defined(CONFIG_NRF_RPC_ORD_VAR_SECTIONS)

#define NRF_RPC_ORD_VAR_CREATE(_type, _name, _array_key, _var_key)	       \
	_type _name __used						       \
	__attribute__((__section__(".nrf_rpc." _array_key ".b." _var_key)))

#define NRF_RPC_ORD_VAR_ARRAY(_name, _array_key)			       \
	const uint8_t RP_CONCAT(_name, _ord_var_end) __used		       \
	__attribute__((__section__(".nrf_rpc." _array_key ".c")));	       \
	const uint8_t *const _name __used				       \
	__attribute__((__section__(".nrf_rpc." _array_key ".a"))) =	       \
		&RP_CONCAT(_name, _ord_var_end);


#define NRF_RPC_ORD_VAR_FOR_EACH(_it, _var, _array_ptr, _type)		       \
	for ((_var) = (_type *)((const uint8_t *const *)(_array_ptr) + 1);     \
		(const uint8_t *const)_var <				       \
			*(const uint8_t *const *)(_array_ptr);		       \
		(_var) = (_type *)(_var) + 1, (void)_it)

#elif defined(CONFIG_NRF_RPC_ORD_VAR_CONSTRUCTORS)

struct _nrf_rpc_ord_var_entry {
	const char *key;
	void *data;
	struct _nrf_rpc_ord_var_entry *next;
};

extern struct _nrf_rpc_ord_var_entry *_nrf_rpc_ord_var_first;

#define NRF_RPC_ORD_VAR_CREATE(_type, _name, _array_key, _var_key)	       \
	extern _type _name;						       \
	static struct _nrf_rpc_ord_var_entry RP_CONCAT(_name, _entry) = {      \
		.key = _array_key ".b." _var_key,			       \
		.data = &_name,						       \
	};								       \
	void __attribute__((constructor)) RP_CONCAT(_name, _constr) ()	       \
	{								       \
		RP_CONCAT(_name, _entry).next = _nrf_rpc_ord_var_first;	       \
		_nrf_rpc_ord_var_first = &RP_CONCAT(_name, _entry);	       \
	}								       \
	_type _name

#define NRF_RPC_ORD_VAR_ARRAY(_name, _array_key)			       \
	static struct _nrf_rpc_ord_var_entry _name = {			       \
		.key = _array_key ".a",					       \
		.data = NULL,						       \
	};								       \
	static struct _nrf_rpc_ord_var_entry RP_CONCAT(_name, _array_last) = { \
		.key = _array_key ".c",					       \
		.data = NULL,						       \
	};								       \
	void __attribute__((constructor)) RP_CONCAT(_name, _array_constr) ()   \
	{								       \
		_name.next = &RP_CONCAT(_name, _array_last);		       \
		RP_CONCAT(_name, _array_last).next = _nrf_rpc_ord_var_first;   \
		_nrf_rpc_ord_var_first = &RP_CONCAT(_name, _array_last);       \
	}

#define NRF_RPC_ORD_VAR_FOR_EACH(_it, _var, _array_ptr, _type)		       \
	for (_it = ((struct _nrf_rpc_ord_var_entry *)_array_ptr)->next, _var = (_type *)((struct _nrf_rpc_ord_var_entry *)_array_ptr)->next->data;   \
		_var != NULL;						       \
		_it = ((struct _nrf_rpc_ord_var_entry *)_it)->next, 	       \
		_var = (_type *)((struct _nrf_rpc_ord_var_entry *)_it)->data)

#else

#error Implementation for NRF_RPC_ORD_VAR was not selected

#endif

#define NRF_RPC_GROUP_DEFINE(_name, _id) \
	NRF_RPC_ORD_VAR_ARRAY(RP_CONCAT(_name, _cmd_array), "cmd_" RP_STRINGIFY(_name));      \
	NRF_RPC_ORD_VAR_ARRAY(RP_CONCAT(_name, _evt_array), "evt_" RP_STRINGIFY(_name));      \
	NRF_RPC_ORD_VAR_CREATE(const struct nrf_rpc_group, _name, "grp", RP_STRINGIFY(_name)) \
	 = {		  \
		.group_id = (_id), \
		/* TODO: .tr_gruop */ \
		.cmd_array = &RP_CONCAT(_name, _cmd_array),			\
		.evt_array = &RP_CONCAT(_name, _evt_array),			\
	};


#define NRF_RPC_CMD_DECODER(_group, _name, _cmd, _handler) \
	RP_STATIC_ASSERT(_cmd <= 0xFE, "Command out of range");     \
	NRF_RPC_ORD_VAR_CREATE(const struct nrf_rpc_decoder, RP_CONCAT(_name, _cmd_dec), "cmd_" RP_STRINGIFY(_group), RP_STRINGIFY(_name)) \
	 = {   \
		.code = _cmd,					    \
		.handler = _handler,				    \
	}

#define NRF_RPC_EVT_DECODER(_group, _name, _evt, _handler) \
	RP_STATIC_ASSERT(_evt <= 0xFE, "Event out of range");     \
	NRF_RPC_ORD_VAR_CREATE(const struct nrf_rpc_decoder, RP_CONCAT(_name, _evt_dec), "evt_" RP_STRINGIFY(_group), RP_STRINGIFY(_name)) \
	 = {   \
		.code = _evt,					    \
		.handler = _handler,				    \
	}

#define NRF_RPC_USER_GROUP_FIRST 64
#define NRF_RPC_USER_GROUP_LAST 127

rp_err_t nrf_rpc_init(void);
