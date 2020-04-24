.. _transport:

Transport
#########

Bottom layer of the nRF_RPC is a transport layer.
It is OS-dependent.
Its main goal is to transfer packets between two sites and to handle thread pool.
The transport implementation can be selected by the configuration.

Currently default transport is `OpenAMP <https://github.com/OpenAMP/open-amp/>`_ on `Zephyr <https://www.zephyrproject.org/>`_.

For nRF_RPC top level API users it is not important to know details about the transport layer.
This knowlage is important to implement a new transport or port to a different OS.

The template header describing the nRF_RPC transport APIS is ``template/nrf_rpc_tr_tmpl.h``.
Header file ``include/rp_trans.h`` is


Endpoints
=========

Important concept of nRF_RPC transport is an `endpoint`.
The endpoint is a destination where packets are send.
One endpoint is associated to a thread that is responsible for reading packet from it.

Endpoints on the remote side are represented by the :c:struct:`nrf_rpc_tr_remote_ep` structure.
nRF_RPC sends packets to remote endpoint using this structure.
Endpoints on the local side are represented by the :c:struct:`nrf_rpc_tr_local_ep` structure.
nRF_RPC receives packets from local endpoint using this structure.

There is one special endpoint called null endpoint.
It is represented as a NULL value in pointers to the :c:struct:`nrf_rpc_tr_local_ep` or the :c:struct:`nrf_rpc_tr_remote_ep`.
It is used by the nRF_RPC to transmit internal packets that are not associated with any thread or endpoint.
It transmits e.g. information about error on the other side or a packet informing that the event handling finished and the thread from the thread pool is now free.

:cpp:func:`nrf_rpc_tr_send` sends a packet to the remote endpoint.
Buffer containing packet to send is allocated and managed by the transport layer,
so it have to be created with a :cpp:func:`nrf_rpc_tr_alloc_tx_buf`.
Buffer is released automatically when it was send,
but if it was not send :cpp:func:`nrf_rpc_tr_free_tx_buf` must be called.

:cpp:func:`nrf_rpc_tr_read` reads a packet to the local endpoint.
Read function returns a pointer to the buffer allocated and managed by the transport layer,
so when parsing is done :cpp:func:`nrf_rpc_tr_release_buffer` must be called.

:cpp:func:`nrf_rpc_tr_current_get` returns (and allocates if necessary) a local endpoint associated with the calling thread.


Packet filtering
================

To increase performance by reducing thread context switching a filter callback is called before it goes to destination endpoint.
Filter callback :cpp:func:`nrf_rpc_tr_filter` may interpret the packet and decide if it should go to destination endpoint.
If not buffer holding the packet is released and NULL pointer goes to the destination packet instead of buffer pointer.


Thread pool
===========

Transport layer is also responsible for handling the thread pool.
Each thread from the local thread pool waits for an incoming packet and calls :cpp:func:`nrf_rpc_tr_receive_handler` if it arrived to the associated endpoint.

:cpp:func:`nrf_rpc_tr_remote_reserve` and :cpp:func:`nrf_rpc_tr_remote_release` reserves and releases a thread from the remote thread pool returning remote endpoint associated with it.
