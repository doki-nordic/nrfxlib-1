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
Endpoints on the local side are represented by the :c:struct:`nrf_rpc_tr_local_ep` structure.

<hr>

The RP SER library can use any transport for communication with the remote CPU. This layer is fully hardware and OS dependent.  User can define it own transport using template.


Transport layer configuration is located in ``include/rp_trans.h``, where you can add your own transport or choose one of the available implementations.
