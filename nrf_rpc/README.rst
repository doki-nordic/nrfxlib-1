.. _nrf_rpc:

nRF RPC (Remote Procedure Call) library
########################################

The nRF RPC is a remote procedure call library for |NCS| enabling inter-processor communication on Nordic Semiconductor SoCs.
The library is RTOS-agnostic implementing serialization of function calls. It is designed to be used with an underlying transport layer, for example OpenAMP.

The nRF RPC library provides a possibility to call a function on "remote" processors in both synchronous and asynchronous way, from a "local" processor.

Depending on the transport layer the remote processor is not limited to a single device. It also could be a separate device of any type (e.g. a PC), or another core on the same system.

The nRF RPC library simplifies the serialization of user APIs, such as a Bluetooth stack, and executing functions implementing those APIs on a remote CPU.
The library is operating system independent so it can be used with any operating system after porting OS-dependent layers of the library.

An API layer above the core nRF RPC API uses the `TinyCBOR <https://github.com/zephyrproject-rtos/tinycbor>`_ library as serialization.
nRF RPC requires Zephyr Project fork of TinyCBOR, because of API differences.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   doc/architecture
   doc/usage

API documentation
=================

.. _nrf_rpc_core_api_documentation:

Core API documentation
----------------------

This API is using pointers to raw packet data.
:ref:`nrf_rpc_cbor_api_documentation` provides serialization layer over it that uses TinyCBOR.

.. doxygengroup:: nrf_rpc
   :project: nrfxlib
   :members:

.. _nrf_rpc_cbor_api_documentation:

TinyCBOR API documentation
--------------------------

This API is created on top of core nRF RPC API and it is not independent.
See :ref:`nrf_rpc_core_api_documentation` to get more information needed to use nRF RPC together with TinyCBOR.

.. doxygengroup:: nrf_rpc_cbor
   :project: nrfxlib
   :members:
