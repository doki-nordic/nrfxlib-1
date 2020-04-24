.. _nrf_rpc:

nRF_RPC (Remote Procedure Calls) library
########################################

The nRF_RPC is a remote procedure calls library for for Nordic Semicoductor SoCs.
RTOS-agnostic serialization library .

The nRF_RPC library provides a possibility to call a function on the remote processors in both synchronous and asynchronous way.

Depending on the transport layer the remote processor is not limited to a single device. It also could be a separate device of any type (including e.g. a PC), or another core on the same system.

The nRF_RPC library simplify the serialization of user API such as Bluetooth stack and executing it on a remote CPU.
The library is operating system independent so it can be used with any operating system after porting just a transport layer of the library.

Additional layer of the API is added that uses `TinyCBOR <https://intel.github.io/tinycbor/current/>`_ library as serialization.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   doc/architecture
   doc/usage
   doc/transport

API documentation
=================

.. doxygengroup:: nrf_rpc
   :project: nrfxlib
   :members:
