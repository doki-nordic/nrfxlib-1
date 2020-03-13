.. _parallel_remote_procedure:

Parallel remote procedure call
##############################

The Remote Procedure Serialization module can create any count of instance. This can be useful when
library is uses in multi-thread operating system like Zephyr then each instance has it own transport
endpoint and receive thread which processes incoming packet on different instance parallel with different
processing thread priority. To create a new instance use :c:macro:`RP_SER_DEFINE`.

Multi-instance sequence chart:

.. image:: img/sequence_chart.png
   :alt: Event execution
   :align: center
