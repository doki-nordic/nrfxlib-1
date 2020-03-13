.. _transport:

Transport
#########

Library can use multiple different transport. This layer is fully hardware and OS dependent. The default transport is
`OpenAMP <https://github.com/OpenAMP/open-amp/>`_. User can define it own transport using template. Tranport layer should be a part of yours operating system.

Template header:
``template/rp_transp_tmpl.h``

Transport layer configuration is in ``include/rp_trans.h`` there you can add  yours own transport or choose one from available default transport.