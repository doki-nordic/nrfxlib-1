#
# Copyright (c) 2020 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

zephyr_include_directories(include)

zephyr_library()
zephyr_library_sources(nrf_rpc.c)

if (CONFIG_NRF_RPC_CBOR)
	zephyr_library_sources(nrf_rpc_cbor.c)
endif()

zephyr_linker_sources(SECTIONS nrf_rpc.ld)
