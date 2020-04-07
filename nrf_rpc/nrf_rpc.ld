	SECTION_DATA_PROLOGUE(rp_ser_decoder,,SUBALIGN(4))
	{
		KEEP(*(SORT_BY_NAME(".rp_ser_decoder*")))
	} GROUP_LINK_IN(ROMABLE_REGION)
