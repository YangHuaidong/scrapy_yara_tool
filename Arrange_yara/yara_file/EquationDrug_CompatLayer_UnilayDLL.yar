rule EquationDrug_CompatLayer_UnilayDLL {
	meta:
		description = "EquationDrug - Unilay.DLL"
		author = "Florian Roth @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "a3a31937956f161beba8acac35b96cb74241cd0f"
	strings:
		$s0 = "unilay.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and $s0
}