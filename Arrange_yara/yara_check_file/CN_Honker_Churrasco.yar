rule CN_Honker_Churrasco {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Churrasco.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5a3c935d82a5ff0546eff51bb2ef21c88198f5b8"
	strings:
		$s0 = "HEAD9 /" ascii
		$s1 = "logic_er" fullword ascii
		$s6 = "proggam" fullword ascii
		$s16 = "DtcGetTransactionManagerExA" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 12 times */
		$s17 = "GetUserNameA" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 305 times */
		$s18 = "OLEAUT" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1276KB and all of them
}