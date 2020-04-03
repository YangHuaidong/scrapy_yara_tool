rule PoisonIvy_Sample_APT_4 {
	meta:
		description = "Detects a PoisonIvy Sample APT"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "558f0f0b728b6da537e2666fbf32f3c9c7bd4c0c"
	strings:
		$s0 = "Microsoft Software installation Service" fullword wide /* PEStudio Blacklist: strings */ /* score: '15.04' */
		$s1 = "idll.dll" fullword ascii /* score: '11.02' */
		$s2 = "mgmts.dll" fullword wide /* score: '11.0' */
		$s3 = "Microsoft(R) Windows(R)" fullword wide /* score: '6.025' */
		$s4 = "ServiceMain" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 322 times */
		$s5 = "Software installation Service" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 3 times */
		$s6 = "SetServiceStatus" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 741 times */
		$s7 = "OriginalFilename" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 19040 times */
		$s8 = "ZwSetInformationProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 31 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 7 of them
}