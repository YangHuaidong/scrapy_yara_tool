rule CN_Honker_sig_3389_80_AntiFW {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file AntiFW.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5fbc75900e48f83d0e3592ea9fa4b70da72ccaa3"
	strings:
		$s1 = "Set TS to port:80 Successfully!" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "Now,set TS to port 80" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "echo. >>amethyst.reg" fullword ascii
		$s4 = "del amethyst.reg" fullword ascii
		$s5 = "AntiFW.cpp" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and 2 of them
}