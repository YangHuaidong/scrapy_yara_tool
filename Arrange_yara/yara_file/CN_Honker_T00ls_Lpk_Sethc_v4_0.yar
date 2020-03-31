rule CN_Honker_T00ls_Lpk_Sethc_v4_0 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file T00ls Lpk Sethc v4.0.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "98f21f72c761e504814f0a7db835a24a2413a6c2"
	strings:
		$s0 = "LOADER ERROR" fullword ascii /* PEStudio Blacklist: strings */
		$s15 = "2011-2012 T00LS&RICES" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 2077KB and all of them
}