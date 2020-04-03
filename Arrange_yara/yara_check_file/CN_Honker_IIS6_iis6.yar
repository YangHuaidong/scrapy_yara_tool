rule CN_Honker_IIS6_iis6 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file iis6.com"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f0c9106d6d2eea686fd96622986b641968d0b864"
	strings:
		$s0 = "GetMod;ul" fullword ascii
		$s1 = "excjpb" fullword ascii
		$s2 = "LEAUT1" fullword ascii
		$s3 = "EnumProcessModules" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 410 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and all of them
}