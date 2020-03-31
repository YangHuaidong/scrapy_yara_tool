rule CN_Honker_GetSyskey {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GetSyskey.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "17cec5e75cda434d0a1bc8cdd5aa268b42633fe9"
	strings:
		$s2 = "GetSyskey <SYSTEM registry file> [Output system key file]" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "The system key file \"%s\" is created." fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and all of them
}