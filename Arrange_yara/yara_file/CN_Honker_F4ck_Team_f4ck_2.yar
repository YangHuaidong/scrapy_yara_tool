rule CN_Honker_F4ck_Team_f4ck_2 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file f4ck_2.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0783661077312753802bd64bf5d35c4666ad0a82"
	strings:
		$s1 = "F4ck.exe" fullword wide
		$s2 = "@Netapi32.dll" fullword ascii
		$s3 = "Team.F4ck.Net" fullword wide
		$s8 = "Administrators" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 14 times */
		$s9 = "F4ck Team" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 220KB and 2 of them
}