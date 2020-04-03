rule CN_Honker_Safe3WVS {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Safe3WVS.EXE"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "fee3acacc763dc55df1373709a666d94c9364a7f"
	strings:
		$s0 = "2TerminateProcess" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "mscoreei.dll" fullword ascii /* reversed goodware string 'lld.ieerocsm' */
		$s7 = "SafeVS.exe" fullword wide
		$s8 = "www.safe3.com.cn" fullword wide
		$s20 = "SOFTWARE\\Classes\\Interface\\" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}