rule CN_Honker_InvasionErasor {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file InvasionErasor.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b37ecd9ee6b137a29c9b9d2801473a521b168794"
	strings:
		$s1 = "c:\\windows\\system32\\config\\*.*" fullword wide /* PEStudio Blacklist: strings */
		$s2 = "c:\\winnt\\*.txt" fullword wide /* PEStudio Blacklist: os */
		$s3 = "Command1" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "Win2003" fullword ascii /* PEStudio Blacklist: os */
		$s5 = "Win 2000" fullword ascii /* PEStudio Blacklist: os */
	condition:
		uint16(0) == 0x5a4d and filesize < 60KB and all of them
}