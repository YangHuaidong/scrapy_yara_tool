rule CN_Honker_HASH_PwDump7 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file PwDump7.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "93a2d7c3a9b83371d96a575c15fe6fce6f9d50d3"
	strings:
		$s1 = "%s\\SYSTEM32\\CONFIG\\SAM" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "No Users key!" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "NO PASSWORD*********************:" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "Unable to dump file %S" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 380KB and all of them
}