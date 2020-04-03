rule CN_Honker_ACCESS_brute {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ACCESS_brute.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f552e05facbeb21cb12f23c34bb1881c43e24c34"
	strings:
		$s1 = ".dns166.co" ascii /* PEStudio Blacklist: strings */
		$s2 = "SExecuteA" ascii /* PEStudio Blacklist: strings */
		$s3 = "ality/clsCom" ascii
		$s4 = "NT_SINK_AddRef" ascii
		$s5 = "WINDOWS\\Syswm" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 20KB and all of them
}