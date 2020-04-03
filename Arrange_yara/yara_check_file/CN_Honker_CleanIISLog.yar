rule CN_Honker_CleanIISLog {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file CleanIISLog.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "827cd898bfe8aa7e9aaefbe949d26298f9e24094"
	strings:
		$s1 = "Usage: CleanIISLog <LogFile>|<.> <CleanIP>|<.>" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}