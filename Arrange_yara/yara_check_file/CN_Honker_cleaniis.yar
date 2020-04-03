rule CN_Honker_cleaniis {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file cleaniis.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "372bc64c842f6ff0d9a1aa2a2a44659d8b88cb40"
	strings:
		$s1 = "iisantidote <logfile dir> <ip or string to hide>" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "IIS log file cleaner by Scurt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}