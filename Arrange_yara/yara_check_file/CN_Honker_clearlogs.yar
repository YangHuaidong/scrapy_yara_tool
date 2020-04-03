rule CN_Honker_clearlogs {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file clearlogs.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "490f3bc318f415685d7e32176088001679b0da1b"
	strings:
		$s2 = "- http://ntsecurity.nu/toolbox/clearlogs/" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "Error: Unable to clear log - " fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 140KB and all of them
}