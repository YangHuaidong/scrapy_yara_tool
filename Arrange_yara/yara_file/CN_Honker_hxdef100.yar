rule CN_Honker_hxdef100 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file hxdef100.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "bf30ccc565ac40073b867d4c7f5c33c6bc1920d6"
	strings:
		$s6 = "BACKDOORSHELL" fullword ascii /* PEStudio Blacklist: strings */
		$s15 = "%tmpdir%" fullword ascii
		$s16 = "%cmddir%" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}