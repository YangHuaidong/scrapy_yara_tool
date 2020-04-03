rule CN_Honker_HASH_32 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file 32.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "bf4a8b4b3e906e385feab5ea768f604f64ba84ea"
	strings:
		$s5 = "[Undefined OS version]  Major: %d Minor: %d" fullword ascii
		$s8 = "Try To Run As Administrator ..." fullword ascii /* PEStudio Blacklist: strings */
		$s9 = "Specific LUID NOT found" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and all of them
}