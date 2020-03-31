rule CN_Honker_DictionaryGenerator {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file DictionaryGenerator.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b3071c64953e97eeb2ca6796fab302d8a77d27bc"
	strings:
		$s1 = "`PasswordBuilder" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "cracker" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 3650KB and all of them
}