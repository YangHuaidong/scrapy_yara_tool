rule CN_Honker_Alien_ee {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ee.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "15a7211154ee7aca29529bd5c2500e0d33d7f0b3"
	strings:
		$s1 = "GetIIS UserName and PassWord." fullword wide /* PEStudio Blacklist: strings */
		$s2 = "Read IIS ID For FreeHost." fullword wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and all of them
}