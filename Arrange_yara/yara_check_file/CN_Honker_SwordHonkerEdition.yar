rule CN_Honker_SwordHonkerEdition {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SwordHonkerEdition.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3f9479151c2cada04febea45c2edcf5cece1df6c"
	strings:
		$s0 = "\\bin\\systemini\\MyPort.ini" fullword wide /* PEStudio Blacklist: strings */
		$s1 = "PortThread=200 //" fullword wide /* PEStudio Blacklist: strings */
		$s2 = " Port Open -> " fullword wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 375KB and all of them
}