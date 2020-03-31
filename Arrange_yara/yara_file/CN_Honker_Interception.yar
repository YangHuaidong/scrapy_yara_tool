rule CN_Honker_Interception {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Interception.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ea813aed322e210ea6ae42b73b1250408bf40e7a"
	strings:
		$s2 = ".\\dat\\Hookmsgina.dll" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "WinlogonHackEx " fullword wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 160KB and all of them
}