rule CN_Honker_windows_exp {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file exp.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "04334c396b165db6e18e9b76094991d681e6c993"
	strings:
		$s0 = "c:\\windows\\system32\\command.com /c " fullword ascii /* PEStudio Blacklist: strings */
		$s8 = "OH,Sry.Too long command." fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 220KB and all of them
}