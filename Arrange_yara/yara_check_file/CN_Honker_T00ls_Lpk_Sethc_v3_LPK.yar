rule CN_Honker_T00ls_Lpk_Sethc_v3_LPK {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file LPK.DAT"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "cf2549bbbbdb7aaf232d9783873667e35c8d96c1"
	strings:
		$s1 = "FreeHostKillexe.exe" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "\\sethc.exe /G everyone:F" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "c:\\1.exe" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "Set user Group Error! Username:" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and all of them
}