rule CN_Honker__LPK_LPK_LPK {
	meta:
		description = "Sample from CN Honker Pentest Toolset - from files LPK.DAT, LPK.DAT, LPK.DAT"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		super_rule = 1
		hash0 = "5a1226e73daba516c889328f295e728f07fdf1c3"
		hash1 = "2b2ab50753006f62965bba83460e3960ca7e1926"
		hash2 = "cf2549bbbbdb7aaf232d9783873667e35c8d96c1"
	strings:
		$s1 = "C:\\WINDOWS\\system32\\cmd.exe" fullword wide /* PEStudio Blacklist: strings */
		$s2 = "Password error!" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "\\sathc.exe" fullword ascii
		$s4 = "\\sothc.exe" fullword ascii
		$s5 = "\\lpksethc.bat" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1057KB and all of them
}