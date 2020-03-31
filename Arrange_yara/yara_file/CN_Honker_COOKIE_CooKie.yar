rule CN_Honker_COOKIE_CooKie {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file CooKie.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f7727160257e0e716e9f0cf9cdf9a87caa986cde"
	strings:
		$s4 = "-1 union select 1,username,password,4,5,6,7,8,9,10 from admin" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "CooKie.exe" fullword wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 360KB and all of them
}