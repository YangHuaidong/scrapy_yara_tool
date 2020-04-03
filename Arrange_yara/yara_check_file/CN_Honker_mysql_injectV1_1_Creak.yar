rule CN_Honker_mysql_injectV1_1_Creak {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file mysql_injectV1.1_Creak.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "a1f066789f48a76023598c5777752c15f91b76b0"
	strings:
		$s0 = "1http://192.169.200.200:2217/mysql_inject.php?id=1" fullword ascii /* PEStudio Blacklist: strings */
		$s12 = "OnGetPassword" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 5890KB and all of them
}