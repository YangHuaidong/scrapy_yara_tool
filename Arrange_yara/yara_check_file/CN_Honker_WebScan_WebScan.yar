rule CN_Honker_WebScan_WebScan {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file WebScan.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "a0b0e2422e0e9edb1aed6abb5d2e3d156b7c8204"
	strings:
		$s1 = "wwwscan.exe" fullword wide /* PEStudio Blacklist: strings */
		$s2 = "WWWScan Gui" fullword wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and all of them
}