rule CN_Honker_CoolScan_scan {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file scan.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e1c5fb6b9f4e92c4264c7bea7f5fba9a5335c328"
	strings:
		$s0 = "User-agent:\\s{0,32}(huasai|huasai/1.0|\\*)" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "scan web.exe" fullword wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 3680KB and all of them
}