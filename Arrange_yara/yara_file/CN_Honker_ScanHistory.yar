rule CN_Honker_ScanHistory {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ScanHistory.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "14c31e238924ba3abc007dc5a3168b64d7b7de8d"
	strings:
		$s1 = "ScanHistory.exe" fullword wide /* PEStudio Blacklist: strings */
		$s2 = ".\\Report.dat" fullword wide /* PEStudio Blacklist: strings */
		$s3 = "select  * from  Results order by scandate desc" fullword wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}