rule CN_Honker_sig_3389_2_3389 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file 3389.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "48d1974215e5cb07d1faa57e37afa91482b5a376"
	strings:
		$s1 = "C:\\Documents and Settings\\Administrator\\" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "net user guest /active:yes" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "\\Microsoft Word.exe" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 80KB and all of them
}