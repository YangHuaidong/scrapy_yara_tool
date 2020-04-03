rule CN_Honker_FTP_scanning {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file FTP_scanning.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5a3543ee5aed110c87cbc3973686e785bcb5c44e"
	strings:
		$s1 = "CNotSupportedE" fullword ascii /* PEStudio Blacklist: strings */
		$s2 = "nINet.dll" fullword ascii
		$s9 = "?=MODULE" fullword ascii /* PEStudio Blacklist: strings */
		$s13 = "MSIE 6*" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 550KB and all of them
}