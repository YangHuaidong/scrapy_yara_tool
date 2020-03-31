rule CN_Honker_smsniff_smsniff {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file smsniff.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "8667a785a8ced76d0284d225be230b5f1546f140"
	strings:
		$s1 = "smsniff.exe" fullword wide
		$s5 = "SmartSniff" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 267KB and all of them
}