rule CN_Honker_hashq_Hashq {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Hashq.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "7518b647db5275e8a9e0bf4deda3d853cc9d5661"
	strings:
		$s1 = "Hashq.exe" fullword wide
		$s5 = "CnCert.Net" fullword wide
		$s6 = "Md5 query tool" fullword wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 600KB and all of them
}