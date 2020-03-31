rule CN_Honker_ms10048_x86 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms10048-x86.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e57b453966e4827e2effa4e153f2923e7d058702"
	strings:
		$s1 = "[+] Set to %d exploit half succeeded" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and all of them
}