rule CN_Honker_arp3_7_arp3_7 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file arp3.7.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "db641a9dfec103b98548ac7f6ca474715040f25c"
	strings:
		$s1 = "CnCerT.Net.SKiller.exe" fullword wide /* PEStudio Blacklist: strings */
		$s2 = "www.80sec.com" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 4000KB and all of them
}