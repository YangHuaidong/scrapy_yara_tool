rule CN_Honker_HconSTFportable {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file HconSTFportable.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "00253a00eadb3ec21a06911a3d92728bbbe80c09"
	strings:
		$s1 = "HconSTFportable.exe" fullword wide /* PEStudio Blacklist: strings */
		$s2 = "www.Hcon.in" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 354KB and all of them
}