rule CN_Honker_dirdown_dirdown {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file dirdown.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "7b8d51c72841532dded5fec7e7b0005855b8a051"
	strings:
		$s0 = "\\Decompress\\obj\\Release\\Decompress.pdb" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "Decompress.exe" fullword wide
		$s5 = "Get8Bytes" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 45KB and all of them
}