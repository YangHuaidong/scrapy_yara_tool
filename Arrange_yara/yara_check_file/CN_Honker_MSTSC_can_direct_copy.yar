rule CN_Honker_MSTSC_can_direct_copy {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file MSTSC_can_direct_copy.EXE"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "2f3cbfd9f82f8abafdb1d33235fa6bfa1e1f71ae"
	strings:
		$s1 = "srv\\newclient\\lib\\win32\\obj\\i386\\mstsc.pdb" fullword ascii
		$s2 = "Clear Password" fullword wide /* PEStudio Blacklist: strings */
		$s3 = "/migrate -- migrates legacy connection files that were created with " fullword wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 600KB and all of them
}