rule CN_Honker_CnCerT_CCdoor_CMD_2 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file CnCerT.CCdoor.CMD.dll2"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "7f3a6fb30845bf366e14fa21f7e05d71baa1215a"
	strings:
		$s0 = "cmd.dll" fullword wide
		$s1 = "cmdpath" fullword ascii
		$s2 = "Get4Bytes" fullword ascii
		$s3 = "ExcuteCmd" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 22KB and all of them
}