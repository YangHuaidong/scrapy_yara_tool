rule CN_Honker_CnCerT_CCdoor_CMD {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file CnCerT.CCdoor.CMD.dll"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "1c6ed7d817fa8e6534a5fd36a94f4fc2f066c9cd"
	strings:
		$s2 = "CnCerT.CCdoor.CMD.dll" fullword wide
		$s3 = "cmdpath" fullword ascii
		$s4 = "Get4Bytes" fullword ascii
		$s5 = "ExcuteCmd" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 22KB and all of them
}