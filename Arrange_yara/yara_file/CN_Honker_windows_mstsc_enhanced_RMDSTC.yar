rule CN_Honker_windows_mstsc_enhanced_RMDSTC {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file RMDSTC.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3ca2b1b6f31219baf172abcc8f00f07f560e465f"
	strings:
		$s0 = "zava zir5@163.com" fullword wide
		$s1 = "By newccc" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and all of them
}