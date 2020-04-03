rule CN_Honker_SkinHRootkit_SkinH {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SkinH.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "d593f03ae06e54b653c7850c872c0eed459b301f"
	strings:
		$s0 = "(C)360.cn Inc.All Rights Reserved." fullword wide
		$s1 = "SDVersion.dll" fullword wide
		$s2 = "skinh.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}