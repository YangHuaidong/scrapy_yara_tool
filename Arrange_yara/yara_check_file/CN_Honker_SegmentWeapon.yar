rule CN_Honker_SegmentWeapon {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SegmentWeapon.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "494ef20067a7ce2cc95260e4abc16fcfa7177fdf"
	strings:
		$s0 = "C:\\WINDOWS\\system32\\msvbvm60.dll\\3" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "http://www.nforange.com/inc/1.asp?" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}