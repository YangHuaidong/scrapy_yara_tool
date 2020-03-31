rule CN_Honker_SAMInside {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SAMInside.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "707ba507f9a74d591f4f2e2f165ff9192557d6dd"
	strings:
		$s0 = "www.InsidePro.com" fullword wide
		$s1 = "SAMInside.exe" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 650KB and all of them
}