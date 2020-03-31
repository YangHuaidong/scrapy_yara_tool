rule CN_Honker_Fckeditor {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Fckeditor.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "4b16ae12c204f64265acef872526b27111b68820"
	strings:
		$s0 = "explorer.exe http://user.qzone.qq.com/568148075" fullword wide /* PEStudio Blacklist: strings */
		$s7 = "Fckeditor.exe" fullword wide /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 1340KB and all of them
}