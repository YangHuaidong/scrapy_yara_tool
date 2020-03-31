rule CN_Honker_CookiesView {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file CookiesView.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "c54e1f16d79066edfa0f84e920ed1f4873958755"
	strings:
		$s0 = "V1.0  Http://www.darkst.com Code:New4" fullword ascii
		$s1 = "maotpo@126.com" fullword ascii
		$s2 = "www.baidu.com" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 640KB and all of them
}