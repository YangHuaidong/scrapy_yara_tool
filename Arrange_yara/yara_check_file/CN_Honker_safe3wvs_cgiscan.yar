rule CN_Honker_safe3wvs_cgiscan {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file cgiscan.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f94bbf2034ad9afa43cca3e3a20f142e0bb54d75"
	strings:
		$s2 = "httpclient.exe" fullword wide
		$s3 = "www.safe3.com.cn" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 357KB and all of them
}