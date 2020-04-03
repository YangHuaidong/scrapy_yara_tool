rule CN_Honker_T00ls_scanner {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file T00ls_scanner.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "70b04b910d82b32b90cd7f355a0e3e17dd260cb3"
	strings:
		$s0 = "http://cn.bing.com/search?first=1&count=50&q=ip:" fullword wide
		$s17 = "Team:www.t00ls.net" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 330KB and all of them
}