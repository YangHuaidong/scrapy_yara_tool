rule CN_Honker_shell_brute_tool {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file shell_brute_tool.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f6903a15453698c35dce841e4d09c542f9480f01"
	strings:
		$s0 = "http://24hack.com/xyadmin.asp" fullword ascii /* PEStudio Blacklist: strings */
		$s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* PEStudio Blacklist: agent */
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}