rule CN_Honker_Webshell_PHP_php4 {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php4.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "179975f632baff6ee4d674fe3fabc324724fee9e"
	strings:
		$s0 = "nc -l -vv -p port(" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x4850 and filesize < 1KB and all of them
}