rule CN_Honker_Webshell_PHP_BlackSky {
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php6.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "a60a599c6c8b6a6c0d9da93201d116af257636d7"
	strings:
		$s0 = "eval(gzinflate(base64_decode('" ascii /* PEStudio Blacklist: strings */
		$s1 = "B1ac7Sky-->" fullword ascii
	condition:
		filesize < 641KB and all of them
}