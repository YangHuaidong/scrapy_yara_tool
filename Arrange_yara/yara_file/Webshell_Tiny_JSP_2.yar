rule Webshell_Tiny_JSP_2 {
	meta:
		description = "Detects a tiny webshell - chine chopper"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2015-12-05"
		score = 100
	strings:
		$s1 = "<%eval(Request(" nocase
	condition:
		uint16(0) == 0x253c and filesize < 40 and all of them
}