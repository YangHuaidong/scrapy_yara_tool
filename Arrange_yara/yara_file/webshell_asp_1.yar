rule webshell_asp_1 {
	meta:
		description = "Web Shell - file 1.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "8991148adf5de3b8322ec5d78cb01bdb"
	strings:
		$s4 = "!22222222222222222222222222222222222222222222222222" fullword
		$s8 = "<%eval request(\"pass\")%>" fullword
	condition:
		all of them
}