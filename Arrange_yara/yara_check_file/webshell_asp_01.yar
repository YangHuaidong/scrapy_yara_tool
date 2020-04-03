rule webshell_asp_01 {
	meta:
		description = "Web Shell - file 01.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 50
		hash = "61a687b0bea0ef97224c7bd2df118b87"
	strings:
		$s0 = "<%eval request(\"pass\")%>" fullword
	condition:
		all of them
}