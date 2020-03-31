rule WebShell_indexer_asp_php {
	meta:
		description = "PHP Webshells Github Archive - file indexer.asp.php.txt"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "e9a7aa5eb1fb228117dc85298c7d3ecd8e288a2d"
	strings:
		$s0 = "<meta http-equiv=\"Content-Language\" content=\"tr\">" fullword
		$s1 = "<title>WwW.SaNaLTeRoR.OrG - inDEXER And ReaDer</title>" fullword
		$s2 = "<form action=\"?Gonder\" method=\"post\">" fullword
		$s4 = "<form action=\"?oku\" method=\"post\">" fullword
		$s7 = "var message=\"SaNaLTeRoR - " fullword
		$s8 = "nDexEr - Reader\"" fullword
	condition:
		3 of them
}