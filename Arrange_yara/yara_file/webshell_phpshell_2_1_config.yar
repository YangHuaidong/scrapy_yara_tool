rule webshell_phpshell_2_1_config {
	meta:
		description = "Web Shell - file config.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "bd83144a649c5cc21ac41b505a36a8f3"
	strings:
		$s1 = "; (choose good passwords!).  Add uses as simple 'username = \"password\"' lines." fullword
	condition:
		all of them
}