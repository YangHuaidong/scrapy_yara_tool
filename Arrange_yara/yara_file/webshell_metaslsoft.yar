rule webshell_metaslsoft {
	meta:
		description = "Web Shell - file metaslsoft.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "aa328ed1476f4a10c0bcc2dde4461789"
	strings:
		$s7 = "$buff .= \"<tr><td><a href=\\\"?d=\".$pwd.\"\\\">[ $folder ]</a></td><td>LINK</t"
	condition:
		all of them
}