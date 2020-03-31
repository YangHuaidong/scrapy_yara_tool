rule FSO_s_test {
	meta:
		description = "Webshells Auto-generated - file test.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "82cf7b48da8286e644f575b039a99c26"
	strings:
		$s0 = "$yazi = \"test\" . \"\\r\\n\";"
		$s2 = "fwrite ($fp, \"$yazi\");"
	condition:
		all of them
}