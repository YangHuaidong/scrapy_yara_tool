rule PhpShell {
	meta:
		description = "Webshells Auto-generated - file PhpShell.php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "539baa0d39a9cf3c64d65ee7a8738620"
	strings:
		$s2 = "href=\"http://www.gimpster.com/wiki/PhpShell\">www.gimpster.com/wiki/PhpShell</a>."
	condition:
		all of them
}