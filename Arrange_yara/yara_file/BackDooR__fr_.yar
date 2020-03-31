rule BackDooR__fr_ {
	meta:
		description = "Webshells Auto-generated - file BackDooR (fr).php"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "a79cac2cf86e073a832aaf29a664f4be"
	strings:
		$s3 = "print(\"<p align=\\\"center\\\"><font size=\\\"5\\\">Exploit include "
	condition:
		all of them
}