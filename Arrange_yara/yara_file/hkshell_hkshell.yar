rule hkshell_hkshell {
	meta:
		description = "Webshells Auto-generated - file hkshell.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "168cab58cee59dc4706b3be988312580"
	strings:
		$s1 = "PrSessKERNELU"
		$s2 = "Cur3ntV7sion"
		$s3 = "Explorer8"
	condition:
		all of them
}