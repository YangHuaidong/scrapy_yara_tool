rule bdcli100 {
	meta:
		description = "Webshells Auto-generated - file bdcli100.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "b12163ac53789fb4f62e4f17a8c2e028"
	strings:
		$s5 = "unable to connect to "
		$s8 = "backdoor is corrupted on "
	condition:
		all of them
}