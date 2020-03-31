rule SetupBDoor {
	meta:
		description = "Webshells Auto-generated - file SetupBDoor.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "41f89e20398368e742eda4a3b45716b6"
	strings:
		$s1 = "\\BDoor\\SetupBDoor"
	condition:
		all of them
}