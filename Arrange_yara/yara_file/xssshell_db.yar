rule xssshell_db {
	meta:
		description = "Webshells Auto-generated - file db.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "cb62e2ec40addd4b9930a9e270f5b318"
	strings:
		$s8 = "'// By Ferruh Mavituna | http://ferruh.mavituna.com"
	condition:
		all of them
}