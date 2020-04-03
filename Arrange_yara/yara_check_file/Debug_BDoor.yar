rule Debug_BDoor {
	meta:
		description = "Webshells Auto-generated - file BDoor.dll"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "e4e8e31dd44beb9320922c5f49739955"
	strings:
		$s1 = "\\BDoor\\"
		$s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
	condition:
		all of them
}