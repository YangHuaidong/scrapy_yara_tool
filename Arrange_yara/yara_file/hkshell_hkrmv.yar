rule hkshell_hkrmv {
	meta:
		description = "Webshells Auto-generated - file hkrmv.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "bd3a0b7a6b5536f8d96f50956560e9bf"
	strings:
		$s5 = "/THUMBPOSITION7"
		$s6 = "\\EvilBlade\\"
	condition:
		all of them
}