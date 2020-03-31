rule installer {
	meta:
		description = "Webshells Auto-generated - file installer.cmd"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "a507919ae701cf7e42fa441d3ad95f8f"
	strings:
		$s0 = "Restore Old Vanquish"
		$s4 = "ReInstall Vanquish"
	condition:
		all of them
}