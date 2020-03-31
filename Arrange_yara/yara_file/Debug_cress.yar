rule Debug_cress {
	meta:
		description = "Webshells Auto-generated - file cress.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "36a416186fe010574c9be68002a7286a"
	strings:
		$s0 = "\\Mithril "
		$s4 = "Mithril.exe"
	condition:
		all of them
}