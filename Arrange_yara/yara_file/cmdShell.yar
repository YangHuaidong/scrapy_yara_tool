rule cmdShell {
	meta:
		description = "Webshells Auto-generated - file cmdShell.asp"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "8a9fef43209b5d2d4b81dfbb45182036"
	strings:
		$s1 = "if cmdPath=\"wscriptShell\" then"
	condition:
		all of them
}