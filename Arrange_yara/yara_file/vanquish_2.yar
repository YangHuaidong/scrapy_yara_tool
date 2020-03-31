rule vanquish_2 {
	meta:
		description = "Webshells Auto-generated - file vanquish.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "2dcb9055785a2ee01567f52b5a62b071"
	strings:
		$s2 = "Vanquish - DLL injection failed:"
	condition:
		all of them
}