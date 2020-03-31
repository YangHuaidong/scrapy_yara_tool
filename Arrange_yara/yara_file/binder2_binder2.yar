rule binder2_binder2 {
	meta:
		description = "Webshells Auto-generated - file binder2.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "d594e90ad23ae0bc0b65b59189c12f11"
	strings:
		$s0 = "IsCharAlphaNumericA"
		$s2 = "WideCharToM"
		$s4 = "g 5pur+virtu!"
		$s5 = "\\syslog.en"
		$s6 = "heap7'7oqk?not="
		$s8 = "- Kablto in"
	condition:
		all of them
}