rule u_uay {
	meta:
		description = "Webshells Auto-generated - file uay.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "abbc7b31a24475e4c5d82fc4c2b8c7c4"
	strings:
		$s1 = "exec \"c:\\WINDOWS\\System32\\freecell.exe"
		$s9 = "SYSTEM\\CurrentControlSet\\Services\\uay.sys\\Security"
	condition:
		1 of them
}