rule DllInjection {
	meta:
		description = "Webshells Auto-generated - file DllInjection.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "a7b92283a5102886ab8aee2bc5c8d718"
	strings:
		$s0 = "\\BDoor\\DllInjecti"
	condition:
		all of them
}