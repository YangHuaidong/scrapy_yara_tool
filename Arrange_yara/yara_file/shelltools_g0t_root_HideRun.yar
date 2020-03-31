rule shelltools_g0t_root_HideRun {
	meta:
		description = "Webshells Auto-generated - file HideRun.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "45436d9bfd8ff94b71eeaeb280025afe"
	strings:
		$s0 = "Usage -- hiderun [AppName]"
		$s7 = "PVAX SW, Alexey A. Popoff, Moscow, 1997."
	condition:
		all of them
}