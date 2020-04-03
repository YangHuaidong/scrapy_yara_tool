rule Unpack_TBack {
	meta:
		description = "Webshells Auto-generated - file TBack.dll"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "a9d1007823bf96fb163ab38726b48464"
	strings:
		$s5 = "\\final\\new\\lcc\\public.dll"
	condition:
		all of them
}