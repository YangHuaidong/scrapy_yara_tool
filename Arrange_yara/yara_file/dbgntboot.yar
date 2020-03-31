rule dbgntboot {
	meta:
		description = "Webshells Auto-generated - file dbgntboot.dll"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "4d87543d4d7f73c1529c9f8066b475ab"
	strings:
		$s2 = "now DOS is working at mode %d,faketype %d,against %s,has worked %d minutes,by sp"
		$s3 = "sth junk the M$ Wind0wZ retur"
	condition:
		all of them
}