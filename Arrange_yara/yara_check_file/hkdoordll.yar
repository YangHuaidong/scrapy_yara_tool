rule hkdoordll {
	meta:
		description = "Webshells Auto-generated - file hkdoordll.dll"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "b715c009d47686c0e62d0981efce2552"
	strings:
		$s6 = "Can't uninstall,maybe the backdoor is not installed or,the Password you INPUT is"
	condition:
		all of them
}