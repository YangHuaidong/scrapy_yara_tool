rule rdrbs100 {
	meta:
		description = "Webshells Auto-generated - file rdrbs100.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "7c752bcd6da796d80a6830c61a632bff"
	strings:
		$s3 = "Server address must be IP in A.B.C.D format."
		$s4 = " mapped ports in the list. Currently "
	condition:
		all of them
}