rule EditServer_2 {
	meta:
		description = "Webshells Auto-generated - file EditServer.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "5c1f25a4d206c83cdfb006b3eb4c09ba"
	strings:
		$s0 = "@HOTMAIL.COM"
		$s1 = "Press Any Ke"
		$s3 = "glish MenuZ"
	condition:
		all of them
}