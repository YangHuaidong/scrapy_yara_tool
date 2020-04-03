rule HDConfig {
	meta:
		description = "Webshells Auto-generated - file HDConfig.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "7d60e552fdca57642fd30462416347bd"
	strings:
		$s0 = "An encryption key is derived from the password hash. "
		$s3 = "A hash object has been created. "
		$s4 = "Error during CryptCreateHash!"
		$s5 = "A new key container has been created."
		$s6 = "The password has been added to the hash. "
	condition:
		all of them
}