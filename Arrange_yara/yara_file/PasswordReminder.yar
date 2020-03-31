rule PasswordReminder {
	meta:
		description = "Webshells Auto-generated - file PasswordReminder.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "ea49d754dc609e8bfa4c0f95d14ef9bf"
	strings:
		$s3 = "The encoded password is found at 0x%8.8lx and has a length of %d."
	condition:
		all of them
}