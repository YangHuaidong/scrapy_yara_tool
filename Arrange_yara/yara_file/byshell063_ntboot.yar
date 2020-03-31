rule byshell063_ntboot {
	meta:
		description = "Webshells Auto-generated - file ntboot.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "99b5f49db6d6d9a9faeffb29fd8e6d8c"
	strings:
		$s0 = "SYSTEM\\CurrentControlSet\\Services\\NtBoot"
		$s1 = "Failure ... Access is Denied !"
		$s2 = "Dumping Description to Registry..."
		$s3 = "Opening Service .... Failure !"
	condition:
		all of them
}