rule byloader {
	meta:
		description = "Webshells Auto-generated - file byloader.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		hash = "0f0d6dc26055653f5844ded906ce52df"
	strings:
		$s0 = "SYSTEM\\CurrentControlSet\\Services\\NtfsChk"
		$s1 = "Failure ... Access is Denied !"
		$s2 = "NTFS Disk Driver Checking Service"
		$s3 = "Dumping Description to Registry..."
		$s4 = "Opening Service .... Failure !"
	condition:
		all of them
}