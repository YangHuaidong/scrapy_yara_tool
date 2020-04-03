rule APT_Project_Sauron_arping_module {
	meta:
		description = "Detects strings from arping module - Project Sauron report by Kaspersky"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-08"
	strings:
		$s1 = "Resolve hosts that answer"
		$s2 = "Print only replying Ips"
		$s3 = "Do not display MAC addresses"
	condition:
		all of them
}