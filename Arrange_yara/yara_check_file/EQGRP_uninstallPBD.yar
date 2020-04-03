rule EQGRP_uninstallPBD {
	meta:
		description = "EQGRP Toolset Firewall - file uninstallPBD.bat"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "692fdb449f10057a114cf2963000f52ce118d9a40682194838006c66af159bd0"
	strings:
		$s1 = "memset 00e9a05c 4 38845b88" fullword ascii
		$s2 = "_hidecmd" fullword ascii
		$s3 = "memset 013abd04 1 0d" fullword ascii
	condition:
		all of them
}