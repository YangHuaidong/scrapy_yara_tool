rule EQGRP_epicbanana_2_1_0_1 {
	meta:
		description = "EQGRP Toolset Firewall - file epicbanana_2.1.0.1.py"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "4b13cc183c3aaa8af43ef3721e254b54296c8089a0cd545ee3b867419bb66f61"
	strings:
		$s1 = "failed to create version-specific payload" fullword ascii
		$s2 = "(are you sure you did \"make [version]\" in versions?)" fullword ascii
	condition:
		1 of them
}