rule EQGRP_callbacks {
	meta:
		description = "EQGRP Toolset Firewall - Callback addresses"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
	strings:
		$s1 = "30.40.50.60:9342" fullword ascii wide /* DoD */
	condition:
		1 of them
}