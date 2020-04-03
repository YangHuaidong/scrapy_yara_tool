rule EQGRP_MixText {
	meta:
		description = "EQGRP Toolset Firewall - file MixText.py"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "e4d24e30e6cc3a0aa0032dbbd2b68c60bac216bef524eaf56296430aa05b3795"
	strings:
		$s1 = "BinStore enabled implants." fullword ascii
	condition:
		1 of them
}