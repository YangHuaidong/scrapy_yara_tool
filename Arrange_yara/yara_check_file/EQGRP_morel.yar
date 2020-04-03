rule EQGRP_morel {
	meta:
		description = "Detects tool from EQGRP toolset - file morel.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		hash1 = "a9152e67f507c9a179bb8478b58e5c71c444a5a39ae3082e04820a0613cd6d9f"
	strings:
		$s1 = "%d - %d, %d" fullword ascii
		$s2 = "%d - %lu.%lu %d.%lu" fullword ascii
		$s3 = "%d - %d %d" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 60KB and all of them )
}