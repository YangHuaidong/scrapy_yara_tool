rule EQGRP_bo {
	meta:
		description = "EQGRP Toolset Firewall - file bo"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "aa8b363073e8ae754b1836c30f440d7619890ded92fb5b97c73294b15d22441d"
	strings:
		$s1 = "ERROR: failed to open %s: %d" fullword ascii
		$s2 = "__libc_start_main@@GLIBC_2.0" fullword ascii
		$s3 = "serial number: %s" fullword ascii
		$s4 = "strerror@@GLIBC_2.0" fullword ascii
		$s5 = "ERROR: mmap failed: %d" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 20KB and all of them )
}