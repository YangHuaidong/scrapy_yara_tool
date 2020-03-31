rule Equation_Kaspersky_HDD_reprogramming_module {
	meta:
		description = "Equation Group Malware - HDD reprogramming module"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "ff2b50f371eb26f22eb8a2118e9ab0e015081500"
	strings:
		$s0 = "nls_933w.dll" fullword ascii
		$s1 = "BINARY" fullword wide
		$s2 = "KfAcquireSpinLock" fullword ascii
		$s3 = "HAL.dll" fullword ascii
		$s4 = "READ_REGISTER_UCHAR" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300000 and all of ($s*)
}