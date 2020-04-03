rule Dos_c {
	meta:
		description = "Chinese Hacktool Set - file c.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3deb6bd52fdac6d5a3e9a91c585d67820ab4df78"
	strings:
		$s0 = "!Win32 .EXE." fullword ascii
		$s1 = ".MPRESS1" fullword ascii
		$s2 = ".MPRESS2" fullword ascii
		$s3 = "XOLEHLP.dll" fullword ascii
		$s4 = "</body></html>" fullword ascii
		$s8 = "DtcGetTransactionManagerExA" fullword ascii  /* Goodware String - occured 12 times */
		$s9 = "GetUserNameA" fullword ascii  /* Goodware String - occured 305 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}