rule MiniDumpTest_msdsc {
	meta:
		description = "Auto-generated rule - file msdsc.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://github.com/giMini/RWMC/"
		date = "2015-08-31"
		hash = "477034933918c433f521ba63d2df6a27cc40a5833a78497c11fb0994d2fd46ba"
	strings:
		$s1 = "MiniDumpTest1.exe" fullword wide
		$s2 = "MiniDumpWithTokenInformation" fullword ascii
		$s3 = "MiniDumpTest1" fullword wide
		$s6 = "Microsoft 2008" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 20KB and all of them
}