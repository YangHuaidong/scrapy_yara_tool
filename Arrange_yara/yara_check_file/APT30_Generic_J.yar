rule APT30_Generic_J {
	meta:
		description = "FireEye APT30 Report Sample - file baff5262ae01a9217b10fcd5dad9d1d5"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "49aca228674651cba776be727bdb7e60"
		hash2 = "5c7a6b3d1b85fad17333e02608844703"
		hash3 = "649fa64127fef1305ba141dd58fb83a5"
		hash4 = "9982fd829c0048c8f89620691316763a"
		hash5 = "baff5262ae01a9217b10fcd5dad9d1d5"
		hash6 = "9982fd829c0048c8f89620691316763a"
	strings:
		$s0 = "Launcher.EXE" fullword wide
		$s1 = "Symantec Security Technologies" fullword wide
		$s2 = "\\Symantec LiveUpdate.lnk" fullword ascii
		$s3 = "Symantec Service Framework" fullword wide
		$s4 = "\\ccSvcHst.exe" fullword ascii
		$s5 = "\\wssfmgr.exe" fullword ascii
		$s6 = "Symantec Corporation" fullword wide
		$s7 = "\\5.1.0.29" fullword ascii
		$s8 = "\\Engine" fullword ascii
		$s9 = "Copyright (C) 2000-2010 Symantec Corporation. All rights reserved." fullword wide
		$s10 = "Symantec LiveUpdate" fullword ascii
		$s11 = "\\Norton360" fullword ascii
		$s15 = "BinRes" fullword ascii
		$s16 = "\\readme.lz" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}