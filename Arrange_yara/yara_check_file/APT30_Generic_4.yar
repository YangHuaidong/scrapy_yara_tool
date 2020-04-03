rule APT30_Generic_4 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		super_rule = 1
		hash0 = "bb390f99bfde234bbed59f6a0d962ba874b2396c"
		hash1 = "b47e20ac5889700438dc241f28f4e224070810d2"
		hash2 = "a9a50673ac000a313f3ddba55d63d9773b9f4143"
		hash3 = "ac96d7f5957aef09bd983465c497de24c6d17a92"
	strings:
		$s0 = "del NetEagle_Scout.bat" fullword
		$s1 = "NetEagle_Scout.bat" fullword
		$s2 = "\\visit.exe" fullword
		$s3 = "\\System.exe" fullword
		$s4 = "\\System.dat" fullword
		$s5 = "\\ieupdate.exe" fullword
		$s6 = "GOTO ERROR" fullword
		$s7 = ":ERROR" fullword
		$s9 = "IF EXIST " fullword
		$s10 = "ioiocn" fullword
		$s11 = "SetFileAttribute" fullword
		$s12 = "le_0*^il" fullword
		$s13 = "le_.*^il" fullword
		$s14 = "le_-*^il" fullword
	condition:
		filesize < 250KB and uint16(0) == 0x5A4D and all of them
}