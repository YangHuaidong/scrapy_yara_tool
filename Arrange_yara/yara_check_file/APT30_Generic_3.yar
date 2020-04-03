rule APT30_Generic_3 {
	meta:
		description = "FireEye APT30 Report Sample"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		super_rule = 1
		hash0 = "b90ac3e58ed472829e2562023e6e892d2d61ac44"
		hash1 = "342036ace2e9e6d504b0dec6399e4fa92de46c12"
		hash2 = "5cdf397dfd9eb66ff5ff636777f6982c1254a37a"
	strings:
		$s0 = "Acrobat.exe" fullword wide
		$s14 = "********************************" fullword
		$s16 = "FFFF:>>>>>>>>>>>>>>>>>@" fullword
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}