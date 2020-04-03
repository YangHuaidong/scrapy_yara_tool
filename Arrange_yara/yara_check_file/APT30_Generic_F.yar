rule APT30_Generic_F {
	meta:
		description = "FireEye APT30 Report Sample - file 4c10a1efed25b828e4785d9526507fbc"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash1 = "09010917cd00dc8ddd21aeb066877aa2"
		hash2 = "4c10a1efed25b828e4785d9526507fbc"
		hash3 = "b7b282c9e3eca888cbdb5a856e07e8bd"
		hash4 = "df1799845b51300b03072c6569ab96d5"
	strings:
		$s0 = "\\~zlzl.exe" fullword ascii
		$s2 = "\\Internet Exp1orer" fullword ascii
		$s3 = "NodAndKabIsExcellent" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}