rule APT30_Sample_22 {
	meta:
		description = "FireEye APT30 Report Sample - file fad06d7b4450c4631302264486611ec3"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "0d17a58c24753e5f8fd5276f62c8c7394d8e1481"
	strings:
		$s1 = "(\\TEMP" fullword ascii
		$s2 = "Windows\\Cur" fullword ascii
		$s3 = "LSSAS.exeJ" fullword ascii
		$s4 = "QC:\\WINDOWS" fullword ascii
		$s5 = "System Volume" fullword ascii
		$s8 = "PROGRAM FILE" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}