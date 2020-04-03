rule APT30_Sample_3 {
	meta:
		description = "FireEye APT30 Report Sample - file 59e055cee87d8faf6f701293e5830b5a"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "d0320144e65c9af0052f8dee0419e8deed91b61b"
	strings:
		$s5 = "Software\\Mic" ascii
		$s6 = "HHOSTR" ascii
		$s9 = "ThEugh" fullword ascii
		$s10 = "Moziea/" ascii
		$s12 = "%s%s(X-" ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}