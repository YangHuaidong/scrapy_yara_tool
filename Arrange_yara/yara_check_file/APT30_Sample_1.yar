rule APT30_Sample_1 {
	meta:
		description = "FireEye APT30 Report Sample - file 4c6b21e98ca03e0ef0910e07cef45dac"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "8cea83299af8f5ec6c278247e649c9d91d4cf3bc"
	strings:
		$s0 = "#hostid" fullword ascii
		$s1 = "\\Windows\\C" ascii
		$s5 = "TimUmove" fullword ascii
		$s6 = "Moziea/4.0 (c" fullword ascii
		$s7 = "StartupNA" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}