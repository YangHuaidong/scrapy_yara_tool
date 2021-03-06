rule APT30_Sample_9 {
	meta:
		description = "FireEye APT30 Report Sample - file e3ae3cbc024e39121c87d73e87bb2210"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "442bf8690401a2087a340ce4a48151c39101652f"
	strings:
		$s0 = "\\Windo" ascii
		$s2 = "oHHOSTR" ascii
		$s3 = "Softwa]\\Mic" ascii
		$s4 = "Startup'T" ascii
		$s6 = "Ora\\%^" ascii
		$s7 = "\\Ohttp=r" ascii
		$s17 = "help32Snapshot0L" ascii
		$s18 = "TimUmoveH" ascii
		$s20 = "WideChc[lobalAl" ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}