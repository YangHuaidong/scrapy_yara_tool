rule APT30_Sample_27 {
	meta:
		description = "FireEye APT30 Report Sample - file d38e02eac7e3b299b46ff2607dd0f288"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "959573261ca1d7e5ddcd19447475b2139ca24fe1"
	strings:
		$s0 = "Mozilla/4.0" fullword ascii
		$s1 = "dizhi.gif" fullword ascii
		$s5 = "oftHaveAck+" ascii
		$s10 = "HlobalAl" fullword ascii
		$s13 = "$NtRND1$" fullword ascii
		$s14 = "_NStartup" fullword ascii
		$s16 = "GXSYSTEM" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}