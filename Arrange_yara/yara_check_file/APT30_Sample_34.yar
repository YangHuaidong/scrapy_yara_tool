rule APT30_Sample_34 {
	meta:
		description = "FireEye APT30 Report Sample - file a9e8e402a7ee459e4896d0ba83543684"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "216868edbcdd067bd2a9cce4f132d33ba9c0d818"
	strings:
		$s0 = "dizhi.gif" ascii
		$s1 = "eagles.vip.nse" ascii
		$s4 = "o%S:S0" ascii
		$s5 = "la/4.0" ascii
		$s6 = "s#!<4!2>s02==<'s1" ascii
		$s7 = "HlobalAl" ascii
		$s9 = "vcMicrosoftHaveAck7"  ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}