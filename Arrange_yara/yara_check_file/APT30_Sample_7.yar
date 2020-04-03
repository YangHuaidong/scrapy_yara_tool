rule APT30_Sample_7 {
	meta:
		description = "FireEye APT30 Report Sample - file 74b87086887e0c67ffb035069b195ac7"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "868d1f4c106a08bd2e5af4f23139f0e0cd798fba"
	strings:
		$s0 = "datain" fullword ascii
		$s3 = "C:\\Prog" ascii
		$s4 = "$LDDATA$" ascii
		$s5 = "Maybe a Encrypted Flash" fullword ascii
		$s6 = "Jean-loup Gailly" ascii
		$s8 = "deflate 1.1.3 Copyright" ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}