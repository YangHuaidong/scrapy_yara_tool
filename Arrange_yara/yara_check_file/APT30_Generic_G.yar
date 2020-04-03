rule APT30_Generic_G {
	meta:
		description = "FireEye APT30 Report Sample - file 53f1358cbc298da96ec56e9a08851b4b"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "1612b392d6145bfb0c43f8a48d78c75f"
		hash = "53f1358cbc298da96ec56e9a08851b4b"
		hash = "c2acc9fc9b0f050ec2103d3ba9cb11c0"
		hash = "f18be055fae2490221c926e2ad55ab11"
	strings:
		$s0 = "%s\\%s\\%s=%s" fullword ascii
		$s1 = "Copy File %s OK!" fullword ascii
		$s2 = "%s Space:%uM,FreeSpace:%uM" fullword ascii
		$s4 = "open=%s" fullword ascii
		$s5 = "Maybe a Encrypted Flash Disk" fullword ascii
		$s12 = "%04u-%02u-%02u %02u:%02u:%02u" fullword ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}