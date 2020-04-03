rule APT30_Sample_13 {
	meta:
		description = "FireEye APT30 Report Sample - file 95bb314fe8fdbe4df31a6d23b0d378bc"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "a359f705a833c4a4254443b87645fd579aa94bcf"
	strings:
		$s0 = "msofscan.exe" fullword wide
		$s1 = "Microsoft? is a registered trademark of Microsoft Corporation." fullword wide
		$s2 = "Microsoft Office Word Plugin Scan" fullword wide
		$s3 = "? 2006 Microsoft Corporation.  All rights reserved." fullword wide
		$s4 = "msofscan" fullword wide
		$s6 = "2003 Microsoft Office system" fullword wide
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and all of them
}