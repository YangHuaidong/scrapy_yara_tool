rule APT30_Sample_33 {
	meta:
		description = "FireEye APT30 Report Sample - file 5eaf3deaaf2efac92c73ada82a651afe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "72c568ee2dd75406858c0294ccfcf86ad0e390e4"
	strings:
		$s0 = "Version 4.7.3001" fullword wide
		$s1 = "msmsgr.exe" fullword wide
		$s2 = "MYUSER32.dll" fullword ascii
		$s3 = "MYADVAPI32.dll" fullword ascii
		$s4 = "CeleWare.NET1" fullword ascii
		$s6 = "MYMSVCRT.dll" fullword ascii
		$s7 = "Microsoft(R) is a registered trademark of Microsoft Corporation in the" wide
		$s8 = "WWW.CeleWare.NET1" ascii
	condition:
		filesize < 100KB and uint16(0) == 0x5A4D and 6 of them
}