rule FourElementSword_T9000 {
	meta:
		description = "Detects FourElementSword Malware - file 5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
	strings:
		$x1 = "D:\\WORK\\T9000\\" ascii
		$x2 = "%s\\temp\\HHHH.dat" fullword wide
		$s1 = "Elevate.dll" fullword wide
		$s2 = "ResN32.dll" fullword wide
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword wide
		$s4 = "igfxtray.exe" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 500KB and 1 of ($x*) ) or ( all of them )
}