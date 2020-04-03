rule APT30_Sample_12 {
	meta:
		description = "FireEye APT30 Report Sample - file c95cd106c1fecbd500f4b97566d8dc96"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		date = "2015/04/13"
		hash = "b02b5720ff0f73f01eb2ba029a58b645c987c4bc"
	strings:
		$s0 = "Richic" fullword ascii
		$s1 = "Accept: image/gif, */*" fullword ascii
		$s2 = "----------------g_nAV=%d,hWnd:0x%X,className:%s,Title:%s,(%d,%d,%d,%d),BOOL=%d" fullword ascii
	condition:
		filesize < 250KB and uint16(0) == 0x5A4D and all of them
}