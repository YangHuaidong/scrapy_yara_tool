rule CN_Honker_WordpressScanner {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file WordpressScanner.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0b3c5015ba3616cbc616fc9ba805fea73e98bc83"
	strings:
		$s0 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* PEStudio Blacklist: agent */
		$s1 = "(http://www.eyuyan.com)" fullword wide
		$s2 = "GetConnectString" fullword ascii /* PEStudio Blacklist: strings */
		$s4 = "#if !defined(AFX_RESOURCE_DLL) || defined(AFX_TARG_CHS)" fullword ascii /* PEStudio Blacklist: strings */
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}