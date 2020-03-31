rule CN_Honker_MAC_IPMAC {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file IPMAC.exe"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "24d55b6bec5c9fff4cd6f345bacac7abadce1611"
	strings:
		$s1 = "Http://Www.YrYz.Net" fullword wide
		$s2 = "IpMac.txt" fullword ascii
		$s3 = "192.168.0.1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 267KB and all of them
}